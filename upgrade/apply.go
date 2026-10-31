package upgrade

import (
	"archive/zip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	log "github.com/sirupsen/logrus"
)

// Applier is the updater's half, `anix-agent upgrade apply` run as root by
// anixops-agent-updater.service. The request comes from the unprivileged
// Agent and is not trusted: the trust anchor is the installed binary that
// runs Apply (its Version and its compiled-in release key).
type Applier struct {
	// Request is request.json; empty is DefaultDir/RequestFile. Its
	// directory is the staging directory, where result.json goes.
	Request string
	// LibDir holds the installed binaries; empty is DefaultLibDir.
	LibDir string
	// Version is the installed release, which runs Apply.
	Version string
	// PublicKey verifies releases; nil is OfficialPublicKey.
	PublicKey ed25519.PublicKey
	// Systemctl is the systemctl binary; empty is "systemctl".
	Systemctl string
	// Unit is the Agent's unit; empty is AgentUnit.
	Unit string
	// StayUp is how long the new Agent must stay active: 30 s by default.
	StayUp time.Duration
	// Poll spaces the checks while it does: 1 s by default.
	Poll time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
}

func (a *Applier) request() string {
	if a.Request != "" {
		return a.Request
	}
	return filepath.Join(DefaultDir, RequestFile)
}

func (a *Applier) libDir() string {
	if a.LibDir != "" {
		return a.LibDir
	}
	return DefaultLibDir
}

func (a *Applier) key() ed25519.PublicKey {
	if a.PublicKey != nil {
		return a.PublicKey
	}
	return officialKey()
}

func (a *Applier) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Applier) systemctl() string {
	if a.Systemctl != "" {
		return a.Systemctl
	}
	return "systemctl"
}

func (a *Applier) unit() string {
	if a.Unit != "" {
		return a.Unit
	}
	return AgentUnit
}

// ErrNoRequest reports that there was no request to apply.
var ErrNoRequest = errors.New("no upgrade request")

// Apply consumes the request, applies it and writes result.json. The
// error is the failure the result records (nil when the Agent runs the
// target), or ErrNoRequest.
func (a *Applier) Apply(ctx context.Context) (Result, error) {
	path := a.request()
	dir := filepath.Dir(path)
	consumed := path + ".applying"
	// Consume it first, so the path unit does not start the updater again.
	if err := os.Rename(path, consumed); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Result{}, ErrNoRequest
		}
		return Result{}, fmt.Errorf("cannot consume %s: %w", path, err)
	}
	defer func() { _ = os.Remove(consumed) }()

	result := Result{Version: a.Version}
	handOff, err := a.readHandOff(consumed)
	if err == nil {
		result.OperationID, result.CampaignID, result.Action = handOff.OperationID, handOff.CampaignID, handOff.Action
		result.TargetVersion, result.PreviousVersion = handOff.TargetVersion, handOff.PreviousVersion
		err = a.apply(ctx, dir, handOff, &result)
	}
	if assetPattern.MatchString(handOff.File) && filepath.Base(handOff.File) == handOff.File {
		_ = os.Remove(filepath.Join(dir, handOff.File))
	}
	if handOff.Kernel != nil && kernelAssetPattern.MatchString(handOff.Kernel.File) && filepath.Base(handOff.Kernel.File) == handOff.Kernel.File {
		_ = os.Remove(filepath.Join(dir, handOff.Kernel.File))
	}
	if err != nil {
		result.ErrorCode, result.Error = ErrorCode(err, ErrorInstall), err.Error()
		if result.Outcome == "" {
			result.Outcome = OutcomeRefused
		}
	}
	result.FinishedMS = a.now().UnixMilli()
	entry := log.WithFields(log.Fields{"component": "agent-updater", "operation_id": result.OperationID, "action": result.Action,
		"target_version": result.TargetVersion, "version": a.Version, "outcome": result.Outcome, "error_code": result.ErrorCode})
	if err != nil {
		entry.WithError(err).Error("The Agent upgrade was not applied")
	} else {
		entry.Info("The Agent upgrade was applied")
	}
	if data, marshalErr := json.MarshalIndent(result, "", "  "); marshalErr == nil {
		if writeErr := writeFileAtomic(filepath.Join(dir, ResultFile), append(data, '\n'), 0o644); writeErr != nil {
			entry.WithError(writeErr).Warn("Could not write the updater's result")
		}
	}
	return result, err
}

func (a *Applier) readHandOff(path string) (HandOff, error) {
	var handOff HandOff
	data, err := readSmall(path, maxHandOffBytes)
	if err != nil {
		return handOff, codeError(agentcontrol.UpgradeErrorInvalidRequest, "%v", err)
	}
	if err := json.Unmarshal(data, &handOff); err != nil {
		return handOff, codeError(agentcontrol.UpgradeErrorInvalidRequest, "the request is not JSON: %v", err)
	}
	invalid := func(format string, args ...any) (HandOff, error) {
		return handOff, codeError(agentcontrol.UpgradeErrorInvalidRequest, format, args...)
	}
	if handOff.Schema != HandOffSchema {
		return invalid("schema %q is not %s", handOff.Schema, HandOffSchema)
	}
	if !validVersion(handOff.TargetVersion) {
		return invalid("target_version %q is not a release tag", handOff.TargetVersion)
	}
	if handOff.PreviousVersion != "" && !validVersion(handOff.PreviousVersion) {
		return invalid("previous_version %q is not a release tag", handOff.PreviousVersion)
	}
	if handOff.Kernel != nil {
		if handOff.Action != agentcontrol.UpgradeActionUpgrade {
			return invalid("only an upgrade stages a kernel")
		}
		if err := validKernelHandOff(*handOff.Kernel); err != nil {
			return invalid("%v", err)
		}
	}
	switch handOff.Action {
	case agentcontrol.UpgradeActionRollback:
		if handOff.File != "" {
			return invalid("a rollback stages no file")
		}
	case agentcontrol.UpgradeActionUpgrade:
		// A kernel alone: the Agent runs the target already.
		if handOff.File == "" && handOff.Kernel != nil {
			break
		}
		if filepath.Base(handOff.File) != handOff.File || !assetPattern.MatchString(handOff.File) {
			return invalid("file %q is not a release zip in the staging directory", handOff.File)
		}
		if handOff.Size <= 0 || handOff.Size > agentcontrol.MaxUpgradeArtifactBytes || !sha256Pattern.MatchString(handOff.SHA256) {
			return invalid("the release's size or SHA-256 is malformed")
		}
	default:
		return invalid("action %q is not upgrade or rollback", handOff.Action)
	}
	return handOff, nil
}

func (a *Applier) apply(ctx context.Context, dir string, handOff HandOff, result *Result) error {
	if agentcontrol.SameAgentVersion(a.Version, handOff.TargetVersion) {
		if handOff.Kernel != nil && handOff.Action == agentcontrol.UpgradeActionUpgrade {
			return a.kernelOnly(ctx, dir, *handOff.Kernel, result)
		}
		result.Outcome = OutcomeCurrent
		return nil
	}
	if handOff.Action == agentcontrol.UpgradeActionRollback {
		return a.rollback(ctx, handOff, result)
	}
	if handOff.File == "" {
		return codeError(agentcontrol.UpgradeErrorInvalidRequest, "an upgrade to %s stages no release", handOff.TargetVersion)
	}
	order, ok := CompareVersions(handOff.TargetVersion, a.Version)
	if !ok {
		return codeError(agentcontrol.UpgradeErrorDowngrade, "cannot order %s against the installed %s", handOff.TargetVersion, a.Version)
	}
	if order < 0 {
		return codeError(agentcontrol.UpgradeErrorDowngrade, "%s is older than the installed %s; only a rollback to the kept release may go back", handOff.TargetVersion, a.Version)
	}
	return a.upgrade(ctx, dir, handOff, result)
}

func (a *Applier) upgrade(ctx context.Context, dir string, handOff HandOff, result *Result) error {
	lib := a.libDir()
	// Copy the release out of the Agent's directory first: what is verified
	// and unpacked is a file only root can change.
	zipPath, err := copyIn(filepath.Join(dir, handOff.File), lib, handOff.Size)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(zipPath) }()
	if err := verifyFile(zipPath, handOff, a.key()); err != nil {
		return err
	}

	newBinary, err := unpack(zipPath, lib)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(newBinary) }()
	if err := a.checkVersion(ctx, newBinary, handOff.TargetVersion); err != nil {
		return err
	}

	// The kernel goes in first: the new Agent starts with it. A kernel
	// that does not verify fails the upgrade before anything changes.
	if handOff.Kernel != nil {
		if err := a.installKernel(ctx, dir, *handOff.Kernel); err != nil {
			return err
		}
		result.Kernel = handOff.Kernel.Version
	}
	current := filepath.Join(lib, BinaryName)
	if _, err := a.keep(current, handOff.TargetVersion); err != nil {
		return err
	}
	if err := os.Rename(newBinary, current); err != nil {
		return codeError(ErrorInstall, "cannot install the new binary: %v", err)
	}
	if err := a.restartAndWatch(ctx); err != nil {
		result.Outcome = OutcomeRestored
		if handOff.Kernel != nil {
			// The previous Agent ran without this kernel.
			a.removeKernel()
			result.Kernel = ""
		}
		if restoreErr := a.restore(ctx); restoreErr != nil {
			return codeError(ErrorStartFailed, "%v; reinstating %s failed too: %v", err, PrevBinary, restoreErr)
		}
		return codeError(ErrorStartFailed, "%v; %s was reinstated", err, a.Version)
	}
	result.Outcome = OutcomeInstalled
	return nil
}

// kernelOnly installs a kernel for the running Agent and restarts it; when
// the Agent does not stay up with it, the kernel comes out again.
func (a *Applier) kernelOnly(ctx context.Context, dir string, kernel KernelHandOff, result *Result) error {
	if InstalledKernel(a.libDir()) == kernel.Version {
		result.Outcome = OutcomeCurrent
		return nil
	}
	if err := a.installKernel(ctx, dir, kernel); err != nil {
		return err
	}
	if err := a.restartAndWatch(ctx); err != nil {
		result.Outcome = OutcomeRestored
		a.removeKernel()
		if _, restartErr := a.run(ctx, "restart", a.unit()); restartErr != nil {
			return codeError(ErrorStartFailed, "%v; restarting without the kernel failed too: %v", err, restartErr)
		}
		return codeError(ErrorStartFailed, "%v; the kernel was taken out again", err)
	}
	result.Outcome, result.Kernel = OutcomeInstalled, kernel.Version
	return nil
}

func (a *Applier) rollback(ctx context.Context, handOff HandOff, result *Result) error {
	lib := a.libDir()
	record, err := ReadPrevRecord(lib)
	if err != nil {
		return codeError(agentcontrol.UpgradeErrorNoPrevious, "no kept release: %v", err)
	}
	if !agentcontrol.SameAgentVersion(record.Version, handOff.TargetVersion) {
		return codeError(agentcontrol.UpgradeErrorNoPrevious, "the kept release is %s, not %s", record.Version, handOff.TargetVersion)
	}
	prev := filepath.Join(lib, PrevBinary)
	sum, err := fileSHA256(prev)
	if err != nil {
		return codeError(agentcontrol.UpgradeErrorNoPrevious, "%v", err)
	}
	if sum != record.SHA256 {
		return codeError(agentcontrol.UpgradeErrorDigest, "%s's SHA-256 is %s, not the recorded %s", PrevBinary, sum, record.SHA256)
	}
	// Unpack the kept binary to a new file before the swap.
	staged, err := copyFile(prev, lib, ".anix-agent.rollback.*", 0o755)
	if err != nil {
		return codeError(ErrorInstall, "%v", err)
	}
	defer func() { _ = os.Remove(staged) }()
	if err := a.checkVersion(ctx, staged, handOff.TargetVersion); err != nil {
		return err
	}
	current := filepath.Join(lib, BinaryName)
	// The binary being left becomes the kept one.
	if _, err := a.keep(current, handOff.TargetVersion); err != nil {
		return err
	}
	if err := os.Rename(staged, current); err != nil {
		return codeError(ErrorInstall, "cannot reinstate %s: %v", handOff.TargetVersion, err)
	}
	if err := a.restartAndWatch(ctx); err != nil {
		result.Outcome = OutcomeRestored
		if restoreErr := a.restore(ctx); restoreErr != nil {
			return codeError(ErrorStartFailed, "%v; reinstating %s failed too: %v", err, a.Version, restoreErr)
		}
		return codeError(ErrorStartFailed, "%v; %s was reinstated", err, a.Version)
	}
	result.Outcome = OutcomeRolledBack
	return nil
}

// keep copies the installed binary to anix-agent.prev with its record.
func (a *Applier) keep(current, replacedFor string) (string, error) {
	lib := a.libDir()
	temp, err := copyFile(current, lib, ".anix-agent.prev.*", 0o755)
	if err != nil {
		return "", codeError(ErrorInstall, "cannot keep the installed binary: %v", err)
	}
	sum, err := fileSHA256(temp)
	if err != nil {
		_ = os.Remove(temp)
		return "", codeError(ErrorInstall, "%v", err)
	}
	if err := os.Rename(temp, filepath.Join(lib, PrevBinary)); err != nil {
		_ = os.Remove(temp)
		return "", codeError(ErrorInstall, "cannot keep the installed binary: %v", err)
	}
	record, _ := json.MarshalIndent(PrevRecordFile{Version: a.Version, SHA256: sum, KeptAtMS: a.now().UnixMilli(), ReplacedFor: replacedFor}, "", "  ")
	if err := writeFileAtomic(filepath.Join(lib, PrevRecord), append(record, '\n'), 0o644); err != nil {
		return "", codeError(ErrorInstall, "cannot record the kept binary: %v", err)
	}
	return sum, nil
}

// restore reinstates anix-agent.prev (the binary that ran before) and
// restarts the Agent.
func (a *Applier) restore(ctx context.Context) error {
	lib := a.libDir()
	temp, err := copyFile(filepath.Join(lib, PrevBinary), lib, ".anix-agent.restore.*", 0o755)
	if err != nil {
		return err
	}
	if err := os.Rename(temp, filepath.Join(lib, BinaryName)); err != nil {
		_ = os.Remove(temp)
		return err
	}
	_, err = a.run(ctx, "restart", a.unit())
	return err
}

// restartAndWatch restarts the Agent and requires it to stay active, with
// one main process, for StayUp: Restart=on-failure would otherwise show a
// crash-looping Agent as active between attempts.
func (a *Applier) restartAndWatch(ctx context.Context) error {
	if output, err := a.run(ctx, "restart", a.unit()); err != nil {
		return fmt.Errorf("systemctl restart %s: %v %s", a.unit(), err, strings.TrimSpace(output))
	}
	stayUp, poll := a.StayUp, a.Poll
	if stayUp <= 0 {
		stayUp = 30 * time.Second
	}
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Now().Add(stayUp)
	pid := ""
	for {
		output, err := a.run(ctx, "show", "--property=ActiveState", "--property=MainPID", a.unit())
		if err != nil {
			return fmt.Errorf("systemctl show %s: %v", a.unit(), err)
		}
		active, mainPID := parseShow(output)
		switch {
		case active != "active":
			return fmt.Errorf("%s is %s after the restart", a.unit(), active)
		case mainPID == "" || mainPID == "0":
			return fmt.Errorf("%s has no main process after the restart", a.unit())
		case pid == "":
			pid = mainPID
		case pid != mainPID:
			return fmt.Errorf("%s restarted (main process %s, then %s)", a.unit(), pid, mainPID)
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func parseShow(output string) (active, mainPID string) {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			active = value
		case "MainPID":
			mainPID = value
		}
	}
	if active == "" {
		active = "unknown"
	}
	return active, mainPID
}

func (a *Applier) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, a.systemctl(), args...).CombinedOutput() // #nosec G204 -- fixed verbs and unit.
	return string(output), err
}

// checkVersion requires binary's `version` to print version.
func (a *Applier) checkVersion(ctx context.Context, binary, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "version").Output() // #nosec G204 -- a verified binary of LibDir.
	if err != nil {
		return codeError(ErrorVersionMismatch, "%s version: %v", filepath.Base(binary), err)
	}
	if !printsVersion(output, version) {
		return codeError(ErrorVersionMismatch, "the binary does not print %s: %q", version, strings.TrimSpace(string(output)))
	}
	return nil
}

// verifyFile verifies the release copied to path.
func verifyFile(path string, handOff HandOff, key ed25519.PublicKey) error {
	data, err := os.ReadFile(path) // #nosec G304 -- a temporary file of LibDir.
	if err != nil {
		return codeError(ErrorInstall, "%v", err)
	}
	return VerifyRelease(data, handOff.Size, handOff.SHA256, handOff.Signature, key)
}

// copyIn copies a staged file of the Agent's directory into dir: a link
// or anything but a regular file is an invalid request, another size a
// digest mismatch.
func copyIn(source, dir string, size int64) (string, error) {
	file, info, err := openRegular(source)
	if err != nil {
		return "", codeError(agentcontrol.UpgradeErrorInvalidRequest, "cannot read the staged release: %v", err)
	}
	defer func() { _ = file.Close() }()
	if info.Size() != size {
		return "", codeError(agentcontrol.UpgradeErrorDigest, "the staged release is %d bytes, not %d", info.Size(), size)
	}
	path, err := copyReader(io.LimitReader(file, size+1), dir, ".upgrade.*.zip", 0o600, size)
	if err != nil {
		return "", codeError(ErrorInstall, "cannot copy the staged release: %v", err)
	}
	return path, nil
}

// copyFile copies a regular file into a new temporary file of dir.
func copyFile(source, dir, pattern string, mode os.FileMode) (string, error) {
	file, _, err := openRegular(source)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	return copyReader(file, dir, pattern, mode, maxBinaryBytes)
}

func copyReader(reader io.Reader, dir, pattern string, mode os.FileMode, limit int64) (string, error) {
	temp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := temp.Name()
	written, err := io.Copy(temp, io.LimitReader(reader, limit+1))
	if err == nil && written > limit {
		err = fmt.Errorf("over %d bytes", limit)
	}
	if err == nil {
		err = temp.Chmod(mode)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// unpack extracts the regular file anix-agent from the release zip into a
// new file of dir; symbolic links (V2bX) and everything else (a gost in an
// older release) are skipped.
func unpack(zipPath, dir string) (binary string, err error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", codeError(ErrorInstall, "the release is not a zip: %v", err)
	}
	defer func() { _ = reader.Close() }()
	cleanup := func() {
		if binary != "" {
			_ = os.Remove(binary)
		}
	}
	for _, entry := range reader.File {
		name := strings.TrimPrefix(entry.Name, "./")
		if name != BinaryName || !entry.Mode().IsRegular() {
			continue
		}
		if entry.UncompressedSize64 > maxBinaryBytes {
			cleanup()
			return "", codeError(ErrorInstall, "%s in the release is over %d bytes", name, maxBinaryBytes)
		}
		if binary != "" {
			cleanup()
			return "", codeError(ErrorInstall, "the release holds %s twice", name)
		}
		path, _, extractErr := extract(entry, dir, "."+name+".new.*")
		if extractErr != nil {
			return "", codeError(ErrorInstall, "cannot unpack %s: %v", name, extractErr)
		}
		binary = path
	}
	if binary == "" {
		return "", codeError(ErrorInstall, "the release holds no %s binary", BinaryName)
	}
	return binary, nil
}

func extract(entry *zip.File, dir, pattern string) (string, string, error) {
	source, err := entry.Open()
	if err != nil {
		return "", "", err
	}
	defer func() { _ = source.Close() }()
	sum := sha256.New()
	path, err := copyReader(io.TeeReader(source, sum), dir, pattern, 0o755, maxBinaryBytes)
	if err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(sum.Sum(nil)), nil
}
