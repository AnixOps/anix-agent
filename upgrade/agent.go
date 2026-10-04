package upgrade

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
)

// DefaultStaleRequest is how long a request.json may wait for the updater
// before the Agent takes it for abandoned (the path unit was stopped after
// the hand-off) and removes it, so the node is not busy for good.
const DefaultStaleRequest = 15 * time.Minute

// Agent is the Agent's half: the agent.upgrade handler. One Agent serves
// every node identity of the process (Shared), so a host that runs
// proxy-<id> and forward-<id> upgrades once.
type Agent struct {
	// Dir is the staging directory; empty is DefaultDir.
	Dir string
	// LibDir holds the installed binaries; empty is DefaultLibDir.
	LibDir string
	// Version is the running release (panel.Version).
	Version string
	// Arch picks the artifact; empty is runtime.GOARCH.
	Arch string
	// PublicKey verifies releases; nil is OfficialPublicKey.
	PublicKey ed25519.PublicKey
	// HTTPClient downloads artifacts; nil uses the system roots and the
	// proxy of the environment.
	HTTPClient *http.Client
	// Systemctl is the systemctl binary; empty is "systemctl".
	Systemctl string
	// UpdaterUnit is the updater's path unit; empty is UpdaterPathUnit.
	UpdaterUnit string
	// StaleRequest defaults to DefaultStaleRequest.
	StaleRequest time.Duration
	// Now defaults to time.Now.
	Now func() time.Time
	// UpdaterActive replaces the systemctl check (tests).
	UpdaterActive func(context.Context) bool

	mu sync.Mutex
	// flight is the upgrade running here, until its hand-off settled.
	flight *flight
}

// flight is one running upgrade.
type flight struct {
	target, action string
	done           chan struct{}
}

func (f *flight) same(target, action string) bool {
	return agentcontrol.SameAgentVersion(f.target, target) && f.action == action
}

var (
	sharedOnce  sync.Once
	sharedAgent *Agent
)

// Shared answers the process's Agent for the installed layout, created
// with version on the first call.
func Shared(version string) *Agent {
	sharedOnce.Do(func() { sharedAgent = &Agent{Version: version} })
	return sharedAgent
}

func (a *Agent) dir() string {
	if a.Dir != "" {
		return a.Dir
	}
	return DefaultDir
}

func (a *Agent) libDir() string {
	if a.LibDir != "" {
		return a.LibDir
	}
	return DefaultLibDir
}

func (a *Agent) arch() string {
	if a.Arch != "" {
		return a.Arch
	}
	return runtime.GOARCH
}

func (a *Agent) key() ed25519.PublicKey {
	if a.PublicKey != nil {
		return a.PublicKey
	}
	return officialKey()
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Available reports whether the Agent may list upgrade.v1: it embeds the
// release key and the updater's path unit is active. systemctl is-active
// needs no privilege, so the sandboxed anixops-agent user can ask; a host
// without systemd (a container) answers false.
func (a *Agent) Available(ctx context.Context) bool {
	if len(a.key()) != ed25519.PublicKeySize {
		return false
	}
	return a.updaterActive(ctx)
}

func (a *Agent) updaterActive(ctx context.Context) bool {
	if a.UpdaterActive != nil {
		return a.UpdaterActive(ctx)
	}
	systemctl, unit := a.Systemctl, a.UpdaterUnit
	if systemctl == "" {
		systemctl = "systemctl"
	}
	if unit == "" {
		unit = UpdaterPathUnit
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, systemctl, "is-active", unit).Output() // #nosec G204 -- fixed verb, configured unit.
	return err == nil && strings.TrimSpace(string(output)) == "active"
}

// Admit refuses, before the acknowledgement, an agent.upgrade that does
// not parse (upgrade_invalid_request) or arrives while another upgrade is
// in progress (upgrade_in_progress). The same upgrade through the host's
// other node identity is admitted: Handle joins it. Other kinds pass.
func (a *Agent) Admit(operation *agentv1pb.DesiredOperation) error {
	if operation.GetKind() != agentcontrol.OperationKindAgentUpgrade {
		return nil
	}
	request, err := agentcontrol.ParseUpgradeRequest(operation.GetPayloadJson())
	if err != nil {
		return &Error{Code: agentcontrol.UpgradeErrorInvalidRequest, Err: err}
	}
	if agentcontrol.SameAgentVersion(a.Version, request.TargetVersion) {
		return nil
	}
	a.mu.Lock()
	running := a.flight
	a.mu.Unlock()
	if running != nil && !running.same(request.TargetVersion, request.Action) {
		return codeError(agentcontrol.UpgradeErrorBusy, "another upgrade is in progress")
	}
	if pending, ok := a.pendingRequest(); ok && !sameHandOff(pending, request) {
		return codeError(agentcontrol.UpgradeErrorBusy, "the updater has not taken the previous request yet")
	}
	return nil
}

func sameHandOff(handOff HandOff, request agentcontrol.UpgradeRequest) bool {
	return agentcontrol.SameAgentVersion(handOff.TargetVersion, request.TargetVersion) && handOff.Action == request.Action
}

// pendingRequest answers a request.json the updater has not consumed, and
// removes one older than StaleRequest. A request it cannot read still
// counts as pending, for no target.
func (a *Agent) pendingRequest() (HandOff, bool) {
	var handOff HandOff
	path := filepath.Join(a.dir(), RequestFile)
	info, err := os.Lstat(path)
	if err != nil {
		return handOff, false
	}
	stale := a.StaleRequest
	if stale <= 0 {
		stale = DefaultStaleRequest
	}
	if a.now().Sub(info.ModTime()) < stale {
		if data, err := readSmall(path, maxHandOffBytes); err == nil {
			_ = json.Unmarshal(data, &handOff)
		}
		return handOff, true
	}
	log.WithFields(log.Fields{"component": "agent-upgrade", "request": path, "age": a.now().Sub(info.ModTime()).Round(time.Second)}).
		Warn("The updater never took the upgrade request; removing it (is anixops-agent-updater.path active?)")
	_ = os.Remove(path)
	return handOff, false
}

// begin claims the Agent for an upgrade. When another runs it answers it
// instead (running non-nil).
func (a *Agent) begin(target, action string) (running *flight) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.flight != nil {
		return a.flight
	}
	a.flight = &flight{target: target, action: action, done: make(chan struct{})}
	return nil
}

func (a *Agent) end() {
	a.mu.Lock()
	if a.flight != nil {
		close(a.flight.done)
		a.flight = nil
	}
	a.mu.Unlock()
}

// state answers state_json, and an error for FAILED.
func state(phase, version string, err error) (json.RawMessage, error) {
	value := agentcontrol.UpgradeState{Phase: phase, Version: version}
	if err != nil {
		value.ErrorCode = ErrorCode(err, agentcontrol.UpgradeErrorInvalidRequest)
	}
	data, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return nil, marshalErr
	}
	return data, err
}

func progress(ctx context.Context, phase, version string) {
	data, _ := json.Marshal(agentcontrol.UpgradeState{Phase: phase, Version: version})
	if err := agentapi.ReportProgress(ctx, data); err != nil {
		log.WithError(err).WithField("component", "agent-upgrade").Debug("Could not report the upgrade's progress")
	}
}

// Handle runs an agent.upgrade (PROTOCOL.md "Agent upgrades"): current
// when the Agent runs the target already; otherwise download and verify
// (upgrade) or check the kept release (rollback), then hand off to the
// updater. It needs the client's operation context (api/agent): the
// request reaches the updater only after the SUCCEEDED handed_off state
// was sent.
func (a *Agent) Handle(ctx context.Context, operation *agentv1pb.DesiredOperation) (json.RawMessage, error) {
	request, err := agentcontrol.ParseUpgradeRequest(operation.GetPayloadJson())
	if err != nil {
		return state("", "", &Error{Code: agentcontrol.UpgradeErrorInvalidRequest, Err: err})
	}
	if agentcontrol.SameAgentVersion(a.Version, request.TargetVersion) {
		return state(agentcontrol.UpgradePhaseCurrent, a.Version, nil)
	}
	// The same upgrade through the host's other node identity waits for
	// the running one and joins its hand-off; another one is refused.
	for {
		running := a.begin(request.TargetVersion, request.Action)
		if running == nil {
			break
		}
		if !running.same(request.TargetVersion, request.Action) {
			return state("", a.Version, codeError(agentcontrol.UpgradeErrorBusy, "another upgrade is in progress"))
		}
		select {
		case <-running.done:
		case <-ctx.Done():
			return state("", a.Version, codeError(agentcontrol.UpgradeErrorBusy, "the same upgrade is still in progress"))
		}
	}
	handedOff := false
	defer func() {
		if !handedOff {
			a.end()
		}
	}()
	if pending, ok := a.pendingRequest(); ok {
		if sameHandOff(pending, request) {
			// Already with the updater, which restarts the whole Agent.
			return state(agentcontrol.UpgradePhaseHandedOff, request.TargetVersion, nil)
		}
		return state("", a.Version, codeError(agentcontrol.UpgradeErrorBusy, "the updater has not taken the previous request yet"))
	}
	logger := log.WithFields(log.Fields{"component": "agent-upgrade", "operation_id": operation.GetOperationId(),
		"campaign_id": request.CampaignID, "action": request.Action, "target_version": request.TargetVersion, "version": a.Version})

	handOff := HandOff{
		Schema: HandOffSchema, OperationID: operation.GetOperationId(), CampaignID: request.CampaignID,
		Action: request.Action, TargetVersion: request.TargetVersion, PreviousVersion: request.PreviousVersion,
		RequestedAtMS: a.now().UnixMilli(),
	}
	staged := ""
	switch request.Action {
	case agentcontrol.UpgradeActionUpgrade:
		artifact, ok := request.Artifact(a.arch())
		if !ok {
			return state("", a.Version, codeError(agentcontrol.UpgradeErrorNoArtifact, "the release has no artifact for %s", a.arch()))
		}
		if !a.updaterActive(ctx) {
			return state("", a.Version, codeError(agentcontrol.UpgradeErrorUpdater, "%s is not active", UpdaterPathUnit))
		}
		logger.WithField("asset", artifact.Asset).Info("Downloading the Agent release Control pushed")
		staged, err = a.stage(ctx, artifact)
		if err != nil {
			logger.WithError(err).Warn("The Agent release could not be staged")
			return state("", a.Version, err)
		}
		handOff.Arch, handOff.File, handOff.Size = artifact.Arch, filepath.Base(staged), artifact.Size
		handOff.SHA256, handOff.Signature = artifact.SHA256, strings.TrimSpace(artifact.Signature)
	case agentcontrol.UpgradeActionRollback:
		record, err := ReadPrevRecord(a.libDir())
		if err != nil {
			return state("", a.Version, codeError(agentcontrol.UpgradeErrorNoPrevious, "no kept release: %v", err))
		}
		if !agentcontrol.SameAgentVersion(record.Version, request.TargetVersion) {
			return state("", a.Version, codeError(agentcontrol.UpgradeErrorNoPrevious, "the kept release is %s, not %s", record.Version, request.TargetVersion))
		}
	}

	if !a.updaterActive(ctx) {
		a.discard(staged)
		return state("", a.Version, codeError(agentcontrol.UpgradeErrorUpdater, "%s is not active", UpdaterPathUnit))
	}
	data, err := json.Marshal(handOff)
	if err != nil {
		a.discard(staged)
		return state("", a.Version, &Error{Code: agentcontrol.UpgradeErrorUpdater, Err: err})
	}
	temp, err := a.writeTemp(data)
	if err != nil {
		a.discard(staged)
		return state("", a.Version, codeError(agentcontrol.UpgradeErrorUpdater, "cannot write the request: %v", err))
	}
	final := filepath.Join(a.dir(), RequestFile)
	registered := agentapi.AfterTerminal(ctx, func(phase agentv1pb.ObservedPhase) {
		defer a.end()
		if phase != agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED {
			logger.WithField("phase", phase.String()).Warn("The upgrade did not end handed off; dropping the request")
			_ = os.Remove(temp)
			a.discard(staged)
			return
		}
		if err := os.Rename(temp, final); err != nil {
			logger.WithError(err).Error("Could not hand the upgrade to the updater")
			_ = os.Remove(temp)
			a.discard(staged)
			return
		}
		logger.Info("Handed the upgrade to the updater, which restarts the Agent")
	})
	if !registered {
		_ = os.Remove(temp)
		a.discard(staged)
		return state("", a.Version, codeError(agentcontrol.UpgradeErrorUpdater, "no operation context to hand off from"))
	}
	handedOff = true
	return state(agentcontrol.UpgradePhaseHandedOff, request.TargetVersion, nil)
}

// stage downloads artifact into the staging directory and verifies it; a
// release that does not verify is removed.
func (a *Agent) stage(ctx context.Context, artifact agentcontrol.UpgradeArtifact) (string, error) {
	dir := a.dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", codeError(agentcontrol.UpgradeErrorDownload, "cannot create %s: %v", dir, err)
	}
	a.cleanStaging()
	progress(ctx, agentcontrol.UpgradePhaseDownloading, a.Version)
	temp, err := a.download(ctx, artifact)
	if err != nil {
		return "", err
	}
	progress(ctx, agentcontrol.UpgradePhaseVerifying, a.Version)
	data, err := readSmall(temp, artifact.Size)
	if err == nil {
		err = VerifyRelease(data, artifact.Size, artifact.SHA256, artifact.Signature, a.key())
	} else {
		err = codeError(agentcontrol.UpgradeErrorDigest, "%v", err)
	}
	if err != nil {
		_ = os.Remove(temp)
		return "", err
	}
	path := filepath.Join(dir, artifact.Asset)
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return "", codeError(agentcontrol.UpgradeErrorDownload, "cannot stage the release: %v", err)
	}
	return path, nil
}

// download fetches artifact.URL into a temporary file of the staging
// directory, at most artifact.Size bytes: more is a size mismatch
// (upgrade_digest_mismatch).
func (a *Agent) download(ctx context.Context, artifact agentcontrol.UpgradeArtifact) (string, error) {
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 15 * time.Second}}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", codeError(agentcontrol.UpgradeErrorDownload, "%v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return "", codeError(agentcontrol.UpgradeErrorDownload, "%v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", codeError(agentcontrol.UpgradeErrorDownload, "%s answered %s", artifact.URL, response.Status)
	}
	if response.ContentLength > artifact.Size {
		return "", codeError(agentcontrol.UpgradeErrorDigest, "the release is %d bytes, not %d", response.ContentLength, artifact.Size)
	}
	file, err := os.CreateTemp(a.dir(), "."+artifact.Asset+".*.tmp")
	if err != nil {
		return "", codeError(agentcontrol.UpgradeErrorDownload, "%v", err)
	}
	name := file.Name()
	written, err := io.Copy(file, io.LimitReader(response.Body, artifact.Size+1))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	switch {
	case err != nil:
		_ = os.Remove(name)
		return "", codeError(agentcontrol.UpgradeErrorDownload, "%v", err)
	case written > artifact.Size:
		_ = os.Remove(name)
		return "", codeError(agentcontrol.UpgradeErrorDigest, "the release is over %d bytes", artifact.Size)
	}
	return name, nil
}

// cleanStaging removes what an earlier upgrade left: staged zips and
// temporary requests, never request.json or the updater's result.
func (a *Agent) cleanStaging() {
	entries, err := os.ReadDir(a.dir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if assetPattern.MatchString(name) || (strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp")) {
			_ = os.Remove(filepath.Join(a.dir(), name))
		}
	}
}

func (a *Agent) discard(staged string) {
	if staged != "" {
		_ = os.Remove(staged)
	}
}

// writeTemp writes the request to a temporary file next to request.json.
func (a *Agent) writeTemp(data []byte) (string, error) {
	temp, err := os.CreateTemp(a.dir(), "."+RequestFile+".*.tmp")
	if err != nil {
		return "", err
	}
	name := temp.Name()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// LogLastResult logs the updater's result.json, once: it is renamed to
// result.json.seen after.
func (a *Agent) LogLastResult() {
	path := filepath.Join(a.dir(), ResultFile)
	data, err := readSmall(path, maxRecordBytes)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.WithError(err).WithField("component", "agent-upgrade").Warn("Could not read the updater's result")
		}
		return
	}
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		log.WithError(err).WithField("component", "agent-upgrade").Warn("The updater's result is not JSON")
	} else {
		entry := log.WithFields(log.Fields{
			"component": "agent-upgrade", "operation_id": result.OperationID, "campaign_id": result.CampaignID,
			"action": result.Action, "target_version": result.TargetVersion, "outcome": result.Outcome,
			"error_code": result.ErrorCode, "error": result.Error, "gost_staged": result.GostStaged,
			"finished_at": time.UnixMilli(result.FinishedMS).UTC().Format(time.RFC3339), "version": a.Version,
		})
		switch result.Outcome {
		case OutcomeInstalled, OutcomeRolledBack, OutcomeCurrent:
			entry.Info("The updater applied the last Control-pushed upgrade")
		default:
			entry.Warn("The updater did not apply the last Control-pushed upgrade")
		}
	}
	if err := os.Rename(path, path+".seen"); err != nil {
		log.WithError(err).WithField("component", "agent-upgrade").Debug("Could not set the updater's result aside")
	}
}
