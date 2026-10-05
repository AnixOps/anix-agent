// Package upgrade carries out Control-pushed Agent upgrades (upgrade.v1,
// anix-control sdk/api/agent/v1/PROTOCOL.md "Agent upgrades",
// forward-sdk.md section 9 "Upgrades (O4)", owner decision H19).
//
// Control decides the batches; an Agent never upgrades on its own. Two
// halves run on a node:
//
//   - The Agent (Agent, as the unprivileged anixops-agent user) answers the
//     agent.upgrade operation: it downloads the release zip into the
//     staging directory /var/lib/anixops-agent/upgrade, verifies its size,
//     SHA-256 and Ed25519 signature with the official release key compiled
//     in (OfficialPublicKey, never a key Control sends), and hands it to the
//     privileged updater by writing request.json. The observed state goes
//     first, the request second, because the updater restarts the Agent.
//   - The updater (Applier, `anix-agent upgrade apply`, run as root by
//     anixops-agent-updater.service when anixops-agent-updater.path sees the
//     request) trusts nothing in the request: it verifies the release again
//     with the key of the installed binary, refuses a downgrade other than a
//     rollback to the kept release, keeps the running binary as
//     anix-agent.prev, swaps the new one in atomically, restarts
//     anix-agent.service and reinstates the previous binary when the new
//     Agent does not stay up. It never restarts anixops-gost.service.
package upgrade

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
)

// OfficialPublicKey is the official AnixOps release key
// (plugins.official_public_key, OFFICIAL_PUBLIC_KEY of anix-control's
// install.sh and ANIXOPS_OFFICIAL_PUBLIC_KEY of release.yml): base64 of the
// raw Ed25519 public key. Release zips are signed with it; both halves
// verify with it and with nothing else.
const OfficialPublicKey = "jW26nr2tbthASoeq6RmIpx8Ah+uhPNIv9V1ewRVb1VE="

// The installed layout (anix-control internal/agentinstall/install.sh).
const (
	// DefaultLibDir holds the installed binaries, root-owned.
	DefaultLibDir = "/usr/lib/anixops-agent"
	// DefaultDir is the staging directory the Agent may write.
	DefaultDir = "/var/lib/anixops-agent/upgrade"
	// UpdaterPathUnit starts the updater when RequestFile appears.
	UpdaterPathUnit = "anixops-agent-updater.path"
	// AgentUnit is the Agent's unit, which the updater restarts.
	AgentUnit = "anix-agent.service"
	// GostUnit is gost's unit, which nothing here restarts.
	GostUnit = "anixops-gost.service"
	// RelayUnit is the experimental anixops relay's unit, which nothing here
	// restarts either.
	RelayUnit = "anixops-relay.service"

	// RequestFile is the hand-off from the Agent to the updater.
	RequestFile = "request.json"
	// ResultFile is the updater's outcome, which the next Agent logs.
	ResultFile = "result.json"
	// BinaryName is the Agent binary in LibDir and in the release zip.
	BinaryName = "anix-agent"
	// PrevBinary is the binary kept for a rollback, PrevRecord its record.
	PrevBinary = "anix-agent.prev"
	PrevRecord = "anix-agent.prev.json"
	// GostBinary is the pinned gost in LibDir and in the release zip.
	GostBinary = "gost"

	// HandOffSchema is HandOff.Schema.
	HandOffSchema = "anixops.agent-upgrade-handoff/v1"

	// maxHandOffBytes bounds request.json, maxRecordBytes the small JSON
	// files, maxBinaryBytes an unpacked binary.
	maxHandOffBytes = 16 << 10
	maxRecordBytes  = 64 << 10
	maxBinaryBytes  = 512 << 20
)

// PinnedGostSHA256 is the SHA-256 of the gost binary every Agent release
// ships, per GOARCH (H20: release.yml GOST_LINUX_*_BINARY_SHA256, gost
// 3.2.6). The updater stages a release's gost only when it is this one.
var PinnedGostSHA256 = map[string]string{
	"amd64": "a2aea24efb4597b5f57b35b8e1bbcc59f439b80723854d4371f6828b46682ffb",
	"arm64": "343c3e003996ca0437b9cc47dd1500cd0475ba09f5a5f17e50851854e06a1ca7",
}

// Error codes the updater writes to result.json besides the agentcontrol
// UpgradeError* codes.
const (
	// ErrorVersionMismatch: the unpacked binary does not print the target.
	ErrorVersionMismatch = "upgrade_version_mismatch"
	// ErrorStartFailed: the new Agent did not stay active; the previous
	// binary was reinstated.
	ErrorStartFailed = "upgrade_start_failed"
	// ErrorInstall: a file could not be written or swapped.
	ErrorInstall = "upgrade_install_failed"
)

// Error is a failure with one of the upgrade_* codes.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func codeError(code string, format string, args ...any) *Error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// ErrorCode answers the code err carries, or fallback.
func ErrorCode(err error, fallback string) string {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return fallback
}

// HandOff is request.json: what the Agent asks the updater to do. The
// updater checks every field again; File names a file in the staging
// directory, never a path.
type HandOff struct {
	Schema          string `json:"schema"`
	OperationID     string `json:"operation_id"`
	CampaignID      string `json:"campaign_id"`
	Action          string `json:"action"`
	TargetVersion   string `json:"target_version"`
	PreviousVersion string `json:"previous_version,omitempty"`
	Arch            string `json:"arch,omitempty"`
	File            string `json:"file,omitempty"`
	Size            int64  `json:"size,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	Signature       string `json:"signature,omitempty"`
	RequestedAtMS   int64  `json:"requested_at_unix_ms"`
}

// PrevRecordFile is anix-agent.prev.json: the kept binary's version and
// SHA-256.
type PrevRecordFile struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	KeptAtMS    int64  `json:"kept_at_unix_ms"`
	ReplacedFor string `json:"replaced_for,omitempty"`
}

// Outcomes of Result.
const (
	OutcomeInstalled  = "installed"
	OutcomeRolledBack = "rolled_back"
	OutcomeCurrent    = "current"
	OutcomeRestored   = "restored"
	OutcomeRefused    = "refused"
)

// Result is result.json.
type Result struct {
	OperationID     string `json:"operation_id,omitempty"`
	CampaignID      string `json:"campaign_id,omitempty"`
	Action          string `json:"action,omitempty"`
	TargetVersion   string `json:"target_version,omitempty"`
	PreviousVersion string `json:"previous_version,omitempty"`
	// Version is what the updater ran as (the installed release).
	Version    string `json:"version,omitempty"`
	Outcome    string `json:"outcome"`
	ErrorCode  string `json:"error_code,omitempty"`
	Error      string `json:"error,omitempty"`
	GostStaged bool   `json:"gost_staged,omitempty"`
	FinishedMS int64  `json:"finished_at_unix_ms"`
}

var (
	versionPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-(alpha|beta|rc)(?:\.([0-9]+))?)?$`)
	assetPattern   = regexp.MustCompile(`^anix-agent-linux-[a-z0-9-]+\.zip$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParsePublicKey decodes a base64 raw Ed25519 public key.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("the release key is not base64 of a raw Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

// officialKey is OfficialPublicKey, decoded.
func officialKey() ed25519.PublicKey {
	key, err := ParsePublicKey(OfficialPublicKey)
	if err != nil {
		return nil
	}
	return key
}

// CompareVersions orders two release tags (with or without "v"): -1, 0 or
// 1, with alpha < beta < rc < the release. ok is false when either is not
// a release tag.
func CompareVersions(a, b string) (result int, ok bool) {
	pa, okA := parseVersion(a)
	pb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	for i := range pa {
		switch {
		case pa[i] < pb[i]:
			return -1, true
		case pa[i] > pb[i]:
			return 1, true
		}
	}
	return 0, true
}

// parseVersion answers major, minor, patch, the pre-release rank (alpha 0,
// beta 1, rc 2, release 3) and its number.
func parseVersion(version string) ([5]int, bool) {
	var parts [5]int
	match := versionPattern.FindStringSubmatch(strings.TrimSpace(version))
	if match == nil {
		return parts, false
	}
	for i := 1; i <= 3; i++ {
		n, err := strconv.Atoi(match[i])
		if err != nil {
			return parts, false
		}
		parts[i-1] = n
	}
	parts[3] = map[string]int{"alpha": 0, "beta": 1, "rc": 2, "": 3}[match[4]]
	if match[5] != "" {
		n, err := strconv.Atoi(match[5])
		if err != nil {
			return parts, false
		}
		parts[4] = n
	}
	return parts, true
}

// validVersion reports whether version is a release tag.
func validVersion(version string) bool {
	_, ok := parseVersion(version)
	return ok && strings.HasPrefix(version, "v")
}

// VerifyRelease checks data, a release zip, against its size, lowercase hex
// SHA-256 and base64 Ed25519 signature by key: upgrade_digest_mismatch or
// upgrade_signature_invalid.
func VerifyRelease(data []byte, size int64, digest, signature string, key ed25519.PublicKey) error {
	if int64(len(data)) != size {
		return codeError(agentcontrol.UpgradeErrorDigest, "the release is %d bytes, not %d", len(data), size)
	}
	sum := sha256.Sum256(data)
	if actual := hex.EncodeToString(sum[:]); actual != strings.ToLower(strings.TrimSpace(digest)) {
		return codeError(agentcontrol.UpgradeErrorDigest, "the release's SHA-256 is %s, not %s", actual, digest)
	}
	if len(key) != ed25519.PublicKeySize {
		return codeError(agentcontrol.UpgradeErrorSignature, "no release key to verify the signature with")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return codeError(agentcontrol.UpgradeErrorSignature, "the signature is not base64 of an Ed25519 signature")
	}
	if !ed25519.Verify(key, data, sig) {
		return codeError(agentcontrol.UpgradeErrorSignature, "the release signature does not verify with the official release key")
	}
	return nil
}

// openRegular opens path without following a symbolic link at its last
// element and requires a regular file: the staging directory belongs to
// the unprivileged Agent.
func openRegular(path string) (*os.File, os.FileInfo, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, info, nil
}

// readSmall reads a regular file of at most limit bytes.
func readSmall(path string, limit int64) ([]byte, error) {
	file, info, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}

// ReadPrevRecord reads anix-agent.prev.json in libDir.
func ReadPrevRecord(libDir string) (PrevRecordFile, error) {
	var record PrevRecordFile
	data, err := readSmall(filepath.Join(libDir, PrevRecord), maxRecordBytes)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("%s: %w", PrevRecord, err)
	}
	if !validVersion(record.Version) || !sha256Pattern.MatchString(record.SHA256) {
		return record, fmt.Errorf("%s does not name a release and its SHA-256", PrevRecord)
	}
	return record, nil
}

// writeFileAtomic writes data to path through a new temporary file in the
// same directory and a rename, so a path someone else prepared (a link in
// the Agent's directory) is replaced, never written through.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// fileSHA256 answers the SHA-256 of a regular file.
func fileSHA256(path string) (string, error) {
	file, _, err := openRegular(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// printsVersion reports whether output (a binary's `version`) names
// version as one of its words.
func printsVersion(output []byte, version string) bool {
	for _, field := range bytes.Fields(output) {
		if agentcontrol.SameAgentVersion(string(field), version) {
			return true
		}
	}
	return false
}
