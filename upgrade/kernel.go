package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"golang.org/x/crypto/ssh"
)

// The kernel that comes with an upgrade (agentcontrol.UpgradeKernel):
// anx-node, AnixOps' own node kernel with ANX, from the private anx
// release, which Control hosts. The Agent stages its package next to the
// release zip; the updater verifies it with the kernel release key below,
// installs LibDir/anx-node (and LibDir/anx-server, the accepting end of
// anx_line transports, when the package holds it) and restarts the Agent,
// which then runs anx-node as its anixcore core (core.DefaultCoreConfigs).
const (
	// KernelBinary is the installed kernel in LibDir.
	KernelBinary = "anx-node"
	// KernelPrevBinary is the kernel kept when a new one is installed.
	KernelPrevBinary = "anx-node.prev"
	// ServerBinary is anx-server, installed next to anx-node from the same
	// package: the Agent runs it for the accepting anx_line ends.
	ServerBinary = "anx-server"
	// ServerPrevBinary is the anx-server kept when a new one is installed.
	ServerPrevBinary = "anx-server.prev"
	// KernelRecord is the installed kernel's version and SHA-256.
	KernelRecord = "anx-node.json"
	// KernelReleaseKey is the anx release's signing key (the anx repository's
	// release/allowed_signers): its SHA256SUMS.sig is `ssh-keygen -Y sign`
	// by this key in KernelSignatureNamespace. Both halves verify with it
	// and with nothing else.
	KernelReleaseKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9RCOAuDwKyWAXIp0szDWKN5t98NKsCK4isHLR05yLT"
	// KernelSignatureNamespace is the namespace of the kernel signature.
	KernelSignatureNamespace = "anx-release"
)

// kernelReleaseKey is KernelReleaseKey; tests sign with their own.
var kernelReleaseKey = KernelReleaseKey

var kernelAssetPattern = regexp.MustCompile(`^anx-node-[0-9a-z.-]+-[a-z0-9_]+-linux-musl\.tar\.gz$`)

// KernelHandOff is the kernel of a HandOff: the package staged as File in
// the staging directory and what verifies it.
type KernelHandOff struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Asset         string `json:"asset"`
	File          string `json:"file"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	Sums          string `json:"sums"`
	SumsSignature string `json:"sums_signature"`
}

// KernelRecordFile is anx-node.json: the installed kernel.
type KernelRecordFile struct {
	Version       string `json:"version"`
	SHA256        string `json:"sha256"`
	InstalledAtMS int64  `json:"installed_at_unix_ms"`
	// Server says whether the package held anx-server. A record without
	// it predates installing anx-server: that kernel counts as installed
	// only with anx-server next to it, so an Agent that skipped it gets it
	// from the next hand-off of the same version.
	Server *bool `json:"server,omitempty"`
}

// ReadKernelRecord reads anx-node.json in libDir.
func ReadKernelRecord(libDir string) (KernelRecordFile, error) {
	var record KernelRecordFile
	data, err := readSmall(filepath.Join(libDir, KernelRecord), maxRecordBytes)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("%s: %w", KernelRecord, err)
	}
	if !agentcontrol.KernelVersionPattern.MatchString(record.Version) || !sha256Pattern.MatchString(record.SHA256) {
		return record, fmt.Errorf("%s does not name a kernel release and its SHA-256", KernelRecord)
	}
	return record, nil
}

// InstalledKernel answers the version of the kernel installed in libDir,
// "" when there is none.
func InstalledKernel(libDir string) string {
	record, err := ReadKernelRecord(libDir)
	if err != nil {
		return ""
	}
	for _, binary := range []string{KernelBinary, ServerBinary} {
		if binary == ServerBinary && record.Server != nil && !*record.Server {
			continue
		}
		if info, err := os.Stat(filepath.Join(libDir, binary)); err != nil || !info.Mode().IsRegular() {
			return ""
		}
	}
	return record.Version
}

// VerifyKernel checks a kernel package against the hand-off: its size and
// SHA-256, that Sums lists it with that SHA-256, and Sums' SSH signature
// by KernelReleaseKey.
func VerifyKernel(data []byte, kernel KernelHandOff) error {
	if int64(len(data)) != kernel.Size {
		return codeError(agentcontrol.UpgradeErrorDigest, "the kernel package is %d bytes, not %d", len(data), kernel.Size)
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != kernel.SHA256 {
		return codeError(agentcontrol.UpgradeErrorDigest, "the kernel package's SHA-256 is %s, not %s", actual, kernel.SHA256)
	}
	if listed, ok := agentcontrol.KernelSum(kernel.Sums, kernel.Asset); !ok || listed != actual {
		return codeError(agentcontrol.UpgradeErrorDigest, "the kernel's SHA256SUMS does not list %s with %s", kernel.Asset, actual)
	}
	if err := VerifySSHSignature([]byte(kernel.Sums), kernel.SumsSignature, kernelReleaseKey, KernelSignatureNamespace); err != nil {
		return codeError(agentcontrol.UpgradeErrorSignature, "the kernel's SHA256SUMS: %v", err)
	}
	return nil
}

// VerifySSHSignature checks an armored SSH signature (`ssh-keygen -Y
// sign`, PROTOCOL.sshsig) of message by authorizedKey (one
// authorized_keys line) in namespace.
func VerifySSHSignature(message []byte, armored, authorizedKey, namespace string) error {
	const begin, end = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"
	text := strings.TrimSpace(armored)
	if !strings.HasPrefix(text, begin) || !strings.HasSuffix(text, end) {
		return errors.New("not an armored SSH signature")
	}
	blob, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text[len(begin):len(text)-len(end)]), ""))
	if err != nil {
		return fmt.Errorf("the signature is not base64: %w", err)
	}
	if !bytes.HasPrefix(blob, []byte("SSHSIG")) {
		return errors.New("the signature has no SSHSIG preamble")
	}
	var wire struct {
		Version       uint32
		PublicKey     []byte
		Namespace     string
		Reserved      []byte
		HashAlgorithm string
		Signature     []byte
	}
	if err := ssh.Unmarshal(blob[6:], &wire); err != nil {
		return fmt.Errorf("the signature is malformed: %w", err)
	}
	if wire.Version != 1 {
		return fmt.Errorf("signature version %d is not 1", wire.Version)
	}
	if wire.Namespace != namespace {
		return fmt.Errorf("the signature's namespace is %q, not %q", wire.Namespace, namespace)
	}
	signer, err := ssh.ParsePublicKey(wire.PublicKey)
	if err != nil {
		return fmt.Errorf("the signature's key: %w", err)
	}
	trusted, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return fmt.Errorf("the trusted key: %w", err)
	}
	if !bytes.Equal(signer.Marshal(), trusted.Marshal()) {
		return errors.New("the signature is not by the kernel release key")
	}
	var digest []byte
	switch wire.HashAlgorithm {
	case "sha512":
		sum := sha512.Sum512(message)
		digest = sum[:]
	case "sha256":
		sum := sha256.Sum256(message)
		digest = sum[:]
	default:
		return fmt.Errorf("hash algorithm %q is not sha256 or sha512", wire.HashAlgorithm)
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(wire.Signature, &signature); err != nil {
		return fmt.Errorf("the signature is malformed: %w", err)
	}
	signed := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace     string
		Reserved      []byte
		HashAlgorithm string
		Hash          []byte
	}{namespace, wire.Reserved, wire.HashAlgorithm, digest})...)
	if err := trusted.Verify(signed, &signature); err != nil {
		return fmt.Errorf("the signature does not verify: %w", err)
	}
	return nil
}

// validKernelHandOff checks the kernel of a hand-off, which comes from the
// unprivileged Agent.
func validKernelHandOff(kernel KernelHandOff) error {
	switch {
	case kernel.Name != agentcontrol.KernelAnxNode:
		return fmt.Errorf("kernel %q is not %s", kernel.Name, agentcontrol.KernelAnxNode)
	case !agentcontrol.KernelVersionPattern.MatchString(kernel.Version):
		return fmt.Errorf("kernel version %q is malformed", kernel.Version)
	case !kernelAssetPattern.MatchString(kernel.Asset) || !strings.HasPrefix(kernel.Asset, agentcontrol.KernelAnxNode+"-"+kernel.Version+"-"):
		return fmt.Errorf("kernel asset %q is malformed", kernel.Asset)
	case kernel.File != kernel.Asset:
		return fmt.Errorf("kernel file %q is not the staged %s", kernel.File, kernel.Asset)
	case kernel.Size <= 0 || kernel.Size > agentcontrol.MaxUpgradeKernelBytes || !sha256Pattern.MatchString(kernel.SHA256):
		return errors.New("the kernel's size or SHA-256 is malformed")
	case kernel.Sums == "" || len(kernel.Sums) > maxRecordBytes || kernel.SumsSignature == "" || len(kernel.SumsSignature) > maxRecordBytes:
		return errors.New("the kernel's SHA256SUMS or signature is missing or too large")
	}
	return nil
}

// installKernel copies the staged kernel package out of the Agent's
// directory, verifies it, unpacks anx-node and anx-server (whose SHA-256s
// SHA256SUMS lists too), checks that anx-node runs, keeps the installed
// ones as *.prev and swaps the new ones in. A package without anx-server
// installs anx-node only.
func (a *Applier) installKernel(ctx context.Context, dir string, kernel KernelHandOff) error {
	lib := a.libDir()
	packagePath, err := copyIn(filepath.Join(dir, kernel.File), lib, kernel.Size)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(packagePath) }()
	data, err := os.ReadFile(packagePath) // #nosec G304 -- a temporary file of LibDir.
	if err != nil {
		return codeError(ErrorInstall, "%v", err)
	}
	if err := VerifyKernel(data, kernel); err != nil {
		return err
	}
	dist := strings.TrimSuffix(kernel.Asset, ".tar.gz") + "/"
	binary, digest, err := unpackListed(data, dist+KernelBinary, lib, kernel.Sums)
	if errors.Is(err, errNoMember) {
		return codeError(ErrorInstall, "the kernel package holds no %s", dist+KernelBinary)
	}
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(binary) }()
	if err := checkKernelRuns(ctx, binary); err != nil {
		return err
	}
	server, _, err := unpackListed(data, dist+ServerBinary, lib, kernel.Sums)
	if errors.Is(err, errNoMember) {
		server = ""
	} else if err != nil {
		return err
	}
	if server != "" {
		defer func() { _ = os.Remove(server) }()
	}
	if err := keepPrevious(lib, KernelBinary, KernelPrevBinary); err != nil {
		return codeError(ErrorInstall, "cannot keep the installed kernel: %v", err)
	}
	if server != "" {
		if err := keepPrevious(lib, ServerBinary, ServerPrevBinary); err != nil {
			return codeError(ErrorInstall, "cannot keep the installed anx-server: %v", err)
		}
	}
	if err := os.Rename(binary, filepath.Join(lib, KernelBinary)); err != nil {
		return codeError(ErrorInstall, "cannot install the kernel: %v", err)
	}
	if server != "" {
		if err := os.Rename(server, filepath.Join(lib, ServerBinary)); err != nil {
			return codeError(ErrorInstall, "cannot install anx-server: %v", err)
		}
	}
	withServer := server != ""
	record, _ := json.MarshalIndent(KernelRecordFile{Version: kernel.Version, SHA256: digest, InstalledAtMS: a.now().UnixMilli(), Server: &withServer}, "", "  ")
	if err := writeFileAtomic(filepath.Join(lib, KernelRecord), append(record, '\n'), 0o644); err != nil {
		return codeError(ErrorInstall, "cannot record the kernel: %v", err)
	}
	return nil
}

// errNoMember is untarFile's answer for a package without the member.
var errNoMember = errors.New("the kernel package does not hold the member")

// unpackListed extracts member into a new file of dir and requires
// SHA256SUMS to list it with its SHA-256; errNoMember when the package
// does not hold it.
func unpackListed(data []byte, member, dir, sums string) (string, string, error) {
	path, digest, err := untarFile(data, member, dir)
	if err != nil {
		return "", "", err
	}
	if listed, ok := agentcontrol.KernelSum(sums, member); !ok || listed != digest {
		_ = os.Remove(path)
		return "", "", codeError(agentcontrol.UpgradeErrorDigest, "the kernel's SHA256SUMS does not list %s with %s", member, digest)
	}
	return path, digest, nil
}

// keepPrevious copies LibDir's name, when installed, to prev.
func keepPrevious(lib, name, prev string) error {
	current := filepath.Join(lib, name)
	if _, err := os.Lstat(current); err != nil {
		return nil
	}
	kept, err := copyFile(current, lib, "."+name+".prev.*", 0o755)
	if err != nil {
		return err
	}
	if err := os.Rename(kept, filepath.Join(lib, prev)); err != nil {
		_ = os.Remove(kept)
		return err
	}
	return nil
}

// removeKernel takes out a kernel that was just installed when the Agent
// did not stay up with it: the kept ones come back, or none.
func (a *Applier) removeKernel() {
	lib := a.libDir()
	_ = os.Remove(filepath.Join(lib, KernelRecord))
	if err := os.Rename(filepath.Join(lib, KernelPrevBinary), filepath.Join(lib, KernelBinary)); err != nil {
		_ = os.Remove(filepath.Join(lib, KernelBinary))
	}
	if err := os.Rename(filepath.Join(lib, ServerPrevBinary), filepath.Join(lib, ServerBinary)); err != nil {
		_ = os.Remove(filepath.Join(lib, ServerBinary))
	}
}

// untarFile extracts the regular file member of a .tar.gz into a new file
// of dir and answers its path and SHA-256, errNoMember when the package
// does not hold it.
func untarFile(data []byte, member, dir string) (string, string, error) {
	compressed, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", "", codeError(ErrorInstall, "the kernel package is not gzip: %v", err)
	}
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return "", "", errNoMember
		}
		if err != nil {
			return "", "", codeError(ErrorInstall, "the kernel package is not a tar: %v", err)
		}
		if strings.TrimPrefix(header.Name, "./") != member || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size > maxBinaryBytes {
			return "", "", codeError(ErrorInstall, "%s is over %d bytes", member, maxBinaryBytes)
		}
		sum := sha256.New()
		path, err := copyReader(io.TeeReader(reader, sum), dir, "."+filepath.Base(member)+".new.*", 0o755, maxBinaryBytes)
		if err != nil {
			return "", "", codeError(ErrorInstall, "cannot unpack %s: %v", member, err)
		}
		return path, hex.EncodeToString(sum.Sum(nil)), nil
	}
}

// checkKernelRuns requires `anx-node version` to answer "anx-node ...".
// It prints the crate version, not the release's, so only the name is
// checked; SHA256SUMS already names the binary.
func checkKernelRuns(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "version").Output() // #nosec G204 -- a verified binary of LibDir.
	if err != nil {
		return codeError(ErrorVersionMismatch, "%s version: %v", KernelBinary, err)
	}
	if fields := strings.Fields(string(output)); len(fields) == 0 || fields[0] != KernelBinary {
		return codeError(ErrorVersionMismatch, "the kernel does not answer as %s: %q", KernelBinary, strings.TrimSpace(string(output)))
	}
	return nil
}
