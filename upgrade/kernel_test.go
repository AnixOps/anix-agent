package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnixOps/anix-agent/v5/conf"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"golang.org/x/crypto/ssh"
)

// kernelKey is a test kernel release key: it signs like `ssh-keygen -Y
// sign` (PROTOCOL.sshsig) and stands in for KernelReleaseKey.
type kernelKey struct {
	signer     ssh.Signer
	authorized string
}

func newKernelKey(t *testing.T) kernelKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return kernelKey{signer: signer, authorized: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))}
}

// trust makes k the kernel release key for the test.
func (k kernelKey) trust(t *testing.T) {
	t.Helper()
	previous := kernelReleaseKey
	kernelReleaseKey = k.authorized
	t.Cleanup(func() { kernelReleaseKey = previous })
}

func (k kernelKey) sign(t *testing.T, message []byte, namespace string) string {
	t.Helper()
	hash := sha512.Sum512(message)
	signed := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace     string
		Reserved      []byte
		HashAlgorithm string
		Hash          []byte
	}{namespace, nil, "sha512", hash[:]})...)
	signature, err := k.signer.Sign(rand.Reader, signed)
	if err != nil {
		t.Fatal(err)
	}
	blob := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Version       uint32
		PublicKey     []byte
		Namespace     string
		Reserved      []byte
		HashAlgorithm string
		Signature     []byte
	}{1, k.signer.PublicKey().Marshal(), namespace, nil, "sha512", ssh.Marshal(signature)})...)
	encoded := base64.StdEncoding.EncodeToString(blob)
	var armored strings.Builder
	armored.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(encoded) > 70 {
		armored.WriteString(encoded[:70] + "\n")
		encoded = encoded[70:]
	}
	armored.WriteString(encoded + "\n-----END SSH SIGNATURE-----\n")
	return armored.String()
}

// fakeKernel answers `version` like anx-node.
func fakeKernel(broken bool) []byte {
	marker := ""
	if broken {
		marker = "exit 3\n"
	}
	return []byte("#!/bin/sh\n" + marker + "if [ \"$1\" = version ]; then echo 'anx-node 0.1.0'; fi\n")
}

// kernelPackage is an anx-node release package for version holding
// binary, its SHA256SUMS (package and binary, as the release lists them)
// and the hand-off naming it.
func kernelPackage(t *testing.T, key kernelKey, version string, binary []byte) ([]byte, KernelHandOff) {
	t.Helper()
	dist := "anx-node-" + version + "-x86_64-linux-musl"
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	for _, entry := range []struct {
		name string
		data []byte
	}{{dist + "/LICENSE", []byte("license")}, {dist + "/anx-server", []byte("server")}, {dist + "/anx-node", binary}} {
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o755, Size: int64(len(entry.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	asset := dist + ".tar.gz"
	sums := digest(data) + "  " + asset + "\n" + digest(binary) + "  " + dist + "/anx-node\n" + digest([]byte("server")) + "  " + dist + "/anx-server\n"
	return data, KernelHandOff{
		Name: agentcontrol.KernelAnxNode, Version: version, Arch: "amd64", Asset: asset, File: asset,
		Size: int64(len(data)), SHA256: digest(data), Sums: sums, SumsSignature: key.sign(t, []byte(sums), KernelSignatureNamespace),
	}
}

func TestVerifySSHSignature(t *testing.T) {
	key := newKernelKey(t)
	message := []byte("abc  anx-node-0.1.0-x86_64-linux-musl.tar.gz\n")
	signature := key.sign(t, message, KernelSignatureNamespace)
	if err := VerifySSHSignature(message, signature, key.authorized, KernelSignatureNamespace); err != nil {
		t.Fatalf("a good signature: %v", err)
	}
	other := newKernelKey(t)
	for name, check := range map[string]func() error{
		"other message": func() error {
			return VerifySSHSignature([]byte("abd"), signature, key.authorized, KernelSignatureNamespace)
		},
		"other key": func() error {
			return VerifySSHSignature(message, signature, other.authorized, KernelSignatureNamespace)
		},
		"other namespace": func() error { return VerifySSHSignature(message, signature, key.authorized, "file") },
		"signed elsewhere": func() error {
			return VerifySSHSignature(message, key.sign(t, message, "file"), key.authorized, KernelSignatureNamespace)
		},
		"not armored": func() error { return VerifySSHSignature(message, "c2ln", key.authorized, KernelSignatureNamespace) },
		"truncated": func() error {
			return VerifySSHSignature(message, "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----", key.authorized, KernelSignatureNamespace)
		},
	} {
		if err := check(); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// The embedded key parses.
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(KernelReleaseKey)); err != nil {
		t.Fatalf("KernelReleaseKey: %v", err)
	}
}

func TestVerifyKernel(t *testing.T) {
	key := newKernelKey(t)
	key.trust(t)
	data, kernel := kernelPackage(t, key, "0.1.0-alpha.2", fakeKernel(false))
	if err := VerifyKernel(data, kernel); err != nil {
		t.Fatalf("VerifyKernel: %v", err)
	}
	for name, mutate := range map[string]func(*KernelHandOff){
		"size":     func(k *KernelHandOff) { k.Size++ },
		"sha256":   func(k *KernelHandOff) { k.SHA256 = strings.Repeat("1", 64) },
		"unlisted": func(k *KernelHandOff) { k.Sums = strings.Replace(k.Sums, k.Asset, "other.tar.gz", 1) },
		"signature": func(k *KernelHandOff) {
			k.SumsSignature = newKernelKey(t).sign(t, []byte(k.Sums), KernelSignatureNamespace)
		},
	} {
		changed := kernel
		mutate(&changed)
		err := VerifyKernel(data, changed)
		var coded *Error
		if !errors.As(err, &coded) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func (f *applyFixture) stageKernel(t *testing.T, key kernelKey, binary []byte) KernelHandOff {
	t.Helper()
	data, kernel := kernelPackage(t, key, "0.1.0-alpha.2", binary)
	writeFile(t, filepath.Join(f.dir, kernel.File), data, 0o600)
	return kernel
}

func TestApplyInstallsTheKernelWithTheAgent(t *testing.T) {
	f := newApplyFixture(t)
	key := newKernelKey(t)
	key.trust(t)
	kernel := f.stageKernel(t, key, fakeKernel(false))
	f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", false)}), func(h *HandOff) { h.Kernel = &kernel })
	result, err := f.applier.Apply(context.Background())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.Outcome != OutcomeInstalled || result.Kernel != "0.1.0-alpha.2" {
		t.Fatalf("result %+v", result)
	}
	if !bytes.Equal(readFile(t, filepath.Join(f.lib, KernelBinary)), fakeKernel(false)) {
		t.Fatal("the kernel is not installed")
	}
	if !bytes.Equal(readFile(t, filepath.Join(f.lib, ServerBinary)), []byte("server")) {
		t.Fatal("anx-server is not installed with the kernel")
	}
	if InstalledKernel(f.lib) != "0.1.0-alpha.2" {
		t.Fatalf("InstalledKernel = %q", InstalledKernel(f.lib))
	}
	if exists(filepath.Join(f.dir, kernel.File)) {
		t.Fatal("the staged kernel package was left behind")
	}
}

func TestApplyInstallsAKernelForTheRunningAgent(t *testing.T) {
	f := newApplyFixture(t)
	key := newKernelKey(t)
	key.trust(t)
	kernel := f.stageKernel(t, key, fakeKernel(false))
	f.request(t, HandOff{
		Schema: HandOffSchema, OperationID: "op-k", CampaignID: "c-1", Action: agentcontrol.UpgradeActionUpgrade,
		TargetVersion: "v4.1.0", Kernel: &kernel,
	})
	result, err := f.applier.Apply(context.Background())
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if result.Outcome != OutcomeInstalled || result.Kernel != "0.1.0-alpha.2" || f.restarts(t) != 1 {
		t.Fatalf("result %+v, %d restarts", result, f.restarts(t))
	}
	if !bytes.Equal(readFile(t, filepath.Join(f.lib, BinaryName)), f.old) {
		t.Fatal("the Agent binary changed")
	}
	// A replay finds it installed.
	f.stageKernel(t, key, fakeKernel(false))
	f.request(t, HandOff{
		Schema: HandOffSchema, OperationID: "op-k", CampaignID: "c-1", Action: agentcontrol.UpgradeActionUpgrade,
		TargetVersion: "v4.1.0", Kernel: &kernel,
	})
	if result, err := f.applier.Apply(context.Background()); err != nil || result.Outcome != OutcomeCurrent {
		t.Fatalf("replay: %+v %v", result, err)
	}
}

func TestApplyRefusesABadKernel(t *testing.T) {
	key := newKernelKey(t)
	key.trust(t)
	for name, mutate := range map[string]func(*testing.T, *applyFixture, *KernelHandOff){
		"foreign signature": func(t *testing.T, _ *applyFixture, k *KernelHandOff) {
			k.SumsSignature = newKernelKey(t).sign(t, []byte(k.Sums), KernelSignatureNamespace)
		},
		"binary not listed": func(t *testing.T, _ *applyFixture, k *KernelHandOff) {
			lines := strings.Split(k.Sums, "\n")
			k.Sums = lines[0] + "\n"
			k.SumsSignature = key.sign(t, []byte(k.Sums), KernelSignatureNamespace)
		},
		"anx-server not listed": func(t *testing.T, _ *applyFixture, k *KernelHandOff) {
			lines := strings.Split(k.Sums, "\n")
			k.Sums = lines[0] + "\n" + lines[1] + "\n"
			k.SumsSignature = key.sign(t, []byte(k.Sums), KernelSignatureNamespace)
		},
		"does not run": func(t *testing.T, f *applyFixture, k *KernelHandOff) {
			*k = f.stageKernel(t, key, fakeKernel(true))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newApplyFixture(t)
			kernel := f.stageKernel(t, key, fakeKernel(false))
			mutate(t, f, &kernel)
			f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", false)}), func(h *HandOff) { h.Kernel = &kernel })
			if _, err := f.applier.Apply(context.Background()); err == nil {
				t.Fatal("applied")
			}
			if exists(filepath.Join(f.lib, KernelBinary)) || exists(filepath.Join(f.lib, ServerBinary)) || f.restarts(t) != 0 {
				t.Fatal("a refused kernel changed the installation")
			}
			if !bytes.Equal(readFile(t, filepath.Join(f.lib, BinaryName)), f.old) {
				t.Fatal("the Agent binary changed")
			}
		})
	}
}

func TestApplyTakesTheKernelOutWhenTheAgentFails(t *testing.T) {
	f := newApplyFixture(t)
	key := newKernelKey(t)
	key.trust(t)
	kernel := f.stageKernel(t, key, fakeKernel(false))
	f.stage(t, "v4.2.0", releaseZip(t, zipEntry{name: BinaryName, data: fakeAgent("v4.2.0", true)}), func(h *HandOff) { h.Kernel = &kernel })
	result, err := f.applier.Apply(context.Background())
	if err == nil || result.Outcome != OutcomeRestored || result.Kernel != "" {
		t.Fatalf("result %+v %v", result, err)
	}
	if exists(filepath.Join(f.lib, KernelBinary)) || exists(filepath.Join(f.lib, ServerBinary)) || InstalledKernel(f.lib) != "" {
		t.Fatal("the kernel stayed with the previous Agent")
	}
}

func TestTheCoreRunsTheInstalledKernel(t *testing.T) {
	if got := filepath.Join(DefaultLibDir, KernelBinary); got != conf.InstalledAnxNodePath {
		t.Fatalf("upgrades install anx-node at %s, the core runs %s", got, conf.InstalledAnxNodePath)
	}
	if got := filepath.Join(DefaultLibDir, ServerBinary); got != conf.InstalledAnxServerPath {
		t.Fatalf("upgrades install anx-server at %s, the Agent runs %s", got, conf.InstalledAnxServerPath)
	}
}
