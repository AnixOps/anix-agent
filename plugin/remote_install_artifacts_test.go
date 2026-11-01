package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/require"
)

// fakeArtifacts is Control's AgentArtifacts for the installer: it answers
// the documents of the release, as tampered.
type fakeArtifacts struct {
	manifest, artifact []byte
	release            *agentv1pb.PluginRelease
	addresses          []*agentv1pb.PluginReleaseAddress
	err                error
}

func (f *fakeArtifacts) GetPluginManifest(_ context.Context, address *agentv1pb.PluginReleaseAddress) (*agentv1pb.PluginRelease, []byte, error) {
	f.addresses = append(f.addresses, address)
	return f.release, f.manifest, f.err
}

func (f *fakeArtifacts) DownloadPluginArtifact(_ context.Context, address *agentv1pb.PluginReleaseAddress, limit int64) (*agentv1pb.PluginRelease, []byte, error) {
	f.addresses = append(f.addresses, address)
	if int64(len(f.artifact)) > limit {
		return nil, nil, errors.New("over the limit")
	}
	return f.release, f.artifact, f.err
}

func hexDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func artifactsFixture(t *testing.T) (*Supervisor, ed25519.PublicKey, InstallRequest, *fakeArtifacts, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	request := signedRequest(t, privateKey, []byte("plugin release by certificate"), "wireguard", "4.0.0")
	source := &fakeArtifacts{
		manifest: []byte(request.ManifestJSON), artifact: request.Artifact,
		release: &agentv1pb.PluginRelease{
			PluginId: "wireguard", Version: "4.0.0",
			ArtifactSha256: hexDigest(request.Artifact), ArtifactSize: int64(len(request.Artifact)),
			ManifestSha256: hexDigest([]byte(request.ManifestJSON)), ManifestSize: int64(len(request.ManifestJSON)),
			Signature: request.Signature, SignatureAlgorithm: "ed25519", Publisher: manifestPublisher,
			KeyId: trustRootKeyID(publicKey), PluginApiVersion: pluginAPIVersion,
		},
	}
	return supervisor, publicKey, request, source, root
}

func TestRemoteInstallerNeedsAgentArtifacts(t *testing.T) {
	supervisor, _, _, _, _ := artifactsFixture(t)
	_, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor})
	require.ErrorContains(t, err, "AgentArtifacts")
}

func TestRemoteInstallerDownloadsFromAgentArtifactsAndReplaysWithoutFetching(t *testing.T) {
	supervisor, publicKey, request, source, root := artifactsFixture(t)
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, Artifacts: source})
	require.NoError(t, err)
	envelope := testEnvelope("artifacts-install", "wireguard", "4.0.0", 1, remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0"))
	result, err := installer.Handle(context.Background(), envelope)
	require.NoError(t, err)
	require.Contains(t, string(result), `"desired_version":"4.0.0"`)
	require.FileExists(t, filepath.Join(root, "wireguard", "4.0.0", pluginBinaryName))
	require.Len(t, source.addresses, 2)
	require.Equal(t, &agentv1pb.PluginReleaseAddress{PluginId: "wireguard", Version: "4.0.0", Sha256: hexDigest([]byte(request.ManifestJSON)), Size: int64(len(request.ManifestJSON))}, source.addresses[0])
	require.Equal(t, hexDigest(request.Artifact), source.addresses[1].GetSha256())

	replayed, err := installer.Handle(context.Background(), envelope)
	require.NoError(t, err)
	require.JSONEq(t, string(result), string(replayed))
	require.Len(t, source.addresses, 2, "an exact replay downloads nothing")
}

func TestRemoteInstallerRejectsTamperedManifestWithoutDownloadingArtifact(t *testing.T) {
	supervisor, publicKey, request, source, _ := artifactsFixture(t)
	tampered := strings.Replace(request.ManifestJSON, `"name":"wireguard"`, `"name":"tampered"`, 1)
	source.manifest = []byte(tampered)
	source.release.ManifestSha256, source.release.ManifestSize = hexDigest(source.manifest), int64(len(source.manifest))
	var spec remoteInstallSpec
	require.NoError(t, json.Unmarshal(remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0"), &spec))
	spec.Manifest.SHA256, spec.Manifest.Size = hexDigest(source.manifest), int64(len(source.manifest))
	payload, err := json.Marshal(spec)
	require.NoError(t, err)
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, Artifacts: source})
	require.NoError(t, err)
	_, err = installer.Handle(context.Background(), testEnvelope("tampered-install", "wireguard", "4.0.0", 1, payload))
	require.ErrorContains(t, err, "verify downloaded plugin manifest")
	require.Len(t, source.addresses, 1, "the artifact is not downloaded")
}

func TestRemoteInstallerRejectsArtifactMetadataAbove64MiB(t *testing.T) {
	supervisor, publicKey, request, source, _ := artifactsFixture(t)
	var spec remoteInstallSpec
	require.NoError(t, json.Unmarshal(remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0"), &spec))
	spec.Artifact.Size = maxPluginArtifactBytes + 1
	payload, err := json.Marshal(spec)
	require.NoError(t, err)
	installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, Artifacts: source})
	require.NoError(t, err)
	_, err = installer.Handle(context.Background(), testEnvelope("oversized-artifact", "wireguard", "4.0.0", 1, payload))
	require.ErrorContains(t, err, "size must be between 1 and 67108864 bytes")
	require.Empty(t, source.addresses)
}

func TestRemoteInstallerVerifiesWhatAgentArtifactsSends(t *testing.T) {
	tests := map[string]struct {
		tamper func(*fakeArtifacts)
		err    string
	}{
		"artifact digest": {func(f *fakeArtifacts) {
			f.artifact = append([]byte(nil), f.artifact...)
			f.artifact[0] ^= 1
		}, "SHA-256 mismatch"},
		"artifact size":      {func(f *fakeArtifacts) { f.artifact = f.artifact[:len(f.artifact)-1] }, "size does not match"},
		"manifest digest":    {func(f *fakeArtifacts) { f.manifest = append([]byte(" "), f.manifest[1:]...) }, "SHA-256 mismatch"},
		"release signature":  {func(f *fakeArtifacts) { f.release.Signature = "other" }, "signature"},
		"release key":        {func(f *fakeArtifacts) { f.release.KeyId = "ffffffffffffffff" }, "key_id"},
		"release publisher":  {func(f *fakeArtifacts) { f.release.Publisher = "Someone" }, "publisher"},
		"release algorithm":  {func(f *fakeArtifacts) { f.release.SignatureAlgorithm = "rsa" }, "signature_algorithm"},
		"release api":        {func(f *fakeArtifacts) { f.release.PluginApiVersion = "v9" }, "plugin_api_version"},
		"release artifact":   {func(f *fakeArtifacts) { f.release.ArtifactSha256 = hexDigest([]byte("x")) }, "artifact_sha256"},
		"release size":       {func(f *fakeArtifacts) { f.release.ManifestSize++ }, "manifest_size"},
		"release identity":   {func(f *fakeArtifacts) { f.release.Version = "4.0.1" }, "version"},
		"no release":         {func(f *fakeArtifacts) { f.release = nil }, "no plugin release"},
		"refused by Control": {func(f *fakeArtifacts) { f.err = errors.New("plugin_release_not_assigned: no") }, "plugin_release_not_assigned"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			supervisor, publicKey, request, source, root := artifactsFixture(t)
			test.tamper(source)
			installer, err := NewRemoteInstaller(RemoteInstallerConfig{Supervisor: supervisor, Artifacts: source})
			require.NoError(t, err)
			envelope := testEnvelope("artifacts-tampered", "wireguard", "4.0.0", 1, remoteInstallPayload(t, publicKey, request, "wireguard", "4.0.0"))
			_, err = installer.Handle(context.Background(), envelope)
			require.ErrorContains(t, err, test.err)
			require.NoFileExists(t, filepath.Join(root, "wireguard", "4.0.0", pluginBinaryName))
		})
	}
}
