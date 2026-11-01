package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func remoteInstallPayload(t *testing.T, publicKey ed25519.PublicKey, request InstallRequest, pluginID, version string) []byte {
	t.Helper()
	manifestDigest := sha256.Sum256([]byte(request.ManifestJSON))
	artifactDigest := sha256.Sum256(request.Artifact)
	manifestAsset := remoteAsset{SHA256: hex.EncodeToString(manifestDigest[:]), Size: int64(len(request.ManifestJSON))}
	artifactAsset := remoteAsset{SHA256: hex.EncodeToString(artifactDigest[:]), Size: int64(len(request.Artifact))}
	manifestAsset.URL = releaseAssetURL(pluginID, version, "manifest", manifestAsset)
	artifactAsset.URL = releaseAssetURL(pluginID, version, "artifact", artifactAsset)
	payload, err := json.Marshal(remoteInstallSpec{
		APIVersion: PluginInstallAPIVersion, PluginID: pluginID, Version: version, Artifact: artifactAsset,
		Manifest: remoteManifestAsset{
			remoteAsset: manifestAsset, Signature: request.Signature, Publisher: manifestPublisher,
			KeyID: trustRootKeyID(publicKey), APIVersion: pluginAPIVersion,
		},
	})
	require.NoError(t, err)
	return payload
}

func releaseAssetURL(pluginID, version, kind string, asset remoteAsset) string {
	return fmt.Sprintf("/api/v3/agent/plugin-releases/%s/%s/%s?sha256=%s&size=%d", pluginID, version, kind, asset.SHA256, asset.Size)
}

func TestInstallUsesAtomicVersionDirectoryAndCleansStaleStage(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	supervisor, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	pluginDir := filepath.Join(root, "wireguard")
	require.NoError(t, os.MkdirAll(filepath.Join(pluginDir, ".1.0.0.staging-crashed"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, ".1.0.0.staging-crashed", "partial"), []byte("partial"), 0o600))
	request := signedRequest(t, privateKey, []byte("atomic artifact"), "wireguard", "1.0.0")
	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	require.NoDirExists(t, filepath.Join(pluginDir, ".1.0.0.staging-crashed"))
	require.FileExists(t, filepath.Join(pluginDir, "1.0.0", manifestFileName))
	require.FileExists(t, filepath.Join(pluginDir, "1.0.0", signatureFileName))
	require.FileExists(t, filepath.Join(pluginDir, "1.0.0", pluginBinaryName))
	_, err = supervisor.Install(context.Background(), request)
	require.NoError(t, err)
	entries, err := os.ReadDir(pluginDir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotContains(t, entry.Name(), ".staging-")
	}
}

func TestInterruptedOperationExactReplayRepairsCurrentRevision(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	first, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	_, err = first.Install(context.Background(), signedRequest(t, privateKey, []byte("repair replay"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	config := []byte(`{"listen":"127.0.0.1:51820"}`)
	_, err = first.Handle(context.Background(), "plugin.configure", testEnvelope("initial-config", "wireguard", "1.0.0", 1, config))
	require.NoError(t, err)
	repairEnvelope := testEnvelope("repair-config", "wireguard", "1.0.0", 1, config)
	first.mu.Lock()
	first.state.Journal[repairEnvelope.OperationID] = newJournalEntry("plugin.configure", repairEnvelope, time.Unix(10, 0))
	require.NoError(t, first.persistLocked())
	first.mu.Unlock()
	require.NoError(t, first.Close(context.Background()))

	restarted, err := NewSupervisor(Config{RootDir: root, PublicKey: publicKey, Runner: &fakeRunner{}, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restarted.Close(context.Background())) })
	result, err := restarted.Handle(context.Background(), "plugin.configure", repairEnvelope)
	require.NoError(t, err)
	require.Contains(t, string(result), `"desired_revision":1`)
	restarted.mu.Lock()
	journal := restarted.state.Journal[repairEnvelope.OperationID]
	restarted.mu.Unlock()
	require.Equal(t, "succeeded", journal.State)
}

func TestUpdateAppliesTargetConfigAndHealthFailureRestoresOldVersion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	runner := &configRecordingRunner{}
	badConfig := []byte(`{"listen":"bad"}`)
	supervisor, err := NewSupervisor(Config{
		RootDir: root, SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: runner,
		Health: &configRejectingHealth{runner: runner, rejectConfig: string(badConfig)},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("update-v1"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("update-v2"), "wireguard", "2.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"listen":"127.0.0.1:51820"}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("update-config-v1", "wireguard", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("update-enable-v1", "wireguard", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)

	_, err = supervisor.Handle(context.Background(), "plugin.update", testEnvelope("update-bad-v2", "wireguard", "2.0.0", 3, badConfig))
	require.ErrorContains(t, err, "injected config health failure")
	stateJSON, inspectErr := supervisor.inspect("wireguard")
	require.NoError(t, inspectErr)
	require.Contains(t, string(stateJSON), `"desired_version":"1.0.0"`)
	require.Contains(t, string(stateJSON), `"observed_version":"1.0.0"`)
	require.Contains(t, string(stateJSON), `"config_hash":"`+configHash(oldConfig)+`"`)
	_, statErr := os.Stat(filepath.Join(root, "wireguard", "2.0.0", "config.json"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
	configs := runner.Configs()
	require.Equal(t, [][]byte{oldConfig, badConfig, oldConfig}, configs)
}

func TestUpdatePersistsSuccessfulTargetConfigHash(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	root := t.TempDir()
	runner := &configRecordingRunner{}
	supervisor, err := NewSupervisor(Config{RootDir: root, SocketDir: shortSocketDir(t), PublicKey: publicKey, Runner: runner, Health: &fakeHealth{}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, supervisor.Close(context.Background())) })
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("success-v1"), "wireguard", "1.0.0"))
	require.NoError(t, err)
	_, err = supervisor.Install(context.Background(), signedRequest(t, privateKey, []byte("success-v2"), "wireguard", "2.0.0"))
	require.NoError(t, err)
	oldConfig := []byte(`{"listen":"127.0.0.1:51820"}`)
	newConfig := []byte(`{"listen":"127.0.0.1:51821"}`)
	_, err = supervisor.Handle(context.Background(), "plugin.configure", testEnvelope("success-config-v1", "wireguard", "1.0.0", 1, oldConfig))
	require.NoError(t, err)
	_, err = supervisor.Handle(context.Background(), "plugin.enable", testEnvelope("success-enable-v1", "wireguard", "1.0.0", 2, []byte(`{}`)))
	require.NoError(t, err)
	result, err := supervisor.Handle(context.Background(), "plugin.update", testEnvelope("success-update-v2", "wireguard", "2.0.0", 3, newConfig))
	require.NoError(t, err)
	require.Contains(t, string(result), `"desired_version":"2.0.0"`)
	require.Contains(t, string(result), `"config_hash":"`+configHash(newConfig)+`"`)
	stored, err := os.ReadFile(filepath.Join(root, "wireguard", "2.0.0", "config.json"))
	require.NoError(t, err)
	require.Equal(t, newConfig, stored)
	require.Equal(t, [][]byte{oldConfig, newConfig}, runner.Configs())
}
