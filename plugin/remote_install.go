package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/AnixOps/anix-agent/v5/api/agent"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

const (
	PluginInstallAPIVersion = "anixops.io/plugin-install/v1alpha1"
	maxRemoteManifestBytes  = 1 << 20
)

type RemoteInstallerConfig struct {
	Supervisor *Supervisor
	// Artifacts downloads the release from Control's AgentArtifacts by the
	// agent client certificate (artifacts.v1).
	Artifacts ArtifactSource
}

// ArtifactSource is Control's AgentArtifacts service
// (agent.PluginArtifacts). It returns the documents of a content address
// with the release Control describes them by; the installer verifies both.
type ArtifactSource interface {
	GetPluginManifest(ctx context.Context, address *agentv1pb.PluginReleaseAddress) (*agentv1pb.PluginRelease, []byte, error)
	DownloadPluginArtifact(ctx context.Context, address *agentv1pb.PluginReleaseAddress, limit int64) (*agentv1pb.PluginRelease, []byte, error)
}

type RemoteInstaller struct {
	supervisor *Supervisor
	artifacts  ArtifactSource
}

type remoteInstallSpec struct {
	APIVersion string              `json:"api_version"`
	PluginID   string              `json:"plugin_id"`
	Version    string              `json:"version"`
	Artifact   remoteAsset         `json:"artifact"`
	Manifest   remoteManifestAsset `json:"manifest"`
}

type remoteAsset struct {
	// URL is not used: the documents come from AgentArtifacts by their
	// content address. Control's install payload still names it.
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type remoteManifestAsset struct {
	remoteAsset
	Signature  string `json:"signature"`
	Publisher  string `json:"publisher"`
	KeyID      string `json:"key_id"`
	APIVersion string `json:"api_version"`
}

func NewRemoteInstaller(config RemoteInstallerConfig) (*RemoteInstaller, error) {
	if config.Supervisor == nil {
		return nil, errors.New("plugin supervisor is required")
	}
	if config.Artifacts == nil {
		return nil, errors.New("plugin artifact source (AgentArtifacts) is required")
	}
	return &RemoteInstaller{supervisor: config.Supervisor, artifacts: config.Artifacts}, nil
}

func (i *RemoteInstaller) Handle(ctx context.Context, envelope *agent.OperationEnvelope) (json.RawMessage, error) {
	if envelope == nil {
		return nil, errors.New("plugin install operation envelope is required")
	}
	spec, err := decodeRemoteInstallSpec(envelope.Config)
	if err != nil {
		return nil, err
	}
	if spec.PluginID != envelope.PluginID || spec.Version != envelope.TargetVersion {
		return nil, errors.New("plugin install payload does not match the operation target")
	}
	if err := i.validateSpec(spec); err != nil {
		return nil, err
	}
	return i.supervisor.HandleInstall(ctx, envelope, func(fetchCtx context.Context) (InstallRequest, error) {
		manifestJSON, err := i.fetchManifest(fetchCtx, spec)
		if err != nil {
			return InstallRequest{}, err
		}
		manifest, err := VerifyManifest(string(manifestJSON), spec.Manifest.Signature, i.supervisor.publicKey)
		if err != nil {
			return InstallRequest{}, fmt.Errorf("verify downloaded plugin manifest: %w", err)
		}
		if manifest.ID != spec.PluginID || manifest.Version != spec.Version {
			return InstallRequest{}, errors.New("downloaded plugin manifest identity does not match install payload")
		}
		if manifest.Publisher != spec.Manifest.Publisher || manifest.APIVersion != spec.Manifest.APIVersion {
			return InstallRequest{}, errors.New("downloaded plugin manifest metadata does not match install payload")
		}
		if !strings.EqualFold(manifest.ArtifactSHA256, spec.Artifact.SHA256) {
			return InstallRequest{}, errors.New("downloaded plugin manifest artifact hash does not match install payload")
		}
		artifact, err := i.fetchArtifact(fetchCtx, spec)
		if err != nil {
			return InstallRequest{}, err
		}
		return InstallRequest{ManifestJSON: string(manifestJSON), Signature: spec.Manifest.Signature, Artifact: artifact}, nil
	})
}

func decodeRemoteInstallSpec(raw json.RawMessage) (*remoteInstallSpec, error) {
	var spec remoteInstallSpec
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return nil, fmt.Errorf("decode plugin install payload: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("decode plugin install payload: multiple JSON values")
	}
	return &spec, nil
}

func (i *RemoteInstaller) validateSpec(spec *remoteInstallSpec) error {
	if spec == nil {
		return errors.New("plugin install payload is required")
	}
	if spec.APIVersion != PluginInstallAPIVersion {
		return fmt.Errorf("unsupported plugin install API version %q", spec.APIVersion)
	}
	if !safeSegment(spec.PluginID) || !safeSegment(spec.Version) {
		return errors.New("plugin install identity is invalid")
	}
	if spec.Manifest.Publisher != manifestPublisher || !isSupportedPluginAPIVersion(spec.Manifest.APIVersion) {
		return errors.New("plugin install manifest metadata is not official or supported")
	}
	if spec.Manifest.KeyID != trustRootKeyID(i.supervisor.publicKey) {
		return errors.New("plugin install manifest key_id does not match the configured official trust root")
	}
	if strings.TrimSpace(spec.Manifest.Signature) == "" || len(spec.Manifest.Signature) > 4096 {
		return errors.New("plugin install manifest signature is invalid")
	}
	if err := validateRemoteAsset(spec.Manifest.remoteAsset, maxRemoteManifestBytes); err != nil {
		return fmt.Errorf("plugin manifest download: %w", err)
	}
	if err := validateRemoteAsset(spec.Artifact, maxPluginArtifactBytes); err != nil {
		return fmt.Errorf("plugin artifact download: %w", err)
	}
	return nil
}

// fetchManifest downloads the manifest from AgentArtifacts.
func (i *RemoteInstaller) fetchManifest(ctx context.Context, spec *remoteInstallSpec) ([]byte, error) {
	release, manifest, err := i.artifacts.GetPluginManifest(ctx, releaseAddress(spec, spec.Manifest.remoteAsset))
	if err != nil {
		return nil, err
	}
	if err := verifyDocument("manifest", manifest, spec.Manifest.remoteAsset, maxRemoteManifestBytes); err != nil {
		return nil, err
	}
	if err := checkRelease(release, spec); err != nil {
		return nil, err
	}
	return manifest, nil
}

// fetchArtifact downloads the artifact from AgentArtifacts.
func (i *RemoteInstaller) fetchArtifact(ctx context.Context, spec *remoteInstallSpec) ([]byte, error) {
	release, artifact, err := i.artifacts.DownloadPluginArtifact(ctx, releaseAddress(spec, spec.Artifact), min(spec.Artifact.Size, maxPluginArtifactBytes))
	if err != nil {
		return nil, err
	}
	if err := verifyDocument("artifact", artifact, spec.Artifact, maxPluginArtifactBytes); err != nil {
		return nil, err
	}
	if err := checkRelease(release, spec); err != nil {
		return nil, err
	}
	return artifact, nil
}

// releaseAddress is the content address of one document of spec.
func releaseAddress(spec *remoteInstallSpec, asset remoteAsset) *agentv1pb.PluginReleaseAddress {
	return &agentv1pb.PluginReleaseAddress{PluginId: spec.PluginID, Version: spec.Version, Sha256: strings.ToLower(asset.SHA256), Size: asset.Size}
}

// verifyDocument checks a downloaded document against its signed
// metadata: its size and SHA-256.
func verifyDocument(kind string, contents []byte, asset remoteAsset, maximum int64) error {
	if int64(len(contents)) > maximum {
		return fmt.Errorf("plugin %s exceeds the download limit", kind)
	}
	if int64(len(contents)) != asset.Size {
		return fmt.Errorf("download plugin %s: body size does not match metadata", kind)
	}
	digest := sha256.Sum256(contents)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), asset.SHA256) {
		return fmt.Errorf("download plugin %s: SHA-256 mismatch", kind)
	}
	return nil
}

// checkRelease cross-checks the release Control describes the download by
// against the install configuration.
func checkRelease(release *agentv1pb.PluginRelease, spec *remoteInstallSpec) error {
	if release == nil {
		return errors.New("Control described no plugin release")
	}
	mismatch := func(field string) error {
		return fmt.Errorf("the plugin release %s from Control does not match the install payload", field)
	}
	switch {
	case release.GetPluginId() != spec.PluginID:
		return mismatch("plugin_id")
	case release.GetVersion() != spec.Version:
		return mismatch("version")
	case !strings.EqualFold(release.GetArtifactSha256(), spec.Artifact.SHA256):
		return mismatch("artifact_sha256")
	case release.GetArtifactSize() != spec.Artifact.Size:
		return mismatch("artifact_size")
	case !strings.EqualFold(release.GetManifestSha256(), spec.Manifest.SHA256):
		return mismatch("manifest_sha256")
	case release.GetManifestSize() != spec.Manifest.Size:
		return mismatch("manifest_size")
	case release.GetSignature() != spec.Manifest.Signature:
		return mismatch("signature")
	case release.GetSignatureAlgorithm() != "ed25519":
		return mismatch("signature_algorithm")
	case release.GetPublisher() != spec.Manifest.Publisher:
		return mismatch("publisher")
	case release.GetKeyId() != spec.Manifest.KeyID:
		return mismatch("key_id")
	case release.GetPluginApiVersion() != spec.Manifest.APIVersion:
		return mismatch("plugin_api_version")
	}
	return nil
}

func validateRemoteAsset(asset remoteAsset, maximum int64) error {
	if !validSHA256(asset.SHA256) {
		return errors.New("sha256 must be a hexadecimal SHA-256 digest")
	}
	if asset.Size <= 0 || asset.Size > maximum {
		return fmt.Errorf("size must be between 1 and %d bytes", maximum)
	}
	return nil
}

func trustRootKeyID(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])[:16]
}
