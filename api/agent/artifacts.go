package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Plugin artifacts by client certificate (artifacts.v1; PROTOCOL.md,
// "Plugin artifacts"). An enrolled Agent downloads the signed plugin
// releases assigned to its node from AgentArtifacts, on Control's agent
// listener, instead of GET /api/v3/agent/plugin-releases/... with the node
// API key. The bytes are the HTTP download's; the caller verifies them as
// before (plugin.RemoteInstaller).

// PluginDownload says how a plugin release can be downloaded now.
type PluginDownload int

const (
	// PluginDownloadHTTP: the HTTP download with the node API key; the
	// Agent is not enrolled, or its session authenticated with the key.
	PluginDownloadHTTP PluginDownload = iota
	// PluginDownloadArtifacts: AgentArtifacts, by the client certificate.
	PluginDownloadArtifacts
	// PluginDownloadUnavailable: the Agent authenticates with its client
	// certificate, but the session did not negotiate artifacts.v1 (or the
	// stream is down). An enrolled Agent does not send its API key.
	PluginDownloadUnavailable
)

// Heartbeat metric keys of the plugin downloads.
const (
	MetricArtifactDownloads = "agent_dataplane_artifact_downloads_total"
	MetricArtifactFailures  = "agent_dataplane_artifact_failures_total"
)

// artifactRetry is the first wait before retrying a download Control
// answered busy or unavailable; it doubles up to artifactRetryMax, for at
// most artifactAttempts tries within the operation's deadline (variables
// for tests).
var (
	artifactRetry    = time.Second
	artifactRetryMax = 15 * time.Second
	artifactAttempts = 6
)

type artifactCounters struct {
	downloads atomic.Uint64
	failures  atomic.Uint64
}

// PluginDownload tells how a plugin release can be downloaded now.
func (c *Client) PluginDownload() PluginDownload {
	c.mu.RLock()
	ready, authentication := c.ready, c.authentication
	negotiated := c.ready && agentcontrol.Negotiated(c.helloCapabilities, c.serverCapabilities, agentcontrol.CapabilityArtifacts)
	c.mu.RUnlock()
	advertised := c.dataPlane != nil && c.dataPlane.config.Artifacts
	switch {
	case negotiated && c.identity != nil && c.identity.certificate() != nil:
		return PluginDownloadArtifacts
	case !advertised:
		// An Agent configured without the stream's data plane keeps the
		// HTTP download.
		return PluginDownloadHTTP
	case c.identity == nil || c.identity.certificate() == nil:
		return PluginDownloadHTTP
	case ready && authentication == authenticationAPIKey:
		// Control did not ask for the certificate (agent_control.mtls
		// off): the session runs on the key anyway.
		return PluginDownloadHTTP
	default:
		return PluginDownloadUnavailable
	}
}

// PluginArtifacts returns the AgentArtifacts client for the current
// session's certificate; ErrSessionGone when the session did not negotiate
// artifacts.v1.
func (c *Client) PluginArtifacts() (*PluginArtifacts, error) {
	if c.PluginDownload() != PluginDownloadArtifacts {
		return nil, fmt.Errorf("plugin artifacts: %w (artifacts.v1 needs a session authenticated by the agent client certificate)", ErrSessionGone)
	}
	identity := c.identity.certificate()
	if identity == nil {
		return nil, fmt.Errorf("plugin artifacts: the agent has no client certificate: %w", ErrSessionGone)
	}
	return &PluginArtifacts{client: c, identity: identity}, nil
}

// PluginArtifacts calls AgentArtifacts with one client certificate.
type PluginArtifacts struct {
	client   *Client
	identity *pki.Identity
}

// GetPluginManifest returns the release and the manifest bytes of address.
// The caller verifies them.
func (a *PluginArtifacts) GetPluginManifest(ctx context.Context, address *agentv1pb.PluginReleaseAddress) (*agentv1pb.PluginRelease, []byte, error) {
	var release *agentv1pb.PluginRelease
	var manifest []byte
	err := a.call(ctx, "manifest", address, func(callCtx context.Context, service agentv1pb.AgentArtifactsClient, trailer *metadata.MD) error {
		response, err := service.GetPluginManifest(callCtx, &agentv1pb.GetPluginManifestRequest{Manifest: address}, grpc.Trailer(trailer))
		if err != nil {
			return err
		}
		if response.GetRelease() == nil {
			return errors.New("Control answered the manifest without its release")
		}
		if int64(len(response.GetManifestJson())) != address.GetSize() {
			return fmt.Errorf("the manifest has %d bytes, its address names %d", len(response.GetManifestJson()), address.GetSize())
		}
		release, manifest = response.GetRelease(), response.GetManifestJson()
		return nil
	})
	return release, manifest, err
}

// DownloadPluginArtifact streams the artifact of address and returns its
// release (from the first chunk) and its bytes, written in offset order and
// never more than address.size or limit. The caller verifies them.
func (a *PluginArtifacts) DownloadPluginArtifact(ctx context.Context, address *agentv1pb.PluginReleaseAddress, limit int64) (*agentv1pb.PluginRelease, []byte, error) {
	if address.GetSize() <= 0 || address.GetSize() > limit {
		return nil, nil, fmt.Errorf("plugin artifact size %d is outside 1..%d", address.GetSize(), limit)
	}
	var release *agentv1pb.PluginRelease
	var artifact []byte
	err := a.call(ctx, "artifact", address, func(callCtx context.Context, service agentv1pb.AgentArtifactsClient, trailer *metadata.MD) error {
		release, artifact = nil, nil
		stream, err := service.DownloadPluginArtifact(callCtx, &agentv1pb.DownloadPluginArtifactRequest{Artifact: address})
		if err != nil {
			return err
		}
		data := make([]byte, 0, address.GetSize())
		for first := true; ; first = false {
			chunk, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				*trailer = stream.Trailer()
				return err
			}
			if first {
				if chunk.GetRelease() == nil {
					return errors.New("the first artifact chunk carries no release")
				}
				release = chunk.GetRelease()
			}
			if chunk.GetOffset() != int64(len(data)) {
				return fmt.Errorf("artifact chunk at offset %d, expected %d", chunk.GetOffset(), len(data))
			}
			if int64(len(data))+int64(len(chunk.GetData())) > address.GetSize() {
				return fmt.Errorf("the artifact exceeds its %d bytes", address.GetSize())
			}
			data = append(data, chunk.GetData()...)
		}
		if release == nil {
			return errors.New("Control sent no artifact chunk")
		}
		if int64(len(data)) != address.GetSize() {
			return fmt.Errorf("the artifact has %d bytes, its address names %d", len(data), address.GetSize())
		}
		artifact = data
		return nil
	})
	return release, artifact, err
}

// call runs one AgentArtifacts call on a connection presenting the
// certificate, retrying plugin_release_download_busy and Unavailable.
func (a *PluginArtifacts) call(ctx context.Context, kind string, address *agentv1pb.PluginReleaseAddress, do func(context.Context, agentv1pb.AgentArtifactsClient, *metadata.MD) error) error {
	c := a.client
	wait := artifactRetry
	var err error
	for attempt := 1; ; attempt++ {
		err = a.attempt(ctx, do)
		if err == nil {
			c.artifacts.downloads.Add(1)
			return nil
		}
		code := errorCodeOf(err)
		st, _ := grpcStatus(err)
		retry := code == agentcontrol.ErrorCodePluginReleaseBusy ||
			(st != nil && (st.Code() == codes.Unavailable || st.Code() == codes.ResourceExhausted) && code == "")
		entry := log.WithFields(log.Fields{
			"component": "agent-artifacts", "node_id": c.config.NodeID, "plugin_id": address.GetPluginId(),
			"version": address.GetVersion(), "document": kind, "error_code": code, "attempt": attempt,
		}).WithError(err)
		if !retry || attempt >= artifactAttempts || ctx.Err() != nil {
			c.artifacts.failures.Add(1)
			switch reason, action := certificateRefusal(err); action {
			case certificateReenroll:
				c.identity.rejected(a.identity, reason)
			case certificateWrongNode:
				c.identity.wrongNode(err)
			}
			entry.Warn("Control refused the plugin release download")
			return fmt.Errorf("download plugin %s from AgentArtifacts: %w", kind, err)
		}
		entry.WithField("retry_in", wait.String()).Info("Control could not serve the plugin release download now; retrying")
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			c.artifacts.failures.Add(1)
			return fmt.Errorf("download plugin %s from AgentArtifacts: %w (last: %v)", kind, ctx.Err(), err)
		case <-timer.C:
		}
		wait = min(wait*2, artifactRetryMax)
	}
}

func (a *PluginArtifacts) attempt(ctx context.Context, do func(context.Context, agentv1pb.AgentArtifactsClient, *metadata.MD) error) error {
	conn, err := a.client.dialIdentity(ctx, a.identity.TLSCertificate())
	if err != nil {
		return fmt.Errorf("dial AgentArtifacts: %w", err)
	}
	defer conn.Close()
	var trailer metadata.MD
	err = do(ctx, agentv1pb.NewAgentArtifactsClient(conn), &trailer)
	return withControlCode(err, trailer)
}

// artifactsMetrics are the plugin downloads' heartbeat metrics.
func (c *Client) artifactsMetrics(metrics map[string]float64) {
	if c.dataPlane == nil || !c.dataPlane.config.Artifacts {
		return
	}
	metrics[MetricArtifactDownloads] = float64(c.artifacts.downloads.Load())
	metrics[MetricArtifactFailures] = float64(c.artifacts.failures.Load())
}
