package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// shortenIdentityRetries makes enrollment and renewal retries fast for one
// test.
func shortenIdentityRetries(t *testing.T) {
	t.Helper()
	saved := []time.Duration{enrollRetryMin, enrollRetryMax, enrollUnsupportedRetry, enrollWaitingRetry, renewRetryMin, renewRetryMax}
	enrollRetryMin, enrollRetryMax, enrollWaitingRetry = 20*time.Millisecond, 100*time.Millisecond, 20*time.Millisecond
	renewRetryMin, renewRetryMax = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() {
		enrollRetryMin, enrollRetryMax, enrollUnsupportedRetry, enrollWaitingRetry, renewRetryMin, renewRetryMax =
			saved[0], saved[1], saved[2], saved[3], saved[4], saved[5]
	})
}

func startClient(t *testing.T, client *Client) {
	t.Helper()
	require.NoError(t, client.Start())
	t.Cleanup(func() { _ = client.Close() })
}

func certificateSessions(streams []fakeStreamAuth) (accepted []fakeStreamAuth) {
	for _, stream := range streams {
		if stream.accepted && stream.certificateSerial != "" {
			accepted = append(accepted, stream)
		}
	}
	return accepted
}

func TestIdentityEnrollsWithAPIKeyThenConnectsWithCertificate(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModePreferred, true)
	root := t.TempDir()
	client := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, client)
	waitReady(t, client)

	status := client.TransportStatus()
	assert.Equal(t, "certificate", status.Authentication)
	assert.Nil(t, status.Deprecation, "an enrolled Agent gets no deprecation signal")
	require.NotNil(t, status.Identity)
	assert.True(t, status.Identity.Enrolled)
	assert.Equal(t, "spiffe://anixops/test-cluster/agent/proxy-12", status.Identity.SPIFFEID)

	enrolls, _, streams, issued := fake.records()
	require.Len(t, enrolls, 1)
	assert.True(t, enrolls[0].apiKey, "the first enrollment bootstraps with the node API key")
	assert.Equal(t, agentcontrol.NodeKindProxy, enrolls[0].nodeKind)
	assert.Equal(t, codes.OK, enrolls[0].err)
	require.NotEmpty(t, streams)
	for _, stream := range streams {
		assert.False(t, stream.apiKey, "an enrolled Agent never sends the API key on the stream")
		assert.Equal(t, issued[0], stream.certificateSerial)
	}

	dir := filepath.Join(root, "proxy-12")
	assertPrivate(t, dir, 0o700)
	for _, name := range []string{"identity.pem", "ca.pem", "identity.json"} {
		assertPrivate(t, filepath.Join(dir, name), 0o600)
	}
	store, err := pki.NewStore(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	inspected := store.Inspect(time.Now())
	assert.Equal(t, pki.StateValid, inspected.State)
	assert.Equal(t, issued[0], inspected.Serial)
	assert.Equal(t, pki.BootstrapNodeAPIKey, inspected.Bootstrap)

	require.Eventually(t, func() bool {
		metrics := client.transportMetrics()
		return metrics[MetricIdentityEnrolled] == 1 && metrics[MetricIdentityExpiresIn] > 0
	}, time.Second, 10*time.Millisecond)
}

func TestIdentityLoadsStoredCertificateAfterRestart(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModePreferred, true)
	root := t.TempDir()
	first := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, first)
	waitReady(t, first)
	require.NoError(t, first.Close())

	// Control now requires mTLS; the restarted Agent needs no API key.
	fake.setMode(fakeModeRequired)
	second := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, second)
	waitReady(t, second)
	assert.Equal(t, "certificate", second.TransportStatus().Authentication)
	enrolls, _, streams, _ := fake.records()
	assert.Len(t, enrolls, 1, "the stored identity is reused, not enrolled again")
	for _, stream := range streams {
		assert.False(t, stream.apiKey)
	}
}

func TestIdentityRenewsAtControlsRenewalTime(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModePreferred, true)
	fake.setLifetime(3 * time.Second)
	root := t.TempDir()
	client := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, client)
	waitReady(t, client)
	_, _, _, issued := fake.records()
	require.Len(t, issued, 1)
	fake.setLifetime(time.Hour)

	require.Eventually(t, func() bool {
		_, renews, _, _ := fake.records()
		return len(renews) > 0 && renews[0].err == codes.OK
	}, 10*time.Second, 20*time.Millisecond)
	_, renews, _, issued := fake.records()
	assert.Equal(t, issued[0], renews[0].serial, "the renewal presents the current certificate")
	assert.False(t, renews[0].apiKey, "a renewal never sends the API key")
	require.Len(t, issued, 2)

	require.Eventually(t, func() bool {
		status := client.TransportStatus().Identity
		return status != nil && status.Serial == issued[1]
	}, 5*time.Second, 20*time.Millisecond)
	store, err := pki.NewStore(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	inspected := store.Inspect(time.Now())
	assert.Equal(t, issued[1], inspected.Serial, "the renewed certificate is stored")
	assert.False(t, inspected.RenewedAt.IsZero())
	assert.Equal(t, pki.BootstrapNodeAPIKey, inspected.Bootstrap, "renewal keeps the enrollment's bootstrap")

	// The next session presents the renewed certificate.
	require.Eventually(t, func() bool {
		_, _, streams, _ := fake.records()
		for _, stream := range certificateSessions(streams) {
			if stream.certificateSerial == issued[1] {
				return true
			}
		}
		return false
	}, 10*time.Second, 50*time.Millisecond)
}

func TestIdentityRevokedCertificateIsDiscardedAndEnrolledAgain(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModePreferred, true)
	root := t.TempDir()
	client := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, client)
	waitReady(t, client)
	_, _, _, issued := fake.records()
	require.Len(t, issued, 1)

	// Revoked while the stream is open: Control ends it at the next
	// heartbeat; the Agent drops the certificate and enrolls again with the
	// API key, which preferred still accepts.
	fake.revoke(issued[0])
	require.Eventually(t, func() bool {
		_, _, _, issued := fake.records()
		return len(issued) == 2
	}, 10*time.Second, 20*time.Millisecond)
	_, _, _, issued = fake.records()
	require.Eventually(t, func() bool {
		_, _, streams, _ := fake.records()
		for _, stream := range certificateSessions(streams) {
			if stream.certificateSerial == issued[1] {
				return true
			}
		}
		return false
	}, 10*time.Second, 20*time.Millisecond)
	enrolls, _, _, _ := fake.records()
	require.Len(t, enrolls, 2)
	assert.True(t, enrolls[1].apiKey)

	store, err := pki.NewStore(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	assert.Equal(t, issued[1], store.Inspect(time.Now()).Serial)
}

func TestIdentityRevokedCertificateRefusedAtRenewal(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModePreferred, true)
	root := t.TempDir()
	client := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	client.identity.prepare(client.ctx)
	identity := client.identity.certificate()
	require.NotNil(t, identity)

	fake.revoke(identity.Serial)
	client.identity.renew(client.ctx, identity)
	assert.Nil(t, client.identity.certificate(), "a certificate Control refuses at renewal is dropped")
	store, err := pki.NewStore(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	assert.Equal(t, pki.StateNotEnrolled, store.Inspect(time.Now()).State)

	client.identity.prepare(client.ctx)
	renewed := client.identity.certificate()
	require.NotNil(t, renewed)
	assert.NotEqual(t, identity.Serial, renewed.Serial)
}

func TestIdentityRequiredModeEnrollsWithCredentialAndNeverSendsTheAPIKey(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	root := t.TempDir()
	credentialFile := filepath.Join(t.TempDir(), "enroll.token")
	client := fake.client(t, &IdentityConfig{Dir: root, Enroll: true, EnrollCredentialFile: credentialFile})
	startClient(t, client)

	// Without a credential the API key is refused for the stream and for
	// enrollment, each with agent_mtls_required.
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.MTLSRequiredRefusals > 0 && status.Identity != nil && status.Identity.LastError != ""
	}, 5*time.Second, 10*time.Millisecond)
	status := client.TransportStatus()
	assert.False(t, status.Connected)
	assert.Contains(t, status.LastError, agentcontrol.ErrorCodeMTLSRequired)
	assert.Contains(t, status.Identity.LastError, "EnrollCredentialFile")
	enrolls, _, streams, _ := fake.records()
	require.NotEmpty(t, enrolls)
	assert.Equal(t, codes.Unauthenticated, enrolls[0].err)
	assert.True(t, enrolls[0].apiKey)
	for _, stream := range streams {
		assert.False(t, stream.accepted, "required never accepts the API key")
	}
	refusedEnrolls := len(enrolls)

	// Once refused, the API key is not offered for enrollment again.
	time.Sleep(200 * time.Millisecond)
	enrolls, _, _, _ = fake.records()
	assert.Len(t, enrolls, refusedEnrolls)

	fake.addCredential("anixagt_test-credential")
	require.NoError(t, os.WriteFile(credentialFile, []byte("anixagt_test-credential\n"), 0o600))
	require.Eventually(t, func() bool { return client.TransportStatus().Connected }, 10*time.Second, 10*time.Millisecond)

	status = client.TransportStatus()
	assert.Equal(t, "certificate", status.Authentication)
	enrolls, _, streams, issued := fake.records()
	last := enrolls[len(enrolls)-1]
	assert.True(t, last.credential)
	assert.False(t, last.apiKey, "a credential enrollment sends no API key")
	assert.Equal(t, codes.OK, last.err)
	for _, stream := range streams {
		if stream.accepted {
			assert.False(t, stream.apiKey)
			assert.Equal(t, issued[0], stream.certificateSerial)
		}
	}
	_, err := os.Stat(credentialFile)
	assert.True(t, errors.Is(err, os.ErrNotExist), "the used one-time credential is removed")
}

func TestIdentityEnrollsWithAPIKeyAgainAfterControlLeavesRequiredMode(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: true})
	startClient(t, client)
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.MTLSRequiredRefusals > 0 && status.Identity != nil && status.Identity.LastError != ""
	}, 5*time.Second, 10*time.Millisecond)

	// The operator rolls Control back to preferred (H5 keeps it as an
	// override): an API key session proves the key is accepted again, so
	// the Agent enrolls with it instead of waiting for a credential.
	fake.setMode(fakeModePreferred)
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.Connected && status.Authentication == "certificate"
	}, 10*time.Second, 10*time.Millisecond)
	enrolls, _, _, _ := fake.records()
	last := enrolls[len(enrolls)-1]
	assert.True(t, last.apiKey)
	assert.Equal(t, codes.OK, last.err)
}

func TestIdentityKeepsAPIKeyWhenControlHasNoEnrollment(t *testing.T) {
	shortenIdentityRetries(t)
	enrollUnsupportedRetry = time.Hour
	// Control v4.0: no AgentEnrollment service, legacy credentials only.
	fake := newFakeControl(t, fakeModeOptional, false)
	root := t.TempDir()
	client := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, client)
	waitReady(t, client)

	status := client.TransportStatus()
	assert.Equal(t, "api-key", status.Authentication)
	require.NotNil(t, status.Identity)
	assert.False(t, status.Identity.Enrolled)
	assert.Contains(t, status.Identity.LastError, "does not serve AgentEnrollment")
	assert.WithinDuration(t, time.Now().Add(time.Hour), status.Identity.NextEnrollment, time.Minute)
	_, err := os.Stat(filepath.Join(root, "proxy-12", "identity.pem"))
	assert.True(t, errors.Is(err, os.ErrNotExist))
	enrolls, _, streams, _ := fake.records()
	require.Len(t, enrolls, 0, "the fake records only served calls; Unimplemented never reaches it")
	require.NotEmpty(t, streams)
	assert.True(t, streams[len(streams)-1].apiKey)
}

func TestIdentityKeepsAPIKeyWhenControlCannotEnroll(t *testing.T) {
	shortenIdentityRetries(t)
	enrollUnsupportedRetry = time.Hour
	// Control 4.1 in preferred mode without its built-in CA: AgentEnrollment
	// answers FailedPrecondition, and no certificate is requested.
	fake := newFakeControl(t, fakeModePreferred, true)
	fake.mu.Lock()
	fake.pkiEnabled = false
	fake.mu.Unlock()
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: true})
	startClient(t, client)
	waitReady(t, client)
	status := client.TransportStatus()
	assert.Equal(t, "api-key", status.Authentication)
	require.NotNil(t, status.Deprecation)
	assert.Contains(t, status.Identity.LastError, "cannot enroll agents now")
	enrolls, _, _, _ := fake.records()
	assert.Len(t, enrolls, 1, "the deprecation signal does not retry an unavailable enrollment at once")
}

func TestIdentityFallsBackToAPIKeyWhenControlDoesNotRequestTheCertificate(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModePreferred, true)
	root := t.TempDir()
	first := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, first)
	waitReady(t, first)
	require.NoError(t, first.Close())

	// The rollback switch: agent_control.mtls: off requests no certificate.
	fake.setMode(fakeModeOff)
	second := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, second)
	waitReady(t, second)
	status := second.TransportStatus()
	assert.Equal(t, "api-key", status.Authentication)
	require.NotNil(t, status.Identity)
	assert.True(t, status.Identity.Enrolled, "the identity is kept for when Control asks again")
}

func TestIdentityDisabledEnrollmentUsesAPIKey(t *testing.T) {
	fake := newFakeControl(t, fakeModePreferred, true)
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: false})
	startClient(t, client)
	waitReady(t, client)
	assert.Equal(t, "api-key", client.TransportStatus().Authentication)
	enrolls, _, _, _ := fake.records()
	assert.Empty(t, enrolls)
}

func TestIdentityRefusesInsecureCredentialFile(t *testing.T) {
	fake := newFakeControl(t, fakeModeRequired, true)
	credentialFile := filepath.Join(t.TempDir(), "enroll.token")
	require.NoError(t, os.WriteFile(credentialFile, []byte("anixagt_x"), 0o644))
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: true, EnrollCredentialFile: credentialFile})
	_, _, err := client.identity.bootstrap()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chmod 600")

	require.NoError(t, os.WriteFile(credentialFile, []byte("not-a-credential"), 0o600))
	require.NoError(t, os.Chmod(credentialFile, 0o600))
	_, _, err = client.identity.bootstrap()
	require.Error(t, err)
	assert.Contains(t, err.Error(), agentcontrol.EnrollmentCredentialPrefix)
}

func TestIdentityNeedsTLS(t *testing.T) {
	_, err := NewClient(Config{
		Target: "127.0.0.1:1", NodeID: 1, APIKey: "key", AgentVersion: "test-agent",
		Identity: &IdentityConfig{Dir: t.TempDir(), Enroll: true},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs TLS")
}

func TestCertificateRefusalClassification(t *testing.T) {
	for _, message := range []string{
		"agent client certificate revoked", "agent certificate revoked", "agent client certificate expired",
		"the client certificate is not a valid agent certificate of this cluster",
		"x-node-id does not match the client certificate",
	} {
		_, refused := certificateRefusal(status.Error(codes.Unauthenticated, message))
		assert.True(t, refused, message)
	}
	for _, err := range []error{
		status.Error(codes.Unavailable, "agent certificate check failed"),
		status.Error(codes.PermissionDenied, "node is disabled or no longer exists"),
		status.Error(codes.Unauthenticated, "invalid node credentials"),
		errors.New("agent client certificate revoked"),
	} {
		_, refused := certificateRefusal(err)
		assert.False(t, refused, err.Error())
	}
}

func assertPrivate(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, mode, info.Mode().Perm(), path)
}
