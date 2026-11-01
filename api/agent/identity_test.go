package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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

// waitIssued waits until Control has issued n certificates and returns their
// serials.

func waitIssued(t *testing.T, fake *fakeControl, n int) []string {
	t.Helper()
	require.Eventually(t, func() bool {
		_, _, _, issued := fake.records()
		return len(issued) >= n
	}, 10*time.Second, 10*time.Millisecond, "Control did not issue %d certificate(s)", n)
	_, _, _, issued := fake.records()
	require.Len(t, issued, n)
	return issued
}

// waitEnrolled waits until the Agent has installed and stored its
// certificate.
func waitEnrolled(t *testing.T, client *Client) {
	t.Helper()
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.Identity != nil && status.Identity.Enrolled
	}, 10*time.Second, 10*time.Millisecond, "the Agent did not enroll")
}

func certificateSessions(streams []fakeStreamAuth) (accepted []fakeStreamAuth) {
	for _, stream := range streams {
		if stream.accepted && stream.certificateSerial != "" {
			accepted = append(accepted, stream)
		}
	}
	return accepted
}

// withCredential issues a one-time credential and writes it to a new
// credential file of an identity rooted at root.
func (f *fakeControl) withCredential(t *testing.T, root, credential string) *IdentityConfig {
	t.Helper()
	file := filepath.Join(t.TempDir(), "enroll.token")
	f.writeCredential(t, file, credential)
	return &IdentityConfig{Dir: root, Enroll: true, EnrollCredentialFile: file}
}

func (f *fakeControl) writeCredential(t *testing.T, file, credential string) {
	t.Helper()
	f.addCredential(credential)
	require.NoError(t, os.WriteFile(file, []byte(credential+"\n"), 0o600))
}

func TestIdentityEnrollsWithCredentialThenConnectsWithCertificate(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	root := t.TempDir()
	identity := fake.withCredential(t, root, "anixagt_test-credential")
	client := fake.client(t, identity)
	startClient(t, client)
	waitReady(t, client)

	status := client.TransportStatus()
	require.NotNil(t, status.Identity)
	assert.True(t, status.Identity.Enrolled)
	assert.Equal(t, "spiffe://anixops/test-cluster/agent/proxy-12", status.Identity.SPIFFEID)

	enrolls, _, streams, issued := fake.records()
	require.Len(t, enrolls, 1)
	assert.True(t, enrolls[0].credential)
	assert.Equal(t, agentcontrol.NodeKindProxy, enrolls[0].nodeKind)
	assert.Equal(t, codes.OK, enrolls[0].err)
	require.NotEmpty(t, issued)
	require.NotEmpty(t, streams)
	for _, stream := range streams {
		assert.Equal(t, issued[0], stream.certificateSerial, "every session presents the certificate")
	}
	_, err := os.Stat(identity.EnrollCredentialFile)
	assert.True(t, errors.Is(err, os.ErrNotExist), "the used one-time credential is removed")

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
	assert.Equal(t, pki.BootstrapEnrollmentCredential, inspected.Bootstrap)

	require.Eventually(t, func() bool {
		metrics := client.transportMetrics()
		return metrics[MetricIdentityEnrolled] == 1 && metrics[MetricIdentityExpiresIn] > 0
	}, time.Second, 10*time.Millisecond)
}

func TestIdentityWaitsForACredentialWithoutOpeningAStream(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	credentialFile := filepath.Join(t.TempDir(), "enroll.token")
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: true, EnrollCredentialFile: credentialFile})
	startClient(t, client)
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.Identity != nil && strings.Contains(status.Identity.LastError, "EnrollCredentialFile")
	}, 5*time.Second, 10*time.Millisecond)
	assert.False(t, client.TransportStatus().Connected)
	enrolls, _, streams, _ := fake.records()
	assert.Empty(t, enrolls, "no enrollment without a credential")
	assert.Empty(t, streams, "no stream without a certificate")

	fake.writeCredential(t, credentialFile, "anixagt_late")
	require.Eventually(t, func() bool { return client.TransportStatus().Connected }, 10*time.Second, 10*time.Millisecond)
}

func TestIdentityRejectedCredentialIsNotRetried(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	credentialFile := filepath.Join(t.TempDir(), "enroll.token")
	require.NoError(t, os.WriteFile(credentialFile, []byte("anixagt_unknown\n"), 0o600))
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: true, EnrollCredentialFile: credentialFile})
	startClient(t, client)
	require.Eventually(t, func() bool {
		enrolls, _, _, _ := fake.records()
		return len(enrolls) == 1
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, codes.Unauthenticated, func() codes.Code { enrolls, _, _, _ := fake.records(); return enrolls[0].err }())
	time.Sleep(200 * time.Millisecond)
	enrolls, _, _, _ := fake.records()
	assert.Len(t, enrolls, 1, "a rejected credential is not sent again")
	assert.Contains(t, client.TransportStatus().Identity.LastError, "rejected the enrollment credential")

	fake.writeCredential(t, credentialFile, "anixagt_new")
	require.Eventually(t, func() bool { return client.TransportStatus().Connected }, 10*time.Second, 10*time.Millisecond)
}

func TestIdentityLoadsStoredCertificateAfterRestart(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	root := t.TempDir()
	first := fake.client(t, fake.withCredential(t, root, "anixagt_first"))
	startClient(t, first)
	waitReady(t, first)
	require.NoError(t, first.Close())

	// The restarted Agent has no credential any more: it needs none.
	second := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, second)
	waitReady(t, second)
	enrolls, _, _, issued := fake.records()
	assert.Len(t, enrolls, 1, "the stored identity is reused, not enrolled again")
	assert.Equal(t, issued[0], second.TransportStatus().Identity.Serial)
}

func TestIdentityRenewsAtControlsRenewalTime(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	fake.setLifetime(3 * time.Second)
	root := t.TempDir()
	client := fake.client(t, fake.withCredential(t, root, "anixagt_first"))
	startClient(t, client)
	waitReady(t, client)
	issued := waitIssued(t, fake, 1)
	fake.setLifetime(time.Hour)

	require.Eventually(t, func() bool {
		_, renews, _, _ := fake.records()
		return len(renews) > 0 && renews[0].err == codes.OK
	}, 10*time.Second, 20*time.Millisecond)
	_, renews, _, issued := fake.records()
	assert.Equal(t, issued[0], renews[0].serial, "the renewal presents the current certificate")
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
	assert.Equal(t, pki.BootstrapEnrollmentCredential, inspected.Bootstrap, "renewal keeps the enrollment's bootstrap")

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
	fake := newFakeControl(t, fakeModeRequired, true)
	root := t.TempDir()
	identity := fake.withCredential(t, root, "anixagt_first")
	client := fake.client(t, identity)
	startClient(t, client)
	waitReady(t, client)
	issued := waitIssued(t, fake, 1)

	// Revoked while the stream is open: Control ends it at the next
	// heartbeat; the Agent drops the certificate and enrolls again with the
	// new credential the operator issued.
	fake.writeCredential(t, identity.EnrollCredentialFile, "anixagt_second")
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
	assert.True(t, enrolls[1].credential)

	store, err := pki.NewStore(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	assert.Equal(t, issued[1], store.Inspect(time.Now()).Serial)
}

func TestIdentityRevokedCertificateRefusedAtRenewal(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	root := t.TempDir()
	config := fake.withCredential(t, root, "anixagt_first")
	client := fake.client(t, config)
	client.identity.prepare(client.ctx)
	identity := client.identity.certificate()
	require.NotNil(t, identity)

	fake.revoke(identity.Serial)
	client.identity.renew(client.ctx, identity)
	assert.Nil(t, client.identity.certificate(), "a certificate Control refuses at renewal is dropped")
	store, err := pki.NewStore(root, agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	require.NoError(t, err)
	assert.Equal(t, pki.StateNotEnrolled, store.Inspect(time.Now()).State)

	fake.writeCredential(t, config.EnrollCredentialFile, "anixagt_second")
	client.identity.prepare(client.ctx)
	renewed := client.identity.certificate()
	require.NotNil(t, renewed)
	assert.NotEqual(t, identity.Serial, renewed.Serial)
}

func TestIdentityWaitsWhenControlHasNoEnrollment(t *testing.T) {
	shortenIdentityRetries(t)
	enrollUnsupportedRetry = time.Hour
	// No AgentEnrollment service.
	fake := newFakeControl(t, fakeModeRequired, false)
	root := t.TempDir()
	client := fake.client(t, fake.withCredential(t, root, "anixagt_first"))
	startClient(t, client)
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.Identity != nil && strings.Contains(status.Identity.LastError, "does not serve AgentEnrollment")
	}, 10*time.Second, 10*time.Millisecond)

	status := client.TransportStatus()
	assert.False(t, status.Connected)
	assert.False(t, status.Identity.Enrolled)
	assert.WithinDuration(t, time.Now().Add(time.Hour), status.Identity.NextEnrollment, time.Minute)
	_, err := os.Stat(filepath.Join(root, "proxy-12", "identity.pem"))
	assert.True(t, errors.Is(err, os.ErrNotExist))
	_, _, streams, _ := fake.records()
	assert.Empty(t, streams, "no stream without a certificate")
}

func TestIdentityWaitsWhenControlCannotEnroll(t *testing.T) {
	shortenIdentityRetries(t)
	enrollUnsupportedRetry = time.Hour
	// Control without its built-in CA: AgentEnrollment answers
	// FailedPrecondition.
	fake := newFakeControl(t, fakeModeRequired, true)
	fake.mu.Lock()
	fake.pkiEnabled = false
	fake.mu.Unlock()
	client := fake.client(t, fake.withCredential(t, t.TempDir(), "anixagt_first"))
	startClient(t, client)
	require.Eventually(t, func() bool {
		status := client.TransportStatus()
		return status.Identity != nil && strings.Contains(status.Identity.LastError, "cannot enroll agents now")
	}, 10*time.Second, 10*time.Millisecond)
	assert.False(t, client.TransportStatus().Connected)
	enrolls, _, _, _ := fake.records()
	assert.Len(t, enrolls, 1, "an unavailable enrollment is not retried at once")
}

func TestIdentityKeepsTheCertificateWhenControlDoesNotRequestIt(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	root := t.TempDir()
	first := fake.client(t, fake.withCredential(t, root, "anixagt_first"))
	startClient(t, first)
	waitReady(t, first)
	require.NoError(t, first.Close())

	// agent_control.mtls: off requests no certificate: the stream has no
	// credential, and the identity is kept for when Control asks again.
	fake.setMode(fakeModeOff)
	second := fake.client(t, &IdentityConfig{Dir: root, Enroll: true})
	startClient(t, second)
	require.Eventually(t, func() bool {
		return strings.Contains(second.TransportStatus().LastError, "did not request the agent client certificate")
	}, 5*time.Second, 10*time.Millisecond)
	status := second.TransportStatus()
	assert.False(t, status.Connected)
	assert.True(t, status.Identity.Enrolled)

	fake.setMode(fakeModeRequired)
	waitReady(t, second)
}

func TestIdentityDisabledEnrollmentNeverEnrolls(t *testing.T) {
	shortenIdentityRetries(t)
	fake := newFakeControl(t, fakeModeRequired, true)
	identity := fake.withCredential(t, t.TempDir(), "anixagt_first")
	identity.Enroll = false
	client := fake.client(t, identity)
	startClient(t, client)
	time.Sleep(200 * time.Millisecond)
	assert.False(t, client.TransportStatus().Connected)
	enrolls, _, streams, _ := fake.records()
	assert.Empty(t, enrolls)
	assert.Empty(t, streams)
}

func TestIdentityRefusesInsecureCredentialFile(t *testing.T) {
	fake := newFakeControl(t, fakeModeRequired, true)
	credentialFile := filepath.Join(t.TempDir(), "enroll.token")
	require.NoError(t, os.WriteFile(credentialFile, []byte("anixagt_x"), 0o644))
	client := fake.client(t, &IdentityConfig{Dir: t.TempDir(), Enroll: true, EnrollCredentialFile: credentialFile})
	_, err := client.identity.bootstrap()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chmod 600")

	require.NoError(t, os.WriteFile(credentialFile, []byte("not-a-credential"), 0o600))
	require.NoError(t, os.Chmod(credentialFile, 0o600))
	_, err = client.identity.bootstrap()
	require.Error(t, err)
	assert.Contains(t, err.Error(), agentcontrol.EnrollmentCredentialPrefix)
}

func TestClientNeedsTheIdentity(t *testing.T) {
	_, err := NewClient(Config{Target: "127.0.0.1:1", NodeID: 1, UseTLS: true, AgentVersion: "test-agent"})
	require.ErrorContains(t, err, "agent identity")
}

func TestIdentityNeedsTLS(t *testing.T) {
	_, err := NewClient(Config{
		Target: "127.0.0.1:1", NodeID: 1, AgentVersion: "test-agent",
		Identity: &IdentityConfig{Dir: t.TempDir(), Enroll: true},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs TLS")
}

func TestCertificateRefusalClassification(t *testing.T) {
	// Controls before the error codes: their messages.
	for _, message := range []string{
		"agent client certificate revoked", "agent certificate revoked", "agent client certificate expired",
		"the client certificate is not a valid agent certificate of this cluster",
	} {
		_, action := certificateRefusal(status.Error(codes.Unauthenticated, message))
		assert.Equal(t, certificateReenroll, action, message)
	}
	_, action := certificateRefusal(status.Error(codes.Unauthenticated, "x-node-id does not match the client certificate"))
	assert.Equal(t, certificateWrongNode, action, "another node's certificate is a configuration error, not a reason to enroll again")

	// The codes: the message prefix, or the trailer.
	for code, want := range map[string]certificateAction{
		agentcontrol.ErrorCodeCertRevoked:      certificateReenroll,
		agentcontrol.ErrorCodeCertExpired:      certificateReenroll,
		agentcontrol.ErrorCodeCertInvalid:      certificateReenroll,
		agentcontrol.ErrorCodeCertWrongCluster: certificateReenroll,
		agentcontrol.ErrorCodeCertWrongNode:    certificateWrongNode,
		agentcontrol.ErrorCodeMTLSRequired:     certificateKept,
		"agent_cert_something_new":             certificateKept,
	} {
		_, action := certificateRefusal(status.Error(codes.Unauthenticated, code+": refused"))
		assert.Equal(t, want, action, code)
		coded := withControlCode(status.Error(codes.Unauthenticated, "refused"), metadata.Pairs(agentcontrol.MetadataErrorCode, code))
		_, action = certificateRefusal(coded)
		assert.Equal(t, want, action, "trailer "+code)
	}
	// agent_cert_revoked also comes as PermissionDenied (a node disabled
	// after the certificate check).
	_, action = certificateRefusal(status.Error(codes.PermissionDenied, agentcontrol.ErrorCodeCertRevoked+": node is disabled"))
	assert.Equal(t, certificateReenroll, action)

	for _, err := range []error{
		status.Error(codes.Unavailable, "agent certificate check failed"),
		status.Error(codes.PermissionDenied, "node is disabled or no longer exists"),
		status.Error(codes.Unauthenticated, "invalid node credentials"),
		errors.New("agent client certificate revoked"),
	} {
		_, action := certificateRefusal(err)
		assert.Equal(t, certificateKept, action, err.Error())
	}
}

func TestControlErrorCodeShape(t *testing.T) {
	assert.Equal(t, "plugin_release_download_busy", controlErrorCode(status.Error(codes.ResourceExhausted, "plugin_release_download_busy: two downloads run"), nil))
	assert.Equal(t, "", controlErrorCode(status.Error(codes.Unavailable, "database: down"), nil), "a first word without _ is no code")
	assert.Equal(t, "", controlErrorCode(status.Error(codes.Unavailable, "Agent_Cert: x"), nil))
	assert.Equal(t, "agent_cert_expired", controlErrorCode(status.Error(codes.Unauthenticated, "expired"), metadata.Pairs(agentcontrol.MetadataErrorCode, "agent_cert_expired")))
}

func assertPrivate(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, mode, info.Mode().Perm(), path)
}

func TestReadCredentialFile(t *testing.T) {
	dir := t.TempDir()
	write := func(content string, mode os.FileMode) string {
		file, err := os.CreateTemp(dir, "credential-*")
		require.NoError(t, err)
		_, err = file.WriteString(content)
		require.NoError(t, err)
		require.NoError(t, file.Close())
		require.NoError(t, os.Chmod(file.Name(), mode))
		return file.Name()
	}
	prefixes := []string{agentcontrol.JoinTokenPrefix, agentcontrol.EnrollmentCredentialPrefix}

	credential, err := ReadCredentialFile(write("  anixjoin_abc\n", 0o600), prefixes...)
	require.NoError(t, err)
	assert.Equal(t, "anixjoin_abc", credential)
	credential, err = ReadCredentialFile(write("anixagt_abc", 0o400), prefixes...)
	require.NoError(t, err)
	assert.Equal(t, "anixagt_abc", credential)
	credential, err = ReadCredentialFile(write("\n", 0o600), prefixes...)
	require.NoError(t, err)
	assert.Empty(t, credential)

	_, err = ReadCredentialFile(write("anixjoin_abc", 0o640), prefixes...)
	assert.ErrorContains(t, err, "chmod 600")
	_, err = ReadCredentialFile(write("anixjoin_abc", 0o600), agentcontrol.EnrollmentCredentialPrefix)
	assert.ErrorContains(t, err, "does not hold an anixagt_ enrollment credential")
	_, err = ReadCredentialFile(filepath.Join(dir, "missing"), prefixes...)
	assert.ErrorIs(t, err, os.ErrNotExist)

	// The read stops at the size limit.
	credential, err = ReadCredentialFile(write("anixjoin_"+strings.Repeat("a", 2*maxCredentialFileBytes), 0o600), prefixes...)
	require.NoError(t, err)
	assert.Len(t, credential, maxCredentialFileBytes)
}
