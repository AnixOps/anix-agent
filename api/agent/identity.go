package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// IdentityConfig turns on the Agent's mTLS identity on the control stream
// (node-ops-service.md, section 5.3): the Agent enrolls with Control's
// AgentEnrollment, keeps its key and certificate under Dir, renews the
// certificate at Control's renewal time (two thirds of its lifetime), and
// presents it instead of the node API key.
type IdentityConfig struct {
	// Dir is the identity root; pki.DefaultRoot when empty. The node's files
	// live in Dir/proxy-<id>.
	Dir string
	// Enroll lets the Agent enroll when it has no valid identity. Without
	// it, a stored identity is still used and renewed, but never created.
	Enroll bool
	// EnrollCredentialFile holds a one-time anixagt_ enrollment credential
	// (`anix-control agent token create`). It is used before the node API
	// key, and is the only bootstrap Control accepts under
	// agent_control.mtls: required. It is removed after a successful
	// enrollment.
	EnrollCredentialFile string
	// Cluster pins the SPIFFE cluster of issued certificates; empty accepts
	// Control's.
	Cluster string
}

// Retry schedule of enrollment and renewal; variables so tests can shorten
// them.
var (
	enrollRetryMin         = 30 * time.Second
	enrollRetryMax         = 30 * time.Minute
	enrollUnsupportedRetry = 30 * time.Minute
	// enrollWaitingRetry is short: while waiting for a one-time credential
	// an attempt only reads the credential file (the API key bootstrap was
	// refused), so a credential written after a refusal is used promptly.
	enrollWaitingRetry = 5 * time.Second
	renewRetryMin      = time.Minute
	renewRetryMax      = 30 * time.Minute
	identityRPCTimeout = 30 * time.Second
	renewJitterMax     = 30 * time.Minute
)

// Enrollment failure classes, which pick the retry delay.
const (
	enrollFailureTransient   = "transient"
	enrollFailureUnsupported = "unsupported"
	enrollFailureRejected    = "rejected"
	enrollFailureWaiting     = "waiting"
)

// wrongNodeLogInterval spaces out the error logged for agent_cert_wrong_node.
const wrongNodeLogInterval = 10 * time.Minute

// IdentityStatus describes the Agent's identity for status output.
type IdentityStatus struct {
	Enrolled   bool      `json:"enrolled"`
	Dir        string    `json:"dir"`
	SPIFFEID   string    `json:"spiffe_id,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	RenewAfter time.Time `json:"renew_after,omitzero"`
	// NextEnrollment is when an unenrolled Agent tries again.
	NextEnrollment time.Time `json:"next_enrollment,omitzero"`
	LastError      string    `json:"last_error,omitempty"`
}

// identityManager enrolls, stores, renews and drops one node's identity.
type identityManager struct {
	client         *Client
	store          *pki.Store
	enroll         bool
	credentialFile string
	cluster        string
	now            func() time.Time

	mu      sync.Mutex
	loaded  bool
	current *pki.Identity
	renewAt time.Time
	// renewFailures counts renewals that failed since the last success.
	renewFailures int
	nextEnrollAt  time.Time
	enrollFails   int
	failureClass  string
	// apiKeyRefused: Control answered agent_mtls_required to the API key
	// bootstrap; only an enrollment credential can enroll now.
	apiKeyRefused bool
	// refusedCredential is the SHA-256 of an enrollment credential Control
	// rejected, so the Agent does not retry it.
	refusedCredential string
	lastError         string
	certNotRequested  bool
	// wrongNodeLoggedAt and wrongNodeRefusals track agent_cert_wrong_node
	// refusals (a configuration error).
	wrongNodeLoggedAt time.Time
	wrongNodeRefusals uint64
	// enrolling is set while an enrollment runs, so prepare and maintain
	// never enroll twice at once.
	enrolling bool
	changed   chan struct{}
	// onEnrolled runs after an enrollment installed a new identity.
	onEnrolled func()
	// onRejected runs after Control refused the certificate and it was
	// discarded, with Control's code (agent_cert_revoked, ...).
	onRejected func(code string)
}

func newIdentityManager(client *Client, config IdentityConfig) (*identityManager, error) {
	if !client.config.UseTLS {
		return nil, errors.New("the agent identity needs TLS to Control (GRPCUseTLS or an https ApiHost)")
	}
	if client.config.NodeID > int(^uint32(0)) {
		return nil, fmt.Errorf("agent node ID %d is out of range", client.config.NodeID)
	}
	node := client.Node()
	store, err := pki.NewStore(config.Dir, node)
	if err != nil {
		return nil, err
	}
	if config.EnrollCredentialFile != "" && !strings.HasPrefix(config.EnrollCredentialFile, "/") {
		return nil, fmt.Errorf("agent enrollment credential file %q must be an absolute path", config.EnrollCredentialFile)
	}
	return &identityManager{
		client: client, store: store, enroll: config.Enroll, credentialFile: config.EnrollCredentialFile,
		cluster: config.Cluster, now: time.Now, changed: make(chan struct{}, 1),
	}, nil
}

func (m *identityManager) fields() log.Fields {
	return log.Fields{"component": "agent-identity", "node": m.store.Node().String()}
}

func (m *identityManager) signalChanged() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// certificate is the identity to present on the next connection, nil
// without one.
func (m *identityManager) certificate() *pki.Identity {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil || m.current.Expired(m.now()) {
		return nil
	}
	return m.current
}

// prepare runs before each stream session: it loads the stored identity,
// drops an expired one, and enrolls when the node has none and the retry
// time has come. It never fails the session: without an identity the
// stream authenticates with the node API key.
func (m *identityManager) prepare(ctx context.Context) {
	m.mu.Lock()
	first := !m.loaded
	if first {
		m.loadLocked()
	}
	m.dropExpiredLocked()
	due := m.current == nil && m.enroll && !m.now().Before(m.nextEnrollAt)
	m.mu.Unlock()
	if due {
		m.enrollOnce(ctx)
	}
	if first {
		// The background loop waits for the first load.
		m.signalChanged()
	}
}

// dropExpiredLocked discards a certificate that expired before it could be
// renewed, so the Agent enrolls again.
func (m *identityManager) dropExpiredLocked() {
	if m.current != nil && m.current.Expired(m.now()) {
		log.WithFields(m.fields()).WithField("not_after", m.current.NotAfter).
			Warn("Agent certificate expired before it could be renewed; enrolling again")
		m.discardLocked()
	}
}

func (m *identityManager) loadLocked() {
	m.loaded = true
	identity, err := m.store.Load(pki.Expectation{Node: m.store.Node(), Cluster: m.cluster, Now: m.now()})
	switch {
	case errors.Is(err, pki.ErrNotEnrolled):
		if m.enroll {
			log.WithFields(m.fields()).WithField("dir", m.store.Dir()).Info("Agent identity is not enrolled yet; enrolling with Control's AgentEnrollment")
		} else {
			log.WithFields(m.fields()).WithField("dir", m.store.Dir()).Info("Agent identity is not enrolled and AgentIdentity.Enroll is off; the control stream authenticates with the node API key")
		}
		return
	case err != nil:
		log.WithFields(m.fields()).WithError(err).Warn("Stored agent identity is unusable; enrolling again")
		_ = m.store.Discard()
		return
	}
	m.setCurrentLocked(identity)
	log.WithFields(m.fields()).WithFields(log.Fields{
		"spiffe_id": identity.SPIFFEID, "serial": identity.Serial,
		"not_after": identity.NotAfter.UTC().Format(time.RFC3339), "renew_after": identity.RenewAfter.UTC().Format(time.RFC3339),
	}).Info("Agent identity loaded")
}

// setCurrentLocked installs identity and picks its renewal time: Control's
// renew_after plus a jitter of at most a tenth of the time left after it.
func (m *identityManager) setCurrentLocked(identity *pki.Identity) {
	m.current = identity
	m.renewFailures = 0
	m.enrollFails = 0
	m.failureClass = ""
	m.lastError = ""
	jitter := identity.NotAfter.Sub(identity.RenewAfter) / 10
	if jitter > renewJitterMax {
		jitter = renewJitterMax
	}
	m.renewAt = identity.RenewAfter
	if jitter > 0 {
		m.client.randMu.Lock()
		m.renewAt = m.renewAt.Add(time.Duration(m.client.config.Rand.Int63n(int64(jitter))))
		m.client.randMu.Unlock()
	}
	m.signalChanged()
}

func (m *identityManager) discardLocked() {
	if err := m.store.Discard(); err != nil {
		log.WithFields(m.fields()).WithError(err).Warn("Could not remove the stored agent identity")
	}
	m.current = nil
	m.nextEnrollAt = time.Time{}
	m.signalChanged()
}

// rejected handles Control refusing the certificate identity presented:
// revoked, expired, or not of this cluster. The identity is dropped and the
// next session enrolls again (with the API key when Control still allows
// it).
func (m *identityManager) rejected(identity *pki.Identity, reason, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if identity == nil || m.current != identity {
		return
	}
	log.WithFields(m.fields()).WithFields(log.Fields{"serial": identity.Serial, "reason": reason, "error_code": code}).
		Warn("Control refused the agent certificate; discarding it and enrolling again")
	m.discardLocked()
	if hook := m.onRejected; hook != nil {
		// Outside the lock: the hook may call back into the client.
		go hook(code)
	}
}

// wrongNode logs, at most once per wrongNodeLogInterval, that Control
// refused the certificate as another node's: the configuration names
// another node than the certificate. The certificate is kept; enrolling
// again would not fix the configuration.
func (m *identityManager) wrongNode(err error) {
	m.mu.Lock()
	now := m.now()
	due := m.wrongNodeLoggedAt.IsZero() || now.Sub(m.wrongNodeLoggedAt) >= wrongNodeLogInterval
	if due {
		m.wrongNodeLoggedAt = now
	}
	m.wrongNodeRefusals++
	m.mu.Unlock()
	if due {
		log.WithFields(m.fields()).WithError(err).Error("Control refused the agent certificate as another node's (agent_cert_wrong_node): this Agent's NodeID does not match its certificate. This is a configuration error; the Agent keeps the certificate and retries slowly. Fix NodeID, or remove the identity directory to enroll again")
	}
}

// enrollSoon brings the next enrollment forward after a signal that Control
// can enroll now (a deprecation notice, an agent_mtls_required refusal),
// unless the last attempt found enrollment unavailable.
func (m *identityManager) enrollSoon() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil && m.failureClass != enrollFailureUnsupported && m.failureClass != enrollFailureRejected {
		m.nextEnrollAt = time.Time{}
		m.signalChanged()
	}
}

// apiKeyAccepted records that Control served a session authenticated with
// the node API key, so it is not in agent_control.mtls: required (any
// more): an earlier refusal of the API key bootstrap no longer holds, and an
// Agent waiting for a credential may enroll with the key again.
func (m *identityManager) apiKeyAccepted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.apiKeyRefused {
		return
	}
	m.apiKeyRefused = false
	if m.current == nil && m.failureClass == enrollFailureWaiting {
		m.nextEnrollAt = time.Time{}
		m.signalChanged()
	}
}

// noteCertificateNotRequested logs once that Control did not ask for the
// client certificate, so the stream fell back to the node API key.
func (m *identityManager) noteCertificateNotRequested() {
	m.mu.Lock()
	first := !m.certNotRequested
	m.certNotRequested = true
	m.mu.Unlock()
	if first {
		log.WithFields(m.fields()).Warn("Control did not request the agent client certificate (agent_control.mtls: off, or Control runs without its agent PKI); the control stream authenticates with the node API key")
	}
}

// status describes the identity.
func (m *identityManager) status() IdentityStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := IdentityStatus{Dir: m.store.Dir(), LastError: m.lastError}
	if m.current != nil {
		status.Enrolled = true
		status.SPIFFEID, status.Serial = m.current.SPIFFEID, m.current.Serial
		status.NotAfter, status.RenewAfter = m.current.NotAfter, m.renewAt
	} else if m.enroll {
		status.NextEnrollment = m.nextEnrollAt
	}
	return status
}

// metrics are the identity's heartbeat metrics.
func (m *identityManager) metrics() map[string]float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	metrics := map[string]float64{MetricIdentityEnrolled: 0, MetricIdentityWrongNode: float64(m.wrongNodeRefusals)}
	if m.current != nil {
		metrics[MetricIdentityEnrolled] = 1
		metrics[MetricIdentityExpiresIn] = m.current.NotAfter.Sub(m.now()).Seconds()
	}
	return metrics
}

// Heartbeat metric keys of the identity.
const (
	// MetricIdentityEnrolled is 1 while the Agent holds a valid certificate.
	MetricIdentityEnrolled = "agent_identity_enrolled"
	// MetricIdentityExpiresIn is the time left on the certificate, in
	// seconds.
	MetricIdentityExpiresIn = "agent_identity_expires_in_seconds"
	// MetricIdentityWrongNode counts agent_cert_wrong_node refusals: the
	// certificate names another node than the configuration.
	MetricIdentityWrongNode = "agent_identity_wrong_node_refusals_total"
)

// readCredential reads the one-time enrollment credential, "" without
// one. The file must be private to the Agent's user.
func (m *identityManager) readCredential() (string, error) {
	if m.credentialFile == "" {
		return "", nil
	}
	file, err := os.Open(m.credentialFile)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %04o; an enrollment credential must be private (chmod 600)", m.credentialFile, info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxCredentialFileBytes))
	if err != nil {
		return "", err
	}
	credential := strings.TrimSpace(string(raw))
	if credential == "" {
		return "", nil
	}
	if !strings.HasPrefix(credential, agentcontrol.EnrollmentCredentialPrefix) {
		return "", fmt.Errorf("%s does not hold an %s enrollment credential", m.credentialFile, agentcontrol.EnrollmentCredentialPrefix)
	}
	return credential, nil
}

// maxCredentialFileBytes bounds the read of the credential file; an
// anixagt_ credential is about 50 bytes.
const maxCredentialFileBytes = 4096

func credentialDigest(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(digest[:])
}

// bootstrap picks how to enroll: the enrollment credential, else the node
// API key unless Control refused it.
func (m *identityManager) bootstrap() (method, credential string, err error) {
	credential, err = m.readCredential()
	if err != nil {
		return "", "", err
	}
	m.mu.Lock()
	refusedCredential, apiKeyRefused := m.refusedCredential, m.apiKeyRefused
	m.mu.Unlock()
	if credential != "" && credentialDigest(credential) != refusedCredential {
		return pki.BootstrapEnrollmentCredential, credential, nil
	}
	if !apiKeyRefused && strings.TrimSpace(m.client.config.APIKey) != "" {
		return pki.BootstrapNodeAPIKey, "", nil
	}
	if credential != "" {
		return "", "", fmt.Errorf("Control rejected the enrollment credential in %s and requires one (agent_control.mtls: required); issue a new one with `anix-control agent token create -node %s`", m.credentialFile, m.store.Node())
	}
	return "", "", fmt.Errorf("Control requires a one-time enrollment credential (agent_control.mtls: required); issue one with `anix-control agent token create -node %s` and write it to AgentIdentity.EnrollCredentialFile", m.store.Node())
}

// enrollOnce runs one enrollment and schedules the next on failure.
func (m *identityManager) enrollOnce(ctx context.Context) {
	m.mu.Lock()
	// Rechecked under the lock: prepare and maintain may both find an
	// attempt due, and the first one reschedules the next.
	if m.current != nil || m.enrolling || !m.enroll || m.now().Before(m.nextEnrollAt) {
		m.mu.Unlock()
		return
	}
	m.enrolling = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.enrolling = false
		m.mu.Unlock()
	}()
	method, credential, err := m.bootstrap()
	if err != nil {
		m.enrollFailed(enrollFailureWaiting, err)
		return
	}
	identity, err := m.enrollWith(ctx, method, credential)
	if err != nil {
		m.classifyEnrollFailure(method, credential, err)
		return
	}
	m.mu.Lock()
	installed := m.installLocked(nil, identity)
	m.mu.Unlock()
	if !installed {
		return
	}
	log.WithFields(m.fields()).WithFields(log.Fields{
		"spiffe_id": identity.SPIFFEID, "serial": identity.Serial, "bootstrap": method,
		"not_after": identity.NotAfter.UTC().Format(time.RFC3339), "renew_after": identity.RenewAfter.UTC().Format(time.RFC3339),
	}).Info("Agent enrolled; the control stream now authenticates with its client certificate instead of the node API key")
	if method == pki.BootstrapEnrollmentCredential {
		if err := os.Remove(m.credentialFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.WithFields(m.fields()).WithError(err).Warn("Could not remove the used enrollment credential")
		}
	}
	if m.onEnrolled != nil {
		m.onEnrolled()
	}
}

func (m *identityManager) enrollWith(ctx context.Context, method, credential string) (*pki.Identity, error) {
	key, err := pki.GenerateKey()
	if err != nil {
		return nil, err
	}
	csr, err := pki.NewCSR(key, m.store.Node())
	if err != nil {
		return nil, err
	}
	conn, err := m.client.dialIdentity(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("dial agent enrollment: %w", err)
	}
	defer conn.Close()
	pairs := []string{
		agentcontrol.MetadataNodeID, strconv.Itoa(m.client.config.NodeID),
		agentcontrol.MetadataNodeKind, m.client.config.NodeKind,
	}
	if method == pki.BootstrapNodeAPIKey {
		pairs = append(pairs, agentcontrol.MetadataAPIKey, m.client.config.APIKey)
	}
	callCtx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, pairs...), identityRPCTimeout)
	defer cancel()
	var trailer metadata.MD
	response, err := agentv1pb.NewAgentEnrollmentClient(conn).Enroll(callCtx, &agentv1pb.EnrollAgentRequest{
		CsrDer: csr, EnrollmentCredential: credential,
		AgentVersion: m.client.config.AgentVersion, InstanceId: m.client.config.InstanceID,
	}, grpc.Trailer(&trailer))
	if err != nil {
		if refused := mtlsRequiredError("enrollment", err, trailer); refused != nil {
			return nil, refused
		}
		return nil, withControlCode(err, trailer)
	}
	identity, err := pki.FromIssued(key, response.GetCertificate(), pki.Expectation{
		Node: m.store.Node(), Cluster: m.cluster, Now: m.now(),
	})
	if err != nil {
		return nil, err
	}
	identity.EnrolledAt, identity.Bootstrap = m.now().UTC(), method
	return identity, nil
}

// installLocked stores identity and makes it current, if expected is still
// the current identity (nil for an enrollment). A failed save keeps the
// identity for this process only; the next start enrolls again.
func (m *identityManager) installLocked(expected, identity *pki.Identity) bool {
	if m.current != expected {
		return false
	}
	if err := m.store.Save(identity); err != nil {
		log.WithFields(m.fields()).WithError(err).Error("Could not store the agent identity; it is kept in memory only")
	}
	m.setCurrentLocked(identity)
	return true
}

func (m *identityManager) classifyEnrollFailure(method, credential string, err error) {
	st, _ := grpcStatus(err)
	rejected := errorCodeOf(err) == agentcontrol.ErrorCodeEnrollmentRejected
	switch {
	case errors.Is(err, ErrMTLSRequired):
		m.mu.Lock()
		m.apiKeyRefused = true
		m.mu.Unlock()
		m.enrollFailed(enrollFailureWaiting, fmt.Errorf("%w; write a one-time credential from `anix-control agent token create -node %s` to AgentIdentity.EnrollCredentialFile", err, m.store.Node()))
	case st != nil && st.Code() == codes.Unimplemented:
		m.enrollFailed(enrollFailureUnsupported, fmt.Errorf("Control does not serve AgentEnrollment (a Control before v4.1); the control stream keeps the node API key: %w", err))
	case st != nil && st.Code() == codes.FailedPrecondition:
		m.enrollFailed(enrollFailureUnsupported, fmt.Errorf("Control cannot enroll agents now (agent_control.mtls: off, or Control runs without its built-in CA); the control stream keeps the node API key: %w", err))
	case rejected || (st != nil && (st.Code() == codes.Unauthenticated || st.Code() == codes.PermissionDenied)):
		// agent_enrollment_rejected: this bootstrap is unusable; it is
		// not tried again.
		if method == pki.BootstrapEnrollmentCredential {
			m.mu.Lock()
			m.refusedCredential = credentialDigest(credential)
			m.mu.Unlock()
			// Try the node API key next, if Control still takes it.
			m.enrollFailed(enrollFailureTransient, fmt.Errorf("Control rejected the enrollment credential in %s (used, expired, revoked or for another node): %w", m.credentialFile, err))
			m.mu.Lock()
			m.nextEnrollAt = time.Time{}
			m.mu.Unlock()
			return
		}
		m.enrollFailed(enrollFailureRejected, fmt.Errorf("Control rejected the node API key for enrollment (replaced credentials, or a disabled node): %w", err))
	default:
		m.enrollFailed(enrollFailureTransient, err)
	}
}

// enrollFailed records a failure and schedules the next attempt.
func (m *identityManager) enrollFailed(class string, err error) {
	m.mu.Lock()
	m.enrollFails++
	previous := m.failureClass
	m.failureClass, m.lastError = class, err.Error()
	var delay time.Duration
	switch class {
	case enrollFailureUnsupported:
		delay = enrollUnsupportedRetry
	case enrollFailureWaiting:
		delay = enrollWaitingRetry
	default:
		delay = enrollRetryMin
		for i := 1; i < m.enrollFails && delay < enrollRetryMax; i++ {
			delay *= 2
		}
		if delay > enrollRetryMax {
			delay = enrollRetryMax
		}
	}
	m.nextEnrollAt = m.now().Add(delay)
	m.mu.Unlock()
	entry := log.WithFields(m.fields()).WithError(err).WithField("retry_in", delay.String())
	switch {
	case class == enrollFailureUnsupported && previous == enrollFailureUnsupported:
		entry.Debug("Agent enrollment is still unavailable")
	case class == enrollFailureUnsupported:
		entry.Info("Agent enrollment is unavailable")
	case class == enrollFailureWaiting && previous == enrollFailureWaiting:
		entry.Debug("Agent enrollment is waiting for an enrollment credential")
	default:
		entry.Warn("Agent enrollment failed")
	}
}

// maintain keeps the identity current until ctx ends: it renews the
// certificate at its renewal time, and enrolls an Agent without one when the
// retry time comes, also while a session authenticated with the API key is
// open (the client then reconnects with the certificate). The first attempt
// is prepare's, before the first session.
func (m *identityManager) maintain(ctx context.Context) {
	for {
		m.mu.Lock()
		m.dropExpiredLocked()
		wait := time.Hour
		var renewing *pki.Identity
		enrolling := false
		switch {
		case !m.loaded:
		case m.current != nil:
			renewing, wait = m.current, m.renewAt.Sub(m.now())
		case m.enroll:
			enrolling, wait = true, m.nextEnrollAt.Sub(m.now())
		}
		m.mu.Unlock()
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-m.changed:
			timer.Stop()
			continue
		case <-timer.C:
		}
		switch {
		case renewing != nil:
			m.renew(ctx, renewing)
		case enrolling:
			m.enrollOnce(ctx)
		}
	}
}

// renew replaces identity with a certificate for a new key; on failure it
// schedules a retry, or drops the identity when Control refuses it.
func (m *identityManager) renew(ctx context.Context, identity *pki.Identity) {
	renewed, err := m.renewWith(ctx, identity)
	if err == nil {
		m.mu.Lock()
		installed := m.installLocked(identity, renewed)
		m.mu.Unlock()
		if !installed {
			return
		}
		log.WithFields(m.fields()).WithFields(log.Fields{
			"serial": renewed.Serial, "not_after": renewed.NotAfter.UTC().Format(time.RFC3339),
			"renew_after": renewed.RenewAfter.UTC().Format(time.RFC3339),
		}).Info("Agent certificate renewed")
		return
	}
	switch reason, action := certificateRefusal(err); action {
	case certificateReenroll:
		m.rejected(identity, reason, refusalCode(err))
		return
	case certificateWrongNode:
		m.wrongNode(err)
	}
	m.mu.Lock()
	m.renewFailures++
	delay := renewRetryMin
	for i := 1; i < m.renewFailures && delay < renewRetryMax; i++ {
		delay *= 2
	}
	if delay > renewRetryMax {
		delay = renewRetryMax
	}
	if m.current == identity {
		m.renewAt = m.now().Add(delay)
		m.lastError = err.Error()
	}
	m.mu.Unlock()
	log.WithFields(m.fields()).WithError(err).WithFields(log.Fields{
		"retry_in": delay.String(), "not_after": identity.NotAfter.UTC().Format(time.RFC3339),
	}).Warn("Agent certificate renewal failed; the current certificate stays in use until it expires")
}

func (m *identityManager) renewWith(ctx context.Context, identity *pki.Identity) (*pki.Identity, error) {
	key, err := pki.GenerateKey()
	if err != nil {
		return nil, err
	}
	csr, err := pki.NewCSR(key, m.store.Node())
	if err != nil {
		return nil, err
	}
	conn, err := m.client.dialIdentity(ctx, identity.TLSCertificate())
	if err != nil {
		return nil, fmt.Errorf("dial agent enrollment: %w", err)
	}
	defer conn.Close()
	callCtx, cancel := context.WithTimeout(ctx, identityRPCTimeout)
	defer cancel()
	var trailer metadata.MD
	response, err := agentv1pb.NewAgentEnrollmentClient(conn).Renew(callCtx, &agentv1pb.RenewAgentCertificateRequest{CsrDer: csr}, grpc.Trailer(&trailer))
	if err != nil {
		return nil, withControlCode(err, trailer)
	}
	renewed, err := pki.FromIssued(key, response.GetCertificate(), pki.Expectation{
		Node: m.store.Node(), Cluster: m.cluster, Now: m.now(),
	})
	if err != nil {
		return nil, err
	}
	renewed.EnrolledAt, renewed.RenewedAt, renewed.Bootstrap = identity.EnrolledAt, m.now().UTC(), identity.Bootstrap
	return renewed, nil
}

// sessionCredentials presents an identity on one connection and records
// whether Control asked for it.
type sessionCredentials struct {
	identity  *pki.Identity
	requested bool
	presented bool
	mu        sync.Mutex
}

func (s *sessionCredentials) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requested = true
	if certificate := s.identity.TLSCertificate(); certificate != nil {
		s.presented = true
		return certificate, nil
	}
	return &tls.Certificate{}, nil
}

func (s *sessionCredentials) state() (requested, presented bool) {
	if s == nil {
		return false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requested, s.presented
}
