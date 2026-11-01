package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v5/api/agent/pki"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testJoinToken    = "anixjoin_Ri0cFz3Vq9cZb1mH2kTnWm6xP8yJ4aLs7dQe5uGo0fA"
	testMachineID    = "0123456789abcdef0123456789abcdef"
	testFingerprint  = "ba1c6ef50d244f2c023396a3bb3cf4c8feea7522676a99a3316e08990ed9dfa3"
	testControlURL   = "https://panel.example.com"
	testJoinedNode   = "proxy-12"
	testJoinedSPIFFE = "spiffe://anixops/test-cluster/agent/proxy-12"
)

// joinFixture is an in-process Control with the agent PKI, trusted through
// joinRootCAs, and a machine ID.
type joinFixture struct {
	control *agenttest.Control
	dir     string
	pkiDir  string
}

func newJoinFixture(t *testing.T) *joinFixture {
	t.Helper()
	control := agenttest.New(t, agenttest.ModeRequired)
	control.AddJoinToken(testJoinToken, agenttest.JoinGroup{Name: "HK"})
	dir := t.TempDir()
	machineID := filepath.Join(dir, "machine-id")
	require.NoError(t, os.WriteFile(machineID, []byte(testMachineID+"\n"), 0o644))
	useJoinHooks(t, control.ServerCAs, []string{machineID})
	return &joinFixture{control: control, dir: dir, pkiDir: filepath.Join(dir, "pki")}
}

func useJoinHooks(t *testing.T, roots *x509.CertPool, machineIDs []string) {
	t.Helper()
	previousRoots, previousIDs, previousTimeout := joinRootCAs, machineIDFiles, joinDialTimeout
	joinRootCAs, machineIDFiles, joinDialTimeout = roots, machineIDs, 2*time.Second
	t.Cleanup(func() { joinRootCAs, machineIDFiles, joinDialTimeout = previousRoots, previousIDs, previousTimeout })
}

// tokenFile writes token to a new file of mode.
func (f *joinFixture) tokenFile(t *testing.T, token string, mode os.FileMode) string {
	t.Helper()
	file, err := os.CreateTemp(f.dir, "join-token-*")
	require.NoError(t, err)
	_, err = file.WriteString(token + "\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())
	require.NoError(t, os.Chmod(file.Name(), mode))
	return file.Name()
}

// args are the installer's arguments for tokenFile, then extra.
func (f *joinFixture) args(tokenFile string, extra ...string) []string {
	return append([]string{
		"--control", testControlURL, "--grpc", f.control.Address, "--token-file", tokenFile, "--pki-dir", f.pkiDir,
	}, extra...)
}

type joinRun struct {
	stdout string
	stderr string
	status int
}

func runJoinCommand(t *testing.T, args ...string) joinRun {
	t.Helper()
	join := newJoinCommand()
	var stdout, stderr bytes.Buffer
	join.SetOut(&stdout)
	join.SetErr(&stderr)
	join.SetArgs(args)
	err := join.Execute()
	return joinRun{stdout: stdout.String(), stderr: stderr.String(), status: ExitCode(err)}
}

// decodeJoinOutput checks that stdout is exactly one JSON object with the
// installer's keys, and decodes it.
func decodeJoinOutput(t *testing.T, stdout string) joinOutput {
	t.Helper()
	require.True(t, strings.HasSuffix(stdout, "\n"), "stdout %q", stdout)
	require.Equal(t, 1, strings.Count(stdout, "\n"), "one line: %q", stdout)
	var keys map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &keys))
	names := make([]string, 0, len(keys))
	for key := range keys {
		names = append(names, key)
	}
	assert.ElementsMatch(t, []string{"node", "node_name", "group", "created", "approval", "spiffe_id", "not_after"}, names)
	var output joinOutput
	decoder := json.NewDecoder(strings.NewReader(stdout))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&output))
	return output
}

func requireNoIdentity(t *testing.T, pkiDir string) {
	t.Helper()
	stores, err := pki.List(pkiDir)
	require.NoError(t, err)
	assert.Empty(t, stores)
}

func TestJoinStoresTheIdentityAndPrintsJSON(t *testing.T) {
	f := newJoinFixture(t)
	tokenFile := f.tokenFile(t, testJoinToken, 0o600)
	started := time.Now()

	run := runJoinCommand(t, f.args(tokenFile, "--json", "--name", "hk-01", "--host", "203.0.113.5",
		"--address", "203.0.113.5", "--address", "", "--address", "2001:db8::5")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Empty(t, run.stderr)
	output := decodeJoinOutput(t, run.stdout)
	assert.Equal(t, joinOutput{
		Node: testJoinedNode, NodeName: "hk-01", Group: "HK", Created: true, Approval: "approved",
		SPIFFEID: testJoinedSPIFFE, NotAfter: output.NotAfter,
	}, output)
	notAfter, err := time.Parse(time.RFC3339, output.NotAfter)
	require.NoError(t, err)
	assert.WithinDuration(t, started.Add(7*24*time.Hour), notAfter, time.Minute)

	// What the Agent sent.
	requests := f.control.JoinRequests()
	require.Len(t, requests, 1)
	request := requests[0]
	hostname, _ := os.Hostname()
	assert.Equal(t, testJoinToken, request.GetJoinToken())
	assert.Equal(t, testFingerprint, request.GetMachineFingerprint())
	assert.Equal(t, hostname, request.GetHostname())
	assert.Equal(t, "hk-01", request.GetRequestedName())
	assert.Equal(t, "203.0.113.5", request.GetConnectHost())
	assert.Equal(t, []string{"203.0.113.5", "2001:db8::5"}, request.GetPublicAddresses())
	assert.Equal(t, runtime.GOARCH, request.GetArch())
	assert.Equal(t, runtime.GOOS, request.GetOs())
	assert.Equal(t, version, request.GetAgentVersion())
	assert.Equal(t, hostname+"-"+strconv.Itoa(os.Getpid())+"-join", request.GetInstanceId())
	assert.False(t, request.GetReset_())
	csr, err := x509.ParseCertificateRequest(request.GetCsrDer())
	require.NoError(t, err)
	assert.Equal(t, pki.JoinCSRCommonName, csr.Subject.CommonName)

	// The identity is where `anix-agent server` looks, as the server
	// loads it, and the used token is gone.
	node := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12}
	store, err := pki.NewStore(f.pkiDir, node)
	require.NoError(t, err)
	identity, err := store.Load(pki.Expectation{Node: node, Cluster: "test-cluster", Now: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, testJoinedSPIFFE, identity.SPIFFEID)
	assert.Equal(t, pki.BootstrapJoinToken, identity.Bootstrap)
	assert.True(t, identity.Key.PublicKey.Equal(csr.PublicKey), "the certificate is for the key of the CSR")
	for _, name := range []string{"identity.pem", "ca.pem", "identity.json"} {
		info, err := os.Stat(filepath.Join(store.Dir(), name))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
	}
	info, err := os.Stat(store.Dir())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	_, err = os.Stat(tokenFile)
	assert.True(t, os.IsNotExist(err), "the token file is removed: %v", err)

	// `anix-agent identity --json` with the configuration the installer
	// writes next.
	config := filepath.Join(f.dir, "config.json")
	document := `{"Cores": [], "Nodes": [{"ApiHost": "` + testControlURL + `", "GRPCHost": "` + f.control.Address + `",
		"GRPCUseTLS": true, "AgentNode": "` + output.Node + `",
		"AgentIdentity": {"Enroll": "auto", "CertDir": "` + f.pkiDir + `"}}]}`
	require.NoError(t, os.WriteFile(config, []byte(document), 0o600))
	useConfig(t, config)
	roots, nodes := identityRoots()
	statuses, err := collectIdentityStatuses(roots, nodes, time.Now())
	require.NoError(t, err)
	var printed bytes.Buffer
	require.NoError(t, printIdentityStatuses(&printed, statuses, true, time.Now()))
	var decoded []pki.Status
	require.NoError(t, json.Unmarshal(printed.Bytes(), &decoded))
	require.Len(t, decoded, 1, printed.String())
	assert.Equal(t, testJoinedNode, decoded[0].Node)
	assert.Equal(t, pki.StateValid, decoded[0].State)
	assert.Equal(t, testJoinedSPIFFE, decoded[0].SPIFFEID)
	assert.Equal(t, pki.BootstrapJoinToken, decoded[0].Bootstrap)
}

func useConfig(t *testing.T, path string) {
	t.Helper()
	previous := config
	config = path
	t.Cleanup(func() { config = previous })
}

func TestJoinPrintsAHumanLine(t *testing.T) {
	f := newJoinFixture(t)
	f.control.AddJoinToken("anixjoin_pending", agenttest.JoinGroup{Name: "JP", RequireApproval: true})
	run := runJoinCommand(t, f.args(f.tokenFile(t, "anixjoin_pending", 0o600), "--name", "jp-01")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Equal(t, 1, strings.Count(run.stdout, "\n"), run.stdout)
	for _, want := range []string{"Joined " + testControlURL, "jp-01 (proxy-12)", "group JP", testJoinedSPIFFE, filepath.Join(f.pkiDir, "proxy-12"), "approval"} {
		assert.Contains(t, run.stdout, want)
	}

	// The same with --json: approval pending.
	requireRemove(t, filepath.Join(f.pkiDir, "proxy-12"))
	run = runJoinCommand(t, f.args(f.tokenFile(t, "anixjoin_pending", 0o600), "--json", "--reset")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Equal(t, "pending", decodeJoinOutput(t, run.stdout).Approval)
}

func requireRemove(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(path))
}

func TestJoinWithAnEnrollmentCredentialEnrollsTheCredentialsNode(t *testing.T) {
	f := newJoinFixture(t)
	f.control.NodeID = 7
	f.control.AddCredential("anixagt_one-time")
	tokenFile := f.tokenFile(t, "anixagt_one-time", 0o600)

	run := runJoinCommand(t, f.args(tokenFile, "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	output := decodeJoinOutput(t, run.stdout)
	assert.Equal(t, joinOutput{
		Node: "proxy-7", Approval: "unknown", SPIFFEID: "spiffe://anixops/test-cluster/agent/proxy-7", NotAfter: output.NotAfter,
	}, output)
	// Enroll, without the node metadata: the credential names the node.
	assert.Equal(t, []agenttest.EnrollCall{{Credential: true}}, f.control.EnrollCalls())
	assert.Empty(t, f.control.JoinRequests())
	node := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 7}
	store, err := pki.NewStore(f.pkiDir, node)
	require.NoError(t, err)
	identity, err := store.Load(pki.Expectation{Node: node, Now: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, pki.BootstrapEnrollmentCredential, identity.Bootstrap)
	_, err = os.Stat(tokenFile)
	assert.True(t, os.IsNotExist(err), "the used credential is removed: %v", err)

	// A used credential is rejected.
	requireRemove(t, f.pkiDir)
	run = runJoinCommand(t, f.args(f.tokenFile(t, "anixagt_one-time", 0o600))...)
	assert.Equal(t, joinExitRejected, run.status)
	assert.Contains(t, run.stderr, agentcontrol.ErrorCodeEnrollmentRejected)
	assert.Contains(t, run.stderr, "enrollment credential")
	assert.Empty(t, run.stdout)
}

func TestJoinRejectedTokenExitsThreeWithControlsCode(t *testing.T) {
	f := newJoinFixture(t)
	tokenFile := f.tokenFile(t, "anixjoin_unknown", 0o600)
	run := runJoinCommand(t, f.args(tokenFile, "--json")...)
	assert.Equal(t, joinExitRejected, run.status)
	assert.Empty(t, run.stdout)
	assert.Contains(t, run.stderr, "join_rejected")
	assert.Contains(t, run.stderr, "Control rejected the join token")
	assert.Equal(t, 1, strings.Count(run.stderr, "\n"), run.stderr)
	assert.FileExists(t, tokenFile, "a rejected token is kept")
	requireNoIdentity(t, f.pkiDir)
}

func TestJoinRefusesACertificateOfAnotherNode(t *testing.T) {
	for name, edit := range map[string]func(*agentv1pb.JoinResponse){
		// The certificate's SPIFFE ID names proxy-12.
		"spiffe": func(response *agentv1pb.JoinResponse) {
			response.Node, response.Certificate.Node = "proxy-99", "proxy-99"
		},
		"certificate node": func(response *agentv1pb.JoinResponse) { response.Node = "proxy-99" },
		"no node":          func(response *agentv1pb.JoinResponse) { response.Node = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newJoinFixture(t)
			f.control.EditJoinAnswers(edit)
			tokenFile := f.tokenFile(t, testJoinToken, 0o600)
			run := runJoinCommand(t, f.args(tokenFile, "--json")...)
			assert.Equal(t, joinExitFailed, run.status, run.stderr)
			assert.Empty(t, run.stdout)
			if name != "no node" {
				assert.Contains(t, run.stderr, "proxy-99")
			}
			assert.FileExists(t, tokenFile)
			requireNoIdentity(t, f.pkiDir)
		})
	}
}

func TestJoinLeavesAnExistingIdentityAlone(t *testing.T) {
	f := newJoinFixture(t)
	run := runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	first := decodeJoinOutput(t, run.stdout)
	assert.Zero(t, f.control.TrustBundleCalls(), "nothing to check on a machine without an identity")

	// Control accepts the identity, so even a token it would reject is
	// not used: the token is not sent.
	tokenFile := f.tokenFile(t, "anixjoin_unknown", 0o600)
	run = runJoinCommand(t, f.args(tokenFile, "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Empty(t, run.stderr)
	assert.Equal(t, joinOutput{
		Node: testJoinedNode, Approval: "unknown", SPIFFEID: testJoinedSPIFFE, NotAfter: first.NotAfter,
	}, decodeJoinOutput(t, run.stdout))
	assert.Equal(t, 1, f.control.TrustBundleCalls(), "the identity was checked with Control")
	assert.Len(t, f.control.JoinRequests(), 1)
	assert.Len(t, f.control.Streams(), 0)
	assert.FileExists(t, tokenFile, "an unused token is kept")

	run = runJoinCommand(t, f.args(tokenFile)...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Contains(t, run.stdout, "already holds the identity of proxy-12")
	assert.Contains(t, run.stdout, "Control accepts it")

	// An identity of another cluster than --cluster does not count.
	run = runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json", "--cluster", "other")...)
	assert.Equal(t, joinExitFailed, run.status)
	assert.Contains(t, run.stderr, `cluster "test-cluster"`)
	assert.Len(t, f.control.JoinRequests(), 2)
}

// A node deleted in Control: its certificate is revoked, so the machine
// joins again with the token and becomes a new node; the old directory
// stays.
func TestJoinReplacesAnIdentityControlRefuses(t *testing.T) {
	f := newJoinFixture(t)
	run := runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	oldDir := filepath.Join(f.pkiDir, testJoinedNode)
	oldIdentity, err := os.ReadFile(filepath.Join(oldDir, "identity.pem"))
	require.NoError(t, err)

	f.control.DeleteNode(agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 12})
	tokenFile := f.tokenFile(t, testJoinToken, 0o600)
	run = runJoinCommand(t, f.args(tokenFile, "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	output := decodeJoinOutput(t, run.stdout)
	assert.Equal(t, joinOutput{
		Node: "proxy-13", NodeName: output.NodeName, Group: "HK", Created: true, Approval: "approved",
		SPIFFEID: "spiffe://anixops/test-cluster/agent/proxy-13", NotAfter: output.NotAfter,
	}, output)
	assert.Contains(t, run.stderr, agentcontrol.ErrorCodeCertRevoked)
	assert.Contains(t, run.stderr, oldDir+" is kept")
	assert.Equal(t, 1, f.control.TrustBundleCalls())
	requests := f.control.JoinRequests()
	require.Len(t, requests, 2)
	assert.False(t, requests[1].GetReset_(), "a refused identity is not a --reset")
	assert.NoFileExists(t, tokenFile)

	// The new node's identity is stored; the old one is untouched.
	node := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: 13}
	store, err := pki.NewStore(f.pkiDir, node)
	require.NoError(t, err)
	identity, err := store.Load(pki.Expectation{Node: node, Now: time.Now()})
	require.NoError(t, err)
	assert.Equal(t, pki.BootstrapJoinToken, identity.Bootstrap)
	unchanged, err := os.ReadFile(filepath.Join(oldDir, "identity.pem"))
	require.NoError(t, err)
	assert.Equal(t, oldIdentity, unchanged)

	// The next run checks the new identity, which Control accepts.
	run = runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Equal(t, "proxy-13", decodeJoinOutput(t, run.stdout).Node)
	assert.Len(t, f.control.JoinRequests(), 2)
}

// Every certificate refusal renewal acts on makes the join go ahead.
func TestJoinGoesAheadForEveryCertificateRefusal(t *testing.T) {
	for _, code := range []string{
		agentcontrol.ErrorCodeCertRevoked, agentcontrol.ErrorCodeCertExpired, agentcontrol.ErrorCodeCertInvalid,
		agentcontrol.ErrorCodeCertWrongCluster, agentcontrol.ErrorCodeCertWrongNode,
	} {
		t.Run(code, func(t *testing.T) {
			f := newJoinFixture(t)
			run := runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
			require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
			f.control.RefuseCertificates(code)
			run = runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
			require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
			assert.Contains(t, run.stderr, code)
			assert.Len(t, f.control.JoinRequests(), 2)
			// Control's rejoin rule gives the machine its node back: a new
			// certificate in the same directory.
			output := decodeJoinOutput(t, run.stdout)
			assert.Equal(t, testJoinedNode, output.Node)
			assert.False(t, output.Created)
		})
	}
}

// The check needs Control: without it, the join neither reuses nor
// replaces the identity.
func TestJoinExitsFourWhenTheIdentityCannotBeChecked(t *testing.T) {
	f := newJoinFixture(t)
	run := runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := listener.Addr().String()
	require.NoError(t, listener.Close())
	tokenFile := f.tokenFile(t, testJoinToken, 0o600)
	run = runJoinCommand(t, "--control", testControlURL, "--grpc", closed, "--token-file", tokenFile, "--pki-dir", f.pkiDir, "--json")
	assert.Equal(t, joinExitUnreachable, run.status, run.stderr)
	assert.Empty(t, run.stdout)
	assert.Contains(t, run.stderr, "check the identity of proxy-12")
	assert.Contains(t, run.stderr, "cannot reach Control's agent listener "+closed)
	assert.FileExists(t, tokenFile)

	// An untrusted Control is a TLS failure, the same.
	joinRootCAs = nil
	run = runJoinCommand(t, f.args(tokenFile, "--json")...)
	assert.Equal(t, joinExitUnreachable, run.status, run.stderr)
	assert.Contains(t, run.stderr, "certificate")
	assert.Len(t, f.control.JoinRequests(), 1)
	assert.Zero(t, f.control.TrustBundleCalls())
}

func TestJoinResetAsksForANewNodeAndKeepsTheOldIdentity(t *testing.T) {
	f := newJoinFixture(t)
	run := runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)

	run = runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json", "--reset")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	output := decodeJoinOutput(t, run.stdout)
	assert.Equal(t, "proxy-13", output.Node)
	assert.True(t, output.Created)
	assert.Zero(t, f.control.TrustBundleCalls(), "--reset does not check the identity")
	requests := f.control.JoinRequests()
	require.Len(t, requests, 2)
	assert.True(t, requests[1].GetReset_())
	assert.Equal(t, testFingerprint, requests[1].GetMachineFingerprint())
	stores, err := pki.List(f.pkiDir)
	require.NoError(t, err)
	require.Len(t, stores, 2)
	assert.Equal(t, []string{"proxy-12", "proxy-13"}, []string{stores[0].Node().String(), stores[1].Node().String()})

	// Without --reset the machine is the node it joined last.
	run = runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	assert.Equal(t, "proxy-13", decodeJoinOutput(t, run.stdout).Node)
	assert.Len(t, f.control.JoinRequests(), 2)

	// A machine that lost its identities rejoins its node (Control's rule).
	requireRemove(t, f.pkiDir)
	run = runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--json")...)
	require.Equal(t, 0, run.status, "stderr: %s", run.stderr)
	output = decodeJoinOutput(t, run.stdout)
	assert.Equal(t, "proxy-13", output.Node)
	assert.False(t, output.Created)
	assert.Contains(t, runJoinCommand(t, f.args(f.tokenFile(t, testJoinToken, 0o600), "--reset")...).stdout, "Joined ")
}

func TestJoinRefusesBadTokenFiles(t *testing.T) {
	f := newJoinFixture(t)
	for name, test := range map[string]struct {
		token string
		mode  os.FileMode
		want  string
	}{
		"readable by others": {testJoinToken, 0o644, "chmod 600"},
		"readable by group":  {testJoinToken, 0o640, "chmod 600"},
		"another credential": {"anixops_key", 0o600, "does not hold an anixjoin_ join token or an anixagt_ enrollment credential"},
		"empty":              {"", 0o600, "is empty"},
	} {
		t.Run(name, func(t *testing.T) {
			run := runJoinCommand(t, f.args(f.tokenFile(t, test.token, test.mode), "--json")...)
			assert.Equal(t, joinExitUsage, run.status)
			assert.Contains(t, run.stderr, test.want)
			assert.Empty(t, run.stdout)
		})
	}
	run := runJoinCommand(t, f.args(filepath.Join(f.dir, "missing"))...)
	assert.Equal(t, joinExitUsage, run.status)
	assert.Contains(t, run.stderr, "does not exist")
	assert.Empty(t, f.control.JoinRequests())
	requireNoIdentity(t, f.pkiDir)
}

func TestJoinRefusesBadArguments(t *testing.T) {
	f := newJoinFixture(t)
	tokenFile := f.tokenFile(t, testJoinToken, 0o600)
	for name, args := range map[string][]string{
		"no control":        {"--grpc", f.control.Address, "--token-file", tokenFile},
		"plaintext":         {"--control", "http://panel.example.com", "--grpc", f.control.Address, "--token-file", tokenFile},
		"no grpc":           {"--control", testControlURL, "--token-file", tokenFile},
		"grpc without port": {"--control", testControlURL, "--grpc", "panel.example.com", "--token-file", tokenFile},
		"grpc port 0":       {"--control", testControlURL, "--grpc", "panel.example.com:0", "--token-file", tokenFile},
		"no token file":     {"--control", testControlURL, "--grpc", f.control.Address},
		"relative pki dir":  f.args(tokenFile, "--pki-dir", "pki"),
		"bad cluster":       f.args(tokenFile, "--cluster", "Not A Cluster"),
		"bad address":       f.args(tokenFile, "--address", "panel.example.com"),
		"unknown flag":      f.args(tokenFile, "--node", "proxy-12"),
		"argument":          f.args(tokenFile, "extra"),
	} {
		t.Run(name, func(t *testing.T) {
			run := runJoinCommand(t, args...)
			assert.Equal(t, joinExitUsage, run.status, run.stderr)
			assert.True(t, strings.HasPrefix(run.stderr, "anix-agent join: "), run.stderr)
			assert.Empty(t, run.stdout)
		})
	}
	assert.Empty(t, f.control.JoinRequests())
	assert.FileExists(t, tokenFile)
}

func TestJoinNeedsAVerifiedTLSConnection(t *testing.T) {
	f := newJoinFixture(t)
	_, port, err := net.SplitHostPort(f.control.Address)
	require.NoError(t, err)
	for name, test := range map[string]struct {
		target string
		roots  *x509.CertPool
		want   string
	}{
		// The system roots do not hold the test CA.
		"untrusted": {f.control.Address, nil, "certificate"},
		// The server name is the target's host, which the certificate
		// does not name.
		"server name": {net.JoinHostPort("localhost", port), f.control.ServerCAs, "localhost"},
	} {
		t.Run(name, func(t *testing.T) {
			joinRootCAs = test.roots
			tokenFile := f.tokenFile(t, testJoinToken, 0o600)
			run := runJoinCommand(t, "--control", testControlURL, "--grpc", test.target, "--token-file", tokenFile, "--pki-dir", f.pkiDir, "--json")
			assert.Equal(t, joinExitUnreachable, run.status, run.stderr)
			assert.Contains(t, run.stderr, test.want)
			assert.Empty(t, run.stdout)
			assert.FileExists(t, tokenFile)
		})
	}
	assert.Empty(t, f.control.JoinRequests())
	requireNoIdentity(t, f.pkiDir)

	// Nothing listens.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closed := listener.Addr().String()
	require.NoError(t, listener.Close())
	joinRootCAs = f.control.ServerCAs
	run := runJoinCommand(t, "--control", testControlURL, "--grpc", closed, "--token-file", f.tokenFile(t, testJoinToken, 0o600), "--pki-dir", f.pkiDir)
	assert.Equal(t, joinExitUnreachable, run.status, run.stderr)
	assert.Contains(t, run.stderr, "cannot reach Control's agent listener "+closed)
}

func TestMachineFingerprint(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		return path
	}
	etc := write("etc-machine-id", "  "+testMachineID+"\n")
	dbus := write("dbus-machine-id", "fedcba9876543210fedcba9876543210\n")
	empty := write("empty", "\n")
	missing := filepath.Join(dir, "missing")

	assert.Equal(t, testFingerprint, machineFingerprint([]string{etc, dbus}))
	// The fallback when the first is missing or empty.
	assert.Equal(t, testFingerprint, machineFingerprint([]string{missing, empty, etc}))
	assert.NotEqual(t, testFingerprint, machineFingerprint([]string{missing, dbus}))
	assert.Len(t, machineFingerprint([]string{dbus}), 64)
	assert.Equal(t, strings.ToLower(machineFingerprint([]string{dbus})), machineFingerprint([]string{dbus}))
	// No machine ID: no fingerprint, so the machine never rejoins.
	assert.Equal(t, "", machineFingerprint([]string{missing, empty}))
}

func TestExitCode(t *testing.T) {
	assert.Equal(t, 0, ExitCode(nil))
	assert.Equal(t, 1, ExitCode(assert.AnError))
	assert.Equal(t, 3, ExitCode(&exitError{code: 3, err: assert.AnError}))
}
