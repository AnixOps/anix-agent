package forward

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v4/api/agent"
	"github.com/AnixOps/anix-agent/v4/api/agent/agenttest"
	agentstate "github.com/AnixOps/anix-agent/v4/api/agent/state"
	"github.com/AnixOps/anix-agent/v4/upgrade"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	forwardv1 "github.com/AnixOps/anix-control/sdk/api/forward/v1"
	"github.com/AnixOps/anix-control/sdk/forward/driver"
	"github.com/AnixOps/anix-control/sdk/forward/driver/fake"
	"github.com/AnixOps/anix-control/sdk/forward/wire"
)

// streamAgent is a forward node's Agent on the in-process Control: the
// forward component with the fake driver behind the control stream.
type streamAgent struct {
	h      *harness
	client *agentapi.Client
	root   string
}

func newForwardControl(t *testing.T, serves ...string) *agenttest.Control {
	control := agenttest.New(t, agenttest.ModeRequired, serves...)
	control.NodeKind = agentcontrol.NodeKindForward
	control.NodeID = testNode.ID
	return control
}

// startStreamAgent starts the component (re-applying its persisted state),
// then the client; root keeps the state and the identity across restarts.
func startStreamAgent(t *testing.T, control *agenttest.Control, root string, host *fake.Host, mutate ...func(*Options)) *streamAgent {
	t.Helper()
	return startUpgradableStreamAgent(t, control, root, host, nil, mutate...)
}

// startUpgradableStreamAgent is startStreamAgent with an agent.upgrade
// handler (nil: none).
func startUpgradableStreamAgent(t *testing.T, control *agenttest.Control, root string, host *fake.Host, upgrader *upgrade.Agent, mutate ...func(*Options)) *streamAgent {
	t.Helper()
	h := &harness{t: t, host: host, dial: newDialer(), sent: &sender{}, dir: filepath.Join(root, "forward")}
	h.start(mutate...)
	credential := filepath.Join(root, "enroll.token")
	if _, err := os.Stat(credential); err != nil {
		control.AddCredential("anixagt_forward")
		if err := os.WriteFile(credential, []byte("anixagt_forward\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	node, err := StartNode(context.Background(), NodeConfig{
		StateRoot: filepath.Join(root, "state"), Component: h.c, Upgrader: upgrader,
		Client: agentapi.Config{
			Target: control.Address, NodeID: int(testNode.ID), // no node key: the one-time credential only (O1)
			UseTLS: true, ServerName: control.ServerName, RootCAs: control.ServerCAs, AgentVersion: "test-agent", InstanceID: "instance-1",
			Heartbeat: 200 * time.Millisecond, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond, DialTimeout: 2 * time.Second,
			Identity: &agentapi.IdentityConfig{Dir: filepath.Join(root, "pki"), Enroll: true, EnrollCredentialFile: credential, Cluster: control.Cluster},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := node.Client()
	a := &streamAgent{h: h, client: client, root: root}
	t.Cleanup(func() { a.stop() })
	return a
}

func (a *streamAgent) stop() {
	_ = a.client.Close()
	a.h.c.Close()
}

func TestForwardNodeOnTheStream(t *testing.T) {
	control := newForwardControl(t, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward,
		agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports)
	root := t.TempDir()
	host := fake.NewHost(nil)
	agent := startStreamAgent(t, control, root, host)

	// The forward node enrolls, and its certificate session negotiates
	// forward.v1 with config.v1 and package-reports.v1 (no users or
	// reports.v1 for a forward node) and a 60 s heartbeat.
	eventually(t, "the forward.v1 session", func() bool { return agent.client.Negotiated(agentcontrol.CapabilityForward) })
	for _, name := range []string{agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports} {
		if !agent.client.Negotiated(name) {
			t.Fatalf("%s not negotiated", name)
		}
	}
	for _, name := range []string{agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports} {
		if agent.client.Negotiated(name) {
			t.Fatalf("%s negotiated on a forward node", name)
		}
	}
	if hb := control.Heartbeats(); len(hb) == 0 || hb[len(hb)-1] != agenttest.ForwardHeartbeatSeconds {
		t.Fatalf("heartbeats %v", hb)
	}
	caps := control.NodeCapabilities()
	if caps == nil || caps.GetNodeRef() != testNode.String() || len(caps.GetEngines()) != 1 || !caps.GetEngines()[0].GetAvailable() {
		t.Fatalf("node capabilities %v", caps)
	}

	// The first report: nothing applied yet.
	eventually(t, "the first report", func() bool { return len(control.ForwardReports()) > 0 })
	if r := control.ForwardReports()[0]; r.GetNodeRef() != testNode.String() || r.GetGeneration() != 0 {
		t.Fatalf("first report %v", r)
	}

	// Control pushes the node's state; the Agent applies it, answers the
	// snapshot and reports the generation and counters.
	one := state(1, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))
	control.SetDesiredConfig(agenttest.ForwardSnapshot(10, map[string]any{"kind": "forward"}, one), true)
	eventually(t, "the state applied", func() bool { return agent.h.c.Status().Generation == 1 })
	eventually(t, "ConfigStatus", func() bool {
		for _, s := range control.ConfigStatuses() {
			if s.GetConfigRevision() == 10 && s.GetApplied() {
				return true
			}
		}
		return false
	})
	if err := host.AddTraffic(driver.HopKey{RouteID: "R1"}, fake.Traffic{UpBytes: 500, DownBytes: 700}); err != nil {
		t.Fatal(err)
	}
	two := state(2, hashOf(2), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)), hop("R2", 0, 30002, rr, up("192.0.2.20", 80, 0)))
	control.SetDesiredConfig(agenttest.ForwardSnapshot(11, map[string]any{"kind": "forward"}, two), true)
	eventually(t, "a report of generation 2 with counters", func() bool {
		reports := control.ForwardReports()
		r := reports[len(reports)-1]
		if r.GetGeneration() != 2 || !r.GetApplied() || r.GetStateHash() != hashOf(2) {
			return false
		}
		for _, c := range r.GetCounters() {
			if c.GetRouteId() == "R1" && c.GetUpBytes() == 500 && c.GetDownBytes() == 700 {
				return true
			}
		}
		return false
	})
	// Stop after revision 11 is stored: a stop mid-apply restarts at revision 10.
	eventually(t, "ConfigStatus of revision 11", func() bool {
		for _, s := range control.ConfigStatuses() {
			if s.GetConfigRevision() == 11 && s.GetApplied() {
				return true
			}
		}
		return false
	})
	if refused := control.ForwardRefusals(); len(refused) != 0 {
		t.Fatalf("Control refused forward reports: %v", refused)
	}

	// Restart with Control unreachable: the Agent re-applies the persisted
	// state before connecting (a reboot lost the host's rules).
	agent.stop()
	control.RefuseStreams(true)
	rebooted := fake.NewHost(nil)
	agent = startStreamAgent(t, control, root, rebooted)
	if st := agent.h.c.Status(); st.Generation != 2 || !st.Applied || st.Hops != 2 || rebooted.Applies() != 1 {
		t.Fatalf("after restart without Control: %+v, applies %d", st, rebooted.Applies())
	}
	// Control back: Hello reports the revision it runs, no snapshot is
	// re-applied, and reports resume.
	before := len(control.ForwardReports())
	control.RefuseStreams(false)
	eventually(t, "reports after the reconnect", func() bool { return len(control.ForwardReports()) > before })
	if rebooted.Applies() != 1 {
		t.Fatalf("applies %d after the reconnect", rebooted.Applies())
	}
	hellos := control.Hellos()
	if last := hellos[len(hellos)-1]; last.GetConfigRevision() != 11 {
		t.Fatalf("Hello config_revision %d, want 11", last.GetConfigRevision())
	}
}

func TestForwardNotServedKeepsReportsBack(t *testing.T) {
	// A Control that does not serve forward.v1 (or refuses the attribute):
	// no forward.v1, no package-reports.v1 for a forward node, no reports.
	control := newForwardControl(t, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports)
	agent := startStreamAgent(t, control, t.TempDir(), fake.NewHost(nil))
	eventually(t, "the session", func() bool { return agent.client.Negotiated(agentcontrol.CapabilityConfig) })
	time.Sleep(200 * time.Millisecond)
	if agent.client.Negotiated(agentcontrol.CapabilityForward) || agent.client.Negotiated(agentcontrol.CapabilityPackageReports) {
		t.Fatal("forward.v1 or package-reports.v1 negotiated without Control serving forward.v1")
	}
	if n := len(control.ForwardReports()) + len(control.ForwardRefusals()); n != 0 {
		t.Fatalf("%d forward reports sent without forward.v1", n)
	}
	if hb := control.Heartbeats(); hb[len(hb)-1] == agenttest.ForwardHeartbeatSeconds {
		t.Fatal("a session without forward.v1 got the forward heartbeat")
	}
	// A v2 snapshot cannot arrive without forward.v1; a v1 one leaves the
	// forwarding state alone.
	control.SetDesiredConfig(agenttest.Snapshot(3, map[string]any{"kind": "forward"}), true)
	eventually(t, "ConfigStatus of the v1 snapshot", func() bool { return len(control.ConfigStatuses()) > 0 })
	if !control.ConfigStatuses()[0].GetApplied() || agent.h.c.Status().Generation != 0 {
		t.Fatalf("v1 snapshot: %v, %+v", control.ConfigStatuses()[0], agent.h.c.Status())
	}
}

func TestProxyNodeCarriesForwarding(t *testing.T) {
	// A proxy node's stream carries forwarding too: proxy-<id> state and
	// reports, next to its users and reports.v1.
	control := agenttest.New(t, agenttest.ModePreferred, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward)
	node := agentcontrol.AgentNode{Kind: agentcontrol.NodeKindProxy, ID: control.NodeID}
	registry := driver.NewRegistry()
	host := fake.NewHost(nil)
	if err := registry.Register(fake.New(host, fake.Options{})); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Node: node, Registry: registry, StateDir: t.TempDir() + "/forward", ReportMinGap: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	store, err := agentstate.Open(t.TempDir(), node)
	if err != nil {
		t.Fatal(err)
	}
	client, err := agentapi.NewClient(agentapi.Config{
		Target: control.Address, NodeID: int(control.NodeID), APIKey: control.APIKey, UseTLS: true, ServerName: control.ServerName,
		RootCAs: control.ServerCAs, AgentVersion: "test-agent", InstanceID: "instance-1", Heartbeat: 200 * time.Millisecond,
		ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond, DialTimeout: 2 * time.Second,
		DataPlane: &agentapi.DataPlaneConfig{State: store, Config: c.Applier(nil), Forward: c},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	c.SetSender(client.DataPlane().SendForwardReport)
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	client.DataPlane().Activate()
	eventually(t, "forward.v1 on the proxy node", func() bool { return client.Negotiated(agentcontrol.CapabilityForward) })
	s := &forwardv1.NodeForwardState{NodeRef: node.String(), Generation: 4, StateHash: hashOf(4), Hops: []*forwardv1.NodeHop{hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0))}}
	control.SetDesiredConfig(agenttest.ForwardSnapshot(2, map[string]any{"kind": "proxy"}, s), true)
	eventually(t, "a proxy node's report of generation 4", func() bool {
		for _, r := range control.ForwardReports() {
			if r.GetNodeRef() == node.String() && r.GetGeneration() == 4 && r.GetApplied() {
				return true
			}
		}
		return false
	})
	if hb := control.Heartbeats(); hb[len(hb)-1] == agenttest.ForwardHeartbeatSeconds {
		t.Fatal("a proxy node got the forward heartbeat")
	}
	if _, err := wire.Report(c.Report(context.Background())); err != nil {
		t.Fatal(err)
	}
}

// Control's route diagnosis reaches a forward node as agent.diagnostic: the
// Agent lists agent.diagnostic and diag.v1, runs the forward check on the
// hop it holds and answers the generic state with the check's result.
func TestForwardNodeRunsDiagnosticChecks(t *testing.T) {
	control := newForwardControl(t, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward)
	agent := startStreamAgent(t, control, t.TempDir(), fake.NewHost(nil))
	eventually(t, "the forward.v1 session", func() bool { return agent.client.Negotiated(agentcontrol.CapabilityForward) })
	hellos := control.Hellos()
	listed := map[string]bool{}
	for _, capability := range hellos[len(hellos)-1].GetCapabilities() {
		listed[capability.GetName()+"."+capability.GetVersion()] = true
	}
	if !listed["agent.diagnostic.v1"] || !listed["diag.v1"] {
		t.Fatalf("capabilities %v", listed)
	}
	one := state(3, hashOf(1), hop("R1", 0, 30001, rr, up("192.0.2.10", 443, 0)))
	control.SetDesiredConfig(agenttest.ForwardSnapshot(10, map[string]any{"kind": "forward"}, one), true)
	eventually(t, "the state applied", func() bool { return agent.h.c.Status().Generation == 3 })

	send := func(action string, params map[string]any) *agentv1pb.ObservedState {
		t.Helper()
		id := control.SendOperation("agent.diagnostic", func(_, operationID string, _ uint64) []byte {
			payload, _ := json.Marshal(map[string]any{"task": map[string]any{"id": operationID, "type": "diagnostic", "action": action, "params": params, "timeout": 3}})
			return payload
		})
		var terminal *agentv1pb.ObservedState
		eventually(t, "the check's terminal state", func() bool {
			for _, observed := range control.ObservedStates() {
				if observed.GetOperationId() == id && (observed.GetPhase() == agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED || observed.GetPhase() == agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED) {
					terminal = observed
					return true
				}
			}
			return false
		})
		return terminal
	}
	observed := send(CheckConnect, map[string]any{"route_id": "R1", "hop_index": 0, "timeout_ms": 500, "generation": 3, "target_policy": "public_only"})
	if observed.GetPhase() != agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED {
		t.Fatalf("observed %v", observed)
	}
	var answer struct {
		Success bool        `json:"success"`
		Output  string      `json:"output"`
		Result  CheckResult `json:"result"`
	}
	if err := json.Unmarshal(observed.GetStateJson(), &answer); err != nil {
		t.Fatal(err)
	}
	if !answer.Success || answer.Result.Check != CheckConnect || answer.Result.Generation != 3 || len(answer.Result.Items) != 1 ||
		answer.Result.Items[0].Target != "192.0.2.10:443" || answer.Result.Items[0].Status != VerdictOK {
		t.Fatalf("answer %+v", answer)
	}
	// A check that cannot run fails the operation; one that ran and found
	// a fault succeeds with the fault in its result.
	if failed := send("forward.bogus", map[string]any{}); failed.GetPhase() != agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED {
		t.Fatalf("unknown action: %v", failed)
	}
	missing := send(CheckListen, map[string]any{"route_id": "R9", "hop_index": 0})
	if err := json.Unmarshal(missing.GetStateJson(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Success || answer.Result.Code != "hop_not_applied" {
		t.Fatalf("missing hop %+v", answer)
	}
	if refused := send("service_restart", map[string]any{"service": "gost"}); refused.GetPhase() != agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED ||
		!strings.Contains(refused.GetMessage(), "managed by the forward component") {
		t.Fatalf("restart: %v", refused)
	}
}

func TestForwardNodeAnswersAgentUpgrades(t *testing.T) {
	control := newForwardControl(t, agentcontrol.CapabilityConfig, agentcontrol.CapabilityPackageReports, agentcontrol.CapabilityForward,
		agentcontrol.CapabilityUpgrade)
	root := t.TempDir()
	upgrader := &upgrade.Agent{
		Dir: filepath.Join(root, "upgrade"), LibDir: filepath.Join(root, "lib"), Version: "v4.2.0",
		UpdaterActive: func(context.Context) bool { return true },
	}
	agent := startUpgradableStreamAgent(t, control, root, fake.NewHost(nil), upgrader)
	eventually(t, "the upgrade.v1 session", func() bool { return agent.client.Negotiated(agentcontrol.CapabilityUpgrade) })

	request := func(target string) []byte {
		payload, _ := json.Marshal(agentcontrol.UpgradeRequest{
			Schema: agentcontrol.UpgradeSchemaV1, CampaignID: "c-1", Action: agentcontrol.UpgradeActionRollback, TargetVersion: target,
		})
		return payload
	}
	// The release it runs: current (also the replay after the restart).
	id := control.SendOperation(agentcontrol.OperationKindAgentUpgrade, func(string, string, uint64) []byte { return request("v4.2.0") })
	eventually(t, "the current answer", func() bool {
		for _, observed := range control.ObservedStates() {
			if observed.GetOperationId() == id && observed.GetPhase() == agentv1pb.ObservedPhase_OBSERVED_PHASE_SUCCEEDED {
				var state agentcontrol.UpgradeState
				return json.Unmarshal(observed.GetStateJson(), &state) == nil && state.Phase == agentcontrol.UpgradePhaseCurrent
			}
		}
		return false
	})
	// A request that does not parse is refused before the acknowledgement.
	refused := control.SendOperation(agentcontrol.OperationKindAgentUpgrade, func(string, string, uint64) []byte { return []byte(`{"schema":"x"}`) })
	eventually(t, "the refusal", func() bool {
		for _, ack := range control.OperationAcks() {
			if ack.GetOperationId() == refused {
				return !ack.GetAccepted() && strings.HasPrefix(ack.GetError(), agentcontrol.UpgradeErrorInvalidRequest+": ")
			}
		}
		return false
	})
	// Without the kept release, a rollback fails with its code.
	failed := control.SendOperation(agentcontrol.OperationKindAgentUpgrade, func(string, string, uint64) []byte { return request("v4.1.0") })
	eventually(t, "the rollback failure", func() bool {
		for _, observed := range control.ObservedStates() {
			if observed.GetOperationId() == failed && observed.GetPhase() == agentv1pb.ObservedPhase_OBSERVED_PHASE_FAILED {
				var state agentcontrol.UpgradeState
				return json.Unmarshal(observed.GetStateJson(), &state) == nil && state.ErrorCode == agentcontrol.UpgradeErrorNoPrevious
			}
		}
		return false
	})
}
