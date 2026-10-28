package anxline

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu       sync.Mutex
	calls    []string
	stdin    []string
	missing  map[string]bool // "show id N" fails for these ids
	failWith error
}

func (f *fakeRunner) Run(_ context.Context, stdin, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	f.stdin = append(f.stdin, stdin)
	if len(args) >= 5 && args[2] == "show" && f.missing[args[4]] {
		return "", errors.New("no such endpoint")
	}
	return "", f.failWith
}

func (f *fakeRunner) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

type fakeProber struct {
	mu   sync.Mutex
	dead map[int]bool
}

func (f *fakeProber) Probe(_ context.Context, path Path, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dead[path.Endpoint] {
		return errors.New("timeout")
	}
	return nil
}

func (f *fakeProber) set(endpoint int, dead bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dead[endpoint] = dead
}

func twoPaths(action string) *Multipath {
	return &Multipath{
		Action: action,
		Paths: []Path{
			{Endpoint: 1, Addr: "10.0.1.2", Dev: "eth1", Probe: Probe{Kind: ProbeTCP, Target: "10.0.1.1:4443"}},
			{Endpoint: 2, Addr: "10.0.2.2", Dev: "eth2", Flags: []string{"signal"}, Probe: Probe{Kind: ProbeICMP, Target: "10.0.2.1"}},
		},
	}
}

func TestRSTScriptDefaults(t *testing.T) {
	links := []Link{
		{ID: "srv", FakeTCP: &FakeTCP{Role: RoleServer, Port: 4447, Local: "192.0.2.10"}},
		{ID: "srv-nat", FakeTCP: &FakeTCP{Role: RoleServer, Port: 4448}},
		{ID: "cli", FakeTCP: &FakeTCP{Role: RoleClient, Port: 4447, Peer: "198.51.100.7"}},
		{ID: "mp", Multipath: twoPaths("")},
	}
	script, err := rstScript(DefaultTable, links)
	if err != nil {
		t.Fatal(err)
	}
	want := "table ip anixops_anx_line {}\n" +
		"delete table ip anixops_anx_line\n" +
		"table ip anixops_anx_line {\n" +
		"\tchain output {\n" +
		"\t\ttype filter hook output priority 0; policy accept;\n" +
		"\t\tip saddr 192.0.2.10 tcp sport 4447 tcp flags & rst == rst drop\n" +
		"\t\ttcp sport 4448 tcp flags & rst == rst drop\n" +
		"\t\tip daddr 198.51.100.7 tcp dport 4447 tcp flags & rst == rst drop\n" +
		"\t}\n}\n"
	if script != want {
		t.Fatalf("script:\n%s\nwant:\n%s", script, want)
	}
}

func TestRSTScriptEmptyRemovesTable(t *testing.T) {
	script, err := rstScript("t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if script != "table ip t {}\ndelete table ip t\n" {
		t.Fatalf("script %q", script)
	}
}

func TestRSTRuleTemplates(t *testing.T) {
	f := &FakeTCP{Role: RoleClient, Port: 4447, Peer: "198.51.100.7",
		Rules: []string{"ip daddr {peer} tcp dport {port} tcp flags & rst == rst counter drop"}}
	rules, err := f.rules()
	if err != nil {
		t.Fatal(err)
	}
	if rules[0] != "ip daddr 198.51.100.7 tcp dport 4447 tcp flags & rst == rst counter drop" {
		t.Fatalf("rule %q", rules[0])
	}
	for _, bad := range []string{
		"tcp dport {port} drop; flush ruleset",
		"tcp dport {port} drop }\ntable ip x {",
		"ip saddr {local} drop", // {local} not set
		`tcp dport {port} comment "x" drop`,
	} {
		f.Rules = []string{bad}
		if _, err := f.rules(); err == nil {
			t.Errorf("rule %q accepted", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	good := Config{Enable: true, Links: []Link{
		{ID: "a", FakeTCP: &FakeTCP{Role: RoleServer, Port: 4447}, Multipath: twoPaths(ActionBackup)},
	}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (*Config)(nil).Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"client without peer": func(c *Config) { c.Links[0].FakeTCP = &FakeTCP{Role: RoleClient, Port: 4447} },
		"ipv6 peer":           func(c *Config) { c.Links[0].FakeTCP = &FakeTCP{Role: RoleClient, Port: 4447, Peer: "2001:db8::1"} },
		"bad role":            func(c *Config) { c.Links[0].FakeTCP.Role = "relay" },
		"port":                func(c *Config) { c.Links[0].FakeTCP.Port = 0 },
		"one path":            func(c *Config) { c.Links[0].Multipath.Paths = c.Links[0].Multipath.Paths[:1] },
		"timeout > interval":  func(c *Config) { c.Links[0].Multipath.TimeoutMs = 300 },
		"bad action":          func(c *Config) { c.Links[0].Multipath.Action = "drop" },
		"endpoint id":         func(c *Config) { c.Links[0].Multipath.Paths[0].Endpoint = 256 },
		"probe family":        func(c *Config) { c.Links[0].Multipath.Paths[0].Probe.Target = "[2001:db8::1]:443" },
		"probe kind":          func(c *Config) { c.Links[0].Multipath.Paths[0].Probe.Kind = "udp" },
		"flag":                func(c *Config) { c.Links[0].Multipath.Paths[0].Flags = []string{"fast"} },
		"dev":                 func(c *Config) { c.Links[0].Multipath.Paths[0].Dev = "eth0;rm" },
		"empty link":          func(c *Config) { c.Links[0].FakeTCP, c.Links[0].Multipath = nil, nil },
		"table":               func(c *Config) { c.Table = "a-b" },
		"duplicate endpoint across links": func(c *Config) {
			c.Links = append(c.Links, Link{ID: "b", Multipath: twoPaths("")})
		},
	}
	for name, mutate := range cases {
		c := Config{Enable: true, Links: []Link{
			{ID: "a", FakeTCP: &FakeTCP{Role: RoleServer, Port: 4447}, Multipath: twoPaths(ActionBackup)},
		}}
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func newTestMonitor(action string) (*monitor, *fakeRunner, *fakeProber) {
	runner := &fakeRunner{}
	prober := &fakeProber{dead: map[int]bool{}}
	m := newMonitor("l", *twoPaths(action), "ip", runner, prober, time.Now)
	return m, runner, prober
}

func TestMonitorDeleteAndRestore(t *testing.T) {
	m, runner, prober := newTestMonitor("")
	ctx := context.Background()
	prober.set(2, true)
	m.check(ctx) // one miss: not dead yet (FailAfter 2)
	if calls := runner.take(); len(calls) != 0 {
		t.Fatalf("after one miss: %v", calls)
	}
	m.check(ctx)
	if calls := runner.take(); len(calls) != 1 || calls[0] != "ip mptcp endpoint delete id 2" {
		t.Fatalf("after two misses: %v", calls)
	}
	m.check(ctx) // stays out, no repeat
	if calls := runner.take(); len(calls) != 0 {
		t.Fatalf("repeat: %v", calls)
	}
	prober.set(2, false)
	for range DefaultRecoverAfter - 1 {
		m.check(ctx)
	}
	if calls := runner.take(); len(calls) != 0 {
		t.Fatalf("restored too early: %v", calls)
	}
	m.check(ctx)
	if calls := runner.take(); len(calls) != 1 || calls[0] != "ip mptcp endpoint add 10.0.2.2 dev eth2 id 2 signal" {
		t.Fatalf("restore: %v", calls)
	}
	st := m.status()
	if !st[1].Healthy || st[1].Demoted || st[1].Demotes != 1 || st[1].Restores != 1 {
		t.Fatalf("status %+v", st[1])
	}
}

func TestMonitorBackupKeepsLastPath(t *testing.T) {
	m, runner, prober := newTestMonitor(ActionBackup)
	ctx := context.Background()
	prober.set(1, true)
	m.check(ctx)
	m.check(ctx)
	calls := runner.take()
	if len(calls) != 1 || calls[0] != "ip mptcp endpoint change id 1 backup" {
		t.Fatalf("calls %v", calls)
	}
	// Path 2 dies too: it is the last one in, so it stays.
	prober.set(2, true)
	m.check(ctx)
	m.check(ctx)
	if calls := runner.take(); len(calls) != 0 {
		t.Fatalf("last path taken out: %v", calls)
	}
	prober.set(1, false)
	for range DefaultRecoverAfter {
		m.check(ctx)
	}
	calls = runner.take()
	// Path 1 back; then path 2 (still dead) can go backup.
	if len(calls) != 2 || calls[0] != "ip mptcp endpoint change id 1 nobackup" || calls[1] != "ip mptcp endpoint change id 2 backup" {
		t.Fatalf("calls %v", calls)
	}
	m.close(ctx)
	if calls := runner.take(); len(calls) != 1 || calls[0] != "ip mptcp endpoint change id 2 nobackup" {
		t.Fatalf("close: %v", calls)
	}
}

func TestStartAppliesRulesAndEndpoints(t *testing.T) {
	runner := &fakeRunner{missing: map[string]bool{"1": true}}
	prober := &fakeProber{dead: map[int]bool{}}
	config := Config{Enable: true, Links: []Link{
		{ID: "a", FakeTCP: &FakeTCP{Role: RoleClient, Port: 4447, Peer: "198.51.100.7"}, Multipath: twoPaths("")},
	}}
	m, err := start(config, Options{Runner: runner, Prober: prober})
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	calls := runner.take()
	want := []string{
		"nft -f -",
		"ip mptcp endpoint show id 1",
		"ip mptcp endpoint add 10.0.1.2 dev eth1 id 1 subflow",
		"ip mptcp endpoint show id 2",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	if !strings.Contains(runner.stdin[0], "ip daddr 198.51.100.7 tcp dport 4447") {
		t.Fatalf("nft script %q", runner.stdin[0])
	}
}

func TestStartFailsOnNft(t *testing.T) {
	runner := &fakeRunner{failWith: errors.New("nft: permission denied")}
	config := Config{Enable: true, Links: []Link{{ID: "a", FakeTCP: &FakeTCP{Role: RoleServer, Port: 4447}}}}
	if _, err := start(config, Options{Runner: runner, Prober: &fakeProber{}}); err == nil {
		t.Fatal("start succeeded")
	}
}

func TestNetProberTCPRefusedIsAlive(t *testing.T) {
	p := &NetProber{}
	// Port 1 on loopback is closed: the RST answers, the path works.
	path := Path{Endpoint: 1, Addr: "127.0.0.1", Probe: Probe{Kind: ProbeTCP, Target: "127.0.0.1:1"}}
	if err := p.Probe(context.Background(), path, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}
