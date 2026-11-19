package reachprobe

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestProbeOpenRefusedAndPrivate(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	open := listener.Addr().(*net.TCPAddr).Port
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	refused := closed.Addr().(*net.TCPAddr).Port
	closed.Close()

	p := &Prober{AllowPrivate: true}
	result := p.Probe(context.Background(), []Request{{Host: "127.0.0.1", Ports: []int{open, refused}}}, time.Second)
	target := result.Targets[0]
	if !target.Reachable || target.Ports[0].State != StateOpen || target.Ports[1].State != StateRefused {
		t.Fatalf("got %+v", target)
	}

	strict := &Prober{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}}
	result = strict.Probe(context.Background(), []Request{{Host: "node.example", Ports: []int{443}}, {Host: "192.168.1.1", Ports: []int{443}}}, time.Second)
	for _, target := range result.Targets {
		if target.Reachable || target.Error == "" || len(target.Ports) != 0 {
			t.Fatalf("a private address was probed: %+v", target)
		}
	}
}

func TestCheckParamsAndVerdict(t *testing.T) {
	p := &Prober{}
	for _, params := range []map[string]any{
		{},
		{"targets": []any{map[string]any{"host": "a.example"}}},
		{"targets": []any{map[string]any{"host": "a.example", "ports": []any{0.0}}}},
		{"targets": []any{map[string]any{"host": "", "ports": []any{443.0}}}},
	} {
		if _, _, _, err := p.Check(context.Background(), Action, params); err == nil {
			t.Fatalf("params %v were accepted", params)
		}
	}
	targets, timeout, err := ParseParams(map[string]any{
		"targets":    []any{map[string]any{"host": "A.Example.", "ports": []any{443.0, 22.0}}},
		"timeout_ms": 50000.0,
	})
	if err != nil || targets[0].Host != "a.example" || len(targets[0].Ports) != 2 || timeout != maxTimeout {
		t.Fatalf("got %v %v %v", targets, timeout, err)
	}
	_, verdict, summary, err := p.Check(context.Background(), Action, map[string]any{
		"targets": []any{map[string]any{"host": "10.0.0.1", "ports": []any{443.0}}},
	})
	if err != nil || verdict != "failed" || summary != "0 of 1 targets reachable" {
		t.Fatalf("got %q %q %v", verdict, summary, err)
	}
}
