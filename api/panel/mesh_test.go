package panel

import (
	"strings"
	"testing"
)

func TestParseMesh(t *testing.T) {
	if m, err := ParseMesh([]byte(`{"nodes":[]}`)); err != nil || m != nil {
		t.Fatalf("no member = %v, %v", m, err)
	}
	m, err := ParseMesh([]byte(`{"mesh":{"networks":[{"id":"cn","name":"n","secret":"s","secure_mode":true,"address":"10.150.0.5/16",` +
		`"peers":[{"server":"203.0.113.1"}],"routing":{"policy":"latency"}}],"takeover":{"service_names":["old.service"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Networks) != 1 || m.Networks[0].ID != "cn" || string(m.Networks[0].Routing) != `{"policy":"latency"}` || m.Takeover.Empty() {
		t.Fatalf("mesh = %+v", m)
	}
	for name, document := range map[string]string{
		"bad id":       `{"mesh":{"networks":[{"id":"CN","name":"n","secret":"s","address":"a"}]}}`,
		"repeated id":  `{"mesh":{"networks":[{"id":"cn","name":"n","secret":"s","address":"a"},{"id":"cn","name":"n","secret":"s","address":"a"}]}}`,
		"no secret":    `{"mesh":{"networks":[{"id":"cn","name":"n","address":"a"}]}}`,
		"option name":  `{"mesh":{"networks":[],"takeover":{"service_names":["--now"]}}}`,
		"path name":    `{"mesh":{"networks":[],"takeover":{"process_names":["../x"]}}}`,
		"relative cfg": `{"mesh":{"networks":[],"takeover":{"config_paths":["etc/x.conf"]}}}`,
	} {
		if _, err := ParseMesh([]byte(document)); err == nil || !strings.HasPrefix(err.Error(), "mesh: ") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestParseMeshKeepsTheSections(t *testing.T) {
	m, err := ParseMesh([]byte(`{"mesh":{"networks":[{"id":"cn","name":"n","secret":"s","address":"10.150.0.5/16",` +
		`"dns":{"enabled":true,"suffix":"mesh.internal","names":[]},"host_groups":[{"cidr":"10.127.0.0/24","gateway":"gw-a"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(m.Networks[0].DNS), `"suffix":"mesh.internal"`) || !strings.Contains(string(m.Networks[0].HostGroups), `"gateway":"gw-a"`) {
		t.Fatalf("network = %+v", m.Networks[0])
	}
}

func TestMeshInstanceID(t *testing.T) {
	for id, ok := range map[string]bool{
		"2f6d7c1e-0b8a-4c55-9e0e-6a1f3b9d2c10": true, "Node-1": true, strings.Repeat("a", 64): true,
		"": false, strings.Repeat("a", 65): false, "a b": false, "../x": false, "节点": false,
	} {
		if MeshInstanceID(id) != ok {
			t.Errorf("%q: %v", id, !ok)
		}
	}
}

func TestMeshRegionRequestReport(t *testing.T) {
	report, err := MeshRegionRequest{ID: "r1", Region: "eu", Reason: " 迁往法兰克福\xff "}.Report()
	if err != nil || report.Region != "eu" || report.Reason != "迁往法兰克福" {
		t.Fatalf("report = %+v, %v", report, err)
	}
	long, _ := MeshRegionRequest{Region: "eu", Reason: strings.Repeat("长", MeshRegionRequestReasonMax+1)}.Report()
	if len([]rune(long.Reason)) != MeshRegionRequestReasonMax {
		t.Fatalf("reason = %d characters", len([]rune(long.Reason)))
	}
	for _, region := range []string{"", "EU", "e u", strings.Repeat("a", 33)} {
		if _, err := (MeshRegionRequest{Region: region}).Report(); err == nil {
			t.Errorf("region %q taken", region)
		}
	}
}
