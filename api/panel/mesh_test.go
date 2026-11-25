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
