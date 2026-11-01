package grpc

import (
	"reflect"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

func TestParseAnxNode(t *testing.T) {
	common := panel.CommonNode{ServerPort: 8443}
	node, err := parseAnxNode(common, map[string]string{
		"server_names":   `["www.apple.com"]`,
		"dest":           "www.apple.com:443",
		"alpn":           `["h2","http/1.1"]`,
		"allow_no_sni":   "true",
		"shape_plain":    "true",
		"max_streams":    "512",
		"wg_listen_port": "51820",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &panel.AnxNode{
		CommonNode: common, ServerNames: []string{"www.apple.com"}, Dest: "www.apple.com:443",
		ALPN: []string{"h2", "http/1.1"}, AllowNoSNI: true, ShapePlain: true, MaxStreams: 512, WGListenPort: 51820,
	}
	if !reflect.DeepEqual(node, want) {
		t.Fatalf("anx node = %+v", node)
	}

	node, err = parseAnxNode(common, map[string]string{"server_names": "www.apple.com"})
	if err != nil || node.AllowNoSNI || node.ShapePlain || node.MaxStreams != 0 || node.WGListenPort != 0 {
		t.Fatalf("defaults = %+v, %v", node, err)
	}

	for _, extra := range []map[string]string{
		{"allow_no_sni": "maybe"},
		{"shape_plain": "x"},
		{"max_streams": "0"},
		{"max_streams": "65536"},
		{"max_streams": "many"},
		{"wg_listen_port": "0"},
		{"wg_listen_port": "70000"},
	} {
		if _, err := parseAnxNode(common, extra); err == nil {
			t.Fatalf("parseAnxNode accepted %v", extra)
		}
	}
}
