package grpc

import (
	"reflect"
	"testing"

	"github.com/AnixOps/anix-agent/v5/api/panel"
)

func TestParseIwanNode(t *testing.T) {
	common := panel.CommonNode{ServerPort: 4500}
	node, err := parseIwanNode(common, map[string]string{
		"pool":                   "10.66.0.0/16",
		"mtu":                    "1380",
		"dns_upstream":           "1.1.1.1:53",
		"allow_encrypt":          "false",
		"allow_client_to_client": "true",
		"fixed_addresses":        `{"7":"10.66.0.9"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	deny := false
	want := &panel.IwanNode{
		CommonNode: common, Pool: "10.66.0.0/16", MTU: 1380, DNSUpstream: "1.1.1.1:53",
		AllowEncrypt: &deny, AllowClientToClient: true,
		FixedAddresses: map[string]string{"7": "10.66.0.9"},
	}
	if !reflect.DeepEqual(node, want) {
		t.Fatalf("iwan node = %+v", node)
	}

	node, err = parseIwanNode(common, map[string]string{"pool": "10.66.0.0/24"})
	if err != nil || node.AllowEncrypt != nil || node.MTU != 0 || node.FixedAddresses != nil {
		t.Fatalf("defaults = %+v, %v", node, err)
	}
	for _, extra := range []map[string]string{
		{"allow_encrypt": "maybe"},
		{"allow_client_to_client": "x"},
		{"fixed_addresses": "[1]"},
	} {
		if _, err := parseIwanNode(common, extra); err == nil {
			t.Fatalf("%v should be refused", extra)
		}
	}
}
