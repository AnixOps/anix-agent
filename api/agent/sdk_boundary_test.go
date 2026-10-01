package agent

import (
	"reflect"
	"testing"

	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
)

func TestConfigCapabilitiesUseSharedSDK(t *testing.T) {
	field, ok := reflect.TypeOf(Config{}).FieldByName("Capabilities")
	if !ok {
		t.Fatal("Config.Capabilities field is missing")
	}

	got := field.Type.Elem().Elem()
	want := reflect.TypeOf(agentv1pb.Capability{})
	if got != want {
		t.Fatalf("Config.Capabilities element type = %v, want shared SDK %v", got, want)
	}
}
