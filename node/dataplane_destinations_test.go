package node

import (
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v5/api/agent/agenttest"
	"github.com/AnixOps/anix-agent/v5/common/destinations"
	"github.com/AnixOps/anix-agent/v5/conf"
	agentcontrol "github.com/AnixOps/anix-control/sdk/agentcontrol"
	agentv1pb "github.com/AnixOps/anix-control/sdk/api/agent/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// destinationCore is a recordingCore that counts traffic by destination.
type destinationCore struct {
	*recordingCore
	mu     sync.Mutex
	window []destinations.Traffic
	reads  int
}

func (c *destinationCore) GetDestinationTraffic(string) ([]destinations.Traffic, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	window := c.window
	c.window = nil
	return window, nil
}

func (c *destinationCore) setDestinations(window ...destinations.Traffic) {
	c.mu.Lock()
	c.window = window
	c.mu.Unlock()
}

func (c *destinationCore) destinationReads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func TestStreamReportsDestinationsWhenControlServesThem(t *testing.T) {
	for _, served := range []bool{true, false} {
		capabilities := []string{agentcontrol.CapabilityConfig, agentcontrol.CapabilityUsers, agentcontrol.CapabilityReports}
		if served {
			capabilities = append(capabilities, agentcontrol.CapabilityDestinations)
		}
		fixture := newStreamNodeFixture(t, agenttest.ModeRequired, capabilities...)
		fixture.control.SetDesiredConfig(agenttest.Snapshot(3, proxyDocument(443)), false)
		fixture.control.UpsertUsers(&agentv1pb.NodeUser{UserId: 1, Uuid: "user-1"})
		core := &destinationCore{recordingCore: fixture.core}
		node := New()
		require.NoError(t, node.Start([]conf.NodeConfig{fixture.nodeConfig(t)}, core))
		controller := node.controllers[0]
		require.Eventually(t, func() bool { return len(fixture.control.Streams()) > 0 }, 5*time.Second, 10*time.Millisecond)

		core.setDestinations(
			destinations.Traffic{UID: 1, Entry: destinations.Entry{User: "user-1", Domain: "youtube.com", Protocol: "tls", Upload: 10, Download: 900, Connections: 2}},
			destinations.Traffic{UID: 1, Entry: destinations.Entry{User: "user-1", Domain: "idle.com"}},
		)
		require.NoError(t, controller.reportUserTrafficTask())
		assert.Equal(t, 1, core.destinationReads(), "the window is read either way")
		if served {
			require.Eventually(t, func() bool { return len(fixture.control.Destinations()) == 1 }, 5*time.Second, 10*time.Millisecond)
			assert.True(t, proto.Equal(&agentv1pb.DestinationTraffic{UserId: 1, Domain: "youtube.com", Protocol: "tls", UploadBytes: 10, DownloadBytes: 900, Connections: 2},
				fixture.control.Destinations()[0]), "%v", fixture.control.Destinations()[0])
		} else {
			time.Sleep(200 * time.Millisecond)
			assert.Empty(t, fixture.control.Destinations(), "no legacy transport: the window is dropped")
		}
		node.Close()
	}
}
