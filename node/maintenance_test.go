package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/AnixOps/anix-agent/v4/plugin"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AnixOps/anix-agent/v4/api/panel"
	"github.com/AnixOps/anix-agent/v4/common/maintenance"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

type maintenanceNodeAPI struct {
	errorTestNodeAPI
	url string
}

func (a *maintenanceNodeAPI) GetAPIHost() string { return a.url }
func nodeMaintenanceStore(t *testing.T, path string) *maintenance.Store {
	t.Helper()
	s, err := maintenance.Open(path, "1", "development", "1.0.0")
	require.NoError(t, err)
	return s
}
func nodeMaintenanceEvent() maintenance.Event {
	first := time.Now().Add(-time.Hour - 2*time.Minute)
	return maintenance.Event{FirstFailedAt: &first, ConsecutiveFailures: 3, SchemaVersion: 1, EventID: "ws-event", OccurredAt: time.Now().Add(-time.Hour), Environment: "development", Source: "agent", NodeID: "1", PluginID: "machine-telemetry", InstanceID: "machine-telemetry", PluginVersion: "1.0.0", ErrorCode: "PLUGIN_HEALTH_FAILED", Severity: "P2", Status: "open"}
}

func TestMaintenanceWebSocketRetransmitsUntilDurableAck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := nodeMaintenanceStore(t, path)
	event := nodeMaintenanceEvent()
	require.NoError(t, store.Queue(event))
	var mu sync.Mutex
	deliveries := 0
	ids := []string{}
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" || r.Header.Get("X-Node-ID") != "1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			var msg panel.SyncMessage
			if conn.ReadJSON(&msg) != nil {
				return
			}
			if msg.Type != panel.MsgTypeMaintenanceEvents {
				continue
			}
			var batch maintenance.Batch
			if json.Unmarshal(msg.Payload, &batch) != nil {
				return
			}
			if batch.Version != maintenance.Version || len(batch.Events) != 1 {
				return
			}
			mu.Lock()
			deliveries++
			attempt := deliveries
			ids = append(ids, batch.Events[0].EventID)
			mu.Unlock()
			if attempt == 1 {
				return
			} // transport succeeded, Control never persisted it.
			ack := maintenance.Acknowledgment{Version: maintenance.Version, Events: []maintenance.EventResult{{EventID: batch.Events[0].EventID, Persisted: attempt >= 3}}}
			reply, _ := panel.NewSyncMessage(panel.MsgTypeMaintenanceAck, 1, ack)
			if conn.WriteJSON(reply) != nil {
				return
			}
		}
	}))
	defer server.Close()
	config := DefaultSyncConfig()
	config.PingInterval = 20 * time.Millisecond
	config.ReconnectInterval = 10 * time.Millisecond
	config.EnableFallback = false
	sm := NewSyncManager(&maintenanceNodeAPI{url: server.URL}, nil, config)
	sm.SetMaintenanceStore(store)
	require.NoError(t, sm.Start())
	require.Eventually(t, func() bool { events, err := store.Pending(50); return err == nil && len(events) == 0 }, 4*time.Second, 20*time.Millisecond)
	require.NoError(t, sm.Close())
	mu.Lock()
	require.GreaterOrEqual(t, deliveries, 3)
	for _, id := range ids {
		require.Equal(t, event.EventID, id)
	}
	mu.Unlock()
	events, err := nodeMaintenanceStore(t, path).Pending(50)
	require.NoError(t, err)
	require.Empty(t, events)
}
func TestMaintenanceQueueSurvivesSendAndAgentRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := nodeMaintenanceStore(t, path)
	sm := NewSyncManager(&errorTestNodeAPI{}, nil, nil)
	sm.SetMaintenanceStore(store)
	require.NoError(t, sm.QueueMaintenanceEvent(nodeMaintenanceEvent()))
	require.NoError(t, sm.sendHeartbeat())
	require.NoError(t, sm.Close())
	events, err := nodeMaintenanceStore(t, path).Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
	sm = NewSyncManager(&errorTestNodeAPI{}, nil, nil)
	sm.SetMaintenanceStore(store)
	defer sm.Close()
	generic, _ := panel.NewSyncMessage(panel.MsgTypeAck, 1, panel.AckPayload{MessageID: "ws-event", Success: true})
	sm.handleMessage(generic)
	events, err = store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
	for _, raw := range []string{`{"version":"unsupported","events":[{"event_id":"ws-event","persisted":true}]}`, `{"version":"anixops.maintenance/v1","events":[{"event_id":"ws-event","persisted":true}],"unknown":1}`} {
		require.Error(t, sm.handleMaintenanceAck(&panel.SyncMessage{NodeID: 1, Payload: json.RawMessage(raw)}))
	}
	ack, _ := panel.NewSyncMessage(panel.MsgTypeMaintenanceAck, 2, maintenance.Acknowledgment{Version: maintenance.Version, Events: []maintenance.EventResult{{EventID: "ws-event", Persisted: true}}})
	require.Error(t, sm.handleMaintenanceAck(ack))
	events, err = store.Pending(50)
	require.NoError(t, err)
	require.Len(t, events, 1)
}

func TestMaintenanceGRPCNodeUsesAuthenticatedWebSocketBridge(t *testing.T) {
	store := nodeMaintenanceStore(t, filepath.Join(t.TempDir(), "maintenance.json"))
	require.NoError(t, store.Queue(nodeMaintenanceEvent()))
	received := make(chan panel.SyncMessageType, 2)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key" || r.Header.Get("X-Node-ID") != "1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		forbidden, _ := panel.NewSyncMessage(panel.MsgTypeConfigUpdate, 1, panel.ConfigUpdatePayload{ChangeType: "full"})
		_ = conn.WriteJSON(forbidden)
		for {
			var msg panel.SyncMessage
			if conn.ReadJSON(&msg) != nil {
				return
			}
			received <- msg.Type
			if msg.Type == panel.MsgTypeMaintenanceEvents {
				ack, _ := panel.NewSyncMessage(panel.MsgTypeMaintenanceAck, 1, maintenance.Acknowledgment{Version: maintenance.Version, Events: []maintenance.EventResult{{EventID: "ws-event", Persisted: true}}})
				_ = conn.WriteJSON(ack)
			}
		}
	}))
	defer server.Close()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	supervisor, err := plugin.NewSupervisor(plugin.Config{RootDir: t.TempDir(), PublicKey: pub, Maintenance: store, DisableMaintenanceMonitor: true})
	require.NoError(t, err)
	defer supervisor.Close(context.Background())
	// This NodeAPI reports SupportsSync=false, as the gRPC client does.
	controller := NewController(nil, &maintenanceNodeAPI{url: server.URL}, nil)
	require.NoError(t, controller.attachMaintenanceTransport(supervisor))
	require.True(t, controller.syncManager.config.MaintenanceOnly)
	require.NoError(t, controller.syncManager.sendHeartbeat())
	select {
	case kind := <-received:
		require.Equal(t, panel.MsgTypeMaintenanceEvents, kind)
	case <-time.After(time.Second):
		t.Fatal("maintenance-only bridge did not send event")
	}
	require.Eventually(t, func() bool { events, err := store.Pending(50); return err == nil && len(events) == 0 }, time.Second, 10*time.Millisecond)
	require.NoError(t, controller.Close())
}
