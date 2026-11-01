package node

import (
	"encoding/json"
	"time"

	agentapi "github.com/AnixOps/anix-agent/v5/api/agent"
	"github.com/AnixOps/anix-agent/v5/common/maintenance"
)

// streamMaintenanceInterval is how often the data plane reads the outbox
// (0: agentapi.DefaultMaintenanceInterval); tests lower it.
var streamMaintenanceInterval time.Duration

// maintenanceOutbox is the supervisor's durable outbox as the data plane
// drains it on the stream (maintenance.v1).
type maintenanceOutbox struct{ store *maintenance.Store }

func (o maintenanceOutbox) PendingMaintenance(limit int) ([]agentapi.MaintenanceEvent, error) {
	events, err := o.store.Pending(limit)
	if err != nil {
		return nil, err
	}
	pending := make([]agentapi.MaintenanceEvent, 0, len(events))
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		pending = append(pending, agentapi.MaintenanceEvent{ID: event.EventID, JSON: encoded})
	}
	return pending, nil
}

func (o maintenanceOutbox) RemoveMaintenance(ids []string) error { return o.store.Remove(ids) }
