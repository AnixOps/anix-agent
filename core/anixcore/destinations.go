package anixcore

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/AnixOps/anix-agent/v5/common/destinations"
)

// destinationsFeature is the kernel feature of per-user destination
// statistics (GET /v1/inbounds/{tag}/destinations).
const destinationsFeature = "destinations"

type apiDestination struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Protocol    string `json:"protocol"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
	Connections int64  `json:"connections"`
}

// destinations reads and resets tag's per-user destination statistics.
func (c *client) destinations(ctx context.Context, tag string) ([]apiDestination, error) {
	var answer struct {
		Destinations []apiDestination `json:"destinations"`
	}
	path := "/v1/inbounds/" + inboundPath(tag) + "/destinations?reset=true"
	if err := c.do(ctx, http.MethodGet, path, nil, &answer); err != nil {
		return nil, err
	}
	return answer.Destinations, nil
}

// GetDestinationTraffic returns tag's traffic by user and destination
// since the last call (destinations.v1). The kernel counts hosts; they are
// folded into registrable domains (or address networks) here. A kernel
// without the destinations feature reports nothing.
func (c *Core) GetDestinationTraffic(tag string) ([]destinations.Traffic, error) {
	api, created := c.clientFor(tag)
	if !created || !api.destinationStats.Load() {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	entries, err := api.destinations(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("anixcore node %s: %w", tag, err)
	}
	return foldDestinations(entries), nil
}

// foldDestinations merges the kernel's hosts by panel user, registrable
// domain and protocol, in the kernel's order.
func foldDestinations(entries []apiDestination) []destinations.Traffic {
	type key struct {
		uid              int
		domain, protocol string
	}
	index := map[key]int{}
	var traffic []destinations.Traffic
	for _, entry := range entries {
		uid, ok := panelUID(entry.Name)
		if !ok || (entry.Up == 0 && entry.Down == 0 && entry.Connections == 0) {
			continue
		}
		k := key{uid: uid, domain: destinations.Name(entry.Host), protocol: entry.Protocol}
		i, seen := index[k]
		if !seen {
			i = len(traffic)
			index[k] = i
			traffic = append(traffic, destinations.Traffic{UID: uid, Entry: destinations.Entry{
				User: strconv.Itoa(uid), Domain: k.domain, Protocol: k.protocol,
			}})
		}
		traffic[i].Upload += max(entry.Up, 0)
		traffic[i].Download += max(entry.Down, 0)
		traffic[i].Connections += max(entry.Connections, 0)
	}
	return traffic
}
