// Package destinations counts each user's connections and bytes by
// destination for destination statistics (destinations.v1; Control's
// docs/reference/destination-stats.md). It is kernel-neutral: a proxy
// kernel's hook opens a Stat for each connection it routes, with the user,
// the destination host and the sniffed protocol, and adds the connection's
// bytes to it; the node reads a Collector's Snapshot once per report
// window.
//
// Only the registrable domain of a destination is kept (www.youtube.com
// counts as youtube.com), or the address network of a destination without
// a domain (/24, /48 for IPv6). A user's destinations beyond MaxPerUser,
// and every destination beyond MaxEntries, count as one entry with an
// empty domain ("other").
package destinations

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
)

const (
	// MaxPerUser bounds the destinations of one user in a Collector.
	MaxPerUser = 200
	// MaxEntries bounds a Collector, as Control bounds a DestinationReport.
	MaxEntries = 50000
	// maxDomainLength and maxProtocolLength are Control's bounds.
	maxDomainLength   = 255
	maxProtocolLength = 32
)

// Name is the destination host's registrable domain, or its address
// network when host is an address; "" when there is nothing to name.
// host may carry a port.
func Name(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		bits := 48
		if addr.Is4() {
			bits = 24
		}
		prefix, err := addr.WithZone("").Prefix(bits)
		if err != nil {
			return ""
		}
		return prefix.String()
	}
	host = strings.ToLower(host)
	if domain, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		host = domain
	}
	if len(host) > maxDomainLength {
		return ""
	}
	return host
}

// Stat counts one user's traffic to one destination. Upload and Download
// take the bytes of every connection opened on it; Release ends one.
type Stat struct {
	Upload   atomic.Int64
	Download atomic.Int64

	connections atomic.Int64
	open        atomic.Int64
}

// Release ends a connection Open counted. A connection releases its Stat
// once; a Stat with open connections is never evicted.
func (s *Stat) Release() {
	if s != nil {
		s.open.Add(-1)
	}
}

// Entry is one user's traffic to one destination in a window.
type Entry struct {
	User        string
	Domain      string
	Protocol    string
	Upload      int64
	Download    int64
	Connections int64
}

type key struct {
	user, domain, protocol string
}

// Collector holds the Stats of one inbound.
type Collector struct {
	mu      sync.Mutex
	stats   map[key]*Stat
	perUser map[string]int
}

// NewCollector returns an empty Collector.
func NewCollector() *Collector {
	return &Collector{stats: map[key]*Stat{}, perUser: map[string]int{}}
}

// Open counts a connection of user to host (an address or a domain, with
// or without port) over protocol (the sniffed protocol, or "") and returns
// the Stat its bytes go to; the caller releases it when the connection
// ends. nil for a connection without a user.
func (c *Collector) Open(user, host, protocol string) *Stat {
	if c == nil || user == "" {
		return nil
	}
	k := key{user: user, domain: Name(host), protocol: strings.ToLower(strings.TrimSpace(protocol))}
	if len(k.protocol) > maxProtocolLength {
		k.protocol = ""
	}
	if k.domain == "" {
		k.protocol = ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stat, ok := c.stats[k]
	if !ok && k.domain != "" && (c.perUser[user] >= MaxPerUser || len(c.stats) >= MaxEntries) {
		k = key{user: user}
		stat, ok = c.stats[k]
	}
	if !ok {
		stat = &Stat{}
		c.stats[k] = stat
		c.perUser[user]++
	}
	stat.connections.Add(1)
	stat.open.Add(1)
	return stat
}

// Snapshot returns the traffic since the last Snapshot and starts a new
// window. A Stat without traffic in the window and without open
// connections is dropped.
func (c *Collector) Snapshot() []Entry {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var entries []Entry
	for k, stat := range c.stats {
		upload := stat.Upload.Swap(0)
		download := stat.Download.Swap(0)
		connections := stat.connections.Swap(0)
		if upload > 0 || download > 0 || connections > 0 {
			entries = append(entries, Entry{
				User: k.user, Domain: k.domain, Protocol: k.protocol,
				Upload: max(upload, 0), Download: max(download, 0), Connections: connections,
			})
			continue
		}
		if stat.open.Load() <= 0 {
			delete(c.stats, k)
			if c.perUser[k.user]--; c.perUser[k.user] <= 0 {
				delete(c.perUser, k.user)
			}
		}
	}
	return entries
}

// Collectors holds a Collector per inbound tag.
type Collectors struct {
	collectors sync.Map // map[string]*Collector
}

// Get returns tag's Collector, creating it.
func (c *Collectors) Get(tag string) *Collector {
	if collector, ok := c.collectors.Load(tag); ok {
		return collector.(*Collector)
	}
	collector, _ := c.collectors.LoadOrStore(tag, NewCollector())
	return collector.(*Collector)
}

// Snapshot returns tag's traffic since its last Snapshot.
func (c *Collectors) Snapshot(tag string) []Entry {
	collector, ok := c.collectors.Load(tag)
	if !ok {
		return nil
	}
	return collector.(*Collector).Snapshot()
}

// Delete forgets tag's Collector (its inbound was removed).
func (c *Collectors) Delete(tag string) {
	c.collectors.Delete(tag)
}

// Traffic is an Entry of a user the core knows, by user id.
type Traffic struct {
	UID int
	Entry
}

// Resolve keeps the entries whose user uid knows (a positive id).
func Resolve(entries []Entry, uid func(user string) int) []Traffic {
	traffic := make([]Traffic, 0, len(entries))
	for _, entry := range entries {
		if id := uid(entry.User); id > 0 {
			traffic = append(traffic, Traffic{UID: id, Entry: entry})
		}
	}
	return traffic
}
