// Package forward is the Agent's forward component (forward-sdk.md sections
// 6 to 8, F3b). Every engine it had a driver for (nftables, gost and the
// experimental anixops relay) was removed: routes run on the network model.
// It keeps the forwarding state Control sends, probes entry addresses for
// Control's entry HA (vantage.go), runs the forward diagnostics and reports
// health and hop errors; RetireNftables cleans up after the nftables driver.
//
// # Wiring
//
// The component rides the Agent Control stream of the node it serves (a
// forward node, forward-<id>, or a proxy node, proxy-<id>; one per host):
//
//   - Hello: forward.v1 with NodeCapabilities in its node_capabilities
//     attribute (HelloCapability, sdk/forward/wire), next to config.v1 and
//     package-reports.v1 (api/agent DataPlaneConfig.Forward).
//   - State: config.v1 snapshots of format anixops.nodeconfig/v2 carry the
//     node's NodeForwardState; the node's ConfigApplier hands every
//     snapshot to ApplySnapshot before the rest of the document.
//   - Reports: a PackageReport (plugin_id forward, kind forward.report)
//     through the data plane's SendForwardReport.
//
// # Start
//
// BuildDrivers lists every engine unavailable in the Hello (all were
// removed), so their hops come back as hop errors. Start
// re-applies the persisted state before the Agent connects to Control.
//
// # Persisted state
//
// Options.StateDir/state.json (directory 0700, file 0600, written by
// rename): the NodeForwardState last accepted from Control, its node and
// whether every engine applied it. It is the Agent's own state, separate
// from gost's directory (/var/lib/anixops-gost, which the gost driver owns)
// and from the Agent's PKI directory. A file of another node is discarded.
//
// # Snapshot rules
//
// A snapshot without forwarding (v1, or v2 without the member) leaves
// forwarding alone; generation 0 keeps what runs; only a newer generation
// is applied, the same one compared by state_hash; an empty state removes
// everything the drivers own. ConfigStatus is negative only for a document
// that cannot be applied as a whole; a hop a driver cannot run, or an
// engine whose Apply failed, is a hop error in the report, and a failed
// apply is retried every DefaultRetryInterval (30 s).
//
// # Loops and intervals
//
//   - health: every upstream probed with a TCP connect every
//     health.interval_ms (5 s) with timeout_ms (2 s); failure_threshold (3)
//     failures open the breaker for open_ms (30 s), then one trial; a hop
//     never loses its last upstream (H21);
//   - vantage probes (L4, vantage.go): the entry addresses of other routes
//     the state names (vantage_probes), global unicast only, dialled every
//     interval_ms (30 s); judged after 3 dials in a row and reported for
//     Control's entry HA;
//   - reconcile, every DefaultReconcileInterval (5 s) and after an apply or
//     a breaker change: Observe every driver, EnforceQuotas (gost's soft
//     quota) and assert the health selection through SetUpstreams where
//     the driver's rotation differs (after a changing apply or a gost
//     restart); a failed SetUpstreams is retried next round;
//   - least connections, every 10 s (H21): leastconn.Reweighter over the
//     health selection of each LEAST_CONN hop, from the
//     driver's sockets (ActiveConns);
//   - reports, every 60 s and after an apply or a health change, at most
//     one every 10 s, with the last counters of ended counter epochs
//     (Retired, the drivers' WithRetiredCounters) for 10 minutes.
//
// # Not here yet
//
//   - Link certificates (H28): until Control issues forward link
//     certificates, gost carries RAW links only and a hop with an encrypted
//     link is reported with a hop error saying so (Options.LinkCertificates).
//   - Target names: the drivers take IP literals; resolving names (TTL, at
//     most every 60 s, target policy re-checked) is not implemented, so a
//     hop with a named target is a hop error.
//   - UDP health exchanges, passive failures, probes (F3c), entry HA via
//     DDNS (L2, Control's).
package forward
