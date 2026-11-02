// Package forward is the Agent's forward component (forward-sdk.md sections
// 6 to 8, F3b). Every engine it had a driver for (nftables, gost and the
// experimental anixops relay) was removed, and the driver framework with
// them: routes run on the network model. It keeps the forwarding state
// Control sends, probes entry addresses for Control's entry HA (vantage.go),
// runs the forward diagnostics and reports hop errors and vantage results;
// Prepare cleans up after the nftables driver (RetireNftables).
//
// # Wiring
//
// The component rides the Agent Control stream of the node it serves (a
// forward node, forward-<id>, or a proxy node, proxy-<id>; one per host):
//
//   - Hello: forward.v1 with NodeCapabilities in its node_capabilities
//     attribute (HelloCapability, sdk/forward/wire), every removed engine
//     listed unavailable, next to config.v1 and package-reports.v1
//     (api/agent DataPlaneConfig.Forward).
//   - State: config.v1 snapshots of format anixops.nodeconfig/v2 carry the
//     node's NodeForwardState; the node's ConfigApplier hands every
//     snapshot to ApplySnapshot before the rest of the document.
//   - Reports: a PackageReport (plugin_id forward, kind forward.report)
//     through the data plane's SendForwardReport.
//
// # Persisted state
//
// Options.StateDir/state.json (directory 0700, file 0600, written by
// rename): the NodeForwardState last accepted from Control and its node.
// Start loads it before the Agent connects to Control; a file of another
// node is discarded.
//
// # Snapshot rules
//
// A snapshot without forwarding (v1, or v2 without the member) leaves
// forwarding alone; generation 0 keeps what there is; only a newer
// generation is taken, the same one is ignored. ConfigStatus is negative
// only for a document that cannot be read as a whole; every hop of the
// state is a hop error in the report, since no engine runs it here.
//
// # Loops
//
//   - vantage probes (L4, vantage.go): the entry addresses of other routes
//     the state names (vantage_probes), global unicast only, dialled every
//     interval_ms (30 s); judged after 3 dials in a row and reported for
//     Control's entry HA;
//   - reports, every 60 s and after an apply or a vantage change, at most
//     one every 10 s.
package forward
