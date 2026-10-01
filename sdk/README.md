# Anix Agent SDK (frozen)

> **Moved.** The Agent contract now lives in Control's SDK module,
> `github.com/AnixOps/anix-control/sdk`: `api/agent/v1` (Go package
> `agentv1pb`), `agentcontrol` and `plugincontrol`. It is wire-identical to
> this module's v1.1.0 (only `go_package` changed). This module is frozen at
> `sdk/v1.1.0` and receives no further changes. Never link both modules into
> one binary: both register `anix.agent.v1`, which panics at startup.


This nested Go module is the canonical source for public Anix Agent protocol
contracts. Consumers import the generated v1 bindings as:

```go
import agentv1pb "github.com/AnixOps/anix-agent/sdk/api/grpc/agent/v1"
```

The SDK must remain free of Agent runtime, filesystem, configuration, plugin,
and platform dependencies. Local development may use a shared `go.work`; CI
and released consumers must pin a published SDK version.

## v1.1.0 package operation contract

SDK v1.1.0 is additive only: it adds the `plugincontrol` contract for
Control-to-Agent package operations without changing existing fields.
`Operation` carries the package identity, generation, idempotency key,
operation kind, and required valid JSON configuration; `RuntimeStatus` carries
the corresponding observed package state. The existing v1.0.0
`anix.agent.v1` Agent Control protobuf, including `DesiredOperation.payload_json`,
remains unchanged.

Release the SDK before changing a Control dependency:

```bash
GOWORK=off ./scripts/check-breaking.sh
GOWORK=off go test ./...
git tag -a sdk/v1.1.0 -m "Anix Agent SDK v1.1.0"
git push origin dev_new sdk/v1.1.0
```

After the tag is published, Control may run:

```bash
GOWORK=off go get github.com/AnixOps/anix-agent/sdk@v1.1.0
```

For paired local development, keep the workspace file outside both repositories.
It should `use` Control, Agent, and this SDK module, then add a version-specific
`replace` for the SDK version pinned by the root modules. The replacement stays
in the untracked workspace file; neither root `go.mod` may commit a `replace`.
