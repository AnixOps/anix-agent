# Specification: node controller pieces and rate limits (`node`, `limiter`)

## Scope

Deleted before implementation, to be written new:

- packages `limiter`, `common/task`, `common/file`, `common/format`;
- `node/cert.go`, `node/lego.go`, `node/cert_test.go`, `node/lego_test.go`,
  `node/task.go`;
- functions `Controller.startWith`, `Controller.Close`,
  `Controller.buildNodeTag`, `Controller.addLimiter` (controller.go),
  `Controller.startNodeLocked` (reload.go), and
  `Controller.reportUserTrafficTask`, `onlineToReport`, `rollbackTraffic`,
  `compareUserList`, `userSyncKey` (user.go).

You may edit the `Controller` struct and other `node` code where the
removed pieces were used (for example the job and limiter fields,
`applyStreamAlive`, `syncCoreUserRateLimits`, tests that set up a
limiter). Keep such edits minimal and say which in your report.

| Area | New home |
|---|---|
| A. Periodic jobs | `node/jobs.go` |
| B. Node certificates | `node/certificate.go`, `node/acme.go` |
| C. Traffic report | `node/report.go` |
| D. User list diff | `node/users.go` |
| E. Controller start / stop / reconcile | in place, plus `node/lifecycle.go` if you prefer |
| F. Rate limits | `node/ratelimit.go` |

## Context the implementer may rely on

- `vCore.Core` (`core/interface.go`): `AddNode`, `DelNode`,
  `AddUsers(tag, info, users) (added int, err)`, `DelUsers(tag, info, users)`,
  `UserTraffic(tag, reset)`; optional `vCore.OnlineDeviceProvider`,
  `vCore.TrafficRollbacker`, `vCore.RateLimitUpdater`;
  `vCore.ErrNodeNotFound`.
- `panel.NodeInfo`, `panel.UserInfo`, `panel.UserTraffic`,
  `panel.OnlineUser` (`api/panel`).
- `conf.Options` (`LimitConfig`, `CertConfig`, `Name`,
  `DeviceOnlineMinTraffic`) and `conf.CertConfig` (`conf/node.go`).
- `Controller` fields that stay: `server`, `nodeID`, `apiHost`, `tag`,
  `userList`, `aliveMap`, `info`,
  `logHook`, `reconcileMu`, `nodeAdded`, `stream`, `protocolID`,
  `started`, `Options` (embedded), and the helpers `setUsers`,
  `protocolTagSuffix`, `replaceNodeLocked`, `addCoreNodeLocked`,
  `reportRuntimeHealth`, `reportDestinations`, `submitTraffic`,
  `syncCoreUserRateLimits`, `getCoreOnlineDevice`, `mergeOnlineDevices`,
  `nodeConfigEqual`, `newRemoteLogHook`.
- The tests in `node/*_test.go` describe the expected behaviour and must
  keep passing (they may be adapted where a name changes or where they
  reached into the removed limiter: assert on `aliveMap` / `rates`
  instead). Run with `-race` for the alive/stream/reload tests.

## A. Periodic jobs

A controller runs up to three background jobs while its node runs:

1. **Report** every `info.PushInterval`: section C. Always started.
2. **Certificate renewal** once a day, first run immediately: section B,
   only when the node's `Security` is `panel.Tls` and `CertMode` is `http`
   or `dns`.
3. **Dynamic speed limit check** every
   `DynamicSpeedLimitConfig.Periodic` seconds (60 when that is 0 or
   less), only when `LimitConfig.EnableDynamicSpeedLimit` is true and
   `DynamicSpeedLimitConfig` is set. Starting it resets the per-user
   traffic counter (`traffic map[uuid]bytes`).

Requirements:

- A job runs its function once per interval; runs never overlap. The
  first run is after one interval, except where stated.
- A run's error is logged with the controller's tag and the job keeps
  running (a failing run must not stop later runs).
- Stopping a job waits for nothing longer than the run in progress and is
  safe to call twice, and on a job that was never started.
- `Close` stops all jobs. When a reconcile changes the node and the new
  `PushInterval` is non-zero and differs, the report job restarts with
  the new interval.
- The speed check: every user whose counted traffic reached
  `DynamicSpeedLimitConfig.Traffic` bytes is penalised through
  `rates.penalize(uuid, DynamicSpeedLimitConfig.SpeedLimit,
  now + ExpireTime minutes)` and removed from the counter; then
  `syncCoreUserRateLimits` runs.
- The counter is guarded the same way the current code guards it: it is
  touched only from the report job, the speed check job and the reconcile
  path. The implementer must make concurrent access safe (a mutex is
  fine).

## B. Node certificates

`CertConfig.CertMode` decides where a TLS node's certificate comes from:

| Mode | At node start (`ensureCertificate`) | Daily renewal |
|---|---|---|
| `""`, `none` | nothing | no |
| `file` | `CertFile` and `KeyFile` must be set, else error | no |
| `self` | both paths must be set; when either file is missing, write a new self-signed certificate for `CertDomain` | no |
| `http`, `dns` | both paths must be set; when either file is missing, obtain one from the ACME CA | yes |
| anything else | error naming the mode | — |

Self-signed certificate: ECDSA P-256 key, subject CN and DNS SAN
`CertDomain`, valid from now for 10 years, server-auth usage; certificate
PEM "CERTIFICATE", key PEM "PRIVATE KEY" (PKCS#8). Key file mode 0600,
certificate 0644. Parent directories are created (0755).

ACME (library `github.com/go-acme/lego/v4`, already a dependency; use its
public API as documented, no other project's code):

- CA: Let's Encrypt production (the library default).
- Account: one per e-mail, stored as JSON at
  `<dir of CertFile>/user/user-<Email>.json` with members `Email`,
  `Registration` (the library's registration resource) and `Key` (the
  account's ECDSA P-256 private key, PEM "EC PRIVATE KEY", SEC 1). Files
  written by earlier Agent versions use exactly this layout and must keep
  loading. A missing file, or one for another e-mail, registers a new
  account (terms of service accepted) and writes the file (mode 0600).
- Challenge: `http` serves HTTP-01 on port 80 of all addresses; `dns`
  sets every `DNSEnv` entry as a process environment variable, then uses
  the library's DNS provider named by `Provider`.
- Obtain: one certificate for `CertDomain`, bundled, RSA 2048 key; write
  the certificate PEM to `CertFile` and the key to `KeyFile` (0600),
  creating directories.
- Renew (daily job): read `CertFile`; when it expires in more than 30
  days do nothing; otherwise renew through the library and write both
  files as above. Errors are logged, never fatal.

## C. Traffic report (the report job)

One run:

1. Read the window: `server.UserTraffic(tag, true)`. On error log a
   warning and continue with an empty window.
2. When the dynamic speed limit is on, add each user's upload+download to
   the counter, keyed by the uuid of the `userList` entry whose `Id` is
   the traffic's `UID` (traffic of unknown ids is ignored).
3. Online devices: the core's online list (`getCoreOnlineDevice`; an
   error is logged at info and treated as empty), de-duplicated with
   `mergeOnlineDevices`. A user whose traffic in this window is below
   `DeviceOnlineMinTraffic * 1000` bytes is left out (a ping is not a
   device); a user with no traffic entry is kept. The result is
   `map[uid][]ip` plus the number of merged devices before filtering.
4. `reportDestinations()`.
5. `submitTraffic(window, online)`. On error: give the window back
   (step 6) and log an error. On success, when there was traffic or
   online users, log at info how many users' traffic, and online users
   of the total, were reported.
6. Give back (only on a failed submit): when the core implements
   `TrafficRollbacker`, hand it the window (log a warning on error); when
   the dynamic speed limit is on, subtract each entry from the counter
   (never below 0).
7. `syncCoreUserRateLimits()`.

A run never fails (it always returns nil).

## D. User list diff

`diffUsers(running, wanted []panel.UserInfo) (removed, added)`: two users
are the same when all of these match: `Uuid`, `SpeedLimit`,
`DeviceLimit`, `WireGuardPeerIP`, `WireGuardPublicKey`,
`WireGuardPresharedKey`, and `Extra["ss2022_key"]`. A changed user is
therefore removed and added again. `added` keeps the order of `wanted`;
the order of `removed` is not significant. Duplicates within one list
count once.

## E. Controller lifecycle

Tag: `Options.Name` + `protocolTagSuffix()` when `Name` is set, else
`"[" + apiHost + "]-" + info.Type + ":" + info.Id` + `protocolTagSuffix()`.
(Logs rewrite this form; it must stay byte-identical.)

`startWith(info, users, alive)`:
warn when there are no users; set the tag; install the remote log hook
for the tag; `setUsers(users, alive)`; for TLS nodes ensure the
certificate (B); `AddNode`; mark `nodeAdded`; `AddUsers` with
`userList`; log how many were added; keep `info`; start the jobs (A);
set `started`. Any error is returned wrapped with what failed.

`Close()`: stop the jobs, close and drop the log hook, and when
`nodeAdded`, `DelNode(tag)` (error returned) and clear `nodeAdded`.
Safe to call more than once.

`startNodeLocked(info)` (reconcile path, `reconcileMu` held): when `Name`
is empty recompute the tag from `info`; TLS → ensure certificate; add the
node with `addCoreNodeLocked`; add `userList`; if adding users fails,
delete the node again (when that delete fails with anything but
`ErrNodeNotFound`, leave `nodeAdded` true so the next reconcile deletes
first) and return the error; else set `nodeAdded`. Errors are logged
with the tag and returned wrapped.

`reconcileLocked(newN, newU, newA)`: as documented on the current
function (unchanged node → no reload; changed node → take newU/newA,
`replaceNodeLocked`, reset the speed counter, restart the report job on a
new interval; otherwise store newA, report runtime health, and apply the
user diff when newU is not nil).

`applyUserDiffLocked(newU)`: diff (D); delete removed users then add new
ones through the core (errors logged and returned, nothing else changed);
when anything changed update `rates` and drop removed users from the
speed counter; store `newU`; log the counts when non-zero.

## F. Rate limits

Replaces the `limiter` package. Each controller owns one `rateLimits`
(field `rates`), created by `setUsers(users, alive)` (the new name of the
removed `addLimiter`: under `reconcileMu` it stores `userList`, keeps an
alive list that came from the stream earlier (`aliveFromStream`) or else
takes `alive` (never nil), and creates `rates` from
`LimitConfig.SpeedLimit` and the users). Rates are bytes per second, 0 is
no limit; Mbps converts as `mbps * 1_000_000 / 8` (0 or less → 0).

- `newRateLimits(nodeMbps int, users []panel.UserInfo)`.
- `update(added, removed []panel.UserInfo)`: drop removed, (re)add added
  with their own limit `SpeedLimit` (Mbps); a re-added user has no
  penalty.
- `penalize(uuid string, mbps int, until time.Time)`; unknown uuid is
  ignored.
- `rate(uuid string) int`: the lowest non-zero of the node limit, the
  user's own limit and an unexpired penalty.
- Safe for concurrent use.

`syncCoreUserRateLimits` pushes `rates.rate(uuid)` for every user to a
core implementing `vCore.RateLimitUpdater` (nothing when `rates` is nil).

What the old limiter also did and that is dropped: a global registry by
tag, a regexp copy of the block rules (anixcore applies `info.Rules`
itself), a table of online IPs (nothing filled it; online devices come
from the core only), and a copy of the alive list (the controller's
`aliveMap` is the only copy; `applyStreamAlive` and `reconcileLocked`
just set it).

## Test names

The optional ACME DNS integration test is skipped unless
`ANIXOPS_ACME_INTEGRATION=1`; it reads `ANIXOPS_ACME_EMAIL`,
`ANIXOPS_ACME_DOMAIN` and `ANIXOPS_ACME_PROVIDER` (defaults
`test@example.com`, `test.example.com`, `cloudflare`) and the provider's
own environment variables.

## Rules for the implementer

- Do not read the forked upstream project (V2bX, InazumaV/V2bX,
  wyx2685/V2bX) in any form, nor this repository's history before the
  clean-room change (`git log -p`, `git show`, `git blame` of the files
  in scope). Work from this document, the current non-scope code and the
  tests.
- The files and functions in scope are deleted before you start; write
  them new. Your workspace is an export without git history.
- Keep the code short and direct; no speculative options.
