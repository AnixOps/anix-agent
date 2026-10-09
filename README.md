# AnixOps Agent

维护入口：[Agent 运维手册](docs/MAINTENANCE_P0.md)

Agent 分批交付与验收状态：[docs/P4_EXECUTION_STATUS.md](docs/P4_EXECUTION_STATUS.md)；维护事件契约：[docs/contracts/maintenance-event.schema.json](docs/contracts/maintenance-event.schema.json)

AnixOps Agent 是 AnixOps 维护的多内核代理节点 Agent，用于连接 AnixOps
Control，并兼容旧 V2Board/UniProxy 接口；它执行节点配置同步、用户认证、
流量统计、在线状态上报和证书管理。
项目源自 V2bX，迁移期间继续保留必要的旧命令和发行资产兼容入口。

- Agent 仓库: [AnixOps/anix-agent](https://github.com/AnixOps/anix-agent)
- Control 仓库: [AnixOps/anix-control](https://github.com/AnixOps/anix-control)
- 上游项目: [wyx2685/V2bX](https://github.com/wyx2685/V2bX)

## 主要能力

- Xray-core、Sing-box、Hysteria2 多内核统一管理
- VMess、VLESS、Trojan、Shadowsocks、Hysteria2 等协议
- 用户流量、在线 IP、设备数量与动态限速上报
- 节点自动注册、签名鉴权与凭证加密存储
- ACME 证书申请、续期和自定义证书
- REST、WebSocket、旧版 gRPC API 与 `anix.agent.v1` 双向 gRPC 控制流
- 可选的官方签名插件 Supervisor，以及真实的 `nftables-forward` 和
  `nat-egress` Linux 插件运行时
- Linux、Windows 和 macOS 构建

## 4.2.0-rc.4 范围

`v4.2.0-rc.4` 提供 AnixOps 官方签名软件包与 Agent 二进制，与 AnixOps Control
4.2.0-rc.4 使用同一版本号（H25），是 v4.2 转发与 Agent 控制面的第四个候选版本，
取代 rc.3 的 Agent 包。功能范围与 rc.3 相同，相对 rc.3 的变化在依赖与工具链：
Agent 与 `anixops-relay` 改用 Go 1.26.9 构建，`golang.org/x/net` 升到 v0.60.0，
SDK 固定到 anix-control go_dev `d8684dc2`。下列功能为 rc.3 已有的范围：

- Agent 控制流（AG-1 至 AG-5b）：A2 协商、mTLS 身份（Control 4.2 默认 `required`）、
  配置与用户下发、流上报告与包报告、维护事件、alive 列表和插件制品；
- 转发组件（F3b）：执行 Control 下发的 `forward.v1` 计划（nftables 与 gost 驱动）；
- 实验性 anixops 引擎（H22 A3，**默认关闭**，线格式在 v4.3 之前可能变化）：独立的
  `anixops-relay` 程序与 `anixops-relay.service`，随发布的 zip 一起提供；Agent 侧开关为
  `Forward.AnixOps.Enable`，Control 侧开关为 `forward.anixops_experimental`，两边都开才生效；
  `ANIXOPS_FORWARD=1 ANIXOPS_RELAY=1` 的安装脚本会创建它的账号、目录和单元；
  转发的 sysctl drop-in 把 `net.core.rmem_max` 与 `wmem_max` 提到 7500000（QUIC 用）；
  Control 推送的升级与 Control 自带的 O1 安装器**不会**暂存或安装新的 `anixops-relay`；
- O1 安装布局、`agent.diagnostic` 诊断与转发检查、Control 推送的分阶段升级（`upgrade.v1`）；
- `machine-telemetry` 可选上报 systemd 服务表（H24：只报单元、状态、CPU 与内存，只保留最新）；
- 节点重载失败时恢复原配置；仅转发计划变化时不再重载代理入站；
- `uninstall` 在不带 `--purge` 时保留 `data/`，根安装的管理脚本同样移除 gost 与 relay。

升级顺序：先升级 Agent，再升级 Control。详见 `CHANGELOG.md`。

## 历史 v4 Alpha 运行时预览（非 4.2.0-rc.4 发布范围）

官方插件 Supervisor 仍需通过 `PluginSupervisorEnabled` 显式启用。当前已实现
真实的 `nftables-forward`、`nat-egress` 与 `gost-mesh` 独立进程。Supervisor
可从签名包物化并逐次复验辅助运行时；`gost-mesh` 固定使用 GOST v3.2.6，
提供 QUIC/WSS 聚合隧道、强制双向 TLS、源地址策略路由、健康检查和崩溃清理。
TUIC 不属于 v1，因为该固定 GOST 版本不实现 TUIC。业务流量由内核网络栈或
GOST 子进程承载，不经过 Supervisor 控制进程。

`nftables-forward` 1.2.0 与 `nat-egress` 清单声明 `plugin.runtime-state` 和
`plugin.cleanup`。Supervisor 为它们保留稳定的私有 ownership journal，并在崩溃、禁用、配置变更、升级和关闭
时调用签名 cleanup 入口。清理失败会持久化 `cleanup_pending`，插件保持禁用；
升级目标版本的清理成功后才允许自动启动旧版本，避免旧版本覆盖可能残留的路由
或 NAT 状态。`nftables-forward` 在安装后默认保持 `apply=false`，只有显式规则
和 `apply=true` 才会修改内核；硬退出后的下一次启动先恢复原表快照。
其 1.2 包额外声明 `kernel.observed-state`。Supervisor 每次 heartbeat 都先检查
运行时 Unix health socket；只有仍在 serving 的私有、签名包声明规则集摘要和计数器
才会与自身的 config hash/revision 绑定后发送给 Control，失效时改发无指纹的
`unhealthy` 证据。

特权 namespace 验收已覆盖 marked forwarded traffic、wrong-mark isolation、
policy route、masquerade、正常退出清理和既有状态恢复：

```bash
sudo env GOEXPERIMENT=jsonv2 GOWORK=off \
  bash plugin/nategress/namespace_acceptance.sh
```

`nftables-forward` 还覆盖 IPv4/IPv6 TCP/UDP DNAT、内核规则计数、正常回滚、
`SIGKILL` journal 留存和同一 state path 的重启恢复。常规 CI 使用预构建插件
二进制执行同一 privileged namespace 验收：

```bash
sudo env GOEXPERIMENT=jsonv2 GOWORK=off \
  bash plugin/nftablesforward/namespace_acceptance.sh
```

这些能力仍是预览：生产启用必须使用正式签名 Release，并完成 mark producer、
FORWARD 防火墙策略、Control Secret-ID 私有文件物化、组合拓扑、分批 canary
和运维审批。当前 `gost-mesh` 证据来自隔离 namespace，不等同于跨地域生产验证。
完整生命周期契约见 [官方插件 Supervisor](docs/PLUGIN_SUPERVISOR.md)。

## 默认路径

| 项目 | 默认值 |
|---|---|
| CLI / 管理命令 | `anix-agent` |
| systemd / OpenRC 服务 | `anix-agent` |
| 程序目录 | `/usr/local/anixops-agent` |
| 主程序 | `/usr/local/anixops-agent/anix-agent` |
| 配置目录 | `/etc/anixops/agent` |
| 主配置 | `/etc/anixops/agent/config.json` |
| 官方插件状态 | `/var/lib/anixops-agent/plugins` |
| 插件 Unix socket | `/run/anixops-agent/plugins` |
| 身份 / stream / 转发状态 | `/var/lib/anixops-agent/{pki,stream,forward}` |
| gost（随 Release 附带，固定 3.2.6） | `/usr/lib/anixops-agent/gost`，配置 `/var/lib/anixops-gost` |
| 容器镜像 | `ghcr.io/anixops/anix-agent` |

新节点使用 AnixOps Control 节点页面的一键安装命令（Control 的 `/install.sh`）：
Agent 以 `anixops-agent` 用户运行（仅 `CAP_NET_ADMIN`、`CAP_NET_BIND_SERVICE`，
systemd 沙箱），配置只含凭据（无 `ApiKey`、无 `Cores`）。早期默认目录
（`/var/lib/anix-agent/{pki,stream}`、`/var/lib/anixops/plugins`）会被一次性复制到
新位置，旧目录保留。详见 [docs/INSTALL.md](docs/INSTALL.md)。

## Release 安装

生产环境应固定 Release tag。安装器只下载 GitHub Release 资产，不会在节点机
克隆仓库或执行本地发行构建。

```bash
export VERSION=v4.2.0-rc.4
curl -fsSL \
  "https://raw.githubusercontent.com/AnixOps/anix-agent/${VERSION}/scripts/install.sh" \
  -o /tmp/anix-agent-install.sh
sudo bash /tmp/anix-agent-install.sh "${VERSION}"
rm -f /tmp/anix-agent-install.sh
```

首次安装没有可用配置时，安装器不会直接启动服务。先初始化并检查配置：

```bash
sudo anix-agent initconfig
sudo anix-agent config
sudo /usr/local/anixops-agent/anix-agent validate-config \
  -c /etc/anixops/agent/config.json
sudo anix-agent start
sudo anix-agent status
sudo anix-agent log
```

常用管理命令：

```text
anix-agent start|stop|restart|status|log
anix-agent update [version]
anix-agent uninstall [--purge]
anix-agent validate-config -c /etc/anixops/agent/config.json
anix-agent server -c /etc/anixops/agent/config.json
```

安装器接受稳定版以及 `alpha`、`beta`、`rc` 预发布 tag，例如
`v3.1.0-alpha.2`、`v3.1.0-beta.1` 和 `v3.1.0-rc.1`。

## 从 V2bX_AnixOps 升级

新安装器会自动检测以下旧版安装：

- `/etc/V2bX`
- `/usr/local/V2bX`
- `V2bX.service` 或 `/etc/init.d/V2bX`
- `V2bX`、`v2bx-anixops` 命令

迁移时只把新目录中缺失的配置复制到 `/etc/anixops/agent`，不会删除或覆盖
旧配置目录。旧二进制和旧服务定义会在切换前备份；新服务无法启动时，安装器
会尝试恢复旧二进制和旧服务。迁移成功后，`V2bX`、`v2bx-anixops` 和
`V2bX.service` 继续作为兼容别名。

完整步骤与回滚说明见
[AnixOps Agent 迁移指南](docs/ANIX_AGENT_MIGRATION.md)。

## Release 资产兼容

新 Release 的主资产名为：

```text
anix-agent-linux-64.zip
anix-agent-linux-arm64-v8a.zip
```

新 Release 只发布 `anix-agent-*` 主资产。迁移期安装器在找不到新命名资产时，
会自动回退到同一 tag 的 `V2bX-*` 资产，并接受包内旧 `V2bX` 二进制名，
最终仍安装到新的程序和配置路径。v3 Release 不承诺继续发布 `V2bX-*`
资产名；`anix-agent-*` 包内只保留 `V2bX -> anix-agent` 二进制兼容链接。

## 配置与运行

示例位于 `example/`。直接运行 Agent：

```bash
anix-agent server -c /etc/anixops/agent/config.json
```

Windows：

```powershell
.\anix-agent.exe server -c .\config.json
```

`Transport` 选择现有配置/用户/流量数据面；`AgentControlEnabled` 独立开启 v3
双向控制流。以下示例保留 REST 数据面作为回退，同时启用 Agent-first 预览：

```json
{
  "ApiHost": "https://panel.example.com",
  "Transport": "http",
  "GRPCHost": "panel.example.com:443",
  "GRPCUseTLS": true,
  "GRPCServerName": "panel.example.com",
  "GRPCKeepalive": 30,
  "AgentControlEnabled": true,
  "AgentControlAllowInsecure": false,
  "PluginSupervisorEnabled": true,
  "PluginRoot": "/var/lib/anixops-agent/plugins",
  "PluginSocketDir": "/run/anixops-agent/plugins",
  "PluginOfficialPublicKey": "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M=",
  "NodeID": 1,
  "ApiKey": "your-api-key"
}
```

若不显式设置 `AgentControlEnabled: true`，旧配置不会自动建立新控制流。公网或
非回环地址必须使用 TLS；不要通过放宽明文开关来绕过生产证书配置。
若不显式设置 `PluginSupervisorEnabled: true`，Agent 仍只运行旧数据面，不会
接受官方软件包生命周期操作。上面的 Base64 值是 AnixOps 官方 Ed25519 公钥，
不是私钥；Control 与 Agent 必须使用同一个信任根。安装向导会生成这些字段，
并以 `Transport: "http"` 保留旧数据面回退。

### 控制流 mTLS 身份（AgentIdentity）

开启 `AgentControlEnabled` 且控制流使用 TLS 时，Agent 会向 Control 的
`AgentEnrollment` 申请客户端证书（SAN `spiffe://anixops/<cluster>/agent/proxy-<NodeID>`）：

- 首次使用节点 API key 注册一次；若配置了 `EnrollCredentialFile`，优先使用其中的
  一次性 `anixagt_` 凭证（`anix-control agent token create -node proxy-<id>`）。
  Control 4.2 默认 `agent_control.mtls: required`，此时只接受一次性凭证。
- 私钥在本机生成（ECDSA P-256），与证书一起保存在
  `CertDir/proxy-<NodeID>/identity.pem`，CA 包在 `ca.pem`，元数据在
  `identity.json`；目录 0700、文件 0600，属主为运行 Agent 的用户（root）。
  权限过宽或属主不符的文件会被拒绝并重新注册。私钥不做“派生密钥加密”。
- 在 Control 给出的续期时间（证书寿命的三分之二，7 天证书约第 4.7 天）自动续期；
  证书被吊销、过期或不属于本集群时丢弃并重新注册。
- 注册成功后，控制流只出示证书，不再发送 `x-api-key`。仅当 Control 未请求客户端
  证书（`agent_control.mtls: off`，或 Control 未启用内置 CA）时才回退到 API key。
  REST/UniProxy、旧版 gRPC 与 WebSocket 链路在 AG-3 至 AG-5 之前仍使用 API key。

```json
"AgentIdentity": {
  "Enroll": "auto",
  "CertDir": "/var/lib/anixops-agent/pki",
  "EnrollCredentialFile": "/etc/anixops/agent/enroll.token",
  "Cluster": ""
}
```

`Enroll` 为 `auto`（默认）或 `off`（不注册；已有身份仍会使用和续期）。
`anix-agent identity [--json]` 显示每个节点的 SPIFFE ID、证书序列号、过期与续期时间，
只读本地文件，不连接 Control。容器部署需把 `CertDir` 挂载为持久卷。

### 控制流数据面：节点配置（AgentStream）

开启 `AgentControlEnabled` 后，Agent 在 Hello 中声明 `config.v1`。Control 支持时
（`HelloAck.server_capabilities` 含 `config.v1`），节点配置改由控制流的
`ConfigSnapshot` 下发，不再拉取 UniProxy `config`、v2board `GetConfig`，也不再处理
WebSocket `config_update` 或 `node.reload` 的重新拉取：

- 只应用格式为 `anixops.nodeconfig/v1`、`config_hash` 与内容 SHA-256 一致的快照；
  每个节点控制器取 `legacy_pull.types[<NodeType>]`（未配置 `NodeType` 时取
  `default`），解析逻辑与 UniProxy 应答完全相同，内核按原有方式重启。
- 每个快照都会以 `ConfigStatus` 回复（成功或失败原因）。
- 成功应用的快照保存在 `AgentStream.StateDir/proxy-<NodeID>/config.pb`
  （默认 `/var/lib/anixops-agent/stream`，目录 0700、文件 0600）。重启时即使 Control
  不可达也直接运行该配置，并在 Hello 中上报其 revision，Control 只在配置变化时下发。
- 无本地快照时最多等待 20 秒建立控制流；协商到 `config.v1` 后最多等待 60 秒的快照，
  超时则启动失败（由 systemd 重启），不会退回旧链路。控制流不可用或 Control
  不支持 `config.v1` 时按原方式经旧链路启动。
- 控制流断开 5 分钟内不使用旧链路拉取配置；超过后恢复旧链路拉取。
- `AgentStream.DataPlane: "off"` 可回退到旧链路（控制流只承载操作）。

```json
"AgentStream": {
  "DataPlane": "auto",
  "StateDir": "/var/lib/anixops-agent/stream"
}
```

### 控制流数据面：用户（users.v1）

Control 支持 `users.v1` 时，用户列表改由控制流的 `UserDelta` 下发，不再拉取
UniProxy `user`、v2board `GetUsers`，也不处理 WebSocket `user_update` / `user_ban`：

- 分页的变更在收到 `last_page` 后一次应用；连接在最后一页之前断开时不做任何改动，
  游标保持不变。`full` 为整体替换，其余为按顺序应用的增量。
- 只增删有变化的用户（`DelUsers` / `AddUsers` 与限速器），不重启内核；应用失败时
  每 30 秒用最新集合重试。
- 用户集合与游标保存在 `AgentStream.StateDir/proxy-<NodeID>/users.pb`（0600，
  最多每 2 秒写一次，退出时写入），并作为 `Hello.users_cursor` 上报；重连或重启后从
  游标继续。游标为 0、早于 Control 变更日志的保留范围或超前时，Control 分页全量重发。
- 控制流同时承载配置与用户时不再启动旧的 WebSocket；插件维护 outbox 在协商
  `maintenance.v1` 时也走控制流，不再需要仅维护模式的 WebSocket。
- Control 支持 `alive.v1` 时，设备数限制使用控制流下发的 `AliveList`（所有节点的
  在线设备数，分页，收到 `last_page` 后整体替换，未列出的用户为 0），取代 UniProxy
  `alivelist`；断线时未收完的列表被丢弃。没有 `alive.v1` 时只统计本节点的连接。

### 控制流数据面：上报与 spool（reports.v1、package-reports.v1）

Control 支持 `reports.v1` 时，流量、在线 IP、日志与节点状态改由控制流上报，不再使用
UniProxy `push` / `alive`、v2board 上报接口和 `runtime-health` 路由：

- 每个流量窗口（用户流量与本节点在线 IP）和日志批次带批次号
  `node:proxy-<id>:<boot id>:<序号>`，先持久化到
  `AgentStream.StateDir/proxy-<NodeID>/spool/{traffic,logs}/`（目录 0700、文件
  0600），再按顺序发送；收到 `ReportAck` 后删除，未确认的批次 30 秒后在控制流上重发，
  从不改走旧链路，因此流量只计一次。
- 上限：`SpoolMaxMB`（流量，默认 64）、`LogSpoolMaxMB`（日志，默认 16）、
  `SpoolMaxAgeHours`（默认 72，最大 144，低于 Control 7 天的批次记忆）；超出时先丢弃
  最旧批次并计数。重启后 spool 仍会继续发送。
- 控制流断开 5 分钟内的新数据进入 spool；超过后新数据走旧链路。
- 节点状态（CPU、内存、磁盘、运行时间、内核健康）每分钟通过 `NodeStatus` 上报。
- `package-reports.v1`：Supervisor 为插件进程设置 `ANIXOPS_NODE_ID`，
  `machine-telemetry` 采集本节点的 systemd 服务表；Agent 每 5 分钟（以及每次连接时）
  以 `PackageReport` 发送最新值，`version` 为节点被分配的插件版本。

```json
"AgentStream": {
  "DataPlane": "auto",
  "StateDir": "/var/lib/anixops-agent/stream",
  "SpoolMaxMB": 64,
  "LogSpoolMaxMB": 16,
  "SpoolMaxAgeHours": 72
}
```

### 控制流数据面：维护事件、在线设备数、插件包与错误码

- `maintenance.v1`：插件维护 outbox 以 `MaintenanceEvents`（每批最多 50 条、256 KiB）
  在控制流上发送；`persisted` 删除，带错误（或未知错误码）的拒绝直接丢弃并记录
  `error_code`，`maintenance_unavailable` 保留并在 `retry_after_ms` 之后重发。
- `alive.v1`：见上文“用户”。
- `artifacts.v1`（已注册、以客户端证书连接时）：插件包与清单通过 `AgentArtifacts`
  按内容地址下载，校验与 HTTP 下载相同（大小、SHA-256、Ed25519 签名、清单中的包摘要），
  并核对 `PluginRelease`；`plugin_release_download_busy` 与 `Unavailable` 会重试。
  未协商 `artifacts.v1` 时（尚未注册，或 Control 4.1.x 尚无 AgentArtifacts；v4.2 升级
  先升级 Agent）仍使用带 `X-API-Key` 的 HTTP 下载；若被 `agent_mtls_required` 拒绝，
  安装错误中会明确说明。
- 等待一次性注册凭据时每 5 秒检查一次凭据文件，写入后很快完成注册。
- 错误码：`ConfigStatus.error_code`（`config_format_unsupported`、`config_hash_mismatch`、
  `config_invalid`、`config_apply_failed`）；`reports.v1` 携带 `transient_ack: "v1"`，
  `report_unavailable` 的批次保留并在 `retry_after_ms` 后重发。证书被拒
  （`agent_cert_revoked` / `expired` / `invalid` / `wrong_cluster`）时丢弃证书并重新注册；
  `agent_cert_wrong_node` 视为本地配置错误（保留证书，慢速重试并报错）；
  `agent_enrollment_rejected` 后不再重试同一凭据。
- 内核健康变化时立即发送带当前系统用量的 `NodeStatus`。

Control 4.2 默认 `agent_control.mtls: required`：已注册的 Agent 在 Control 支持上述能力时
完全不访问旧的 REST、gRPC 与 WebSocket 通道（包括维护 WebSocket 与 HTTP 插件下载）；
首次注册仍需一次性注册凭据（`anix-control agent token create`）。

面板 API key 属于敏感信息，不要放入 shell 历史、公开日志或 Issue。

## Docker

```bash
docker run -d \
  --name anix-agent \
  --restart unless-stopped \
  -v /etc/anixops/agent:/etc/anixops/agent \
  ghcr.io/anixops/anix-agent:latest
```

容器入口默认读取 `/etc/anixops/agent/config.json`，并保留容器内 `V2bX`
二进制别名供旧编排配置过渡。

## 开发构建

要求 Go 1.26.9，并设置 `GOEXPERIMENT=jsonv2`。发行产物必须由 GitHub Actions
生成；本地脚本仅用于开发验证，并要求显式启用：

```bash
ALLOW_LOCAL_BUILD=1 ./build.sh -p linux -a amd64
```

Windows PowerShell：

```powershell
$env:ALLOW_LOCAL_BUILD="1"
.\build.ps1 -Platform windows -Arch amd64
```

测试：

```bash
GOEXPERIMENT=jsonv2 GOWORK=off go test ./...
cd sdk && bash api/grpc/gen.sh && git diff --exit-code -- api/grpc/agent/v1
cd .. && bash api/grpc/gen.sh && git diff --exit-code -- api/grpc/v2boardpb
```

## 文档

- [Release 安装指南](docs/INSTALL.md)
- [AnixOps Agent 迁移指南](docs/ANIX_AGENT_MIGRATION.md)
- [运行时与协议迁移](docs/MIGRATION.md)
- [官方插件 Supervisor](docs/PLUGIN_SUPERVISOR.md)
- [API 文档](API_DOCUMENTATION.md)
- [WireGuard 运行时测试](docs/WIREGUARD_RUNTIME_TESTS.md)

## 致谢

- [V2bX](https://github.com/wyx2685/V2bX)
- [Project X](https://github.com/XTLS/)
- [V2Fly](https://github.com/v2fly)
- [XrayR](https://github.com/XrayR/XrayR)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
