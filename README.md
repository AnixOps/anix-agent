# AnixOps Agent

维护入口：[Agent 运维手册](docs/MAINTENANCE_P0.md)

Agent 分批交付与验收状态：[docs/P4_EXECUTION_STATUS.md](docs/P4_EXECUTION_STATUS.md)；维护事件契约：[docs/contracts/maintenance-event.schema.json](docs/contracts/maintenance-event.schema.json)

AnixOps Agent 是 AnixOps 维护的多内核代理节点 Agent，只通过 mTLS 的
`anix.agent.v1` 控制流连接 AnixOps Control；它执行节点配置同步、用户认证、
流量统计、在线状态上报和证书管理。
项目源自 V2bX，迁移期间继续保留必要的旧命令和发行资产兼容入口。

- Agent 仓库: [AnixOps/anix-agent](https://github.com/AnixOps/anix-agent)
- Control 仓库: [AnixOps/anix-control](https://github.com/AnixOps/anix-control)
- 上游项目: [wyx2685/V2bX](https://github.com/wyx2685/V2bX)

## 主要能力

- AnixOps 自研内核 anixcore（anx-node）与 WireGuard 内核
- VMess、VLESS、Trojan、Shadowsocks、Hysteria2 等协议
- 用户流量、在线 IP、设备数量与动态限速上报
- 节点组接入令牌（`anix-agent join`）与一次性注册凭证，mTLS 客户端证书自动续期
- ACME 证书申请、续期和自定义证书
- `anix.agent.v1` 双向 gRPC 控制流：配置、用户、上报、维护事件与插件制品
- 可选的官方签名插件 Supervisor（官方插件现只剩 `machine-telemetry`）
- Linux、Windows 和 macOS 构建

## 5.0.0-rc.28 范围

`v5.0.0-rc.28` 提供 AnixOps 官方签名软件包与 Agent 二进制，与 AnixOps Control
5.0.0-rc.28 使用同一版本号（H25）。rc.26 起 Agent 把 Control 的流量优先级与按用户分类限速（QoS）下发给 anixcore（`PUT /v1/qos`），ANX 协议支持 A2 无 SNI、整形与最大流数选项和 wg 外衣 UDP 端口（W1，需要 anx-node 0.1.0-alpha.9），旧配置里退役的内核名改用已安装的 anx-node，并认识热修复版本号（`<release>.hf.N`）。rc.25 起双网卡入口按 Control 选定的上联网卡拨出 ANX 中转链路（目标地址策略路由）。rc.24 起 Agent 运行面板反向代理（anixcore `reverse_proxy` 入站，需要 anx-node 0.1.0-alpha.6）。相对 rc.21：Agent 只运行 anixcore（anx-node）与 WireGuard，移除 Xray、sing-box、Hysteria 2 与 nftables 转发（启动时清理遗留的 inet anixops_fwd 表），新增 ANX-A 节点协议、ANX-Line C2/C3 回拨与中转链路 RTT/丢包上报。rc.21 起：老 Agent 装的内核缺 anx-server 时，同版本内核会重新安装（补上 ANX-Line 接收端），网络状态可以携带 anx-server 约 2.5KB 的混合公钥（此前超过 1KB 文本上限，经它的转发一直等待）。rc.20 起网络状态上报本机网卡、地址和默认网关（Control 节点页据此给出网络设置选项）。rc.19 起 anixcore 带 anx-node 时声明 hop 出口（rc.18 升级因此回滚），并支持 ANX-Line 反向回拨。rc.17 起：端口转发上报目标健康状态（ANX 路由的端到端健康、延迟与 DNS 入口切换），装了 anx-node 的 Agent 不再因 anixcore 运行目录只读而启动失败（rc.16 升级因此回滚）。rc.16 起内核升级时一并安装 anx-server（ANX-Line 接收端），跨境 l2 外衣带回落目标（`--dest`），转发 sysctl 的套接字缓冲提到 8 MiB，并认识 dev 构建版本号（`vX.Y.Z-rc.N.dev.M`）。rc.13 起 Xray 把 network 为空的 VMess/VLESS 节点按 tcp 处理（rc.12 升级因此回滚）。rc.12 起 Control 推送的升级会一并安装 AnixOps 自研内核 anx-node（含 ANX，验证 anx 发布签名），未列出内核的节点默认用它作为 anixcore 内核并启用 ANX-Line。rc.12 起 Agent 在 anixcore 上运行设备网络模型（`network.v1`：
ANX 中转线路、端口转发及其策略、出口策略路由），不再带 gost（转发引擎、gost-mesh 与 WireGuard gost
中转均已移除，升级时自动清理旧的 gost 单元）；装有 anixcore 时优先用它承载节点，不支持的节点逐个回落到
Xray/sing-box。rc.8 起 anixcore 内核承载 Panabit iWAN
节点（`iwan` 入站，UDP 三层隧道）。rc.7 起节点上探测 REALITY 目标站
（`reality.probe`，含一次真实 REALITY 握手），供 Control 排名、推荐和自动切换目标站；anixcore 内核
执行域名出口分流；出口中转入站不再报限速器错误。rc.6 起 Xray 内核执行 Control 下发的域名出口分流
（`egress`），每个代理节点都提供通用诊断（`anix-agent` 服务状态、重启、日志）。
rc.5 修复了 Xray 节点访问统计只记连接、不记字节的问题，并加入 anixcore 内核驱动（非默认构建）。rc.4 起新增访问统计上报
（`destinations.v1`，需要 Control 5.0.0-rc.4 或更新），默认分支改为 `main`。
rc.2 起一个节点运行 Control 下发的每个协议，同类协议也可以并存（如 SS 与 SS2022 各占一个端口，需要
Control 5.0.0-rc.2）。相对 4.2.0 的变化：
新增 `anix-agent join`（节点组 `anixjoin_` 接入令牌，见下文“控制流 mTLS 身份”一节与
`docs/INSTALL.md`）；Go 模块路径改为
`github.com/AnixOps/anix-agent/v5`，构建时注入版本的 ldflag 改为
`-X github.com/AnixOps/anix-agent/v5/cmd.version=<version>`；SDK 固定到 anix-control
main `5a234986`（anix-control#339 的合并提交，含 `AgentEnrollment.Join` 与 `DestinationReport`）。除此之外依赖与
工具链同 4.2.0（Go 1.26.9、`golang.org/x/net` v0.60.0），4.2.0 的功能范围保持不变：

- Agent 控制流（AG-1 至 AG-5b）：A2 协商、mTLS 身份（Control 4.2 默认 `required`）、
  配置与用户下发、流上报告与包报告、维护事件、alive 列表和插件制品；
- 转发组件（F3b）：上报转发能力、为 Control 的入口高可用做 vantage 探测、执行转发诊断（nftables、gost 与 anixops relay 驱动均已删除）；
- 实验性 anixops relay 引擎已删除（路由改由网络模型 / ANX 承载），安装脚本会清理旧的 `anixops-relay` 单元、账号和目录；
  转发的 sysctl drop-in 把 `net.core.rmem_max` 与 `wmem_max` 提到 8388608（8 MiB，anx-server 的 QUIC 用）；
- O1 安装布局、`agent.diagnostic` 诊断与转发检查、Control 推送的分阶段升级（`upgrade.v1`）；
- `machine-telemetry` 可选上报 systemd 服务表（H24：只报单元、状态、CPU 与内存，只保留最新）；
- 节点重载失败时恢复原配置；仅转发计划变化时不再重载代理入站；
- `uninstall` 在不带 `--purge` 时保留 `data/`，根安装的管理脚本同样移除 gost 与 relay。

升级顺序：先升级 Agent，再升级 Control。详见 `CHANGELOG.md`。

## 历史 v4 Alpha 运行时预览（非 5.0.0-rc.28 发布范围）

官方插件 Supervisor 仍需通过 `PluginSupervisorEnabled` 显式启用。`nftables-forward`
与 `nat-egress` 插件已随 nftables 转发引擎一起删除：中转走网络模型（ANX），出口网卡、
源地址和网关在 Control 的节点页设置。Agent 启动时会删除旧版本留下的 nftables 表
`inet anixops_fwd` 和 tc 根 qdisc `af00:`。

Supervisor 可从签名包物化并逐次复验辅助运行时，并为声明 `plugin.runtime-state` 和
`plugin.cleanup` 的插件保留私有 ownership journal。
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
export VERSION=v5.0.0-rc.28
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

节点配置只描述如何连接 Control 与本机身份；节点的协议、端口、用户都由 Control
通过控制流下发（与 Control 安装脚本写入的配置一致）：

```json
{
  "ApiHost": "https://control.example.com",
  "GRPCHost": "control.example.com:50051",
  "GRPCUseTLS": true,
  "AgentNode": "proxy-1",
  "NodeID": 1,
  "AgentIdentity": {
    "Enroll": "auto",
    "CertDir": "/var/lib/anixops-agent/pki",
    "EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"
  },
  "AgentStream": {"StateDir": "/var/lib/anixops-agent/stream"}
}
```

控制流必须使用 TLS：客户端证书是节点唯一的凭证，没有节点 API key。
`PluginSupervisorEnabled: true`（配合 `PluginRoot`、`PluginSocketDir` 与
`PluginOfficialPublicKey`，后者是 AnixOps 官方 Ed25519 公钥，不是私钥）开启官方插件
Supervisor。旧版本配置中的 `ApiKey`、`Transport`、`AgentControlEnabled`、
`SyncConfig`、`AutoRegister` 等字段已删除，加载时被忽略。

### 控制流 mTLS 身份（AgentIdentity）

Agent 向 Control 的 `AgentEnrollment` 申请客户端证书（SAN
`spiffe://anixops/<cluster>/agent/proxy-<NodeID>`）：

- 首次注册使用 `EnrollCredentialFile` 中的一次性 `anixagt_` 凭证
  （`anix-control agent token create -node proxy-<id>`），或 `anix-agent join`
  的节点组接入令牌。
- 私钥在本机生成（ECDSA P-256），与证书一起保存在
  `CertDir/proxy-<NodeID>/identity.pem`，CA 包在 `ca.pem`，元数据在
  `identity.json`；目录 0700、文件 0600，属主为运行 Agent 的用户（root）。
  权限过宽或属主不符的文件会被拒绝并重新注册。私钥不做“派生密钥加密”。
- 在 Control 给出的续期时间（证书寿命的三分之二，7 天证书约第 4.7 天）自动续期；
  证书被吊销、过期或不属于本集群时丢弃并重新注册。
- 控制流只出示证书。

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

`anix-agent join --control <url> --grpc <host:port> --token-file <file>` 是 Control 5.0
安装脚本以 `anixops-agent` 用户运行的一次性接入：节点组的 `anixjoin_` 接入令牌调用
`AgentEnrollment.Join`（`anixagt_` 凭证调用 `Enroll`），校验证书后写入
`CertDir/<node>`，`anix-agent server` 随后直接使用该身份。本机已有可用身份时先用该证书调用
`GetTrustBundle` 询问 Control：仍被接受则不再接入；被拒绝（如节点已删除、证书已吊销）则用令牌
重新接入并保留旧目录；无法连接 Control 时退出码为 4。`--reset` 跳过检查并申请新节点。须以服务用户
`anixops-agent` 运行（root 写入的文件会被身份存储拒绝）。JSON 输出与退出码见 `docs/INSTALL.md`
“Joining a node group”。

### 控制流数据面：节点配置（AgentStream）

Agent 在 Hello 中声明 `config.v1`，节点配置由控制流的 `ConfigSnapshot` 下发：

- 只应用格式为 `anixops.nodeconfig/v1`、`config_hash` 与内容 SHA-256 一致的快照；
  每个节点控制器取 `runtime.types[<NodeType>]`（未配置 `NodeType` 时取
  `default`，其余协议取 `runtime.protocols`），配置变化时重启内核。
- 每个快照都会以 `ConfigStatus` 回复（成功或失败原因）。
- 成功应用的快照保存在 `AgentStream.StateDir/proxy-<NodeID>/config.pb`
  （默认 `/var/lib/anixops-agent/stream`，目录 0700、文件 0600）。重启时即使 Control
  不可达也直接运行该配置，并在 Hello 中上报其 revision，Control 只在配置变化时下发。
- 无本地快照时最多等待 20 秒建立控制流，之后在后台等待（如等待一次性注册凭证）；
  协商到 `config.v1` 后最多等待 60 秒的快照，超时则启动失败（由 systemd 重启）。
  Control 不支持 `config.v1` 或 `users.v1` 时启动失败：需要升级 Control。

```json
"AgentStream": {
  "StateDir": "/var/lib/anixops-agent/stream"
}
```

### 控制流数据面：用户（users.v1）

用户列表由控制流的 `UserDelta` 下发：

- 分页的变更在收到 `last_page` 后一次应用；连接在最后一页之前断开时不做任何改动，
  游标保持不变。`full` 为整体替换，其余为按顺序应用的增量。
- 只增删有变化的用户（`DelUsers` / `AddUsers` 与限速器），不重启内核；应用失败时
  每 30 秒用最新集合重试。
- 用户集合与游标保存在 `AgentStream.StateDir/proxy-<NodeID>/users.pb`（0600，
  最多每 2 秒写一次，退出时写入），并作为 `Hello.users_cursor` 上报；重连或重启后从
  游标继续。游标为 0、早于 Control 变更日志的保留范围或超前时，Control 分页全量重发。
- 插件维护 outbox 在协商 `maintenance.v1` 时走控制流。
- Control 支持 `alive.v1` 时，设备数限制使用控制流下发的 `AliveList`（所有节点的
  在线设备数，分页，收到 `last_page` 后整体替换，未列出的用户为 0）；断线时未收完的
  列表被丢弃。没有 `alive.v1` 时只统计本节点的连接。

### 控制流数据面：上报与 spool（reports.v1、package-reports.v1）

流量、在线 IP、日志与节点状态由控制流上报（`reports.v1`）：

- 每个流量窗口（用户流量与本节点在线 IP）和日志批次带批次号
  `node:proxy-<id>:<boot id>:<序号>`，先持久化到
  `AgentStream.StateDir/proxy-<NodeID>/spool/{traffic,logs}/`（目录 0700、文件
  0600），再按顺序发送；收到 `ReportAck` 后删除，未确认的批次 30 秒后在控制流上重发，
  因此流量只计一次。
- 上限：`SpoolMaxMB`（流量，默认 64）、`LogSpoolMaxMB`（日志，默认 16）、
  `SpoolMaxAgeHours`（默认 72，最大 144，低于 Control 7 天的批次记忆）；超出时先丢弃
  最旧批次并计数。重启后 spool 仍会继续发送。
- 控制流断开期间的新数据进入 spool，重连后补发。
- 节点状态（CPU、内存、磁盘、运行时间、内核健康）每分钟通过 `NodeStatus` 上报。
- `package-reports.v1`：Supervisor 为插件进程设置 `ANIXOPS_NODE_ID`，
  `machine-telemetry` 采集本节点的 systemd 服务表；Agent 每 5 分钟（以及每次连接时）
  以 `PackageReport` 发送最新值，`version` 为节点被分配的插件版本。
- `destinations.v1`（访问统计）：代理内核按用户统计每个目标的
  连接数与上下行字节。目标只记可注册域名（`www.youtube.com` 记为 `youtube.com`），
  没有域名时记地址网段（IPv4 `/24`、IPv6 `/48`），并带嗅探到的协议（`tls`、`quic`、
  `bittorrent` 等）；每个用户每个窗口最多 200 个目标，超出的合并为一条“其他”。
  每个流量窗口以 `DestinationReport` 上报，批次号 `node:proxy-<id>:<boot id>:destinations-<序号>`，
  单独的 spool `spool/destinations/`（16 MB）。是否记录、保留多久由 Control 管理员在
  “流量与监控 → 访问统计”中设置；Control 不支持 `destinations.v1` 时不上报。

```json
"AgentStream": {
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
- `artifacts.v1`：插件包与清单通过 `AgentArtifacts` 按内容地址下载，校验大小、
  SHA-256、Ed25519 签名与清单中的包摘要，并核对 `PluginRelease`；
  `plugin_release_download_busy` 与 `Unavailable` 会重试。
- 等待一次性注册凭据时每 5 秒检查一次凭据文件，写入后很快完成注册。
- 错误码：`ConfigStatus.error_code`（`config_format_unsupported`、`config_hash_mismatch`、
  `config_invalid`、`config_apply_failed`）；`reports.v1` 携带 `transient_ack: "v1"`，
  `report_unavailable` 的批次保留并在 `retry_after_ms` 后重发。证书被拒
  （`agent_cert_revoked` / `expired` / `invalid` / `wrong_cluster`）时丢弃证书并重新注册；
  `agent_cert_wrong_node` 视为本地配置错误（保留证书，慢速重试并报错）；
  `agent_enrollment_rejected` 后不再重试同一凭据。
- 内核健康变化时立即发送带当前系统用量的 `NodeStatus`。

注册凭证与接入令牌属于敏感信息，不要放入 shell 历史、公开日志或 Issue。

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

要求 Go 1.26.10，并设置 `GOEXPERIMENT=jsonv2`。发行产物必须由 GitHub Actions
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
cd .. && bash api/anxmgmt/gen.sh && git diff --exit-code -- api/anxmgmt
```

## 文档

- [Release 安装指南](docs/INSTALL.md)
- [AnixOps Agent 迁移指南](docs/ANIX_AGENT_MIGRATION.md)
- [运行时与协议迁移](docs/MIGRATION.md)
- [官方插件 Supervisor](docs/PLUGIN_SUPERVISOR.md)
- [WireGuard 运行时测试](docs/WIREGUARD_RUNTIME_TESTS.md)

## 致谢

- [V2bX](https://github.com/wyx2685/V2bX)
- [Project X](https://github.com/XTLS/)
- [V2Fly](https://github.com/v2fly)
