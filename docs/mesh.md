# 内网组网（mesh）：Agent 侧

接口约定在 Control 仓库 `docs/design/mesh-regions/agent-contract.md`；需求见本仓库
`docs/mesh-takeover-requirements.md` 与 Control 仓库 `docs/design/mesh-regions/README.md`。
组网数据面在内核（anixcore 的 mesh 模块）里，Agent 只下发配置、读状态、上报，并配合接管现有组网程序。

代称：功能统一叫「组网」，标识符 `mesh`；团队原来使用的组网程序在文档中称「现有组网程序」。
本仓库的代码、文档和提交不出现该程序的名字，也不包含其任何代码；它的进程名和服务名是部署数据，
由面板（成员 `takeover`）或部署工具（`anix-agent mesh takeover` 的参数）给出。

## 下发：配置成员 `mesh`

配置文档（`anixops.nodeconfig/v1` 与 v2）的成员 `mesh`。没有这个成员时，Agent 停止全部组网网络。

```json
{
  "mesh": {
    "networks": [{
      "id": "cn", "name": "…", "secret": "…", "secure_mode": true, "cipher": "aes-gcm",
      "address": "10.150.0.5/16", "role": "full",
      "listen": [{"transport": "tcp", "port": 11010}, {"transport": "udp", "port": 11010}],
      "peers": [{"server": "…", "port": 11010, "transport": "tcp"}],
      "subnets": {"accept": [], "advertise": []},
      "routing": {"policy": "latency", "paths": []},
      "dns": {"enabled": true, "suffix": "mesh.internal", "names": [{"name": "nas.cn", "address": "10.150.128.7"}]},
      "host_groups": [{"cidr": "10.127.0.0/24", "gateway": "<实例 ID>", "backup_gateway": "<实例 ID>"}]
    }],
    "takeover": {"process_names": [], "service_names": [], "config_paths": []}
  }
}
```

- `networks` 每项是一个地区网络，`id` 为地区代码（1–32 位小写字母、数字或 `-`），边界节点可有多项。
- Agent 只检查 `id`、`name`（成员内不可重复：内核按网络名给出静态公钥）、`secret`、`address` 和 `takeover` 的名字；
  其余字段原样交给内核，由内核校验。
- `kind`（`managed` 或 `legacy`，缺省 `managed`）与 `native_keys`（我方节点在该网络的静态公钥清单）属于内核配置的 `network` 层，
  Agent 原样放进去，不检查、不重排、不去重；`null` 视同未下发，`[]` 原样下发。`managed` 网络的 `native_keys` 缺省、为空或不含本机公钥时，
  内核只暂缓该网络（`native_keys_pending`，其他网络不受影响，静态公钥照常生成）；只有某项格式错误时内核拒绝整份配置，
  本节点全部网络都带该错误。
- 内核 `features` 没有 `mesh_native_keys` 时它不认识 `native_keys`，也就无法只接纳我方节点：Agent 不把 `managed` 网络交给它，
  该网络上报告警 `native_keys_unsupported`；`legacy` 网络照常下发，去掉 `native_keys`（只影响成员实现的判定）。内核升级后，
  Agent 在下一分钟自动补发。内核重启后的重发与首次下发走同一检查：重启后的内核（例如降级）没有 `mesh_native_keys` 时，
  `managed` 网络不再重发，同样上报 `native_keys_unsupported`。
- `kind` 既不是 `managed` 也不是 `legacy`（含大小写不同的写法）时，Agent 不把该网络交给内核（旧内核会拒绝整份配置），
  上报告警 `invalid_kind`，其他网络照常运行；该网络等面板改正后的配置。
- **发布顺序：** 带上述检查的 Agent 必须在内核列出 `mesh_native_keys` 之后发布，否则节点上全部 `managed`（地区）网络都会被扣下。
- `dns`（内网域名，R28）与 `host_groups`（宿主组，R21、R25；网关以实例 ID 指定）由面板始终下发。内核拒绝未知字段，
  所以 Agent 只把本机内核支持的节交给内核：`features` 有 `mesh_dns`（内核 0.3 起）才带 `dns`（另有 `mesh_resolver_address` 才保留其中的 `resolver_address`，否则只去掉这一项），有 `mesh_host_groups`
  （内核 0.4 起）才带 `host_groups`，有 `mesh_external_bridge`（内核 0.4 起）才带 `external_bridge`（桥接节点才有此节）；值为 `null` 视同未下发。内核升级重启后，Agent 按新的 `features` 重新发送，补上新支持的节。
- 一个 Agent 进程里由第一个带内核的节点驱动组网（内核只运行一套网络）。

## 内核接口（需内核提供）

内核在 `GET /v1/status` 的 `features` 里列出 `mesh` 时，Agent 才下发组网；否则每个网络上报
`running: false` 与告警 `unsupported`，配置照常应用，不判为失败。内核更新后 Agent 在下一分钟自动重试。

| 方法与路径 | 请求 | 应答 |
|---|---|---|
| `PUT /v1/mesh` | `{"networks": [MeshConfig]}`，`[]` 停止全部 | 与 `GET` 相同 |
| `GET /v1/mesh` | | `{"instance_id": "…", "static_keys": [{"network", "static_key"}], "networks": [MeshNetworkStatus], "region_requests": [MeshRegionRequest]}` |
| `DELETE /v1/mesh/region_requests/{id}` | | 删除一条已转交的申请；不存在时 404，Agent 视同成功 |

`MeshConfig` 是内核 `"type": "mesh"` 的分层配置（`config_version` 1）：`network{name, secret, secure_mode, cipher, kind, native_keys}`、
`node{address, address_v6, role, listen}`、`peers`、`subnets`、`routing`，内核支持时另有 `dns`、`host_groups`（原样取自面板），
另加 `tag`（`mesh-<id>`）。内核重启后 Agent 重新发送最后一次的网络。

`features` 中与组网有关的名字：

| feature | 含义 | 自哪个内核版本 |
|---|---|---|
| `mesh` | 有 `/v1/mesh` | 0.3 |
| `mesh_dns` | 网络配置接受 `dns` | 0.3 |
| `mesh_resolver_address` | `dns` 节接受 `resolver_address`（固定解析地址） | 0.4 |
| `mesh_host_groups` | 网络配置接受 `host_groups` | 0.4 |
| `mesh_external_bridge` | 网络配置接受 `external_bridge`（外部网络桥接，R36），`GET /v1/mesh` 的网络带 `externalBridge`（摘要） | 0.4 |
| `mesh_region_requests` | `GET /v1/mesh` 带 `region_requests`，并有 `DELETE /v1/mesh/region_requests/{id}` | 0.4 |
| `mesh_native_keys` | 网络配置的 `network` 层接受 `native_keys`，`GET /v1/mesh` 带 `static_keys` | 0.3 |

`instance_id` 是本机的组网实例 ID，即组网状态快照的 `self.id`（首次启动生成，重启与升级不变），1–64 位字母、数字或 `-`，首字符须为字母或数字；
不合规时 Agent 按未给出处理。网络暂缓启动（`takeover_pending`）时内核也应给出。

`static_keys` 是本机各安全模式网络的静态公钥，`network` 为该网络的 `network.name`，`static_key` 为 32 字节 X25519 公钥的标准 base64
（带填充，44 个字符）。不合规的项 Agent 丢弃。内核在保存网络配置时生成该网络的静态密钥，所以只有内核已收到的网络才有公钥。

`MeshRegionRequest`：`id`（1–64 位字母、数字或 `-`，首字符须为字母或数字，内核生成，用于删除）、`network`（发起申请的网络的 `network.name`）、`region`（目标地区代码）、
`reason`（可省略）。节点所有者在本机执行内核命令 `mesh_request_region`（R24）时由内核记下，一直保留到 Agent 删除。

`MeshNetworkStatus`：`tag`、`running`、`error`、`address`、`forward_secrecy`、`peers[{address, subnets, via, hops, latency_ms, forward_secrecy}]`、
`rejected_advertisements`、`overlaps`、`alerts[{code, address, peer, detail}]`、`failure{code, detail}`。告警码 `address_conflict`、
`address_unmanaged`（R29）和 `start_refused`（R12：端口占用、虚拟网卡或路由冲突、同一身份已在线）由内核给出。`failure` 是内核暂缓或
未能启动该网络的原因（与状态快照的 `network.failure` 同一取值，例如 `native_keys_pending`，`detail` 为 `empty` 或 `self_missing`），
Agent 把它转成同码的告警上报，不上报 `failure` 本身。

## 上报：`mesh.status`

会话协商了能力 `mesh` v1 与 `package-reports.v1` 时，Agent 每次应用后和每 60 秒发送一次 PackageReport：
`plugin_id` `mesh`，`kind` `mesh.status`，`version` `v1`。

```json
{
  "instance_id": "2f6d7c1e-0b8a-4c55-9e0e-6a1f3b9d2c10",
  "networks": [{"id": "cn", "running": true, "address": "10.150.0.5/16", "forward_secrecy": true,
    "peers": [{"address": "10.150.0.1", "subnets": [], "via": ["10.150.0.3"], "hops": 1, "latency_ms": 12, "forward_secrecy": true}],
    "rejected_advertisements": 0, "alerts": []}],
  "takeover": {"found": true, "stopped": ["old.service"], "error": ""}
}
```

Agent 自己给出的告警码：`unsupported`（内核没有组网）、`takeover_pending`（现有组网程序仍在运行，网络暂缓启动）、
`native_keys_unsupported`（内核不认识 `native_keys`，`managed` 网络暂不下发）、`invalid_kind`（网络 `kind` 未知，暂不下发）、`external_bridge_unsupported`（内核未列出 `mesh_external_bridge`，网络照常运行但不带 `external_bridge`）、`external_bridge_downgrade_residue`（本节点曾在列出 `mesh_external_bridge` 的内核上为该网络桥接，现在的内核没有这项能力，不会清除新内核留下的桥接规则。请先清除规则，或在降级前让新内核正常退出，然后删除 Agent 状态目录下的 `bridged.json`。内核恢复这项能力后，告警自动消失）。内核暂缓网络的原因（如 `native_keys_pending`）也作为告警上报。

- 运行外部网络桥接的网络带 `externalBridge`（`{allowDigest, routesDigest, allowCount, appliedAt}`）：内核 `GET /v1/mesh` 中该网络
  已生效桥接配置的摘要，Agent 原样转述，不改写、不校验；面板对自己下发的名单按同一算法计算，相等即视为已应用。三种状态：摘要；
  内核明确给出 `null`（该网络没有运行桥接）时原样上报 `null`；Agent 不知道内核当前桥接时（网络被扣下、下发失败、等待接管、读不到内核、
  内核未给出该键）不带该键。面板只把显式 `null` 当作「无桥接」，缺省不能据此释放地址。
- 每个网络带 `static_key`：本机在该网络的静态公钥，按网络名取自内核 `GET /v1/mesh` 的 `static_keys`；面板只采信 Agent 通道的值，
  汇总为各网络的 `native_keys`。旧模式网络、内核读取失败时没有该字段，面板不应把缺省当作移除。
- 公钥由内核在收到网络配置时生成，所以首次接管时（现有组网程序仍在运行，网络从未交给内核）还没有公钥。顺序是：接管完成后 Agent
  把网络交给内核；面板尚未列入本机公钥，内核按 `native_keys_pending` 暂缓该网络并生成公钥；Agent 随即上报公钥（告警
  `native_keys_pending`）；面板推送含本机公钥的清单，内核自动启动该网络。内核已收到过该网络、之后现有程序又运行起来时，
  暂缓期间照常上报公钥。这一顺序依赖内核按网络暂缓而不是拒绝整份配置（AnixOps-core #326）。
- `instance_id` 取自内核 `GET /v1/mesh`；内核没有组网或未给出合规值时省略。面板据此确定宿主组网关，未上报前不下发以该节点为网关的宿主组。
- 节点不在任何地区（配置没有成员 `mesh`，或成员没有网络）时不上报：面板会按 `not_assigned` 拒绝。
- 状态里 `peers[].address` 由面板用来刷新设备地址的最近使用时间（R29），Agent 照内核原样上报。

## 上报：`mesh.region_request`

每次发出 `mesh.status` 后，Agent 把内核保留的地区申请逐条发送为 PackageReport：`plugin_id` `mesh`，`kind` `mesh.region_request`，
`version` `v1`，协商规则与 `mesh.status` 相同。

```json
{"region": "eu", "reason": "节点已迁至法兰克福"}
```

- 发出后 Agent 从内核删除该申请。面板不回执：它记为成员申请，批准后经配置推送生效，拒绝时配置不变。
- `region` 不是地区代码（1–32 位小写字母、数字或 `-`）的申请面板永远不会接受，Agent 不发送，直接删除并记日志。
  `reason` 去掉首尾空白与无效 UTF-8，超过 500 个字符时截断。
- 会话不可用或节点不在任何地区时申请留在内核，下一次上报（至多一分钟）再发送。

## 接管现有组网程序（R12）

Agent 以非特权用户运行，所以只负责检测，停止与恢复由 root 执行：

1. Agent 按成员 `takeover` 检测：`systemctl is-active` 查服务，`/proc/<pid>/comm` 查进程名。
   仍在运行时不启动网络（避免两个节点占用同一地址），上报 `takeover_pending`，每分钟复查。
2. 部署工具以 root 运行 `anix-agent mesh takeover --service <名字> --process <名字>`：
   先停开机自启（`systemctl disable`），再停服务，再按进程名结束进程（SIGTERM，5 秒后 SIGKILL）。
   文件与配置不删除。停掉的服务记录在 `/var/lib/<安装名>-mesh/takeover.json`（root 所有）。
   名字只取命令行参数，不读 Agent 用户可写的文件，因此 Agent 被攻破也不能借它停掉别的服务。
3. Agent 下一次复查发现已停，启动网络。

回滚：先在面板把节点移出组网（成员消失，Agent 停止网络），再以 root 运行 `anix-agent mesh restore`：
按记录恢复开机自启并启动服务，然后删除记录。手动启动的进程不会自动恢复。

## 后续（不在本版）

- 配置自动导入与导入报告（R13、R15）：需要先由另一方写出现有程序配置格式的说明，再照说明实现（净室）。
- 无 Agent 机器的安装命令与只读上报（R31、R32、R35）。
- 内核尚未提供 `/v1/mesh` 的 `instance_id`、`region_requests` 与 `mesh_*` 细分 feature；在此之前 Agent 不上报实例 ID、
  不下发 `dns` 与 `host_groups`、不转交地区申请，其余照常。
- 由安装脚本提供 root 的接管单元，免去部署工具手动执行第 2 步。
