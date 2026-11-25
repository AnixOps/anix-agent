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
      "routing": {"policy": "latency", "paths": []}
    }],
    "takeover": {"process_names": [], "service_names": [], "config_paths": []}
  }
}
```

- `networks` 每项是一个地区网络，`id` 为地区代码（1–32 位小写字母、数字或 `-`），边界节点可有多项。
- Agent 只检查 `id`、`name`、`secret`、`address` 和 `takeover` 的名字；其余字段原样交给内核，由内核校验。
- 一个 Agent 进程里由第一个带内核的节点驱动组网（内核只运行一套网络）。

## 内核接口（需内核提供）

内核在 `GET /v1/status` 的 `features` 里列出 `mesh` 时，Agent 才下发组网；否则每个网络上报
`running: false` 与告警 `unsupported`，配置照常应用，不判为失败。内核更新后 Agent 在下一分钟自动重试。

| 方法与路径 | 请求 | 应答 |
|---|---|---|
| `PUT /v1/mesh` | `{"networks": [MeshConfig]}`，`[]` 停止全部 | 与 `GET` 相同 |
| `GET /v1/mesh` | | `{"networks": [MeshNetworkStatus]}` |

`MeshConfig` 是内核 `"type": "mesh"` 的分层配置（`config_version` 1）：`network{name, secret, secure_mode, cipher}`、
`node{address, address_v6, role, listen}`、`peers`、`subnets`、`routing`，另加 `tag`（`mesh-<id>`）。
内核重启后 Agent 重新发送最后一次的网络。

`MeshNetworkStatus`：`tag`、`running`、`error`、`address`、`forward_secrecy`、`peers[{address, subnets, via, hops, latency_ms, forward_secrecy}]`、
`rejected_advertisements`、`overlaps`、`alerts[{code, address, peer, detail}]`。告警码 `address_conflict`、`address_unmanaged`（R29）
和 `start_refused`（R12：端口占用、虚拟网卡或路由冲突、同一身份已在线）由内核给出。

## 上报：`mesh.status`

会话协商了能力 `mesh` v1 与 `package-reports.v1` 时，Agent 每次应用后和每 60 秒发送一次 PackageReport：
`plugin_id` `mesh`，`kind` `mesh.status`，`version` `v1`。

```json
{
  "networks": [{"id": "cn", "running": true, "address": "10.150.0.5/16", "forward_secrecy": true,
    "peers": [{"address": "10.150.0.1", "subnets": [], "via": ["10.150.0.3"], "hops": 1, "latency_ms": 12, "forward_secrecy": true}],
    "rejected_advertisements": 0, "alerts": []}],
  "takeover": {"found": true, "stopped": ["old.service"], "error": ""}
}
```

Agent 自己给出的告警码：`unsupported`（内核没有组网）、`takeover_pending`（现有组网程序仍在运行，网络暂缓启动）。

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
- 由安装脚本提供 root 的接管单元，免去部署工具手动执行第 2 步。
