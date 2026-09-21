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

## 3.1 Alpha.2 范围

`v3.1.0-alpha.2` 提供 AnixOps 官方签名软件包 `machine-telemetry` 1.1.0，
以及对应的 Control 签名 WebUI 合约。它是正式 3.1--4.0 分阶段版本线的首个
可安装候选，不接管生产业务流量。`AgentControlEnabled` 和
`PluginSupervisorEnabled` 仍必须由操作员显式启用，并应只在 TLS 控制流上的少量
canary 节点验证包签名、重连、幂等操作、观察状态和回滚。现有 REST/UniProxy、
旧版 gRPC 与 WebSocket 链路继续作为数据面和回退路径。

产品发布版本回到 3.1 阶段线；Go 模块路径 `/v4` 是兼容 ABI 命名空间，并不表示
本次已经发布 4.0。`v4.0.0-alpha.1` 至 `v4.0.0-alpha.7` 保留为历史预览制品，
不能作为本阶段的发布范围或生产接管依据。

## 历史 v4 Alpha 运行时预览（非 3.1.0-alpha.2 发布范围）

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

`nftables-forward` 还覆盖 TCP/UDP DNAT、正常回滚、`SIGKILL` journal 留存和
同一 state path 的重启恢复：

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
| 官方插件状态 | `/var/lib/anixops/plugins` |
| 插件 Unix socket | `/run/anixops/plugins` |
| 容器镜像 | `ghcr.io/anixops/anix-agent` |

## Release 安装

生产环境应固定 Release tag。安装器只下载 GitHub Release 资产，不会在节点机
克隆仓库或执行本地发行构建。

```bash
export VERSION=v3.1.0-alpha.2
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
  "PluginRoot": "/var/lib/anixops/plugins",
  "PluginSocketDir": "/run/anixops/plugins",
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

要求 Go 1.25，并设置 `GOEXPERIMENT=jsonv2`。发行产物必须由 GitHub Actions
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
bash api/grpc/gen.sh
git diff --exit-code -- api/grpc/v2boardpb api/grpc/agent/v1
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
