# AnixOps Agent 贡献者与 AI 助手规范

本文件适用于人和 AI 编码助手。保持简短、可执行；详细说明放在 `docs/`。

## 项目概述

`anix-agent` 是 AnixOps 的节点端程序（Go 模块 `github.com/AnixOps/anix-agent/v5`）。
它运行 AnixOps 自研内核 anixcore（anx-node 进程）与 WireGuard 内核，只通过
mTLS 的 `anix.agent.v1` 双向 gRPC 控制流与 AnixOps Control（`AnixOps/anix-control`）交互。
sing-box、xray、hysteria、gost、旧的 nftables 转发驱动、anixops relay 都已删除，不要再引入。
不得链接、静态嵌入或以库形式（含 cgo / FFI）引入任何第三方代理引擎或 GPL / AGPL 模块：anixcore（anx-node）、
anx-server 只作为独立进程，经 gRPC、HTTP 管理接口、配置文件和命令行驱动。CI 的
“No third-party engines or GPL modules” 步骤（`scripts/check_forbidden_deps.sh` 与 go-licenses）强制这一点。
网络计划里的内核转发跳（`kernel_forwards`）由 `kernelfwd/` 直接用 nft 实现，保持轻量。

- 协议契约归 Control 所有：`github.com/AnixOps/anix-control/sdk`（`sdk/api/agent/v1`、
  `sdk/agentcontrol`、`sdk/plugincontrol`）。契约只增不删。
- 客户端证书（mTLS）是唯一凭证。首次注册使用 Control 签发的一次性注册凭证
  （`AgentIdentity.EnrollCredentialFile`）或 `anix-agent join` 的节点组接入令牌。
- 发行产物只有 Linux amd64 / arm64，构建 tag 为 `anixcore`。

## 目录

| 路径 | 内容 |
|---|---|
| `cmd/` | Cobra 命令：`server`、`join`、`upgrade`、`uninstall`、`identity`、`x25519` 等 |
| `api/agent/` | 控制流客户端：mTLS 身份与 PKI、数据面、spool 持久化 |
| `api/anxmgmt/` | anx-node 管理 API 客户端（生成代码） |
| `api/panel/` | 节点配置与用户的数据结构（`ParseNodeInfo`） |
| `conf/` | 配置文件结构与路径 |
| `core/` | 内核接口与选择器；`core/anixcore`、`core/wireguard` |
| `node/` | 节点控制器：配置快照、用户增量、流量上报、证书、网络模型 |
| `anxserver/`、`anxline/`、`anxmtls/` | anx-node 进程管理、ANX-Line 链路（MPTCP / fake-TCP）、链路证书 |
| `forward/` | 入口高可用的 vantage 探测、转发诊断与 forward.report（Control 在用） |
| `kernelfwd/` | 网络计划的内核转发跳：一张 nft 表（DNAT + masquerade + 计数器）与目标 TCP 探测 |
| `networkroute/`、`realityprobe/`、`diagnostic/` | 路由健康、Reality 目标探测、诊断任务 |
| `plugin/` | 插件 Supervisor 与机器监控插件 |
| `upgrade/` | 自升级与旧安装（V2bX、gost、nftables）清理 |
| `limiter/` | 用户 / 节点限速与设备数限制 |
| `scripts/` | `install.sh`、管理脚本 `anix-agent.sh`、发布检查脚本 |

## 运行时约定

- 服务名与管理命令：`anix-agent`；安装目录 `/usr/local/anixops-agent`；
  配置 `/etc/anixops/agent/config.json`；状态 `/var/lib/anixops-agent`。
- 旧的 `V2bX` / `v2bx-anixops` 名称和 `/etc/V2bX` 路径只为迁移老节点保留
  （`cmd/migrate_paths.go`、`upgrade/`、`scripts/install.sh`），5.0 GA 后再删除。
- 配置示例见 `example/config.json`（与 Control 安装脚本一致）。

## 构建、测试与发布

- 不在本机或节点上构建发行产物；发行由 GitHub Actions `release.yml` 生成
  （`scripts/check_release_build_policy.sh` 强制）。`build.sh` 默认拒绝运行，
  仅在显式设置 `ALLOW_LOCAL_BUILD=1` 时用于开发验证。
- 测试命令（CI 同款）：`GOEXPERIMENT=jsonv2 GOWORK=off go test ./... -count=1`。
- Go 版本见 `go.mod`；需要 `GOEXPERIMENT=jsonv2`。
- 版本号规则：5.0.0 起 Control 与 Agent 主版本号.次版本号相同（版本线），补丁号各自独立；
  兼容性由协议修订号决定（`node/agent_control.go` 的 `ProtocolRevision`、`KernelMinVersion`，
  规则见 Control 仓库 `docs/reference/agent-versioning.md`）。实现了 Control 新修订号的契约变更时
  提升 `ProtocolRevision`；开始依赖更新的 anx-node 时提升 `KernelMinVersion`。
- 变更说明写入 `CHANGELOG.md`。
