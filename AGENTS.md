# V2bX AnixOps - 节点端程序文档

## 项目概述

V2bX AnixOps 是一个代理服务节点后端程序，运行 AnixOps 自研内核 anixcore（anx-node）与 WireGuard 内核，只通过 mTLS 的 `anix.agent.v1` 控制流与 AnixOps Control 交互，提供用户认证、流量统计、节点管理等功能。

**项目路径**: `C:\Users\z7299\Documents\GitHub\V2bX_AnixOps`

**配套 Control**: `AnixOps/anix-control`

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                      整体架构                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   用户客户端 (Clash/V2Ray/Sing-box 等)                          │
│         ↓                                                       │
│   ┌─────────────────────────────────────────┐                  │
│   │         V2bX_AnixOps (本项目)            │                  │
│   │  ┌─────────────────────────────────┐    │                  │
│   │  │  多内核支持:                      │    │                  │
│   │  └─────────────────────────────────┘    │                  │
│   │              ↓                           │                  │
│   │  ┌─────────────────────────────────┐    │                  │
│   │  │  节点控制器 (node/)               │    │                  │
│   │  │  - 配置同步                       │    │                  │
│   │  │  - 用户管理                       │    │                  │
│   │  │  - 流量统计                       │    │                  │
│   │  │  - 证书管理                       │    │                  │
│   │  └─────────────────────────────────┘    │                  │
│   └─────────────────────────────────────────┘                  │
│         ↓ anix.agent.v1 控制流（mTLS）                          │
│   ┌─────────────────────────────────────────┐                  │
│   │      anix-control (Control)              │                  │
│   │      - 用户管理                          │                  │
│   │      - 套餐/订阅管理                     │                  │
│   │      - 节点配置下发                      │                  │
│   └─────────────────────────────────────────┘                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 技术栈

| 类别 | 技术 | 版本/说明 |
|------|------|----------|
| 语言 | Go | 1.26.10 (需 GOEXPERIMENT=jsonv2) |
| CLI 框架 | Cobra | 命令行解析 |
| 配置管理 | Viper | 配置文件解析 |
| HTTP 客户端 | Resty | API 请求 |
| 日志 | Logrus | 结构化日志 |

## 目录结构

```
V2bX_AnixOps/
├── main.go                     # 程序入口
├── cmd/                        # 命令行接口
│   ├── cmd.go                  # Cobra 命令定义
│   ├── server.go               # server 命令实现
│   ├── common.go               # 通用函数
│   └── version.go              # 版本信息
├── api/                        # API 层
│   ├── agent/                  # anix.agent.v1 控制流客户端（mTLS 身份、数据面、spool）
│   ├── anxmgmt/                # anx-node 管理 API 客户端（生成代码）
│   └── panel/                  # 节点配置与用户的数据结构
│       ├── node.go             # 节点配置解析（ParseNodeInfo）
│       ├── user.go             # 用户、流量、在线 IP 结构
│       └── version.go          # Agent 版本号
├── conf/                       # 配置文件结构
│   ├── conf.go                 # 主配置结构
│   ├── core.go                 # 内核配置
│   ├── node.go                 # 节点配置
│   ├── limit.go                # 限流配置
│   ├── cert.go                 # 证书配置
│   └── watch.go                # 文件监控配置
├── core/                       # 核心实现层
│   ├── core.go                 # 核心管理器
│   ├── interface.go            # Core 接口定义
│   ├── selector.go             # 多内核选择器
├── node/                       # 节点控制器
│   ├── node.go                 # 节点管理器
│   ├── controller.go           # 节点控制器
│   ├── task.go                 # 定时任务
│   ├── user.go                 # 用户管理与流量上报
│   ├── dataplane.go            # 控制流数据面（配置快照、用户增量）
│   ├── agent_control.go        # 控制流客户端与操作
│   └── cert.go                 # 证书管理
├── limiter/                    # 限流器
│   ├── limiter.go              # 限流器主体
│   ├── dynamic.go              # 动态限速
│   └── rule.go                 # 规则限流
├── common/                     # 通用工具
│   ├── counter/                # 流量统计
│   ├── crypt/                  # 加密工具
│   ├── exec/                   # 命令执行
│   ├── file/                   # 文件操作
│   ├── rate/                   # 速率限制
│   └── task/                   # 任务调度
├── docs/                       # 文档
│   └── PROTOCOL_CONFIG_SPECIFICATION.md  # 协议配置规范
├── example/                    # 配置文件示例
│   ├── config.json             # 基础配置（与 Control 安装脚本一致）
│   ├── config.production.json  # 生产模板
│   └── config.wireguard.json   # WireGuard 内核
├── build.sh                    # Linux/macOS 构建脚本
├── build.ps1                   # Windows 构建脚本
└── Dockerfile                  # Docker 镜像构建
```

## 核心架构

### Core 接口 (`core/interface.go`)
```go
type Core interface {
    Start() error
    Close() error
    AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error
    DelNode(tag string) error
    AddUsers(p *AddUsersParams) (added int, err error)
    GetUserTrafficSlice(tag string, reset bool) ([]UserTraffic, error)
    DelUsers(users []UserInfo, tag string, info *panel.NodeInfo) error
    Protocols() []string
    Type() string
}
```

### 支持的内核和协议

| 内核 | 支持协议 |
|------|----------|

## 配置文件结构

### 主配置示例 (`example/config.json`)
```json
{
  "Log": {
    "Level": "info",
    "Output": ""
  },
  "Cores": [],
  "Nodes": [
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
      "AgentStream": { "StateDir": "/var/lib/anixops-agent/stream" },
      "LimitConfig": { "SpeedLimit": 0, "DeviceLimit": 0 }
    }
  ]
}
```

### 配置结构体对应

| 配置节 | 结构体 | 文件 |
|--------|--------|------|
| Log | LogConfig | conf/log.go |
| Cores | []CoreConfig | conf/core.go |
| Nodes | []NodeConfig | conf/node.go |
| LimitConfig | LimitConfig | conf/limit.go |
| CertConfig | CertConfig | conf/cert.go |

## 与 Control 的交互

节点只通过 `anix.agent.v1` 双向 gRPC 控制流与 Control 通信，客户端证书（mTLS）是唯一凭证：

| 能力 | 方向 | 内容 |
|------|------|------|
| `config.v1` | Control → Agent | 节点配置快照（`runtime.default/types/protocols`） |
| `users.v1` | Control → Agent | 用户增量（`UserDelta`） |
| `alive.v1` | Control → Agent | 全网在线设备数 |
| `reports.v1` | Agent → Control | 流量、在线 IP、日志、节点状态（经 spool） |
| `maintenance.v1` | Agent → Control | 插件维护事件 |
| `artifacts.v1` | Control → Agent | 插件包下载 |

首次注册使用 Control 签发的一次性注册凭证（`AgentIdentity.EnrollCredentialFile`）或 `anix-agent join` 的节点组接入令牌。

## 节点控制器定时任务

| 任务 | 间隔 | 功能 |
|------|------|------|
| UserReport | PushInterval | 上报用户流量 |
| RenewCert | 每天 | 证书续签检查 |
| DynamicSpeedLimit | 配置间隔 | 动态限速检查 |
| OnlineIpReport | 配置间隔 | 在线 IP 上报 |

## 限流器功能

- 用户级速度限制
- 节点级速度限制
- 设备数限制（在线 IP 数）
- 连接数限制
- 动态限速（基于流量使用）
- 规则限流（域名/协议阻止）

## 构建与部署

### 构建与发行

发行构建必须由 GitHub Actions release workflow 生成。生产安装或升级时使用
GitHub Release 附件，不要在节点机或本地 checkout 里执行 `go build` 生成发行产物。

本地构建脚本只保留给开发验证或紧急人工操作，默认拒绝运行实际构建；如确需使用，
必须显式 opt-in：

```bash
# Linux/macOS
ALLOW_LOCAL_BUILD=1 ./build.sh -p linux -a amd64

# 清理本地构建残留不需要 opt-in
./build.sh --clean
```

### Docker 部署
```bash
docker run -d \
  -v /etc/V2bX:/etc/V2bX \
  -v /etc/V2bX/certs:/etc/V2bX/certs \
  --network host \
  --restart always \
  wyx2685/v2bx:latest
```

### 运行
```bash
V2bX server -c /etc/V2bX/config.json
```

## 运维命令约定

- 节点程序默认配置文件路径保持为 `/etc/V2bX/config.json`（默认读取 `config.json`）
- AnixOps 管理脚本命令统一使用 `v2bx-anixops`
- 使用 `v2bx-anixops` 以避免与上游原版 `V2bX` 命令冲突
- 可通过 `v2bx-anixops initconfig` 或菜单入口执行初始化配置向导，生成 `/etc/V2bX/config.json`

## 关键文件

| 文件 | 说明 |
|------|------|
| `main.go` | 程序入口 |
| `cmd/server.go` | server 命令，核心启动逻辑 |
| `conf/conf.go` | 主配置结构定义 |
| `conf/node.go` | 节点配置，API 配置和选项 |
| `core/interface.go` | Core 接口定义 |
| `node/controller.go` | 节点控制器，管理节点生命周期 |
| `node/dataplane.go` | 控制流数据面：配置快照与用户 |
| `node/agent_control.go` | 控制流客户端与操作 |
| `api/panel/node.go` | 节点配置解析 |
| `limiter/limiter.go` | 限流器实现 |

## 项目特点

1. **多内核支持**: 通过接口抽象支持 anixcore 与 WireGuard
2. **热重载**: 配置文件变更自动重启
3. **mTLS 接入**: 一次性注册凭证或节点组接入令牌，客户端证书自动续期
4. **离线可用**: 配置、用户与上报在本地持久化，Control 不可达时继续运行
5. **灵活限流**: 支持节点级、用户级、动态限速
6. **证书管理**: 集成 ACME，支持多种 DNS Provider
7. **跨平台**: 支持 Linux、Windows、macOS
