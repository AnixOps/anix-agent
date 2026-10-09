# V2bX AnixOps - 节点端程序文档

## 项目概述

V2bX AnixOps 是一个代理服务节点后端程序，支持多内核（Xray、Sing-box、Hysteria2），与 V2Board 面板通过 API 进行交互，提供用户认证、流量统计、节点管理等功能。

**项目路径**: `C:\Users\z7299\Documents\GitHub\V2bX_AnixOps`

**配套面板**: `C:\Users\z7299\Documents\GitHub\v2board_AnixOps`

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
│   │  │  - Xray-core (VMess/VLESS/Trojan)│    │                  │
│   │  │  - Sing-box (多协议)              │    │                  │
│   │  │  - Hysteria2 (QUIC 高速传输)      │    │                  │
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
│         ↓ API 通信                                              │
│   ┌─────────────────────────────────────────┐                  │
│   │      v2board_AnixOps (面板端)            │                  │
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
| 语言 | Go | 1.26.9 (需 GOEXPERIMENT=jsonv2) |
| 代理内核 | Xray | v1.251202.0 |
| 代理内核 | Sing-box | v1.13.0 |
| 代理内核 | Hysteria2 | v2.6.4 |
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
├── api/                        # API 客户端层
│   └── panel/
│       ├── panel.go            # API 客户端初始化
│       ├── node.go             # 节点配置获取
│       ├── user.go             # 用户数据获取/上报
│       ├── sync.go             # WebSocket 同步消息定义
│       ├── register.go         # 节点自动注册
│       ├── credential.go       # 凭证存储 (明文)
│       ├── credential_encrypted.go  # 凭证存储 (加密)
│       └── debug.go            # API 调试转储
├── conf/                       # 配置文件结构
│   ├── conf.go                 # 主配置结构
│   ├── core.go                 # 内核配置
│   ├── node.go                 # 节点配置
│   ├── xray.go                 # Xray 配置
│   ├── sing.go                 # Sing-box 配置
│   ├── hy.go                   # Hysteria 配置
│   ├── limit.go                # 限流配置
│   ├── cert.go                 # 证书配置
│   └── watch.go                # 文件监控配置
├── core/                       # 核心实现层
│   ├── core.go                 # 核心管理器
│   ├── interface.go            # Core 接口定义
│   ├── selector.go             # 多内核选择器
│   ├── xray/                   # Xray 内核实现
│   ├── sing/                   # Sing-box 内核实现
│   └── hy2/                    # Hysteria2 内核实现
├── node/                       # 节点控制器
│   ├── node.go                 # 节点管理器
│   ├── controller.go           # 节点控制器
│   ├── task.go                 # 定时任务
│   ├── user.go                 # 用户管理
│   ├── sync.go                 # 数据同步
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
│   ├── sign/                   # 请求签名
│   └── task/                   # 任务调度
├── docs/                       # 文档
│   ├── API_DOCUMENTATION.md    # 前端 API 接口文档
│   ├── BACKEND_API_ISSUES.md   # 后端 API 问题分析
│   └── PROTOCOL_CONFIG_*.md    # 协议配置规范
├── example/                    # 配置文件示例
│   ├── config.json             # 基础配置
│   ├── custom_inbound.json     # 自定义入站
│   └── custom_outbound.json    # 自定义出站
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
| Xray | VMess, VLESS, Trojan, Shadowsocks |
| Sing-box | VMess, VLESS, Trojan, TUIC, AnyTLS, Hysteria, Hysteria2 |
| Hysteria2 | Hysteria2 |

## 配置文件结构

### 主配置示例 (`example/config.json`)
```json
{
  "Log": {
    "Level": "info",
    "Output": ""
  },
  "Cores": [
    {
      "Type": "sing",
      "Log": { "Level": "info", "Timestamp": true },
      "NTP": { "Enable": false, "Server": "time.apple.com" },
      "OriginalPath": "/etc/V2bX/sing_origin.json"
    }
  ],
  "Nodes": [
    {
      "Core": "sing",
      "ApiHost": "http://127.0.0.1",
      "ApiKey": "your-api-key",
      "NodeID": 1,
      "Timeout": 30,
      "ListenIP": "0.0.0.0",
      "CertConfig": { "CertMode": "self" },
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

## API 接口设计

### 与面板交互的 API

| 接口 | 方法 | 功能 |
|------|------|------|
| `/api/v2/server/UniProxy/config` | GET | 获取节点配置 |
| `/api/v2/server/UniProxy/user` | GET | 获取用户列表 |
| `/api/v2/server/UniProxy/alivelist` | GET | 获取在线 IP 数 |
| `/api/v2/server/UniProxy/push` | POST | 上报用户流量 |
| `/api/v2/server/UniProxy/alive` | POST | 上报在线用户 IP |
| `/api/v2/node/register` | POST | 节点自动注册 |
| `/api/v2/node/heartbeat` | POST | 心跳上报 |

### 请求参数
UniProxy API 请求携带 Query 参数：
- `node_id` - 节点 ID（必填）
- `node_type` - 节点类型（可选，建议携带）

并在 Header 携带：
- `X-API-Key` - API Key 鉴权令牌（必填）

### 流量上报格式
```json
POST /api/v2/server/UniProxy/push
{
  "1": [1024000, 2048000],  // [上传字节, 下载字节]
  "2": [512000, 1024000]
}
```

### 在线用户上报格式
```json
POST /api/v2/server/UniProxy/alive
{
  "1": ["192.168.1.100", "10.0.0.50"],
  "2": ["172.16.0.1"]
}
```

## 节点控制器定时任务

| 任务 | 间隔 | 功能 |
|------|------|------|
| NodeInfoMonitor | PullInterval | 监控节点配置变更 |
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

## 自动注册机制

### 配置项
```json
{
  "AutoRegister": true,
  "AuthKey": "your-auth-key",
  "NodeName": "Tokyo-Node-01",
  "NodeHost": "",
  "NodePort": 443,
  "CredentialFile": "data/credential.json",
  "HeartbeatInterval": 60,
  "EnableSign": true,
  "EncryptCredential": true
}
```

### 注册流程
1. 检查本地凭证文件
2. 无凭证时使用 AuthKey 调用注册 API
3. 获取并保存 node_id, api_key, secret
4. 后续请求使用签名认证

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
| `api/panel/panel.go` | API 客户端初始化 |
| `api/panel/node.go` | 节点配置获取和解析 |
| `api/panel/user.go` | 用户数据获取和流量上报 |
| `limiter/limiter.go` | 限流器实现 |
| `docs/API_DOCUMENTATION.md` | 前端 API 文档 (733 行) |

## 项目特点

1. **多内核支持**: 通过接口抽象支持 Xray、Sing-box、Hysteria2
2. **热重载**: 配置文件变更自动重启
3. **自动注册**: 支持通过 AuthKey 自动注册节点
4. **安全增强**: 支持请求签名、凭证加密存储
5. **灵活限流**: 支持节点级、用户级、动态限速
6. **证书管理**: 集成 ACME，支持多种 DNS Provider
7. **跨平台**: 支持 Linux、Windows、macOS

## 前端项目

配套前端项目：`v2board_AnixOps`

## gRPC 正式接入说明（2026-04）

### 传输模式

节点 `ApiConfig` 新增 `Transport` 字段：

- `http`（默认）: 走原有 REST API + WebSocket Sync
- `grpc`: 走 gRPC 接口

新增字段：

- `GRPCHost`: gRPC 目标地址（`host:port`）
- `GRPCUseTLS`: 是否启用 TLS
- `GRPCServerName`: TLS SNI / 证书校验域名
- `GRPCKeepalive`: gRPC keepalive 秒数

### 运行行为

- gRPC 模式下，节点信息与用户/流量/在线上报通过 gRPC 处理。
- SyncManager（WebSocket）当前只在 REST 传输下启用；gRPC 传输使用定时轮询与上报任务。
- gRPC 自动注册复用现有凭证机制，支持明文或加密凭证存储。

### 协议与生成

- Proto 文件已纳入仓库：`api/grpc/v2board.proto`
- 生成脚本：
  - Linux/macOS: `api/grpc/gen.sh`
  - Windows: `api/grpc/gen.ps1`
- 生成输出目录：`api/grpc/v2boardpb/`

### 运维约定与常见检查项

本仓库 gRPC 接入后，建议在日常运维/排障时按以下顺序检查：

验证编译（避免环境 `go.work` 干扰）：

```bash
GOEXPERIMENT=jsonv2 GOWORK=off go test -run TestNonExistent ./...
```

Proto 生成一致性检查（开发机/CI 都适用）：

```bash
bash api/grpc/gen.sh
git diff -- api/grpc/v2boardpb
```

gRPC 配置检查要点：

- `Transport` 必须为 `grpc`
- `GRPCHost` 推荐显式填写 `host:port`，避免依赖 `ApiHost` 推断
- TLS 场景下：`GRPCUseTLS=true`，`GRPCServerName` 填真实域名（证书校验用）
- keepalive：`GRPCKeepalive` 为秒，默认 `30`

说明：

- WebSocket SyncManager 当前只在 REST(`http`) 传输下启用；`grpc` 传输使用定时轮询与上报任务。
