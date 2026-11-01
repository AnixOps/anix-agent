# V2bX 多协议配置规范文档

本文档定义了 V2bX 与后端面板之间的协议配置规范，主要基于 Xray-core (XTLS) 官方配置标准。

## 📌 文档版本

- **版本**: 1.0.0
- **更新日期**: 2024-12-27
- **Xray-core 参考版本**: v24.9.30+

---

## 📋 目录

1. [通用配置结构](#通用配置结构)
2. [VLESS 协议](#vless-协议)
3. [VMess 协议](#vmess-协议)
4. [Trojan 协议](#trojan-协议)
5. [Shadowsocks 协议](#shadowsocks-协议)
6. [传输层配置](#传输层配置)
7. [安全层配置](#安全层配置)
8. [用户配置](#用户配置)
9. [字段映射对照表](#字段映射对照表)
10. [后端实现检查清单](#后端实现检查清单)

---

## 通用配置结构

### CommonNode (通用节点配置)

所有协议类型都包含以下基础字段：

```json
{
  "type": "vless",
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

| 字段 | 类型 | 必填 | 描述 |
|------|------|------|------|
| `type` | string | ✅ | 协议类型，支持: `vless`, `vmess`, `trojan`, `shadowsocks`, `tuic`, `anytls`, `hysteria`, `hysteria2`, `wireguard` |
| `host` | string | ✅ | 服务器主机名或IP |
| `server_port` | int | ✅ | 服务器端口 |
| `server_name` | string | ❌ | SNI 服务器名称 |
| `routes` | array | ❌ | 路由规则数组 |
| `base_config` | object | ❌ | 基础配置（推送/拉取间隔） |

---

## WireGuard 协议

WireGuard 是 P0 双机入口/出口方案的用户接入协议。当前 V2bX 支持从面板接收 WireGuard 节点配置和用户 peer 字段，在国内入口节点上通过系统 `ip`、`wg` 命令应用 WireGuard 接口与 peer，用 `wg show <iface> transfer` 解析 peer 流量增量，并用最近的 `wg show <iface> dump` 握手记录上报 peer 在线状态。V2bX 还提供首版 GOST TUN relay runtime 切片：入口节点启动 GOST TUN over `relay+quic`/`relay+wss` 并为 IPv4 WireGuard CIDR 安装源地址策略路由；出口节点启动匹配的 GOST TUN listener 并可为 IPv4 WireGuard CIDR 应用 iptables NAT。首版 relay 运行时明确拒绝 IPv6 peer CIDR、relay TUN CIDR 和 IPv6 AllowedIPs，避免未实现 `ip -6`/IPv6 NAT 时形成半可用配置。

目标路径保持为：

```text
WireGuard access -> domestic entry termination -> GOST relay+QUIC -> overseas exit NAT
```

### 节点配置响应格式

```json
{
  "type": "wireguard",
  "node_type": "wireguard",
  "host": "entry.example.com",
  "server_port": 51820,
  "server_name": "entry.example.com",
  "cidr": "10.66.0.0/24",
  "server_address": "10.66.0.1/24",
  "server_private_key": "server-private-key",
  "server_public_key": "server-public-key",
  "mtu": 1280,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "allowed_ips": ["0.0.0.0/0"],
  "tunnel_type": "quic",
  "relay": {
    "backend": "gost",
    "mode": "relay+quic",
    "role": "entry",
    "wss_compat": false,
	"wss_path": "/ws",
	"wss_secure": true,
	"wss_server_name": "exit.example.com",
	"wss_ca_file": "/etc/anixops/agent/certs/relay-ca.pem",
	"wss_cert_file": "",
	"wss_key_file": "",
    "exit_nat": true,
    "entry_stats": true,
    "server": "exit.example.com",
    "server_port": 8443,
    "tun_port": 8421,
    "entry_tun_address": "172.31.66.2/24",
    "exit_tun_address": "172.31.66.1/24",
    "outbound_iface": "eth0",
    "routing_table": 0,
    "routing_priority": 0
  }
}
```

`relay.role=entry` expects `relay.server`, `relay.server_port`, `relay.tun_port`, and `relay.entry_tun_address`. It starts:

```text
gost -L tun://:0/:<tun_port>?net=<entry_tun_address>&name=<tun_name>&mtu=<mtu> -F relay+quic://<server>:<server_port>
```

Then it enables IPv4 forwarding, installs source-based routing for the WireGuard `cidr` into a dedicated routing table, and adds WireGuard-to-TUN plus stateful TUN-to-WireGuard FORWARD rules. `tunnel_type=wss` or `relay.wss_compat=true` switches only the entry-to-exit tunnel to `relay+wss`; WSS is compatibility mode, not the default.

`relay.backend` defaults to `gost`. The panel always emits that normalized value; V2bX also treats a legacy payload that contains relay settings but omits `relay.backend` as GOST. An explicitly non-GOST backend is rejected before node startup rather than leaving an interface without its relay path.

For WSS, the entry must use `wss_secure=true` and set
`wss_server_name`; `wss_ca_file` is optional for a public CA and required when
the exit uses a private CA. V2bX encodes these values as GOST TLS dialer
parameters, so certificate verification is never silently disabled.

`relay.role=exit` expects `cidr`, `relay.server_port`, `relay.tun_port`, `relay.entry_tun_address`, and `relay.exit_tun_address`. It is a pure relay/NAT role: `server_address`, `server_private_key`, `server_public_key`, and `public_key` must be empty and are rejected if present. The panel returns an empty user list for this role. V2bX does not create a local WireGuard interface, install user peers, sample peer traffic, or report peer online state on the exit node. It starts:

```text
gost -L tun://:<tun_port>?net=<exit_tun_address>&name=<tun_name>&mtu=<mtu>&route=<wireguard_cidr>&gw=<entry_tun_ip> -L relay+quic://:<server_port>?bind=true
```

V2bX always applies a TUN-to-egress FORWARD allow rule and an `ESTABLISHED,RELATED` return rule back to the TUN, so the relay works with a default-DROP FORWARD policy. When `relay.exit_nat=true`, it additionally applies iptables MASQUERADE for the WireGuard CIDR; set it to `false` only when upstream routing already knows the WireGuard CIDR. `relay.outbound_iface` narrows both forwarding rules and the optional NAT rule to the public egress interface.

For WSS, the exit must set matching `wss_path`, `wss_cert_file`, and
`wss_key_file`. V2bX passes the certificate and private-key paths only to the
exit GOST listener; the entry receives only its CA path and expected server
name. Keep the two nodes' WSS paths identical.

### 用户列表扩展字段

WireGuard 节点的用户（控制流 `UserDelta` 的 `extra_json`）必须带上：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `wireguard_peer_ip` | string | ✅ | 面板自动分配的 peer 地址，例如 `10.66.0.2` |
| `wireguard_public_key` | string | ✅ | 用户 peer 公钥，用于入口节点 `[Peer] PublicKey` |
| `wireguard_preshared_key` | string | ✅ | 用户 peer PSK，用于入口节点 `[Peer] PresharedKey` |

用户私钥不下发给 V2bX，只用于订阅输出。

### 运行前提

- V2bX 配置中需要启用 `wireguard` core。
- 节点配置显式设置 `Core: "wireguard"` 时，V2bX 会自动把首次配置拉取限定为 `node_type=wireguard`；`NodeType` 仍可显式设置，且优先于该推断。
- 入口机需要安装 WireGuard 内核支持、`wireguard-tools`、`iproute2`、`iptables`、GOST。
- 出口机需要安装 GOST、`iproute2`、`iptables`，并允许内核转发。
- GitHub Actions 在有效 RC/tag 时会分别执行 `relay+quic` 与带临时 CA/SNI 验证的 `relay+wss` 特权网络命名空间验收：真实 WireGuard 客户端流量必须经过 V2bX entry、GOST、V2bX exit NAT 和 HTTP 目标；首个成功 artifact 与真实跨地域双机证据仍待记录。WSS 是兼容模式，不是默认模式。

### V2bX WireGuard Core 配置

```json
{
  "Type": "wireguard",
  "RuntimeDir": "/etc/anixops/agent/wireguard",
  "WGPath": "wg",
  "IPPath": "ip",
  "TCPath": "tc",
  "IPTablesPath": "iptables",
  "SysctlPath": "sysctl",
  "GostPath": "gost",
  "OnlineHandshakeTimeoutSeconds": 180,
  "GostRestartDelaySeconds": 3
}
```

`OnlineHandshakeTimeoutSeconds` 控制 peer 在线状态判定窗口。默认 180 秒；设为 `0` 或负数时禁用 WireGuard peer 在线上报。`GostRestartDelaySeconds` 控制 GOST 进程退出后的重启间隔，默认 3 秒。节点会回收旧的 TUN/路由/NAT 状态、上报 runtime health，并持续重试直到恢复或节点被删除。在线状态只表示入口节点最近收到该 peer 握手，不代表完整 `GOST relay+QUIC -> overseas exit NAT` 链路已经可用。

---

## VLESS 协议

### 后端 API 响应格式

```json
{
  "type": "vless",
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  
  "tls": 2,
  "tls_settings": {
    "server_name": "example.com",
    "dest": "example.com",
    "server_port": "443",
    "short_id": "abcd1234",
    "private_key": "your-x25519-private-key",
    "mldsa65Seed": ""
  },
  
  "network": "tcp",
  "network_settings": {},
  
  "encryption": "",
  "encryption_settings": {
    "mode": "",
    "ticket": "",
    "server_padding": "",
    "private_key": ""
  },
  
  "flow": "xtls-rprx-vision"
}
```

### 字段说明

#### 必填字段

| 字段 | 类型 | V2bX 字段名 | Xray 字段名 | 说明 |
|------|------|-------------|-------------|------|
| `type` | string | `type` | - | 必须是 `vless` |
| `server_port` | int | `server_port` | `port` | 监听端口 |

#### TLS 设置

| 字段 | 类型 | 说明 |
|------|------|------|
| `tls` | int | TLS 模式: `0`=None, `1`=TLS, `2`=Reality |

#### 当 `tls=1` (普通 TLS) 时

V2bX 会使用本地证书配置，后端不需要发送证书信息。

#### 当 `tls=2` (Reality) 时

`tls_settings` 字段必填：

| 字段 | 类型 | 必填 | Xray 对应字段 | 说明 |
|------|------|------|---------------|------|
| `server_name` | string | ✅ | `serverNames[]` | Reality 伪装的目标域名 |
| `dest` | string | ✅ | `dest` / `target` | 回落目标，格式: `domain:port` |
| `server_port` | string | ✅ | (组合到 dest) | 回落目标端口 |
| `short_id` | string | ✅ | `shortIds[]` | 客户端 shortId |
| `private_key` | string | ✅ | `privateKey` | X25519 私钥 (使用 `xray x25519` 生成) |
| `mldsa65Seed` | string | ❌ | `mldsa65Seed` | 后量子签名私钥 (可选) |
| `xver` | uint64 | ❌ | `xver` | Proxy Protocol 版本 |

#### VLESS 加密 (encryption)

| 字段 | 类型 | 说明 |
|------|------|------|
| `encryption` | string | 加密类型: `""` (空) 或 `"mlkem768x25519plus"` |

当 `encryption = "mlkem768x25519plus"` 时:

```json
{
  "encryption": "mlkem768x25519plus",
  "encryption_settings": {
    "mode": "native",
    "ticket": "0rtt",
    "server_padding": "100-111-1111.75-0-111.50-0-3333",
    "private_key": "ptjHQxBQxTJ9MWr2cd5qWIflBSACHOevTauCQwa_71U"
  }
}
```

生成的 decryption 字符串格式：
```
mlkem768x25519plus.native.0rtt.100-111-1111.75-0-111.50-0-3333.ptjHQxBQxTJ9MWr2cd5qWIflBSACHOevTauCQwa_71U
```

#### Flow (流控)

| 值 | 说明 |
|----|------|
| `""` (空) | 使用普通 TLS 代理 |
| `xtls-rprx-vision` | 使用 XTLS Vision 模式 (推荐) |

> ⚠️ **重要**: XTLS Vision 仅在 TCP + TLS/Reality 传输模式下可用

### Xray 入站配置生成示例

```json
{
  "inbounds": [{
    "tag": "vless-in",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [
        {
          "id": "user-uuid-here",
          "level": 0,
          "email": "user@example.com",
          "flow": "xtls-rprx-vision"
        }
      ],
      "decryption": "none",
      "fallbacks": []
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "example.com:443",
        "xver": 0,
        "serverNames": ["example.com"],
        "privateKey": "your-x25519-private-key",
        "shortIds": ["abcd1234"]
      }
    }
  }]
}
```

---

## VMess 协议

### 后端 API 响应格式

```json
{
  "type": "vmess",
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  
  "tls": 1,
  "tls_settings": {
    "server_name": "example.com"
  },
  
  "network": "ws",
  "network_settings": {
    "path": "/ws",
    "headers": {
      "Host": "example.com"
    }
  }
}
```

### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | string | ✅ | 必须是 `vmess` |
| `server_port` | int | ✅ | 监听端口 |
| `tls` | int | ❌ | TLS 模式: `0`=None, `1`=TLS |
| `network` | string | ❌ | 传输层协议: `tcp`, `ws`, `grpc`, `httpupgrade`, `xhttp` |
| `network_settings` | object | ❌ | 传输层具体配置 |

> ⚠️ **注意**: VMess 不支持 Reality (`tls=2`)

### Xray 入站配置生成示例

```json
{
  "inbounds": [{
    "tag": "vmess-in",
    "port": 443,
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "user-uuid-here",
          "level": 0,
          "email": "user@example.com"
        }
      ],
      "default": {
        "level": 0
      }
    },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "tlsSettings": {
        "certificates": [
          {
            "certificateFile": "/path/to/cert.pem",
            "keyFile": "/path/to/key.pem"
          }
        ]
      },
      "wsSettings": {
        "path": "/ws",
        "headers": {
          "Host": "example.com"
        }
      }
    }
  }]
}
```

---

## Trojan 协议

### 后端 API 响应格式

```json
{
  "type": "trojan",
  "host": "example.com",
  "server_port": 443,
  "server_name": "example.com",
  
  "network": "tcp",
  "networkSettings": {}
}
```

### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | string | ✅ | 必须是 `trojan` |
| `server_port` | int | ✅ | 监听端口 |
| `network` | string | ❌ | 传输层协议: `tcp`, `ws`, `grpc` |
| `networkSettings` | object | ❌ | 传输层具体配置 |

> ⚠️ **注意**: Trojan 协议被设计工作在加密的 TLS 隧道中，V2bX 强制 `Security = Tls`

### 用户认证

Trojan 使用密码认证，V2bX 使用用户的 `uuid` 作为密码。

### Xray 入站配置生成示例

```json
{
  "inbounds": [{
    "tag": "trojan-in",
    "port": 443,
    "protocol": "trojan",
    "settings": {
      "clients": [
        {
          "password": "user-uuid-here",
          "level": 0,
          "email": "user@example.com"
        }
      ],
      "fallbacks": []
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "certificates": [
          {
            "certificateFile": "/path/to/cert.pem",
            "keyFile": "/path/to/key.pem"
          }
        ]
      }
    }
  }]
}
```

---

## Shadowsocks 协议

### 后端 API 响应格式

```json
{
  "type": "shadowsocks",
  "host": "example.com",
  "server_port": 8388,
  
  "cipher": "2022-blake3-aes-256-gcm",
  "server_key": "base64-encoded-key-here"
}
```

### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | string | ✅ | 必须是 `shadowsocks` |
| `server_port` | int | ✅ | 监听端口 |
| `cipher` | string | ✅ | 加密方式 |
| `server_key` | string | ❌ | 服务器密钥 (SS2022 必填) |

### 支持的加密方式

#### Shadowsocks 2022 (推荐)

| 加密方式 | 密钥长度 |
|----------|----------|
| `2022-blake3-aes-128-gcm` | 16 字节 |
| `2022-blake3-aes-256-gcm` | 32 字节 |
| `2022-blake3-chacha20-poly1305` | 32 字节 |

使用 `openssl rand -base64 <长度>` 生成密钥。

#### 传统加密方式

| 加密方式 | 说明 |
|----------|------|
| `aes-256-gcm` | |
| `aes-128-gcm` | |
| `chacha20-poly1305` / `chacha20-ietf-poly1305` | |
| `xchacha20-poly1305` / `xchacha20-ietf-poly1305` | |
| `none` / `plain` | ⚠️ 不加密，仅测试用 |

### 用户密码

- **传统 SS**: 使用 `uuid` 作为密码
- **SS2022**: 使用 `uuid` 的前 N 个字符进行 base64 编码作为用户密钥

### Xray 入站配置生成示例

```json
{
  "inbounds": [{
    "tag": "shadowsocks-in",
    "port": 8388,
    "protocol": "shadowsocks",
    "settings": {
      "network": "tcp,udp",
      "method": "2022-blake3-aes-256-gcm",
      "password": "server-key-base64",
      "level": 0,
      "clients": [
        {
          "password": "user-key-base64",
          "email": "user@example.com"
        }
      ]
    }
  }]
}
```

---

## 传输层配置

### 传输协议类型

| network 值 | 说明 |
|------------|------|
| `tcp` / `raw` | 原始 TCP 传输 |
| `ws` | WebSocket |
| `grpc` | gRPC |
| `httpupgrade` | HTTP Upgrade |
| `xhttp` / `splithttp` | XHTTP (Beyond REALITY) |
| `kcp` / `mkcp` | mKCP (UDP) |

### TCP 配置

```json
{
  "network": "tcp",
  "network_settings": {
    "acceptProxyProtocol": false,
    "header": {
      "type": "none"
    }
  }
}
```

### WebSocket 配置

```json
{
  "network": "ws",
  "network_settings": {
    "path": "/ws",
    "headers": {
      "Host": "example.com"
    },
    "acceptProxyProtocol": false
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `path` | string | ✅ | WebSocket 路径 |
| `headers` | object | ❌ | HTTP 头部 |
| `acceptProxyProtocol` | bool | ❌ | 是否接受 Proxy Protocol |

### gRPC 配置

```json
{
  "network": "grpc",
  "network_settings": {
    "serviceName": "GunService"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `serviceName` | string | ✅ | gRPC 服务名称 |

### HTTPUpgrade 配置

```json
{
  "network": "httpupgrade",
  "network_settings": {
    "path": "/upgrade",
    "host": "example.com"
  }
}
```

### XHTTP 配置

```json
{
  "network": "xhttp",
  "network_settings": {
    "path": "/xhttp"
  }
}
```

---

## 安全层配置

### 安全模式

| tls 值 | 常量 | 说明 |
|--------|------|------|
| `0` | None | 不加密 |
| `1` | Tls | 普通 TLS |
| `2` | Reality | REALITY |

### TLS 配置

当 `tls=1` 时，V2bX 使用本地证书配置。后端只需要确保 `tls=1`。

V2bX 会根据 `conf/cert.go` 中的配置生成 TLS 设置：

```json
{
  "security": "tls",
  "tlsSettings": {
    "certificates": [
      {
        "certificateFile": "/path/to/cert.pem",
        "keyFile": "/path/to/key.pem",
        "ocspStapling": 3600
      }
    ],
    "rejectUnknownSNI": false
  }
}
```

### Reality 配置

当 `tls=2` 时，需要完整的 `tls_settings`：

```json
{
  "tls": 2,
  "tls_settings": {
    "server_name": "www.microsoft.com",
    "dest": "www.microsoft.com",
    "server_port": "443",
    "short_id": "abcd1234",
    "private_key": "generated-x25519-private-key",
    "mldsa65Seed": "",
    "xver": 0
  }
}
```

生成密钥:
```bash
# 生成 X25519 密钥对
xray x25519

# 输出:
# Private key: ...
# Public key: ...
```

生成的 Xray Reality 配置：

```json
{
  "security": "reality",
  "realitySettings": {
    "show": false,
    "dest": "www.microsoft.com:443",
    "xver": 0,
    "serverNames": ["www.microsoft.com"],
    "privateKey": "...",
    "minClientVer": "",
    "maxClientVer": "",
    "maxTimeDiff": 0,
    "shortIds": ["abcd1234"],
    "mldsa65Seed": ""
  }
}
```

---

## 用户配置

### 用户字段

用户由控制流的 `UserDelta`（`users.v1`）下发，每个 `NodeUser`：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `user_id` | uint64 | ✅ | 用户 ID |
| `uuid` | string | ✅ | 用户 UUID (用于认证) |
| `speed_limit_mbps` | uint32 | ❌ | 速度限制 (Mbps)，0 = 无限制 |
| `device_limit` | uint32 | ❌ | 设备限制，0 = 无限制 |
| `extra_json` | bytes | ❌ | 协议附加字段（如 WireGuard peer） |

### 协议用户映射

| 协议 | 认证字段 | 说明 |
|------|----------|------|
| VLESS | `id` | 使用 `uuid` |
| VMess | `id` | 使用 `uuid` |
| Trojan | `password` | 使用 `uuid` |
| Shadowsocks | `password` | 使用 `uuid` 或 base64 编码后的密钥 |

---

## 字段映射对照表

### 后端 API → V2bX → Xray 映射

#### VLESS/VMess

| 后端 API 字段 | V2bX 结构体字段 | Xray 配置字段 |
|---------------|-----------------|---------------|
| `type` | `NodeInfo.Type` | `protocol` |
| `server_port` | `CommonNode.ServerPort` | `port` |
| `tls` | `VAllssNode.Tls` | `streamSettings.security` |
| `tls_settings.server_name` | `TlsSettings.ServerName` | `realitySettings.serverNames[]` |
| `tls_settings.dest` | `TlsSettings.Dest` | `realitySettings.dest` |
| `tls_settings.server_port` | `TlsSettings.ServerPort` | (组合到 dest) |
| `tls_settings.short_id` | `TlsSettings.ShortId` | `realitySettings.shortIds[]` |
| `tls_settings.private_key` | `TlsSettings.PrivateKey` | `realitySettings.privateKey` |
| `tls_settings.mldsa65Seed` | `TlsSettings.Mldsa65Seed` | `realitySettings.mldsa65Seed` |
| `tls_settings.xver` | `TlsSettings.Xver` | `realitySettings.xver` |
| `network` | `VAllssNode.Network` | `streamSettings.network` |
| `network_settings` | `VAllssNode.NetworkSettings` | `streamSettings.{network}Settings` |
| `flow` | `VAllssNode.Flow` | `clients[].flow` |
| `encryption` | `VAllssNode.Encryption` | `settings.decryption` |

#### Trojan

| 后端 API 字段 | V2bX 结构体字段 | Xray 配置字段 |
|---------------|-----------------|---------------|
| `type` | `NodeInfo.Type` | `protocol` |
| `server_port` | `CommonNode.ServerPort` | `port` |
| `network` | `TrojanNode.Network` | `streamSettings.network` |
| `networkSettings` | `TrojanNode.NetworkSettings` | `streamSettings.{network}Settings` |

#### Shadowsocks

| 后端 API 字段 | V2bX 结构体字段 | Xray 配置字段 |
|---------------|-----------------|---------------|
| `type` | `NodeInfo.Type` | `protocol` |
| `server_port` | `CommonNode.ServerPort` | `port` |
| `cipher` | `ShadowsocksNode.Cipher` | `settings.method` |
| `server_key` | `ShadowsocksNode.ServerKey` | `settings.password` |

---

## 后端实现检查清单

### VLESS 协议

- [ ] `type` 字段返回 `"vless"`
- [ ] `server_port` 必须是有效端口号
- [ ] `tls` 必须是 `0`, `1`, 或 `2`
- [ ] 当 `tls=2` 时:
  - [ ] `tls_settings.server_name` 非空
  - [ ] `tls_settings.dest` 非空
  - [ ] `tls_settings.server_port` 非空
  - [ ] `tls_settings.short_id` 非空
  - [ ] `tls_settings.private_key` 是有效的 X25519 私钥
- [ ] `flow` 返回 `""` 或 `"xtls-rprx-vision"`
- [ ] `network` 是有效的传输协议
- [ ] `network_settings` 包含对应传输协议的配置

### VMess 协议

- [ ] `type` 字段返回 `"vmess"`
- [ ] `server_port` 必须是有效端口号
- [ ] `tls` 只能是 `0` 或 `1`
- [ ] `network` 是有效的传输协议
- [ ] `network_settings` 包含对应传输协议的配置

### Trojan 协议

- [ ] `type` 字段返回 `"trojan"`
- [ ] `server_port` 必须是有效端口号
- [ ] `network` 是有效的传输协议 (默认 `tcp`)
- [ ] `networkSettings` 包含对应传输协议的配置

### Shadowsocks 协议

- [ ] `type` 字段返回 `"shadowsocks"`
- [ ] `server_port` 必须是有效端口号
- [ ] `cipher` 是支持的加密方式
- [ ] 如果是 SS2022 加密:
  - [ ] `server_key` 非空
  - [ ] `server_key` 是正确长度的 base64 编码密钥

### 用户

- [ ] 每个用户包含 `user_id` 和 `uuid`
- [ ] `uuid` 是有效的 UUID 格式

---

## 示例：完整的 VLESS Reality 配置

### 后端 API 响应

```json
{
  "type": "vless",
  "host": "my-server.example.com",
  "server_port": 443,
  "server_name": "www.microsoft.com",
  
  "tls": 2,
  "tls_settings": {
    "server_name": "www.microsoft.com",
    "dest": "www.microsoft.com",
    "server_port": "443",
    "short_id": "6ba85179e30d4fc2",
    "private_key": "your-x25519-private-key-here",
    "mldsa65Seed": "",
    "xver": 0
  },
  
  "network": "tcp",
  "network_settings": {},
  
  "encryption": "",
  "encryption_settings": {},
  
  "flow": "xtls-rprx-vision",
  
  "routes": [],
  "base_config": {
    "push_interval": 60,
    "pull_interval": 60
  }
}
```

### V2bX 生成的 Xray 配置

```json
{
  "inbounds": [{
    "tag": "node-1",
    "port": 443,
    "listen": "0.0.0.0",
    "protocol": "vless",
    "settings": {
      "clients": [],
      "decryption": "none",
      "fallbacks": []
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "www.microsoft.com:443",
        "xver": 0,
        "serverNames": ["www.microsoft.com"],
        "privateKey": "your-x25519-private-key-here",
        "minClientVer": "",
        "maxClientVer": "",
        "maxTimeDiff": 0,
        "shortIds": ["6ba85179e30d4fc2"],
        "mldsa65Seed": ""
      },
      "tcpSettings": {
        "acceptProxyProtocol": false
      }
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls"]
    }
  }]
}
```

---

## 常见问题

### Q1: 为什么我的 VLESS Reality 节点无法工作？

检查以下项:
1. `tls_settings.private_key` 是否使用 `xray x25519` 生成
2. `tls_settings.short_id` 长度是否为偶数个十六进制字符
3. `tls_settings.server_name` 是否与客户端匹配
4. `flow` 是否设置为 `xtls-rprx-vision`

### Q2: Shadowsocks 2022 密钥长度要求？

| 加密方式 | 密钥长度 (字节) | Base64 长度 |
|----------|-----------------|-------------|
| 2022-blake3-aes-128-gcm | 16 | 24 |
| 2022-blake3-aes-256-gcm | 32 | 44 |
| 2022-blake3-chacha20-poly1305 | 32 | 44 |

### Q3: 如何生成各种密钥？

```bash
# X25519 密钥 (Reality 用)
xray x25519

# ML-DSA-65 密钥 (后量子签名用)
xray mldsa65

# Shadowsocks 2022 密钥
openssl rand -base64 32
```

---

## 参考链接

- [Xray 官方文档](https://xtls.github.io/config/)
- [VLESS 协议规范](https://xtls.github.io/config/inbounds/vless.html)
- [VMess 协议规范](https://xtls.github.io/config/inbounds/vmess.html)
- [Trojan 协议规范](https://xtls.github.io/config/inbounds/trojan.html)
- [Shadowsocks 协议规范](https://xtls.github.io/config/inbounds/shadowsocks.html)
- [传输方式配置](https://xtls.github.io/config/transport.html)
- [REALITY 项目](https://github.com/XTLS/REALITY)
