# anixcore 内核驱动

`core/anixcore` 让 Agent 用 AnixOps 自研节点内核 `anixcore`（来自
[networkcore_anixops](https://github.com/AnixOps/networkcore_anixops) 的
`apps/anixcore`）承载节点，走 anixcore 的本地管理 API（HTTP/JSON，Bearer 令牌）。

## 启用

驱动不在默认构建里，需要 `anixcore` build tag：

```bash
GOEXPERIMENT=jsonv2 go build -tags "xray sing hysteria2 anixcore" .
```

不加进默认 tag 的原因：`"Cores": []` 的节点会启动全部编译进来的内核，而
anixcore 是外部程序，节点上没有安装时不应影响其他内核。

## 配置

```json
{
  "Cores": [
    {
      "Type": "anixcore",
      "BinaryPath": "/usr/local/bin/anixcore",
      "RuntimeDir": "/etc/anixops/agent/anixcore",
      "AllowPrivateTargets": false,
      "StartTimeoutSeconds": 10,
      "RestartDelaySeconds": 3
    }
  ]
}
```

- 默认由 Agent 启动 `anixcore run -c <RuntimeDir>/anixcore.json`：管理 API 只监听
  `127.0.0.1` 的随机端口，令牌每次启动随机生成。进程意外退出后按
  `RestartDelaySeconds` 重启，并重新下发全部节点和用户。
- 同时设置 `ApiAddress` 和 `ApiToken` 时不启动进程，直接连接已在运行的 anixcore
  （例如由 systemd 管理）。

## 节点映射

| 面板节点 | anixcore 入站 |
| --- | --- |
| shadowsocks（2022 AES 方法） | `shadowsocks`，多用户；用户密钥为 UUID 前 16/32 字节的 base64，与 sing-box 内核相同。节点在拿到首批用户时才创建（anixcore 在创建时决定多用户模式）。 |
| trojan | `trojan`，tcp / ws / grpc，证书来自 `CertConfig` |
| vless | `vless`，tls 或 reality（reality 只支持 tcp，`xtls-rprx-vision` flow 随 reality 下发）|
| vmess | `vmess`，tcp / ws / grpc |
| hysteria2 | `hysteria2`，必须有证书，支持 salamander 混淆 |
| tuic | `tuic`，必须有证书，`congestion_control` 透传 |

不支持的会在 `AddNode` 时报错：chacha20 的 SS-2022（无多用户模式）、旧 SS 方法、
httpupgrade 等其他传输、AnyTLS、Hysteria v1、WireGuard。

用户名是面板用户 id，流量（`GetUserTrafficSlice`，支持 reset）和在线 IP
（`GetOnlineDevice`）按 id 回报。
