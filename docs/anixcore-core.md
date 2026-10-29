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
- `"AnxLine": true` 表示 `BinaryPath` 是 anx-node（anx 仓库的入口节点程序，配置与
  anixcore 同构）。内核随后列出 `anx_line` 传输，网络模型计划里本设备拨号（dial）的
  anx_line 传输会变成 anx-node 的 ANX-Line 链路：在下发计划之前用 ANX-Line 管理 API
  `AddLinks` 加入，链路 id 等于传输 id，路径经 `anx-line:<传输 id>` 出站。传输变化时
  删掉旧链路再加新的，计划里没有了就删除；anx-node 重启后先补回链路，再下发计划。
  由 Agent 启动时，生成的配置带 `anx_line.mgmt_listen`（`127.0.0.1` 随机端口）；连接
  自行运行的 anx-node（`ApiAddress`）时，必须用 `AnxLineApiAddress` 给出它的
  `anx_line.mgmt_listen`。接收（accept）端由 Agent 自己拉起 anx-server，见
  CHANGELOG。

- `"Cores": []` 的节点：Agent 升级装好的 `/usr/lib/anixops-agent/anx-node` 存在时，
  默认 anixcore 内核就用它（`BinaryPath` 指向它，`AnxLine` 打开）；否则用 PATH 上的
  `anixcore`；两者都没有时不启动 anixcore。anx-node 如何随升级下发见
  `docs/INSTALL.md`「Control-Pushed Upgrades」。

## 节点映射

| 面板节点 | anixcore 入站 |
| --- | --- |
| shadowsocks（2022 AES 方法） | `shadowsocks`，多用户；用户密钥为 UUID 前 16/32 字节的 base64，与 sing-box 内核相同。节点在拿到首批用户时才创建（anixcore 在创建时决定多用户模式）。 |
| trojan | `trojan`，tcp / ws / grpc，证书来自 `CertConfig` |
| vless | `vless`，tls 或 reality（reality 只支持 tcp，`xtls-rprx-vision` flow 随 reality 下发）|
| vmess | `vmess`，tcp / ws / grpc |
| hysteria2 | `hysteria2`，必须有证书，支持 salamander 混淆 |
| tuic | `tuic`，必须有证书，`congestion_control` 透传 |
| iwan（Panabit iWAN） | `iwan`，UDP 三层隧道，透传 `pool`（必填）、`mtu`、`dns_upstream`、`allow_encrypt`、`allow_client_to_client`。登录名是面板用户 id，口令是 UUID 去掉连字符后的前 16 位（小写），`fixed_addresses`（用户 id → 地址）给出的用户带固定地址。iWAN 不加密（networkcore_anixops `docs/protocols/iwan.md` §9）。 |

不支持的会在 `AddNode` 时报错：chacha20 的 SS-2022（无多用户模式）、旧 SS 方法、
httpupgrade 等其他传输、AnyTLS、Hysteria v1、WireGuard。

用户名是面板用户 id，流量（`GetUserTrafficSlice`，支持 reset）和在线 IP
（`GetOnlineDevice`）按 id 回报。
