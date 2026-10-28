# ANX 对外边界

驱动 anx-node / anx-server 需要知道的全部内容。没有列在这里的东西（协议细节、线上格式、整形参数、实验结果）都不对外。

## 1. anx-node 配置

anx-node 的配置文件与公开内核 anixcore 同构（`inbounds`、`management`、`allow_private_targets` 等字段见公开仓库 node-runtime），只多一种入站 `"type": "anx"`。除 `tag` / `type` / `listen` / `listen_port` 外，该入站接受以下字段，未知字段报错：

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `key_file` | string | 必填 | `anx-server keygen` 生成的密钥文件路径 |
| `server_names` | string[] | 必填 | 允许的 SNI |
| `dest` | string | 无 | 伪装目标 `host:port` |
| `alpn` | string[] | `["h2","http/1.1"]` | |
| `max_streams` | u16 | 256 | 每连接最大子流数 |
| `require_device` | bool | false | 要求已签发设备 |
| `enroll_allowed` | bool | true | 允许设备在连接内申领 |
| `device_limit` | u32 | 0 | 每用户设备数上限，0 = 不限 |
| `shape_plain` | bool | false | 只用于互通调试 |
| `state_file` | string | 无 | 设备 / CA 状态落盘路径（含密钥，0600） |
| `mgmt_listen` | `ip:port` | 无 | 本入站的 gRPC 管理面地址；不填不开放 |
| `users` | `{name, password}`[] | `[]` | `password` 为 64 位 hex 用户密钥 |

anx-node 形态下，用户 / 流量 / 在线（`AddUsers`、`RemoveUsers`、`GetTraffic`、`GetOnline`）走 node-runtime 管理接口，ANX-Line 链路 RPC 只在 anx-server 形态可用；这些在 anx-node 的 gRPC 上返回 `UNIMPLEMENTED`。

## 2. 命令行

```text
anx-node run   -c|--config <config.json>
anx-node check -c|--config <config.json>
anx-node version

anx-server keygen [--x25519-only] <key-file>
anx-server userkey
anx-server run --key <file> --sni <name>[,<name>…] [--listen <addr>] [--mgmt <addr>]
               [--bare-listen <addr>] [--quic-listen <addr>] [--quic-sockbuf <bytes>] [--quic-dgram-buf <bytes>]
               [--faketcp-listen <ipv4:port>] [--mptcp]
               [--dest <host:port>] [--users <file>] [--user <hex>[:<name>]]…
               [--alpn h2,http/1.1] [--max-streams N] [--require-device] [--no-enroll] [--shape-plain]
               [--state <file>]
```

`--key` 与 `--sni` 必填，`--listen` 默认 `0.0.0.0:443`，不给 `--mgmt` 就不开管理接口。`--quic-sockbuf` 是 `--quic-listen` 那个 UDP socket 的收发缓冲字节数（受主机 `net.core.rmem_max` / `wmem_max` 截断，启动时 stderr 打出实际值），`--quic-dgram-buf` 是每连接的 UDP 数据报接收缓冲字节数；都是 0 / 不给 = 默认。退出码：0 成功；1 运行失败；`anx-server` 未知子命令为 2。

## 3. 指标

`Stats`：`handshake_failures`、`fallbacks`、`replay_rejects`、`probe_signatures`，按地区的 `regions[].{region, attempts, successes}`，以及 UDP 中继计数 `udp.{from_client, forwarded, forward_errors, from_upstream, to_client, to_client_errors}`。

`LinkStats` 每条链路：`link_id`、`default_route`、`connected`、`carrier`、`switches`、`probes[].{carrier, ok, handshake_ms}`、`rtt_ms`、`sent_packets`、`lost_packets`、`draining`、`egress`、`mptcp`、`fec_repairs_sent`、`fec_recovered`、`rebinds`、`routed_users`、`udp_lane_connected`、`udp_lane_carrier`。`Link` 可带 `udp_lanes`（0 | 1）。

`Stats` 与 `GetTraffic` 的计数器单调递增，请求带 `reset = true` 时读后清零。

## 4. 错误码（gRPC status）

| 码 | 何时 |
| --- | --- |
| `INVALID_ARGUMENT` | 字段格式或取值不合法（密钥长度、地址、`egress` 与承载地址组合等） |
| `NOT_FOUND` | 未知用户 / 设备 / 链路；`SetLinkRoutes` 引用未添加的 `link_id`（整批拒绝） |
| `PERMISSION_DENIED` | 设备申领被拒 |
| `RESOURCE_EXHAUSTED` | 达到设备数上限 |
| `UNIMPLEMENTED` | 当前形态不提供该 RPC（见第 1 节） |

## 5. 能力名单

只列名字，取值的含义与线上形态不对外。

- 外衣：`reality`、`h2`、`bare`
- 承载：`c1`/`tcp`、`c2`/`quic`、`c3`/`faketcp`
- 出口类别：`l1`、`l2`
- 实验开关：`multipath`、`fec`、`quic_ack_frequency`
- 运维开关：`no_rebind`、`port_hop_ms`
