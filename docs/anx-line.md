# ANX-Line 主机侧配置（`AnxLine`）

Agent 配置文件顶层的 `AnxLine` 段，由运维写在本机配置里（Control 的网络计划下发尚未实现）。
仅 Linux，需要 `CAP_NET_ADMIN` 与 `CAP_NET_RAW`，Agent 以 root 运行时都有。
anx-server 本身不改主机防火墙与路由，这些由 Agent 按本段配置完成。

```json5
"AnxLine": {
  "Enable": true,
  // 可选："NFT": "nft", "IP": "ip", "Table": "anixops_anx_line"
  "Links": [
    {
      "ID": "tx-ix",
      "FakeTCP": { "Role": "server", "Port": 4447, "Local": "192.0.2.10" }
    },
    {
      "ID": "ix-jp",
      "FakeTCP": { "Role": "client", "Port": 4447, "Peer": "198.51.100.7" },
      "Multipath": {
        "IntervalMs": 200,
        "TimeoutMs": 200,
        "FailAfter": 2,
        "RecoverAfter": 5,
        "Action": "delete",
        "Paths": [
          { "Endpoint": 1, "Addr": "10.0.1.2", "Dev": "eth1", "Flags": ["subflow"],
            "Probe": { "Kind": "tcp", "Target": "10.0.1.1:4443" } },
          { "Endpoint": 2, "Addr": "10.0.2.2", "Dev": "eth2", "Flags": ["subflow"],
            "Probe": { "Kind": "icmp", "Target": "10.0.2.1" } }
        ]
      }
    }
  ]
}
```

## FakeTCP

| 字段 | 说明 |
| --- | --- |
| `Role` | `server` 或 `client` |
| `Port` | 链路端口（服务端为 anx-server `--faketcp-listen` 的端口） |
| `Local` | 服务端：本机地址，可空（空时只按端口匹配） |
| `Peer` | 客户端：服务端地址，必填 |
| `Rules` | nft 规则模板，替换默认值；占位符 `{port}` `{local}` `{peer}` |

规则装进 Agent 独占的表 `table ip anixops_anx_line`，每次启动整表替换（一个 nft 事务）；
没有此类链路时删表。渲染后的规则只允许 nft 关键字、地址和运算符（不允许 `;`、花括号、引号、换行）。
Agent 停止时规则保留。

## Multipath

| 字段 | 说明 |
| --- | --- |
| `IntervalMs` / `TimeoutMs` | 探测间隔与单次超时（超时不得大于间隔） |
| `FailAfter` / `RecoverAfter` | 连续失败几次判为不可用、连续成功几次恢复 |
| `Action` | 路径不可用时的处理：`delete` 或 `backup`，恢复时还原 |
| `Paths[].Endpoint` | 端点 id（1–255，全机唯一）；启动时缺少的端点由 Agent 补上，已有的不动 |
| `Paths[].Probe` | `tcp`（连接 `host:port`）或 `icmp`；从路径自己的地址发出 |

所有路径都不可用时保留最后一条。Agent 停止时还原它摘掉的端点。
