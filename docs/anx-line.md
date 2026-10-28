# ANX-Line 主机侧：假 TCP 防 RST 与 MPTCP 逐路切换

对应 anx 仓库 `docs/ANX-LINE-SPEC-v0.1-draft.md` §4.2、§5 `multipath` 与 §9 的两项决策（2026-10-28 用户拍板）：

- **TBD-L11 = A**：假 TCP（C3）两端由 Agent 装 nftables 规则，丢掉内核对假 TCP 端口回的 `RST`，
  否则 NAT / 状态防火墙看到 `RST` 会拆表。规则是数据（模板），不是写死的。
- **TBD-L14 = A**：多路径链路（C1 + MPTCP）由 Agent 每 200 ms 逐路探活，判死后
  `ip mptcp endpoint delete`（对 `signal` 端点即 RM_ADDR）或 `change … backup`（MP_PRIO），
  内核约 1 s 内停用该子流，目标切换 1–1.5 s（内核自己判定要约 5 s）。

anx-server 本身不碰防火墙也不碰 MPTCP 端点。

## 配置

Agent 配置文件顶层 `AnxLine` 段（Control 的网络计划 `Transport kind=anx_line` 下发尚未实现，
落地前由运维写在本机配置里；字段与将来的下发数据一一对应）。仅 Linux，需要 `CAP_NET_ADMIN`
（nft、ip mptcp）和 `CAP_NET_RAW`（ICMP 探活），Agent 以 root 运行时都有。

```json5
"AnxLine": {
  "Enable": true,
  // 可选："NFT": "nft", "IP": "ip", "Table": "anixops_anx_line"
  "Links": [
    {
      "ID": "tx-ix",
      // 假 TCP：服务端（anx-server --faketcp-listen 的端口）
      "FakeTCP": { "Role": "server", "Port": 4447, "Local": "192.0.2.10" }
    },
    {
      "ID": "ix-jp",
      // 假 TCP：客户端（入口节点，Peer = 出口节点地址）
      "FakeTCP": { "Role": "client", "Port": 4447, "Peer": "198.51.100.7" },
      // MPTCP 逐路探活与切换
      "Multipath": {
        "IntervalMs": 200,   // 探活间隔
        "TimeoutMs": 200,    // 单次超时（不得大于间隔）
        "FailAfter": 2,      // 连续失败几次判死
        "RecoverAfter": 5,   // 连续成功几次恢复
        "Action": "delete",  // 或 "backup"
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

### FakeTCP

| 字段 | 说明 |
| --- | --- |
| `Role` | `server` 或 `client` |
| `Port` | 假 TCP 端口（服务端的固定端口） |
| `Local` | 服务端：本机发出 `RST` 的源地址，可空（空时只按端口匹配） |
| `Peer` | 客户端：服务端地址，必填 |
| `Rules` | nft 规则模板，替换默认值；占位符 `{port}` `{local}` `{peer}` |

默认规则（§4.2）：

- 服务端：`ip saddr {local} tcp sport {port} tcp flags & rst == rst drop`（无 `Local` 时去掉 `ip saddr`）
- 客户端：`ip daddr {peer} tcp dport {port} tcp flags & rst == rst drop`

所有链路的规则装进一张 Agent 独占的表 `table ip anixops_anx_line`（`chain output`，
`hook output priority 0`），每次启动整表替换（一个 nft 事务）；没有假 TCP 链路时删表。
渲染后的规则只允许 nft 关键字、地址和运算符（不允许 `;`、花括号、引号、换行），模板不能跳出这条链。
Agent 停止时规则保留：anx-server 的假 TCP 承载不随 Agent 停止。

### Multipath

- 每条路径一个 `ip mptcp endpoint`（`Endpoint` = id，1–255，全机唯一）。启动时内核里没有的端点由 Agent
  `ip mptcp endpoint add <Addr> dev <Dev> id <Endpoint> <Flags>` 补上；已有的不动（Agent 重启不打断子流）。
- 探活从路径自己的地址发出（策略路由 `ip rule from <Addr>` 让它走这条路）：
  - `tcp`：从 `Addr` 连 `Target`（`host:port`）；对端回 `RST`（连接被拒）也算通。
  - `icmp`：从 `Addr` 发一个 echo，等对应的 reply。
- 每轮所有路径并行探一次。连续 `FailAfter` 次失败判死，执行 `Action`：
  - `delete`：`ip mptcp endpoint delete id N`（lab 实测的就是这条：RM_ADDR 后约 1 s 恢复）；
    恢复时按原参数重新 `add`。
  - `backup`：`ip mptcp endpoint change id N backup`；恢复时 `nobackup`。`Flags` 本来就含 `backup` 的路径不处理。
- 连续 `RecoverAfter` 次成功恢复。所有路径都死时最后一条不摘（全摘只会让内核停止重试）。
- 默认值下判死约 400–600 ms，加内核约 1 s，切换约 1.4–1.6 s；要更快可以把 `FailAfter` 设为 1（误判风险更高）。
- Agent 停止时把摘掉的端点全部恢复。
