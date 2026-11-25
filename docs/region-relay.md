# 地区中继（region relay）

完整设计在 Control 仓库 `docs/design/region-relay/README.md`。本文只写需求与 Agent 侧的行为。

## 需求

来源：项目需求表 R33、R34（2026-11-25，由 owner 提出并确认）。

- **R33。** 地区内放一台中继机，主面板只与中继通讯，中继再与本地区的所有节点通讯。中继无网页界面、无 API，只做纯转发：面板与节点之间端到端认证和加密，中继看不到也改不了控制内容，不保存密钥和配置。两台中继互为备份。中继或面板不可达时，节点按最后一次配置继续运行。先做中国大陆。
- **R34。** 中国大陆的 Agent 一律经本地区中继连接面板，不回退直连。中继同时缓存签名的安装包和升级包，节点照常验签。

## Agent 的改动

| 需要 | 做法 |
|---|---|
| 拨号地址与证书名分离 | 已有：`GRPCHost` 是面板的 gRPC 目标，`GRPCServerName` 是校验面板证书用的名字。配置了中继后，这两项仍然写面板的，只有 TCP 连接改去中继 |
| 中继列表 | 新配置项 `GRPCRelays`（`host:port` 列表）。设置后，控制流和证书入网/续期（AgentEnrollment）的每条连接都只拨中继，不拨 `GRPCHost`，也不回退直连 |
| 选择与切换 | 第一次连接前测量每台中继的 TCP 连接耗时，选最快的；之后每 10 分钟复测，只有另一台的耗时比当前低 30% 以上，新连接才换过去，避免来回切换。拨号失败的中继按 5 秒起、最长 5 分钟的指数退避跳过；所有中继都在退避时仍按顺序全部尝试 |
| 多个节点身份 | 同一进程里配置相同中继列表的节点（`proxy-<id>`、`forward-<id>`）共用一个选择器，只测量一次 |
| 升级包缓存 | 新配置项 `ReleaseCaches`（https 基础地址列表）。升级时先向中继缓存按 SHA-256 取文件（`/v1/sha256/<sha256>?src=<发布地址>`），哈希不对就丢弃并换下一个来源；再走控制连接；最后走发布地址。无论来源，大小、SHA-256 和发布签名照常校验，信任根只在节点上 |
| 失联时 | 现有行为：最后一次应用的配置快照保存在本地（`api/agent/state`），控制流断开不会清空数据面，重连按退避进行 |
| 生产校验 | `GRPCRelays` 必须是真实的 `host:port`，`ReleaseCaches` 必须是真实的 https 地址 |

配置示例（节点的一项）：

```json
{
  "ApiHost": "https://panel.company.net",
  "GRPCHost": "panel.company.net:50051",
  "GRPCUseTLS": true,
  "GRPCServerName": "panel.company.net",
  "GRPCRelays": ["relay-1.company.net:50051", "relay-2.company.net:50051"],
  "ReleaseCaches": ["https://relay-1.company.net:8443", "https://relay-2.company.net:8443"]
}
```

## 后续

- 面板维护地区的中继列表，安装脚本为大陆节点写入，已安装的节点经控制流更新（Control 契约只增不删，属于下一步）。
- `anix-agent join` 经中继入网。
