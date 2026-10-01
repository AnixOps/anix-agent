# Agent 机器监控与运维手册

首批实现负责机器监控插件的真实健康检测、进程退出记录、持久化上报和受限实例重启。工单、认领、通知、审批与人工关闭由 Control 负责。源码、CI、真实环境分别验收；本文件不代表生产验收通过。

## 启动和配置

使用 GitHub Release 附件安装 Agent，运行 `anix-agent server -c /etc/anixops/agent/config.json`。兼容脚本命令仍为 `v2bx-anixops`。不在生产节点编译发行产物。首次安装优先写入 `example/config.production.json` 对应的生产模板，但不会自动启动；所有 `REPLACE` 值由部署者在节点本地填写。

启动前必须执行：

```bash
anix-agent validate-config -c /etc/anixops/agent/config.json
```

生产配置校验要求 HTTPS ApiHost、TLS gRPC、认证维护 WebSocket、官方签名根、插件目录、节点凭据和明确的 `Environment` / `MaintenanceEnvironment`。失败会返回非零退出码，systemd 不会把配置错误当成成功退出。

节点 `ApiConfig` 需启用 `PluginSupervisorEnabled`，填写 `PluginRoot`、`PluginOfficialPublicKey`，推荐独立 `PluginSocketDir`。完整插件签名与安装约定见 [Supervisor](PLUGIN_SUPERVISOR.md)。

```json
{
  "Transport": "http",
  "AgentControlEnabled": true,
  "PluginSupervisorEnabled": true,
  "PluginRoot": "/var/lib/anixops/plugins",
  "PluginSocketDir": "/run/anixops/plugins",
  "PluginOfficialPublicKey": "BASE64_ED25519_PUBLIC_KEY",
  "MaintenanceEnvironment": "production"
}
```

`ApiHost`、`NodeID`、`ApiKey` 复用现有节点配置和注册后凭据；不另配 HTTP 工单地址。`MaintenanceEnvironment` 支持 development/staging/production，省略为 development。正式环境必须显式填写 production。队列绑定节点和环境，变更环境时不得覆盖原队列；先交付积压事件再人工迁移。

首批运维事件只通过已认证 WebSocket `/api/v2/agent/ws`（兼容 `/api/v2/node/ws`）发送，HTTP/REST 节点复用已有连接；gRPC 节点另开仅发送运维事件的认证 WebSocket，`ApiHost` 必须为 HTTP(S)，`GRPCHost` 单独填写 gRPC 目标。gRPC 主控制流继续执行插件命令；关闭 WebSocket 或缺少 HTTP(S) ApiHost 的配置启用插件运维会启动失败。生产地址使用 HTTPS/WSS。

需要显式配置同步选项时，在 `Options.SyncConfig` 中设置 `EnableWebSocket: true`。默认每 30 秒执行真实 gRPC 健康探针，进程退出同时触发记录。启用 Supervisor 时启动监测，退出时先停止监测，再关闭插件和节点通信。

## 故障与自动动作

- 普通故障需连续失败至少 3 次，且该失败序列持续至少 2 分钟。第一次失败时间保留在工单事件中；短暂恢复不改写未恢复事故的起点。
- 凭据、权限、签名和配置错误立即转人工，不自动重启。签名异常为重大故障。
- 自动重启目前仅允许 `machine-telemetry`。每个节点内插件实例每 30 分钟最多 2 次；实例标识为插件 ID，升级版本不重置预算。
- 预算、故障状态和待发送事件在动作前同一持久化事务提交。磁盘失败时不执行自动动作；Agent 重启不能重置预算。不健康实例的启动恢复也必须经过预算检查。
- 自动动作只重启同一签名版本、同一配置的插件进程。不自动升级、不选择其他配置或版本。已授权安装/更新的失败补偿保持原生命周期约定；人工回滚必须由 Control 发起具体版本操作。
- 持续健康 5 分钟产生一次 recovered 事件。探针间隔超过 1 分钟的空窗不计作连续健康。恢复后再次故障重新累计失败序列；工单是否复用由 Control 判断。

## 持久化与排障

节点目录默认是 `<PluginRoot>/nodes/<注册后 node_id>/`，兼容单节点旧布局见 Supervisor 文档。

- `state.json`：插件版本、操作日志、运行状态。
- `maintenance.json`：待发送事件、故障序列、健康起点、30 分钟重启预算。原子写入、文件及目录 fsync，文件权限 0600。
- `maintenance.json.lock`：跨进程事务锁，防并发读写覆盖事件或预算。

`maintenance_events` 使用 `anixops.maintenance/v1` 批次版本，单批最多 50 条、256 KiB，按实际 JSON 编码长度分批，单事件最多 16 KiB。服务端 `maintenance_ack` 的每条 `persisted=true` 才允许删除。成功写入 WebSocket、普通消息 ACK、超时、拒绝和数据库失败都不能清空队列。重复上报保留原事件 ID，由 Control 去重。混合 ACK 中无法回显 ID 的拒绝项不会阻止其他已持久化事件出队。实例状态按插件 ID 和实例 ID 共同隔离；早期开发队列若缺少插件命名空间将拒绝启动，需先人工迁移，不能静默重置预算。队列容量 100000 条且文件上限 256 MiB；满容量或损坏时拒绝接受新事件并记错，不静默覆盖证据。

日志检查：`plugin maintenance observation failed` 表示探针/持久化或动作失败，`Maintenance acknowledgment rejected` 表示协议或节点不符，`Failed to send heartbeat` 包括队列读取/发送失败。查 Control 连接、磁盘空间和文件权限，再查看 Control 工单时间线。日志与本地状态按受保护运维数据处理。

Agent 生成的事件只有固定错误码、实例、版本、时间、次数及动作结果，不上传进程错误原文、配置、令牌或原始日志。Control 仍须执行服务端数据最小化，不能因字段名含 redacted 而信任其内容。

## 人工处理与权限

技术员可按 Control 授权重启单节点、恢复已验证版本，并填写处理记录。新版本生产升级、批量操作、数据库和系统网络变更需要负责人审批；审批绑定操作和版本。Agent 不代替 Control 作审批决策。

回滚前保留旧签名包及配置，确认目标版本已验证，在 Control 创建该节点的 plugin.rollback 操作并查看审计与健康结果。未确认持久化前，不删除或手工清空 maintenance.json；也不要通过删除文件重置重启预算。

Control 的诊断 30 天、事件/通知 90 天、工单摘要及变更审计 1 年保留策略不适用于尚未确认的 Agent 待发送队列。离线积压不能按年龄提前删除。

## 上线前独立门槛

真实邮件和 Telegram 分别投递、Control 宕机的第三方监测、跨地域网络、实际设备与操作权限演练、灰度观察和维护人员交接均需独立证据。开发测试只访问本机测试服务，不通知真实人员。不得将测试适配器或 schema 定义当作这些门槛已完成。
