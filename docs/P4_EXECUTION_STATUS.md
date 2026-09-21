# Agent 路线图与分层验收

历史文件名保留链接兼容；不以统一 P4 标签认定交付完成。

| 批次 | Agent 范围 | 源码与可调用行为 | CI 证据 | 真实环境 |
|---|---|---|---|---|
| 首批 | machine-telemetry 签名安装/启停/升级失败/人工回滚 | Supervisor 和机器监控包已有运行路径；生命周期、包签名和真实子进程测试 | CI 的完整 Go 测试，需核对具体提交运行结果 | 未验收 |
| 首批 | 健康、退出、受限自愈、可靠运维上报 | 30 秒探针与真实退出；节点隔离的持久化队列；WebSocket 逐事件持久确认；跨重启 2 次/30 分钟预算 | maintenance、Supervisor、WebSocket 重传测试及 race 检查；完整回归 | 未验收 |
| 后续 | 转发、WireGuard、隧道、NAT、流量核算插件化 | 按各插件现有路径继续独立推进，保持隔离 namespace 验收边界 | 各插件测试分别登记，不能用机器监控通过替代 | 跨地域和设备验证未完成 |
| 生产交接 | Release、灰度、真实告警与维护人员接手 | [维护手册](MAINTENANCE_P0.md) 和 [安装指南](INSTALL.md) | CI 不代替演练 | 未验收 |

NetworkCore 的订阅实际运行、进程管理、MITM、浏览器捕获与跨平台客户端按该仓库路线交付，不是首批机器监控的依赖。

验证命令：

```bash
GOEXPERIMENT=jsonv2 GOWORK=off go test ./... -count=1
GOEXPERIMENT=jsonv2 GOWORK=off go test -race ./common/maintenance ./plugin ./node -run 'Test(Maintenance|Outbox|Qualification|Consecutive|ManualErrors|EventRejects|Corrupt)' -count=1
```

`plugin/machine_telemetry_process_test.go` 启动实际签名包子进程，读取 gRPC 监测结果，杀死进程并检查事件、允许的重启及连续恢复。`node/maintenance_test.go` 通过认证 WebSocket 测试断连、数据库未确认、重复投递和 durable ACK。Control 的数据库工单/通知闭环由 Control 仓库集成测试单独证明。

CI 状态以 [Agent CI](https://github.com/AnixOps/anix-agent/actions/workflows/ci.yml) 对应提交为准。生产可用性仍取决于真实双渠道通知、第三方 Control 监测、灰度与交接证据。
