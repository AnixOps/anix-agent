# ANX 公开边界

本目录是 anx 闭源仓库里**唯一可以复制到公开仓库**的内容。公开仓库（建议 anix-agent 的 `contracts/anx/`）只能通过人工 PR 从这里同步，不得从仓库其他位置复制任何东西。

| 文件 | 内容 |
| --- | --- |
| `proto/anx/mgmt/v1/mgmt.proto` | 管理接口 gRPC 定义（只有消息形态，注释已去掉内部机制） |
| `BOUNDARY.md` | anx-node 配置字段、命令行参数、指标名、错误码、能力名单 |

ANX 的实现以独立进程（anx-node / anx-server）交付，公开代码只能通过这里的 gRPC 接口、配置文件和命令行驱动它，不能链接它。

`PushShapeProfileRequest.profile` 是不透明字节，公开侧原样透传，不解析、不构造。
