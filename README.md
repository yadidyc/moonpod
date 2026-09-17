# MoonPod

> MoonBit 通用策略执行与审计引擎：让宿主在执行资源操作前，先得到可解释、可验证的决策。

[![CI](https://github.com/yadidyc/moonpod/actions/workflows/ci.yml/badge.svg)](https://github.com/yadidyc/moonpod/actions/workflows/ci.yml)

MoonPod 是一个纯 MoonBit、无 I/O 副作用的策略核心。它不假设调用方一定是
AI Agent，也不直接启动进程或访问文件系统；宿主把一次待执行操作描述成
`Operation`，MoonPod 返回 `Allow`、`Deny` 或 `ApprovalRequired`，并保存带顺序号的
审计事件。这个边界让同一套规则可以放在 IDE 插件、CI 任务、桌面自动化、服务
连接器或 Agent Runtime 前面。

## 为什么需要通用策略层

把“允许某个工具”写成一个布尔开关通常不够用：文件需要目录范围，命令需要参数
前缀，网络访问需要主机和端口，插件或业务服务还需要动作与资源范围。MoonPod
把这些约束放进一次统一的会话判定中，默认拒绝未知能力，并把调用次数、单次与
会话字节预算、人工审批和策略收窄放在同一个可测试模型里。宿主仍负责操作系统
权限、容器或 Wasm 隔离，MoonPod 负责“这一次调用是否符合策略”。

## 核心模型

- **内置操作：** `ReadFile`、`WriteFile`、`Connect` 和 `RunCommand`，分别提供路径、
  主机—端口、程序名和逐项参数前缀约束。
- **通用资源操作：** `ResourceAccess(tool, action, resource, estimated_bytes)`
  配合 `ResourceRule`，可表达 `plugin.invoke / run / tenant/acme`、业务 API
  路径或工作流资源，而不必为每种领域增加一个枚举分支。
- **会话与审计：** `Session::authorize` 是唯一的决策入口；会话关闭会取消未处理
  的审批，请求、最终决定和消耗字节都可通过 `audit_json()` 导出。
- **策略组合：** `Policy::restrict` 只计算两份策略的共同权限，规则只能收窄、不能
  扩权，适合把组织策略与任务策略叠加。

## 一个通用资源规则

资源前缀按 `/` 分段匹配，精确资源或其子资源才能通过：

```mbt nocheck
let policy = @moonpod.Policy::new(
  ["plugin.invoke"],
  resource_rules=[
    @moonpod.ResourceRule::new(
      tool="plugin.invoke",
      action="run",
      resource_prefix="tenant/acme/reports",
    ),
  ],
)
let session = @moonpod.Session::new(policy)
session.authorize(@moonpod.ResourceAccess(
  tool="plugin.invoke",
  action="run",
  resource="tenant/acme/reports/monthly",
  estimated_bytes=512,
))
```

同一接口可以换成 CI 的 `build / workspace/project-a` 或桌面自动化的
`calendar.read / tenant/acme`，调用方只需负责把自己的资源命名规范传进来。

## JSON 策略与审计导出

命令行通过 `--policy-json` 加载策略，并把演示调用和审计摘要写到标准输出：

```powershell
moon run cmd/main -- --policy-json '{"allowed_tools":["fs.read"],"read_roots":["/workspace"]}' > audit.json
```

除 `allowed_tools` 外，还可配置 `read_roots`、`write_roots`、`protected_paths`、
`network_rules`、`command_rules`、`resource_rules`、`tool_quotas`、审批工具和三类
预算。无效 JSON 或字段类型错误会在任何操作执行前被拒绝。

## 与 MoonPermit 的生态关系

可选子包 `moonpermit_adapter` 将 [`doffice/moonpermit`](https://github.com/doffice/moonpermit)
的 Permit 安全地转换为 MoonPod Policy。MoonPermit 负责从结构化计划推导最小
授权、权限包含和委托证明；MoonPod 负责在宿主边界逐次拦截真实调用。适配器只
接受不会造成扩权的共同子集，无法无损表达的精确路径、过期授权、网络或 Secret
权限会失败关闭。MoonPod 不依赖 MoonPermit，也不重复实现其计划编译器。

## 快速开始与边界

```bash
moon check
moon test
moon run cmd/main
```

演示命令会先运行工作区策略，再运行一个与 Agent 无关的构建产物策略：
`workspace/project-a/report.json` 被允许读取，而同样的请求换成
`workspace/project-b/report.json` 会被拒绝。这两个结果来自同一个
`ResourceRule` 的前缀边界，便于在没有真实执行器的环境中复核策略行为。

接入宿主时遵循：映射请求 → 调用 `Session::authorize` → 仅对 `Allow` 执行副作用 →
持久化审计快照。路径检查是词法级的，不解析符号链接；命令不会经过 shell
解析；当前项目也不充当进程、容器或网络执行器。完整信任边界见
[`docs/threat-model.md`](docs/threat-model.md)。

## 项目结构与许可证

```text
model.mbt            操作、决策、拒绝原因和审计事件
resource_policy.mbt  通用资源规则
path_policy.mbt      跨平台路径归一化和边界判定
policy.mbt           不可变策略与规则求值
policy_restriction.mbt 策略共同权限计算
session.mbt          会话、预算、审批和审计状态
json_policy.mbt      JSON 策略解码和审计导出
moonpermit_adapter   MoonPermit Permit 的失败关闭适配
cmd/main             可运行演示
```

Apache-2.0
