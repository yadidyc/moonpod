# MoonPod

> MoonBit 智能体隔离舱：在宿主执行工具调用之前，先进行可审计的安全策略判定。

[![CI](https://github.com/yadidyc/moonpod/actions/workflows/ci.yml/badge.svg)](https://github.com/yadidyc/moonpod/actions/workflows/ci.yml)

MoonPod 是一个纯 MoonBit、无 I/O 副作用的策略核心。它将智能体提出的文件、网络、命令与自定义工具调用转换为 `Allow` / `Deny` 决策，并记录每次尝试。宿主适配器只应在收到 `Allow` 后执行真实操作。

## 能力

- 默认拒绝的工具白名单
- 防目录穿越的词法路径根隔离
- 网络主机—端口对和命令参数前缀白名单
- 每会话调用次数与 I/O 字节预算
- 防篡改快照式审计日志
- JSON 策略加载和可导出的 JSON 审计记录
- 不依赖操作系统 API，适合嵌入不同 Agent Runtime

## 快速开始

```bash
moon check
moon test
moon run cmd/main
```

## JSON 策略与审计导出

命令行支持通过 `--policy-json` 加载 JSON 策略，并将本次演示操作的审计摘要和事件写成 JSON 到标准输出。可用 shell 重定向保存审计结果：

```powershell
moon run cmd/main -- --policy-json '{"allowed_tools":["fs.read"],"read_roots":["/workspace"]}' > audit.json
```

策略必须包含 `allowed_tools`。可选字段包括 `read_roots`、`write_roots`、`protected_paths`、`network_rules`、`command_rules`、`tool_quotas`、`approval_required_tools`、`max_calls`、`max_operation_bytes` 和 `max_io_bytes`。规则项格式如下：

```json
{
  "allowed_tools": ["fs.read", "net.connect"],
  "read_roots": ["/workspace"],
  "protected_paths": ["/workspace/.env"],
  "network_rules": [
    {"host": "api.example.com", "allowed_ports": [443]}
  ],
  "command_rules": [
    {"program": "moon", "argument_prefix": ["test"]}
  ],
  "tool_quotas": [
    {"tool": "fs.read", "max_calls": 20}
  ],
  "max_calls": 100,
  "max_operation_bytes": 1048576,
  "max_io_bytes": 1048576
}
```

无效 JSON 或不符合字段类型的策略会被拒绝；此时不会执行演示操作。

```mbt check
///|
test "workspace isolation" {
  let moon_test = @moonpod.CommandRule::new(program="moon", argument_prefix=[
    "test",
  ])
  let policy = @moonpod.Policy::new(
    ["fs.read", "fs.write", "net.connect", "process.run"],
    read_roots=["/workspace"],
    write_roots=["/workspace/out"],
    network_rules=[
      @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[443]),
    ],
    command_rules=[moon_test],
    max_calls=20,
    max_io_bytes=1048576,
  )
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="/workspace/input.json", estimated_bytes=1024),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.WriteFile(path="/etc/hosts", bytes=20))
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session
    .authorize(@moonpod.Connect(host="api.example.com", port=443))
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="api.example.com", port=22))
    is @moonpod.Deny(@moonpod.PortNotAllowed(..)),
  )
  assert_true(
    session
    .authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["test", "--target", "all"],
        estimated_output_bytes=4096,
      ),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["publish"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.CommandArgumentsNotAllowed(_)),
  )
}
```

## 集成契约

1. 将智能体请求映射为 `Operation`。
2. 调用 `Session::authorize`。
3. 仅在结果为 `Allow` 时执行宿主操作。
4. 执行层仍需使用 OS 权限、容器、Wasm policy 或其他强隔离机制；MoonPod 是策略门卫，不是操作系统容器。

## 限制

- 路径检查是词法级的，不解析符号链接；宿主在真实文件系统上执行前必须再做规范化与 symlink 防护。
- `RunCommand` 对可执行程序名做精确匹配，并对参数数组做逐项前缀匹配；它不会调用 shell 解析命令字符串。
- 当前未包含进程、容器或网络执行器。

完整的信任边界、攻击面与宿主适配器清单见
[`docs/threat-model.md`](docs/threat-model.md)。

## 项目结构

```text
model.mbt         操作、决策、拒绝原因与审计事件
path_policy.mbt   路径归一化和边界判定
policy.mbt        不可变策略与规则求值
session.mbt       预算、调用计数和审计状态
json_policy.mbt   JSON 策略解码和审计导出
cmd/main          可运行演示
```

## License

Apache-2.0
