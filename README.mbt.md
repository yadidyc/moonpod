# MoonPod

> MoonBit 智能体隔离舱：在宿主执行工具调用之前，先进行可审计的安全策略判定。

[![CI](https://github.com/yadidyc/moonpod/actions/workflows/ci.yml/badge.svg)](https://github.com/yadidyc/moonpod/actions/workflows/ci.yml)

MoonPod 是一个纯 MoonBit、无 I/O 副作用的策略核心。它将智能体提出的文件、网络、命令与自定义工具调用转换为 `Allow` / `Deny` 决策，并记录每次尝试。宿主适配器只应在收到 `Allow` 后执行真实操作。

## 能力

- 默认拒绝的工具白名单
- 防目录穿越的词法路径根隔离
- 网络主机和外部命令白名单
- 每会话调用次数与 I/O 字节预算
- 防篡改快照式审计日志
- 不依赖操作系统 API，适合嵌入不同 Agent Runtime

## 快速开始

```bash
moon check
moon test
moon run cmd/main
```

```mbt check
///|
test "workspace isolation" {
  let policy = @moonpod.Policy::new(
    ["fs.read", "fs.write", "net.connect"],
    read_roots=["/workspace"],
    write_roots=["/workspace/out"],
    allowed_hosts=["api.example.com"],
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
}
```

## 集成契约

1. 将智能体请求映射为 `Operation`。
2. 调用 `Session::authorize`。
3. 仅在结果为 `Allow` 时执行宿主操作。
4. 执行层仍需使用 OS 权限、容器、Wasm policy 或其他强隔离机制；MoonPod 是策略门卫，不是操作系统容器。

## 限制

- 路径检查是词法级的，不解析符号链接；宿主在真实文件系统上执行前必须再做规范化与 symlink 防护。
- `RunCommand` 只约束可执行程序名；宿主应对参数使用更细粒度的前缀策略。
- 当前未包含进程、容器或网络执行器。

完整的信任边界、攻击面与宿主适配器清单见
[`docs/threat-model.md`](docs/threat-model.md)。

## 项目结构

```text
model.mbt         操作、决策、拒绝原因与审计事件
path_policy.mbt   路径归一化和边界判定
policy.mbt        不可变策略与规则求值
session.mbt       预算、调用计数和审计状态
cmd/main          可运行演示
```

## License

Apache-2.0
