# MoonPod integration guide

This guide describes the smallest safe integration for an IDE extension, CI
worker, plugin host, desktop automation tool, or agent runtime. MoonPod is a
decision engine: it never opens a file, starts a process, or connects to a
network on the caller's behalf.

## 1. Keep the trust boundary explicit

The host owns the side effect. It converts an untrusted request into an
`Operation`, asks one `Session` for a `Decision`, and only then invokes the
trusted adapter:

```mbt nocheck
fn authorize_and_execute(
  session : @moonpod.Session,
  operation : @moonpod.Operation,
) -> Bool {
  let decision = session.authorize(operation)
  if decision.is_allowed() {
    // adapter.execute(operation)
    true
  } else {
    false
  }
}
```

Do not let an adapter reinterpret a denial as a warning. Unknown operations,
malformed policy input, and adapter errors should fail closed.

## 2. Build one policy for one trust context

Construct a policy from the narrowest roots, tools, and budgets needed by the
task. Policy construction validates limits and rule shapes:

```mbt nocheck
let policy = try! @moonpod.Policy::new(
  ["fs.read", "process.run", "net.connect"],
  read_roots=["/workspace"],
  protected_paths=["/workspace/.git", "/workspace/.env"],
  command_rules=[
    try! @moonpod.CommandRule::new(
      program="moon",
      argument_prefix=["test"],
    ),
  ],
  network_rules=[
    try! @moonpod.NetworkRule::new(
      host="api.example.com",
      allowed_ports=[443],
    ),
  ],
  max_calls=100,
  max_operation_bytes=1048576,
  max_io_bytes=16777216,
)
let session = @moonpod.Session::new(policy)
```

When an organization policy and a task policy are both available, use
`Policy::restrict`. The result is the common permission set; the task policy
cannot widen the organization policy.

## 3. Map host requests to typed operations

Use the operation that carries the information the policy needs:

| Host request | Operation | Important checks |
| --- | --- | --- |
| Read a file | `ReadFile` | lexical root, protected path, byte estimate |
| Write a file | `WriteFile` | lexical root, protected path, byte count |
| Open a connection | `Connect` | exact host and allowed port |
| Run a program | `RunCommand` | exact program and argument prefix |
| Call a custom tool | `Invoke` | tool allowlist and output estimate |
| Access a named resource | `ResourceAccess` | tool/action pair and slash-separated resource prefix |

Use `Operation::to_json` and `Operation::from_json` only at a serialization
boundary. Decoding proves that the shape is valid; `Session::authorize` is
still required for authorization.

## 4. Handle decisions and approvals

Every call to `Session::authorize` consumes one attempt, including a denial.
For tools requiring human approval, the session returns `ApprovalRequired(id)`
and reserves the operation's estimated bytes:

```mbt nocheck
let decision = session.authorize(operation)
match decision {
  @moonpod.ApprovalRequired(id) => {
    // Present the operation to a human, then use exactly one of these:
    session.approve(id)
    // or session.reject(id)
  }
  _ if decision.is_allowed() => {
    // Execute the side effect through the host adapter.
  }
  _ => {
    // Record and report the denial; do not execute.
  }
}
```

Create a separate `Session` for each isolated run. Close it when the run ends;
closing cancels pending approvals and prevents later operations.

## 5. Export audit records

Use `audit_json()` for a complete snapshot. Use `audit_jsonl()` when the host
writes one structured record at a time to an append-only sink:

```mbt nocheck
let snapshot = session.audit_json()
let append_only_records = session.audit_jsonl()
```

Persist records outside the agent's writable roots. Include the session
identity and host-side timestamp in the surrounding log envelope; MoonPod's
sequence numbers provide ordering within one session.

## 6. JSON and CLI integration

JSON policy documents must declare `"schema_version": 1`. Unknown fields are
rejected. A host can decode and evaluate a batch in order:

```powershell
moon run cmd/main -- --policy-json '{"schema_version":1,"allowed_tools":["fs.read"],"read_roots":["/workspace"]}' --operations-json '[{"tool":"fs.read","path":"/workspace/README.md","estimated_bytes":128}]' --audit-jsonl
```

For a copyable library integration, run:

```bash
moon run examples/policy_guard
moon run examples/batch_audit
```

Both examples are side-effect free: they demonstrate the host decision point
without pretending to provide OS-level isolation.
