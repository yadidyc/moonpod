# MoonPod threat model

## Assets

- Files outside the declared read and write roots
- Network services not present in the host allowlist
- Program and argument combinations not present in the command rules
- Resources and actions outside the declared generic resource rules
- Host availability, bounded through call and byte budgets
- A complete decision trail for incident review

## Trust boundaries

The caller and every `Operation` it proposes are untrusted. The caller may be an
agent, a CI worker, a plugin host, or another automation system. `Policy`
construction and the adapter that performs an allowed operation are trusted.
`Session` is the only mutable decision state and must not be shared between
unrelated runs.

```text
untrusted caller -> Operation -> MoonPod Session -> Decision -> trusted adapter
                                      |
                                      +----------> AuditEvent[]
```

The adapter must fail closed: an unknown operation or an error while evaluating
or enforcing a decision must never become an implicit allow.

## Mitigated in the current release

- Tool use is deny-by-default.
- File paths are normalized lexically and matched on segment boundaries, so
  `/workspace-other` is not treated as a child of `/workspace`.
- `..` traversal above the lexical root is rejected.
- Host and port pairs use exact allowlist matching.
- Executable names use exact matching and arguments use element-wise prefix
  matching; an empty prefix permits only a no-argument invocation.
- Generic `ResourceAccess` operations require an exact tool/action pair and a
  resource within a declared slash-separated prefix.
- Denied calls still consume call budget, limiting repeated probing.
- I/O estimates are checked without integer-addition overflow.
- Audit logs are returned as defensive array copies.

## Deliberately outside the policy core

- Symbolic-link and junction resolution
- OS process isolation and resource quotas
- DNS rebinding and IP-range enforcement
- Authentication, secrets storage, and encrypted audit persistence

These controls belong in the trusted host adapter or a container/Wasm policy.
MoonPod complements those mechanisms; it does not replace them.

## Adapter checklist

1. Convert every tool request to a typed `Operation`.
2. Call `Session::authorize` exactly once before the side effect.
3. Perform the side effect only for `Allow`.
4. Re-resolve file paths on the host and reject symlink/junction escapes.
5. Resolve hosts to permitted IP ranges when the environment requires it.
6. Pass arguments directly without shell interpolation and run child processes
   in an OS sandbox.
7. Persist the returned audit snapshot outside the agent's writable roots.
