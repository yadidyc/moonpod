# MoonPod security guide

MoonPod reduces the authority granted to a host operation, but it is not a
process sandbox or an operating-system permission manager. The host adapter
must preserve the trust boundaries described here.

## Security properties provided by MoonPod

- **Deny by default:** a tool must be listed before an operation can be
  allowed.
- **Scoped paths:** paths are normalized lexically, matched on complete path
  segments, and checked against protected exclusions. `..` traversal above the
  lexical root is rejected.
- **Scoped commands:** program names are exact matches and argument rules are
  element-wise prefixes; a rule for `moon test` does not authorize `moon
  publish`.
- **Scoped network access:** a network rule matches the exact host and an
  explicitly allowed port.
- **Scoped resources:** `ResourceAccess` requires the exact tool/action pair
  and a resource inside a slash-separated prefix.
- **Budgets:** session calls, per-tool calls, per-operation bytes, and total I/O
  bytes bound repeated or oversized requests.
- **Approval gates:** configured tools can reserve their byte estimate until a
  human approves or rejects the request.
- **Structured evidence:** every attempt creates an ordered `AuditEvent`, and
  `audit_jsonl()` exports one record per line for append-only sinks.

## What the host must still enforce

The following controls are deliberately outside the policy core:

1. Re-resolve file paths immediately before the side effect and reject
   symlink, junction, mount, and race-condition escapes.
2. Pass command arguments directly to the process API. Never concatenate them
   into a shell command; run the child in an OS/container/Wasm sandbox.
3. Resolve approved host names to the required IP ranges and account for DNS
   rebinding, proxy behavior, TLS validation, and certificate policy.
4. Store policy documents, credentials, and audit files outside agent-writable
   locations. Apply OS permissions and encryption where required.
5. Authenticate the policy source and the human approver. Do not treat a JSON
   document supplied by the untrusted caller as an organization policy.
6. Isolate sessions between tenants, jobs, or agents. Never share a mutable
   `Session` across unrelated runs.

## Safe adapter sequence

```text
untrusted request
      |
      v
typed Operation -> Session::authorize -> Decision
                                      |
                    +-----------------+-----------------+
                    |                                   |
              Allow / approved                    Deny / pending
                    |                                   |
       host re-checks and executes             no side effect
                    |                                   |
             append audit record
```

The host must call `Session::authorize` exactly once for each proposed side
effect. A denial, parse error, policy error, or adapter failure is not an
implicit allow. For `ApprovalRequired`, execute only after the matching
request ID has been approved; a later request must not reuse that approval.

## Policy authoring checklist

- Pin `schema_version` to `1` and reject unknown fields.
- List only the tools required by the task.
- Use workspace roots rather than broad filesystem roots.
- Exclude `.git`, `.env`, credentials, caches, and generated secrets with
  `protected_paths`.
- Use the smallest command argument prefixes and exact network ports.
- Set realistic call and byte budgets; remember denied attempts consume call
  budget.
- Add approval requirements for irreversible or externally visible actions.
- Combine an organization policy with a task policy using `Policy::restrict`.
- Test both the intended allow path and the nearest dangerous deny path.

## Verification scenarios

Before releasing an adapter, test at least these pairs:

| Allowed case | Expected denial |
| --- | --- |
| `/workspace/src/main.mbt` | `/workspace/.git/config` or `.env` |
| `moon test` | `moon publish` |
| `api.example.com:443` | same host on port `22` |
| `tenant/acme/reports/monthly` | `tenant/acme/other` |
| one call below the quota | the next call above the quota |
| approved operation | rejected or closed-session operation |

Run the repository's full stable-target checks and examples before publishing:

```bash
moon fmt --check
moon info
git diff --exit-code -- '**/pkg.generated.mbti'
moon check --target all --deny-warn
moon test --target all --deny-warn
moon run examples/policy_guard
moon run examples/batch_audit
```

For the complete asset list and non-goals, see
[`threat-model.md`](threat-model.md). For host-side wiring, see
[`integration-guide.md`](integration-guide.md).
