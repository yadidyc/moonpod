# Runnable policy integrations

These examples are standalone MoonBit executables. They use the same public
API as a host application and do not perform real file, network, or process
side effects.

From the repository root:

```bash
moon run examples/policy_guard
moon run examples/batch_audit
```

`policy_guard` maps host requests to `Operation` values and gates the imagined
side effect on `Decision::is_allowed`. It demonstrates workspace protection,
command argument prefixes, and host-port rules.

`batch_audit` loads a strict `schema_version: 1` policy, decodes a JSON batch,
and prints one append-only JSONL audit record per operation. Its output can be
redirected to a log sink without changing the policy engine.
