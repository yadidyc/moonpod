///|
/// Errors raised when a MoonPermit grant cannot be represented by MoonPod
/// without widening its authority.
pub(all) suberror PermitAdapterError {
  ExactPathUnsupported(grant_id~ : String)
  RepositoryRootTreeUnsupported(grant_id~ : String)
  ExactCommandUnsupported(grant_id~ : String)
  UnsupportedEffect(grant_id~ : String, effect~ : String)
  ExpiringGrantUnsupported(grant_id~ : String)
  MultipleGrantsForTool(tool~ : String)
  ByteLimitOutOfRange(grant_id~ : String, limit~ : Int64)
  CallLimitOverflow
  InvalidGeneratedPolicy
} derive(Debug, Eq)

///|
/// Converts the safely representable subset of a MoonPermit permit into a
/// MoonPod policy.
///
/// Supported grants are file read/write trees and command prefixes that allow
/// additional arguments. Exact paths, exact commands, expiry, delete, network,
/// and secret effects fail closed because MoonPod cannot preserve all of their
/// constraints. Optional protected paths and approval tools only narrow the
/// resulting authority.
///
/// # Example
/// ```mbt check
/// test {
///   let permit = @moonpermit.compile_plan("docs-host", [
///     @moonpermit.effect_request(
///       @moonpermit.FileRead(@moonpermit.path_tree("docs")),
///       @moonpermit.budget(max_calls=2, max_bytes=1024),
///     ),
///   ])
///   let policy = @moonpermit_adapter.policy_from_permit(permit, protected_paths=[
///     "docs/.env",
///   ])
///   let session = @moonpod.Session::new(policy)
///   assert_true(
///     session
///     .authorize(@moonpod.ReadFile(path="docs/guide.md", estimated_bytes=10))
///     .is_allowed(),
///   )
/// }
/// ```
pub fn policy_from_permit(
  permit : @moonpermit.Permit,
  protected_paths? : Array[String] = [],
  approval_required_tools? : Array[String] = [],
) -> @moonpod.Policy raise PermitAdapterError {
  let allowed_tools : Array[String] = []
  let read_roots : Array[String] = []
  let write_roots : Array[String] = []
  let command_rules : Array[@moonpod.CommandRule] = []
  let tool_quotas : Array[@moonpod.ToolQuota] = []
  let mut finite_call_total = 0
  let mut has_unlimited_calls = false
  let mut tightest_byte_limit : Int? = None
  for grant in permit.grants() {
    let grant_id = grant.id()
    let budget = grant.budget()
    if budget.expires_at() is Some(_) {
      raise PermitAdapterError::ExpiringGrantUnsupported(grant_id~)
    }
    let tool = match grant.effect() {
      @moonpermit.FileRead(scope) => {
        if !scope.is_tree() {
          raise PermitAdapterError::ExactPathUnsupported(grant_id~)
        }
        read_roots.push(tree_root(scope, grant_id~))
        "fs.read"
      }
      @moonpermit.FileWrite(scope) => {
        if !scope.is_tree() {
          raise PermitAdapterError::ExactPathUnsupported(grant_id~)
        }
        write_roots.push(tree_root(scope, grant_id~))
        "fs.write"
      }
      @moonpermit.ProcessExec(scope) => {
        if !scope.allows_extra_arguments() {
          raise PermitAdapterError::ExactCommandUnsupported(grant_id~)
        }
        let rule = @moonpod.CommandRule::new(
          program=scope.program(),
          argument_prefix=scope.arguments(),
        ) catch {
          _ => raise PermitAdapterError::InvalidGeneratedPolicy
        }
        command_rules.push(rule)
        "process.run"
      }
      @moonpermit.FileDelete(_) =>
        raise PermitAdapterError::UnsupportedEffect(
          grant_id~,
          effect="file.delete",
        )
      @moonpermit.NetworkSend(_) =>
        raise PermitAdapterError::UnsupportedEffect(
          grant_id~,
          effect="network.send",
        )
      @moonpermit.SecretRead(_) =>
        raise PermitAdapterError::UnsupportedEffect(
          grant_id~,
          effect="secret.read",
        )
    }
    if allowed_tools.contains(tool) {
      raise PermitAdapterError::MultipleGrantsForTool(tool~)
    }
    allowed_tools.push(tool)
    match budget.max_calls() {
      None => has_unlimited_calls = true
      Some(limit) => {
        if limit > max_int_limit() - finite_call_total {
          raise PermitAdapterError::CallLimitOverflow
        }
        finite_call_total += limit
        let quota = @moonpod.ToolQuota::new(tool~, max_calls=limit) catch {
          _ => raise PermitAdapterError::InvalidGeneratedPolicy
        }
        tool_quotas.push(quota)
      }
    }
    match budget.max_bytes() {
      None => ()
      Some(limit) => {
        if limit > max_int_limit().to_int64() {
          raise PermitAdapterError::ByteLimitOutOfRange(grant_id~, limit~)
        }
        let converted = limit.to_int()
        tightest_byte_limit = match tightest_byte_limit {
          None => Some(converted)
          Some(current) => Some(current.min(converted))
        }
      }
    }
  }
  let max_calls = if has_unlimited_calls {
    max_int_limit()
  } else {
    finite_call_total
  }
  let max_io_bytes = tightest_byte_limit.unwrap_or(max_int_limit())
  @moonpod.Policy::new(
    allowed_tools,
    read_roots~,
    write_roots~,
    protected_paths~,
    command_rules~,
    tool_quotas~,
    max_calls~,
    max_operation_bytes=max_io_bytes,
    max_io_bytes~,
    approval_required_tools~,
  ) catch {
    _ => raise PermitAdapterError::InvalidGeneratedPolicy
  }
}

///|
fn max_int_limit() -> Int {
  2147483647
}

///|
fn tree_root(
  scope : @moonpermit.PathScope,
  grant_id~ : String,
) -> String raise PermitAdapterError {
  let canonical = scope.canonical()
  if canonical == "**" {
    raise PermitAdapterError::RepositoryRootTreeUnsupported(grant_id~)
  }
  guard canonical.has_suffix("/**") else {
    raise PermitAdapterError::ExactPathUnsupported(grant_id~)
  }
  canonical[0:canonical.length() - 3].to_owned()
}
