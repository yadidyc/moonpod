///|
/// Invalid policy configuration.
pub(all) suberror PolicyConfigError {
  InvalidLimit(name~ : String, value~ : Int)
  EmptyNetworkHost
  EmptyPortSet(String)
  InvalidNetworkPort(Int)
  EmptyCommandProgram
  EmptyToolQuotaName
  EmptyApprovalToolName
} derive(Debug, Eq)

///|
/// A deny-by-default policy for agent operations.
pub struct Policy {
  allowed_tools : Array[String]
  read_roots : Array[String]
  write_roots : Array[String]
  protected_paths : Array[String]
  network_rules : Array[NetworkRule]
  command_rules : Array[CommandRule]
  tool_quotas : Array[ToolQuota]
  approval_required_tools : Array[String]
  max_calls : Int
  max_operation_bytes : Int
  max_io_bytes : Int
}

///|
/// Builds an immutable policy.
///
/// Recognized built-in tool keys are `fs.read`, `fs.write`, `net.connect`,
/// and `process.run`. Custom `Invoke` operations use their own tool name.
pub fn Policy::new(
  allowed_tools : Array[String],
  read_roots? : Array[String] = [],
  write_roots? : Array[String] = [],
  protected_paths? : Array[String] = [],
  network_rules? : Array[NetworkRule] = [],
  command_rules? : Array[CommandRule] = [],
  tool_quotas? : Array[ToolQuota] = [],
  max_calls? : Int = 100,
  max_operation_bytes? : Int = 1048576,
  max_io_bytes? : Int = 1048576,
  approval_required_tools? : Array[String] = [],
) -> Policy raise PolicyConfigError {
  if max_calls < 0 {
    raise PolicyConfigError::InvalidLimit(name="max_calls", value=max_calls)
  }
  if max_io_bytes < 0 {
    raise PolicyConfigError::InvalidLimit(
      name="max_io_bytes",
      value=max_io_bytes,
    )
  }
  if max_operation_bytes < 0 {
    raise PolicyConfigError::InvalidLimit(
      name="max_operation_bytes",
      value=max_operation_bytes,
    )
  }
  for tool in approval_required_tools {
    if tool == "" {
      raise PolicyConfigError::EmptyApprovalToolName
    }
  }
  {
    allowed_tools: allowed_tools.copy(),
    read_roots: read_roots.copy(),
    write_roots: write_roots.copy(),
    protected_paths: protected_paths.copy(),
    network_rules: network_rules.copy(),
    command_rules: command_rules.copy(),
    tool_quotas: tool_quotas.copy(),
    approval_required_tools: approval_required_tools.copy(),
    max_calls,
    max_operation_bytes,
    max_io_bytes,
  }
}

///|
/// A practical workspace policy for local coding agents.
pub fn workspace_policy(root : String) -> Policy {
  try! Policy::new(
    ["fs.read", "fs.write", "process.run"],
    read_roots=[root],
    write_roots=[root],
    protected_paths=[root + "/.git", root + "/.env"],
    command_rules=[
      CommandRule::new(program="moon", argument_prefix=["check"]),
      CommandRule::new(program="moon", argument_prefix=["test"]),
      CommandRule::new(program="moon", argument_prefix=["build"]),
    ],
    max_calls=200,
    max_io_bytes=16777216,
  )
}

///|
fn Policy::decide(
  self : Policy,
  attempts : Int,
  tool_attempts : Int,
  used_bytes : Int,
  operation : Operation,
) -> Decision {
  if attempts >= self.max_calls {
    return Deny(CallBudgetExceeded(limit=self.max_calls))
  }
  let tool = operation.tool_name()
  for quota in self.tool_quotas {
    if quota.tool == tool && tool_attempts >= quota.max_calls {
      return Deny(ToolCallQuotaExceeded(tool~, limit=quota.max_calls))
    }
  }
  let cost = operation.byte_cost()
  if cost < 0 {
    return Deny(InvalidByteEstimate(cost))
  }
  if cost > self.max_operation_bytes {
    return Deny(
      OperationByteLimitExceeded(limit=self.max_operation_bytes, requested=cost),
    )
  }
  if !self.allowed_tools.contains(tool) {
    return Deny(ToolNotAllowed(tool))
  }
  let scoped = match operation {
    ReadFile(path~, ..) =>
      if path_is_allowed(path, self.read_roots, self.protected_paths) {
        Allow
      } else {
        Deny(PathNotAllowed(path))
      }
    WriteFile(path~, ..) =>
      if path_is_allowed(path, self.write_roots, self.protected_paths) {
        Allow
      } else {
        Deny(PathNotAllowed(path))
      }
    Connect(host~, port~) => {
      let mut host_matched = false
      let mut port_allowed = false
      for rule in self.network_rules {
        if rule.matches_host(host) {
          host_matched = true
          if rule.allows_port(port) {
            port_allowed = true
          }
        }
      }
      if port_allowed {
        Allow
      } else if host_matched {
        Deny(PortNotAllowed(host~, port~))
      } else {
        Deny(HostNotAllowed(host))
      }
    }
    RunCommand(program~, arguments~, ..) => {
      let mut program_matched = false
      let mut arguments_allowed = false
      for rule in self.command_rules {
        if rule.matches_program(program) {
          program_matched = true
          if rule.allows_arguments(arguments) {
            arguments_allowed = true
          }
        }
      }
      if arguments_allowed {
        Allow
      } else if program_matched {
        Deny(CommandArgumentsNotAllowed(program))
      } else {
        Deny(CommandNotAllowed(program))
      }
    }
    Invoke(..) => Allow
  }
  guard scoped is Allow else { return scoped }
  if cost > self.max_io_bytes - used_bytes {
    Deny(IoBudgetExceeded(limit=self.max_io_bytes, requested=cost))
  } else {
    Allow
  }
}

///|
fn Policy::requires_approval(self : Policy, tool : String) -> Bool {
  self.approval_required_tools.contains(tool)
}
