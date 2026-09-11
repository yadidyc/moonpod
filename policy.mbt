///|
/// Invalid policy configuration.
pub(all) suberror PolicyConfigError {
  InvalidLimit(name~ : String, value~ : Int)
} derive(Debug, Eq)

///|
/// A deny-by-default policy for agent operations.
pub struct Policy {
  allowed_tools : Array[String]
  read_roots : Array[String]
  write_roots : Array[String]
  allowed_hosts : Array[String]
  allowed_commands : Array[String]
  max_calls : Int
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
  allowed_hosts? : Array[String] = [],
  allowed_commands? : Array[String] = [],
  max_calls? : Int = 100,
  max_io_bytes? : Int = 1048576,
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
  {
    allowed_tools: allowed_tools.copy(),
    read_roots: read_roots.copy(),
    write_roots: write_roots.copy(),
    allowed_hosts: allowed_hosts.copy(),
    allowed_commands: allowed_commands.copy(),
    max_calls,
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
    allowed_commands=["moon"],
    max_calls=200,
    max_io_bytes=16777216,
  )
}

///|
fn Policy::decide(
  self : Policy,
  attempts : Int,
  used_bytes : Int,
  operation : Operation,
) -> Decision {
  if attempts >= self.max_calls {
    return Deny(CallBudgetExceeded(limit=self.max_calls))
  }
  let cost = operation.byte_cost()
  if cost < 0 {
    return Deny(InvalidByteEstimate(cost))
  }
  let tool = operation.tool_name()
  if !self.allowed_tools.contains(tool) {
    return Deny(ToolNotAllowed(tool))
  }
  let scoped = match operation {
    ReadFile(path~, ..) =>
      if path_is_within(path, self.read_roots) {
        Allow
      } else {
        Deny(PathNotAllowed(path))
      }
    WriteFile(path~, ..) =>
      if path_is_within(path, self.write_roots) {
        Allow
      } else {
        Deny(PathNotAllowed(path))
      }
    Connect(host~, ..) =>
      if self.allowed_hosts.contains(host) {
        Allow
      } else {
        Deny(HostNotAllowed(host))
      }
    RunCommand(program~, ..) =>
      if self.allowed_commands.contains(program) {
        Allow
      } else {
        Deny(CommandNotAllowed(program))
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
