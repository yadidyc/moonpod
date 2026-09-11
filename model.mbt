///|
/// An operation an agent wants the host to perform.
///
/// Byte estimates are charged against the session I/O budget only when the
/// operation is allowed.
pub(all) enum Operation {
  ReadFile(path~ : String, estimated_bytes~ : Int)
  WriteFile(path~ : String, bytes~ : Int)
  Connect(host~ : String, port~ : Int)
  RunCommand(program~ : String, estimated_output_bytes~ : Int)
  Invoke(tool~ : String, estimated_output_bytes~ : Int)
} derive(Debug, Eq)

///|
/// An exact host rule with a set of allowed TCP ports.
///
/// The port array is copied so later caller mutations cannot widen a policy.
pub struct NetworkRule {
  host : String
  allowed_ports : Array[Int]
} derive(Debug, Eq)

///|
/// Creates a validated network rule.
pub fn NetworkRule::new(
  host~ : String,
  allowed_ports~ : Array[Int],
) -> NetworkRule raise PolicyConfigError {
  if host == "" {
    raise PolicyConfigError::EmptyNetworkHost
  }
  if allowed_ports.length() == 0 {
    raise PolicyConfigError::EmptyPortSet(host)
  }
  for port in allowed_ports {
    if port < 1 || port > 65535 {
      raise PolicyConfigError::InvalidNetworkPort(port)
    }
  }
  { host, allowed_ports: allowed_ports.copy(), }
}

///|
fn NetworkRule::matches_host(self : NetworkRule, host : String) -> Bool {
  self.host == host
}

///|
fn NetworkRule::allows_port(self : NetworkRule, port : Int) -> Bool {
  self.allowed_ports.contains(port)
}

///|
/// A machine-readable reason for rejecting an operation.
pub(all) enum DenyReason {
  CallBudgetExceeded(limit~ : Int)
  IoBudgetExceeded(limit~ : Int, requested~ : Int)
  ToolNotAllowed(String)
  PathNotAllowed(String)
  HostNotAllowed(String)
  PortNotAllowed(host~ : String, port~ : Int)
  CommandNotAllowed(String)
  InvalidByteEstimate(Int)
} derive(Debug, Eq)

///|
/// The policy decision returned to the host adapter.
pub(all) enum Decision {
  Allow
  Deny(DenyReason)
} derive(Debug, Eq)

///|
/// One immutable audit entry produced by a session.
pub(all) struct AuditEvent {
  sequence : Int
  operation : Operation
  decision : Decision
  charged_bytes : Int
} derive(Debug, Eq)

///|
/// Returns whether this decision permits the host operation.
pub fn Decision::is_allowed(self : Decision) -> Bool {
  self is Allow
}

///|
/// Returns a stable, human-readable decision summary.
pub fn Decision::summary(self : Decision) -> String {
  match self {
    Allow => "allow"
    Deny(reason) => "deny: " + reason.summary()
  }
}

///|
/// Returns a stable, human-readable denial summary.
pub fn DenyReason::summary(self : DenyReason) -> String {
  match self {
    CallBudgetExceeded(limit~) => "call budget exceeded (limit \{limit})"
    IoBudgetExceeded(limit~, requested~) =>
      "I/O budget exceeded (limit \{limit}, requested \{requested})"
    ToolNotAllowed(tool) => "tool not allowed: \{tool}"
    PathNotAllowed(path) => "path not allowed: \{path}"
    HostNotAllowed(host) => "host not allowed: \{host}"
    PortNotAllowed(host~, port~) => "port not allowed: \{host}:\{port}"
    CommandNotAllowed(program) => "command not allowed: \{program}"
    InvalidByteEstimate(value) => "invalid byte estimate: \{value}"
  }
}

///|
pub fn Operation::tool_name(self : Operation) -> String {
  match self {
    ReadFile(..) => "fs.read"
    WriteFile(..) => "fs.write"
    Connect(..) => "net.connect"
    RunCommand(..) => "process.run"
    Invoke(tool~, ..) => tool
  }
}

///|
fn Operation::byte_cost(self : Operation) -> Int {
  match self {
    ReadFile(estimated_bytes~, ..) => estimated_bytes
    WriteFile(bytes~, ..) => bytes
    Connect(..) => 0
    RunCommand(estimated_output_bytes~, ..) => estimated_output_bytes
    Invoke(estimated_output_bytes~, ..) => estimated_output_bytes
  }
}
