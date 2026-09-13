///|
/// Mutable state for one isolated agent run.
pub struct Session {
  policy : Policy
  mut state : SessionState
  mut attempts : Int
  tool_attempts : Map[String, Int]
  mut used_bytes : Int
  events : Array[AuditEvent]
}

///|
/// Starts a fresh session governed by `policy`.
pub fn Session::new(policy : Policy) -> Session {
  {
    policy,
    state: Active,
    attempts: 0,
    tool_attempts: Map([]),
    used_bytes: 0,
    events: [],
  }
}

///|
/// Returns the current lifecycle state.
pub fn Session::state(self : Session) -> SessionState {
  self.state
}

///|
/// Closes this session. Closing an already closed session has no effect.
pub fn Session::close(self : Session) -> Unit {
  self.state = Closed
}

///|
/// Authorizes an operation and records the result.
///
/// Every attempt consumes one call slot. I/O bytes are charged only for
/// allowed operations. This method never performs the operation itself.
pub fn Session::authorize(self : Session, operation : Operation) -> Decision {
  let tool = operation.tool_name()
  let tool_attempts = match self.tool_attempts.get(tool) {
    Some(count) => count
    None => 0
  }
  let decision = match self.state {
    Closed => Deny(SessionClosed)
    Active =>
      self.policy.decide(
        self.attempts,
        tool_attempts,
        self.used_bytes,
        operation,
      )
  }
  let sequence = self.attempts + 1
  self.attempts = sequence
  self.tool_attempts[tool] = tool_attempts + 1
  let charged_bytes = if decision is Allow { operation.byte_cost() } else { 0 }
  self.used_bytes = self.used_bytes + charged_bytes
  self.events.push({
    sequence,
    operation: operation.snapshot(),
    decision,
    charged_bytes,
  })
  decision
}

///|
/// Number of attempted operations, including denied ones.
pub fn Session::attempts(self : Session) -> Int {
  self.attempts
}

///|
/// Bytes charged by allowed operations.
pub fn Session::used_bytes(self : Session) -> Int {
  self.used_bytes
}

///|
/// Remaining call slots in this session.
pub fn Session::remaining_calls(self : Session) -> Int {
  let remaining = self.policy.max_calls - self.attempts
  if remaining > 0 {
    remaining
  } else {
    0
  }
}

///|
/// Remaining I/O bytes in this session.
pub fn Session::remaining_bytes(self : Session) -> Int {
  self.policy.max_io_bytes - self.used_bytes
}

///|
/// Returns a defensive copy of the audit log.
pub fn Session::audit_log(self : Session) -> Array[AuditEvent] {
  self.events.copy()
}
