///|
/// Mutable state for one isolated agent run.
pub struct Session {
  policy : Policy
  mut attempts : Int
  mut used_bytes : Int
  events : Array[AuditEvent]
}

///|
/// Starts a fresh session governed by `policy`.
pub fn Session::new(policy : Policy) -> Session {
  { policy, attempts: 0, used_bytes: 0, events: [], }
}

///|
/// Authorizes an operation and records the result.
///
/// Every attempt consumes one call slot. I/O bytes are charged only for
/// allowed operations. This method never performs the operation itself.
pub fn Session::authorize(self : Session, operation : Operation) -> Decision {
  let decision = self.policy.decide(self.attempts, self.used_bytes, operation)
  let sequence = self.attempts + 1
  self.attempts = sequence
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
