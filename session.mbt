///|
/// Mutable state for one isolated agent run.
pub struct Session {
  policy : Policy
  mut state : SessionState
  mut attempts : Int
  tool_attempts : Map[String, Int]
  mut used_bytes : Int
  mut reserved_bytes : Int
  events : Array[AuditEvent]
  approvals : Array[ApprovalRequest]
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
    reserved_bytes: 0,
    events: [],
    approvals: [],
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
  for request in self.approvals {
    self.replace_audit_event(request.id, ApprovalCancelled(request.id), 0)
  }
  self.approvals.clear()
  self.reserved_bytes = 0
}

///|
/// Returns a defensive copy of operations awaiting human approval.
pub fn Session::pending_approvals(self : Session) -> Array[ApprovalRequest] {
  let result = []
  for request in self.approvals {
    result.push({ id: request.id, operation: request.operation.snapshot(), })
  }
  result
}

///|
/// Approves a pending operation and charges its reserved byte estimate.
pub fn Session::approve(self : Session, request_id : Int) -> Decision {
  self.resolve_approval(request_id, true)
}

///|
/// Rejects a pending operation and releases its reserved byte estimate.
pub fn Session::reject(self : Session, request_id : Int) -> Decision {
  self.resolve_approval(request_id, false)
}

///|
/// Authorizes an operation and records the result.
///
/// Every attempt consumes one call slot. Operations configured for human
/// approval reserve their byte estimate until approved or rejected. This
/// method never performs the operation itself.
pub fn Session::authorize(self : Session, operation : Operation) -> Decision {
  let tool = operation.tool_name()
  let tool_attempts = match self.tool_attempts.get(tool) {
    Some(count) => count
    None => 0
  }
  let policy_decision = match self.state {
    Closed => Deny(SessionClosed)
    Active =>
      self.policy.decide(
        self.attempts,
        tool_attempts,
        self.used_bytes + self.reserved_bytes,
        operation,
      )
  }
  let sequence = self.attempts + 1
  let decision = match policy_decision {
    Allow if self.policy.requires_approval(tool) => {
      self.reserved_bytes = self.reserved_bytes + operation.byte_cost()
      self.approvals.push({ id: sequence, operation: operation.snapshot(), })
      ApprovalRequired(sequence)
    }
    _ => policy_decision
  }
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
/// Remaining I/O bytes, including reservations for pending approvals.
pub fn Session::remaining_bytes(self : Session) -> Int {
  self.policy.max_io_bytes - self.used_bytes - self.reserved_bytes
}

///|
/// Returns a defensive copy of the audit log.
pub fn Session::audit_log(self : Session) -> Array[AuditEvent] {
  self.events.copy()
}

///|
fn Session::resolve_approval(
  self : Session,
  request_id : Int,
  approved : Bool,
) -> Decision {
  if self.state is Closed {
    return Deny(SessionClosed)
  }
  let mut found_index = -1
  for index, request in self.approvals {
    if request.id == request_id {
      found_index = index
    }
  }
  if found_index < 0 {
    return Deny(ApprovalNotPending(request_id~))
  }
  let request = self.approvals[found_index]
  let byte_cost = request.operation.byte_cost()
  self.reserved_bytes = self.reserved_bytes - byte_cost
  let decision = if approved {
    self.used_bytes = self.used_bytes + byte_cost
    ApprovalGranted(request_id)
  } else {
    Deny(ApprovalRejected(request_id~))
  }
  ignore(self.approvals.remove(found_index))
  self.replace_audit_event(
    request_id,
    decision,
    if approved {
      byte_cost
    } else {
      0
    },
  )
  decision
}

///|
fn Session::replace_audit_event(
  self : Session,
  sequence : Int,
  decision : Decision,
  charged_bytes : Int,
) -> Unit {
  let index = sequence - 1
  if index >= 0 && index < self.events.length() {
    let event = self.events[index]
    self.events[index] = {
      sequence: event.sequence,
      operation: event.operation,
      decision,
      charged_bytes,
    }
  }
}
