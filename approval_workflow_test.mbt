///|
test "approval-required tools pause until explicitly approved" {
  let policy = @moonpod.Policy::new(["custom"], max_io_bytes=10, approval_required_tools=[
    "custom",
  ])
  let session = @moonpod.Session::new(policy)
  let decision = session.authorize(
    @moonpod.Invoke(tool="custom", estimated_output_bytes=6),
  )
  assert_true(decision is @moonpod.ApprovalRequired(1))
  assert_eq(session.used_bytes(), 0)
  let pending = session.pending_approvals()
  assert_eq(pending.length(), 1)
  assert_eq(pending[0].id, 1)
  assert_eq(session.remaining_bytes(), 4)
  let approved = session.approve(1)
  assert_eq(approved, @moonpod.ApprovalGranted(1))
  assert_true(approved.is_allowed())
  assert_eq(session.used_bytes(), 6)
  assert_eq(session.pending_approvals().length(), 0)
  let audit = session.audit_log()
  assert_eq(audit[0].decision, @moonpod.ApprovalGranted(1))
  assert_eq(audit[0].charged_bytes, 6)
}

///|
test "rejected approvals release reserved bytes" {
  let policy = @moonpod.Policy::new(["review", "ordinary"], max_io_bytes=5, approval_required_tools=[
    "review",
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(@moonpod.Invoke(tool="review", estimated_output_bytes=5))
    is @moonpod.ApprovalRequired(1),
  )
  assert_true(
    session.authorize(
      @moonpod.Invoke(tool="ordinary", estimated_output_bytes=1),
    )
    is @moonpod.Deny(@moonpod.IoBudgetExceeded(limit=5, requested=1)),
  )
  assert_true(
    session.reject(1) is @moonpod.Deny(@moonpod.ApprovalRejected(request_id=1)),
  )
  assert_true(
    session.audit_log()[0].decision
    is @moonpod.Deny(@moonpod.ApprovalRejected(request_id=1)),
  )
  assert_eq(session.remaining_bytes(), 5)
  assert_eq(session.used_bytes(), 0)
  assert_true(
    session.authorize(
      @moonpod.Invoke(tool="ordinary", estimated_output_bytes=5),
    )
    is @moonpod.Allow,
  )
  assert_true(
    session.approve(1)
    is @moonpod.Deny(@moonpod.ApprovalNotPending(request_id=1)),
  )
}

///|
test "approval cannot override policy denial and closing cancels requests" {
  let policy = @moonpod.Policy::new([], approval_required_tools=["restricted"])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(
      @moonpod.Invoke(tool="restricted", estimated_output_bytes=0),
    )
    is @moonpod.Deny(@moonpod.ToolNotAllowed("restricted")),
  )
  let allowed_policy = @moonpod.Policy::new(["custom"], approval_required_tools=[
    "custom",
  ])
  let active_session = @moonpod.Session::new(allowed_policy)
  assert_true(
    active_session.authorize(
      @moonpod.Invoke(tool="custom", estimated_output_bytes=4),
    )
    is @moonpod.ApprovalRequired(1),
  )
  active_session.close()
  assert_eq(active_session.pending_approvals().length(), 0)
  assert_true(
    active_session.approve(1) is @moonpod.Deny(@moonpod.SessionClosed),
  )
  assert_eq(active_session.used_bytes(), 0)
  assert_true(
    active_session.audit_log()[0].decision is @moonpod.ApprovalCancelled(1),
  )
}
