///|
test "session starts active and closes explicitly" {
  let session = @moonpod.Session::new(@moonpod.Policy::new([]))
  assert_true(session.state() is @moonpod.Active)
  session.close()
  assert_true(session.state() is @moonpod.Closed)
  session.close()
  assert_true(session.state() is @moonpod.Closed)
}

///|
test "closed session denies and audits further operations" {
  let policy = @moonpod.Policy::new(["custom"])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(@moonpod.Invoke(tool="custom", estimated_output_bytes=3))
    .is_allowed(),
  )
  session.close()
  assert_true(
    session.authorize(@moonpod.Invoke(tool="custom", estimated_output_bytes=5))
    is @moonpod.Deny(@moonpod.SessionClosed),
  )
  assert_eq(session.attempts(), 2)
  assert_eq(session.used_bytes(), 3)
  let log = session.audit_log()
  assert_eq(log.length(), 2)
  assert_eq(log[1].charged_bytes, 0)
  assert_true(log[1].decision is @moonpod.Deny(@moonpod.SessionClosed))
}
