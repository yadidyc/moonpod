///|
test "enforces a byte limit on each operation" {
  let policy = @moonpod.Policy::new(
    ["fs.read", "fs.write", "custom"],
    read_roots=["/workspace"],
    write_roots=["/workspace"],
    max_operation_bytes=8,
    max_io_bytes=100,
  )
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="/workspace/input.mbt", estimated_bytes=8),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.WriteFile(path="/workspace/output.mbt", bytes=9))
    is @moonpod.Deny(@moonpod.OperationByteLimitExceeded(limit=8, requested=9)),
  )
  assert_true(
    session.authorize(@moonpod.Invoke(tool="custom", estimated_output_bytes=10))
    is @moonpod.Deny(@moonpod.OperationByteLimitExceeded(limit=8, requested=10)),
  )
  assert_eq(session.used_bytes(), 8)
}

///|
test "keeps the per-operation and cumulative byte limits independent" {
  let policy = @moonpod.Policy::new(
    ["fs.read"],
    read_roots=["/workspace"],
    max_operation_bytes=6,
    max_io_bytes=10,
  )
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(@moonpod.ReadFile(path="/workspace/first", estimated_bytes=6))
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/second", estimated_bytes=5),
    )
    is @moonpod.Deny(@moonpod.IoBudgetExceeded(limit=10, requested=5)),
  )
}

///|
test "rejects a negative per-operation byte limit" {
  try @moonpod.Policy::new([], max_operation_bytes=-1) catch {
    @moonpod.PolicyConfigError::InvalidLimit(name~, value~) => {
      assert_eq(name, "max_operation_bytes")
      assert_eq(value, -1)
    }
    _ => fail("unexpected configuration error")
  } noraise {
    _ => fail("expected PolicyConfigError")
  }
}
