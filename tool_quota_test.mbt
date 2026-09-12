///|
test "enforces independent per-tool call quotas" {
  let policy = @moonpod.Policy::new(
    ["fs.read", "fs.write"],
    read_roots=["/workspace"],
    write_roots=["/workspace"],
    tool_quotas=[@moonpod.ToolQuota::new(tool="fs.read", max_calls=1)],
  )
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(@moonpod.ReadFile(path="/workspace/main.mbt", estimated_bytes=1))
    .is_allowed(),
  )
  assert_true(
    session
    .authorize(@moonpod.WriteFile(path="/workspace/out.txt", bytes=1))
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/other.mbt", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.ToolCallQuotaExceeded(tool="fs.read", limit=1)),
  )
}

///|
test "denied attempts consume their tool quota" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=["/workspace"], tool_quotas=[
    @moonpod.ToolQuota::new(tool="fs.read", max_calls=1),
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/outside/secret", estimated_bytes=0),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/main.mbt", estimated_bytes=0),
    )
    is @moonpod.Deny(@moonpod.ToolCallQuotaExceeded(tool="fs.read", limit=1)),
  )
}

///|
test "rejects invalid tool quota configuration" {
  try @moonpod.ToolQuota::new(tool="", max_calls=1) catch {
    @moonpod.PolicyConfigError::EmptyToolQuotaName => ()
    _ => fail("unexpected configuration error")
  } noraise {
    _ => fail("expected PolicyConfigError")
  }
  try @moonpod.ToolQuota::new(tool="fs.read", max_calls=-1) catch {
    @moonpod.PolicyConfigError::InvalidLimit(name~, value~) => {
      assert_eq(name, "tool quota: fs.read")
      assert_eq(value, -1)
    }
    _ => fail("unexpected configuration error")
  } noraise {
    _ => fail("expected PolicyConfigError")
  }
}
