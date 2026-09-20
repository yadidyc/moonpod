///|
test "loads JSON policy rules for paths and network ports" {
  let policy = try
    @moonpod.Policy::from_json(
      "{\"allowed_tools\":[\"fs.read\",\"net.connect\"],\"read_roots\":[\"/workspace\"],\"protected_paths\":[\"/workspace/.env\"],\"network_rules\":[{\"host\":\"api.example.com\",\"allowed_ports\":[443]}],\"max_calls\":8,\"max_operation_bytes\":4096,\"max_io_bytes\":2048}",
    )
  catch {
    @moonpod.PolicyJsonError::InvalidField(name) =>
      fail("invalid field: " + name)
    @moonpod.PolicyJsonError::MissingField(name) =>
      fail("missing field: " + name)
    @moonpod.PolicyJsonError::InvalidPolicy => fail("policy validation failed")
    @moonpod.PolicyJsonError::ExpectedObject => fail("expected JSON object")
    @moonpod.PolicyJsonError::InvalidJson => fail("invalid JSON syntax")
  } noraise {
    policy => policy
  }
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="/workspace/src/main.mbt", estimated_bytes=1),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/.env", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session
    .authorize(@moonpod.Connect(host="api.example.com", port=443))
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="api.example.com", port=22))
    is @moonpod.Deny(@moonpod.PortNotAllowed(host="api.example.com", port=22)),
  )
}

///|
test "rejects malformed JSON policies and required fields" {
  try @moonpod.Policy::from_json("{") catch {
    @moonpod.PolicyJsonError::InvalidJson => ()
    _ => fail("malformed JSON should return InvalidJson")
  } noraise {
    _ => fail("malformed JSON should fail")
  }
  try @moonpod.Policy::from_json("{}") catch {
    @moonpod.PolicyJsonError::MissingField(name) =>
      assert_eq(name, "allowed_tools")
    _ => fail("missing allowlist should be reported")
  } noraise {
    _ => fail("missing allowlist should fail")
  }
}

///|
test "loads command prefixes, tool quotas, and approval requirements" {
  let command_policy = try
    @moonpod.Policy::from_json(
      "{\"allowed_tools\":[\"process.run\"],\"command_rules\":[{\"program\":\"moon\",\"argument_prefix\":[\"test\"]}],\"approval_required_tools\":[\"process.run\"]}",
    )
  catch {
    _ => fail("command policy JSON should load")
  } noraise {
    policy => policy
  }
  let command_session = @moonpod.Session::new(command_policy)
  assert_true(
    command_session.authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["test"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.ApprovalRequired(1),
  )
  assert_true(
    command_session.authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["publish"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.CommandArgumentsNotAllowed("moon")),
  )

  let quota_policy = try
    @moonpod.Policy::from_json(
      "{\"allowed_tools\":[\"fs.read\"],\"read_roots\":[\"/workspace\"],\"tool_quotas\":[{\"tool\":\"fs.read\",\"max_calls\":1}]}",
    )
  catch {
    _ => fail("quota policy JSON should load")
  } noraise {
    policy => policy
  }
  let quota_session = @moonpod.Session::new(quota_policy)
  assert_true(
    quota_session
    .authorize(@moonpod.ReadFile(path="/workspace/a", estimated_bytes=0))
    .is_allowed(),
  )
  assert_true(
    quota_session.authorize(
      @moonpod.ReadFile(path="/workspace/b", estimated_bytes=0),
    )
    is @moonpod.Deny(@moonpod.ToolCallQuotaExceeded(tool="fs.read", limit=1)),
  )
}

///|
test "audit export is valid JSON and escapes operation strings" {
  let session = @moonpod.Session::new(
    @moonpod.Policy::new(["fs.read"], read_roots=["/workspace"]),
  )
  ignore(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/a\"b\n.mbt", estimated_bytes=1),
    ),
  )
  try ignore(@json.parse(session.audit_json())) catch {
    _ => fail("audit export should be parseable JSON")
  } noraise {
    _ => ()
  }
}
