///|
test "policy restriction intersects tools roots and protected paths" {
  let base = @moonpod.Policy::new(
    ["fs.read", "fs.write", "custom"],
    read_roots=["/workspace"],
    write_roots=["/workspace"],
    protected_paths=["/workspace/.git"],
    max_calls=10,
    max_operation_bytes=100,
    max_io_bytes=100,
  )
  let restriction = @moonpod.Policy::new(
    ["fs.read", "fs.write"],
    read_roots=["/workspace/src"],
    write_roots=["/workspace/output"],
    protected_paths=["/workspace/src/private"],
    max_calls=3,
    max_operation_bytes=8,
    max_io_bytes=12,
  )
  let policy = base.restrict(restriction)
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="/workspace/src/main.mbt", estimated_bytes=8),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/README.md", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/src/private/key", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  let write_session = @moonpod.Session::new(policy)
  assert_true(
    write_session
    .authorize(@moonpod.WriteFile(path="/workspace/output/result", bytes=1))
    .is_allowed(),
  )
  assert_true(
    write_session.authorize(
      @moonpod.WriteFile(path="/workspace/other/result", bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  let operation_session = @moonpod.Session::new(policy)
  assert_true(
    operation_session.authorize(
      @moonpod.ReadFile(path="/workspace/src/c", estimated_bytes=9),
    )
    is @moonpod.Deny(@moonpod.OperationByteLimitExceeded(limit=8, requested=9)),
  )
  let byte_session = @moonpod.Session::new(policy)
  assert_true(
    byte_session
    .authorize(@moonpod.ReadFile(path="/workspace/src/a", estimated_bytes=8))
    .is_allowed(),
  )
  assert_true(
    byte_session.authorize(
      @moonpod.ReadFile(path="/workspace/src/b", estimated_bytes=5),
    )
    is @moonpod.Deny(@moonpod.IoBudgetExceeded(limit=12, requested=5)),
  )
  let tool_session = @moonpod.Session::new(policy)
  assert_true(
    tool_session.authorize(
      @moonpod.Invoke(tool="custom", estimated_output_bytes=0),
    )
    is @moonpod.Deny(@moonpod.ToolNotAllowed("custom")),
  )
  assert_true(
    session.authorize(
      @moonpod.WriteFile(path="/workspace/output/result", bytes=1),
    )
    is @moonpod.Deny(@moonpod.CallBudgetExceeded(limit=3)),
  )
}

///|
test "policy restriction intersects network command and quota rules" {
  let base = @moonpod.Policy::new(
    ["net.connect", "process.run", "custom"],
    network_rules=[
      @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[
        443, 8443,
      ]),
    ],
    command_rules=[
      @moonpod.CommandRule::new(program="moon", argument_prefix=["test"]),
    ],
    tool_quotas=[@moonpod.ToolQuota::new(tool="custom", max_calls=5)],
  )
  let restriction = @moonpod.Policy::new(
    ["net.connect", "process.run", "custom"],
    network_rules=[
      @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[443, 22]),
    ],
    command_rules=[
      @moonpod.CommandRule::new(program="moon", argument_prefix=[
        "test", "--target",
      ]),
    ],
    tool_quotas=[@moonpod.ToolQuota::new(tool="custom", max_calls=1)],
    approval_required_tools=["custom"],
  )
  let session = @moonpod.Session::new(base.restrict(restriction))
  assert_true(
    session
    .authorize(@moonpod.Connect(host="api.example.com", port=443))
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="api.example.com", port=8443))
    is @moonpod.Deny(@moonpod.PortNotAllowed(host="api.example.com", port=8443)),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="api.example.com", port=22))
    is @moonpod.Deny(@moonpod.PortNotAllowed(host="api.example.com", port=22)),
  )
  assert_true(
    session
    .authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["test", "--target", "native"],
        estimated_output_bytes=0,
      ),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["test"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.CommandArgumentsNotAllowed("moon")),
  )
  assert_true(
    session.authorize(@moonpod.Invoke(tool="custom", estimated_output_bytes=0))
    is @moonpod.ApprovalRequired(6),
  )
  assert_true(session.approve(6).is_allowed())
  assert_true(
    session.authorize(@moonpod.Invoke(tool="custom", estimated_output_bytes=0))
    is @moonpod.Deny(@moonpod.ToolCallQuotaExceeded(tool="custom", limit=1)),
  )
}

///|
test "an empty base policy cannot be widened by restriction" {
  let base = @moonpod.Policy::new(["fs.read", "net.connect"])
  let broader = @moonpod.Policy::new(
    ["fs.read", "fs.write", "net.connect"],
    read_roots=["/workspace"],
    write_roots=["/workspace"],
    network_rules=[
      @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[443]),
    ],
  )
  let session = @moonpod.Session::new(base.restrict(broader))
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/main.mbt", estimated_bytes=0),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed("/workspace/main.mbt")),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="api.example.com", port=443))
    is @moonpod.Deny(@moonpod.HostNotAllowed("api.example.com")),
  )
  assert_true(
    session.authorize(@moonpod.WriteFile(path="/workspace/output", bytes=0))
    is @moonpod.Deny(@moonpod.ToolNotAllowed("fs.write")),
  )
}
