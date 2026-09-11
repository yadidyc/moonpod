///|
fn command_policy(rule : @moonpod.CommandRule) -> @moonpod.Policy {
  try! @moonpod.Policy::new(["process.run"], command_rules=[rule])
}

///|
test "allows moon test by argument prefix" {
  let rule = @moonpod.CommandRule::new(program="moon", argument_prefix=["test"])
  let session = @moonpod.Session::new(command_policy(rule))
  assert_true(
    session
    .authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["test", "--target", "all"],
        estimated_output_bytes=1024,
      ),
    )
    .is_allowed(),
  )
}

///|
test "rejects moon publish when only test is allowed" {
  let rule = @moonpod.CommandRule::new(program="moon", argument_prefix=["test"])
  let session = @moonpod.Session::new(command_policy(rule))
  assert_true(
    session.authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["publish"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.CommandArgumentsNotAllowed("moon")),
  )
}

///|
test "rejects a disguised executable path" {
  let rule = @moonpod.CommandRule::new(program="moon", argument_prefix=["test"])
  let session = @moonpod.Session::new(command_policy(rule))
  assert_true(
    session.authorize(
      @moonpod.RunCommand(
        program="C:\\tools\\moon.exe",
        arguments=["test"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.CommandNotAllowed("C:\\tools\\moon.exe")),
  )
}

///|
test "copies command prefixes and audited arguments" {
  let prefix = ["test"]
  let arguments = ["test"]
  let rule = @moonpod.CommandRule::new(program="moon", argument_prefix=prefix)
  prefix[0] = "publish"
  let session = @moonpod.Session::new(command_policy(rule))
  assert_true(
    session
    .authorize(
      @moonpod.RunCommand(program="moon", arguments~, estimated_output_bytes=0),
    )
    .is_allowed(),
  )
  arguments[0] = "publish"
  guard session.audit_log()[0].operation is @moonpod.RunCommand(arguments~, ..) else {
    fail("expected an audited command")
  }
  assert_eq(arguments[0], "test")
}

///|
test "empty argument prefix matches only no-argument commands" {
  let rule = @moonpod.CommandRule::new(program="moon", argument_prefix=[])
  let session = @moonpod.Session::new(command_policy(rule))
  assert_true(
    session
    .authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=[],
        estimated_output_bytes=0,
      ),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["publish"],
        estimated_output_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.CommandArgumentsNotAllowed("moon")),
  )
}

///|
test "rejects an empty configured program" {
  try @moonpod.CommandRule::new(program="", argument_prefix=["test"]) catch {
    @moonpod.PolicyConfigError::EmptyCommandProgram => ()
    _ => fail("unexpected configuration error")
  } noraise {
    _ => fail("expected PolicyConfigError")
  }
}
