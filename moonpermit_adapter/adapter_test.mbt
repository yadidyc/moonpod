///|
test "converts tree and command-prefix grants without widening" {
  let permit = @moonpermit.compile_plan("host", [
    @moonpermit.effect_request(
      @moonpermit.FileRead(@moonpermit.path_tree("workspace")),
      @moonpermit.budget(max_calls=2, max_bytes=100),
    ),
    @moonpermit.effect_request(
      @moonpermit.ProcessExec(@moonpermit.command_prefix("moon", ["test"])),
      @moonpermit.budget(max_calls=2, max_bytes=40),
    ),
  ])
  let policy = @moonpermit_adapter.policy_from_permit(permit, protected_paths=[
    "workspace/.env",
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="workspace/src/main.mbt", estimated_bytes=20),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="workspace/.env", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session
    .authorize(
      @moonpod.RunCommand(
        program="moon",
        arguments=["test", "--target", "all"],
        estimated_output_bytes=20,
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
    is @moonpod.Deny(@moonpod.CommandArgumentsNotAllowed(_)),
  )
}

///|
test "rejects permit constraints that MoonPod cannot preserve" {
  let exact_path = @moonpermit.compile_plan("exact", [
    @moonpermit.effect_request(
      @moonpermit.FileRead(@moonpermit.path_exact("workspace/README.md")),
      @moonpermit.unlimited_budget(),
    ),
  ])
  try @moonpermit_adapter.policy_from_permit(exact_path) catch {
    @moonpermit_adapter.PermitAdapterError::ExactPathUnsupported(..) => ()
    _ => fail("expected exact path rejection")
  } noraise {
    _ => fail("exact paths must fail closed")
  }

  let secret = @moonpermit.compile_plan("secret", [
    @moonpermit.effect_request(
      @moonpermit.SecretRead("API_TOKEN"),
      @moonpermit.unlimited_budget(),
    ),
  ])
  try @moonpermit_adapter.policy_from_permit(secret) catch {
    @moonpermit_adapter.PermitAdapterError::UnsupportedEffect(
      effect="secret.read",
      ..
    ) => ()
    _ => fail("expected secret effect rejection")
  } noraise {
    _ => fail("secret effects must fail closed")
  }
}

///|
test "rejects expiry and duplicate grants for one MoonPod tool" {
  let expiring = @moonpermit.compile_plan("expiring", [
    @moonpermit.effect_request(
      @moonpermit.FileRead(@moonpermit.path_tree("workspace")),
      @moonpermit.budget(expires_at=10),
    ),
  ])
  try @moonpermit_adapter.policy_from_permit(expiring) catch {
    @moonpermit_adapter.PermitAdapterError::ExpiringGrantUnsupported(..) => ()
    _ => fail("expected expiry rejection")
  } noraise {
    _ => fail("expiry must fail closed")
  }

  let duplicate = @moonpermit.compile_plan("duplicate", [
    @moonpermit.effect_request(
      @moonpermit.FileRead(@moonpermit.path_tree("src")),
      @moonpermit.budget(max_calls=1),
    ),
    @moonpermit.effect_request(
      @moonpermit.FileRead(@moonpermit.path_tree("docs")),
      @moonpermit.budget(max_calls=1),
    ),
  ])
  try @moonpermit_adapter.policy_from_permit(duplicate) catch {
    @moonpermit_adapter.PermitAdapterError::MultipleGrantsForTool(
      tool="fs.read"
    ) => ()
    _ => fail("expected duplicate tool rejection")
  } noraise {
    _ => fail("multiple grants for one tool must fail closed")
  }
}
