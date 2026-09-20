///|
test "allows a read inside its lexical root" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=["/workspace"])
  let session = @moonpod.Session::new(policy)
  let decision = session.authorize(
    @moonpod.ReadFile(path="/workspace/src/main.mbt", estimated_bytes=128),
  )
  assert_true(decision.is_allowed())
  assert_eq(session.used_bytes(), 128)
}

///|
test "rejects traversal and sibling-prefix paths" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=["/workspace"])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace/../secret", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/workspace-other/file", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
}

///|
test "normalizes drive paths, backslashes, and repeated separators" {
  let policy = @moonpod.Policy::new(["fs.write"], write_roots=["C:\\work"])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(@moonpod.WriteFile(path="C:\\work\\\\logs//out.txt", bytes=12))
    .is_allowed(),
  )
}

///|
test "preserves UNC roots without aliasing POSIX paths" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=[
    "\\\\server\\share",
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(
        path="\\\\server\\share\\docs//guide.md",
        estimated_bytes=1,
      ),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/server/share/docs/guide.md", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
}

///|
test "rejects empty paths and traversal beyond every root kind" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=[
    "/safe", "C:\\safe", "\\\\server\\share",
  ])
  let session = @moonpod.Session::new(policy)
  for
    path in [
      "", "/../safe/file", "C:\\..\\safe\\file", "\\\\server\\share\\..\\file",
    ] {
    assert_true(
      session.authorize(@moonpod.ReadFile(path~, estimated_bytes=0))
      is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
    )
  }
}

///|
test "protected paths override allowed workspace roots" {
  let policy = @moonpod.Policy::new(
    ["fs.read", "fs.write"],
    read_roots=["/workspace"],
    write_roots=["/workspace"],
    protected_paths=["/workspace/.git", "/workspace/.env"],
  )
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
      @moonpod.ReadFile(path="/workspace/.git/config", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
  assert_true(
    session.authorize(@moonpod.WriteFile(path="/workspace/.env", bytes=1))
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
}

///|
test "Windows drive paths match protected paths without ASCII case sensitivity" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=["C:\\Work"], protected_paths=[
    "c:\\work\\.git", "C:\\WORK\\.env",
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="c:\\WORK\\src\\main.mbt", estimated_bytes=1),
    )
    .is_allowed(),
  )
  for path in ["C:\\Work\\.GIT\\config", "c:\\work\\.ENV"] {
    assert_true(
      session.authorize(@moonpod.ReadFile(path~, estimated_bytes=1))
      is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
    )
  }
  let drive_policy = @moonpod.Policy::new(["fs.read"], read_roots=["C:\\"], protected_paths=[
    "c:\\Windows\\System32",
  ])
  let drive_session = @moonpod.Session::new(drive_policy)
  assert_true(
    drive_session
    .authorize(
      @moonpod.ReadFile(path="c:\\Users\\public.txt", estimated_bytes=1),
    )
    .is_allowed(),
  )
  assert_true(
    drive_session.authorize(
      @moonpod.ReadFile(path="C:\\WINDOWS\\system32\\config", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
}

///|
test "UNC paths match protected paths without ASCII case sensitivity" {
  let policy = @moonpod.Policy::new(
    ["fs.read"],
    read_roots=["\\\\Server\\Share"],
    protected_paths=["\\\\server\\share\\.env"],
  )
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(
      @moonpod.ReadFile(
        path="\\\\SERVER\\SHARE\\.ENV\\secrets",
        estimated_bytes=1,
      ),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
}

///|
test "POSIX paths remain case sensitive" {
  let policy = @moonpod.Policy::new(["fs.read"], read_roots=["/workspace"], protected_paths=[
    "/workspace/Secret",
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ReadFile(path="/workspace/secret/file", estimated_bytes=1),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ReadFile(path="/Workspace/secret/file", estimated_bytes=1),
    )
    is @moonpod.Deny(@moonpod.PathNotAllowed(_)),
  )
}

///|
test "enforces tool allowlist" {
  let policy = @moonpod.Policy::new([])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(
      @moonpod.Invoke(tool="browser.open", estimated_output_bytes=0),
    )
    is @moonpod.Deny(@moonpod.ToolNotAllowed(_)),
  )
}

///|
test "invalid network rules fail closed" {
  try
    @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[0])
  catch {
    @moonpod.PolicyConfigError::InvalidNetworkPort(port) => assert_eq(port, 0)
    _ => fail("unexpected configuration error")
  } noraise {
    _ => fail("expected PolicyConfigError")
  }
}

///|
test "charges only allowed I/O and enforces byte budget" {
  let policy = @moonpod.Policy::new(
    ["fs.read"],
    read_roots=["/safe"],
    max_io_bytes=10,
  )
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(@moonpod.ReadFile(path="/safe/a", estimated_bytes=7))
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.ReadFile(path="/safe/b", estimated_bytes=4))
    is @moonpod.Deny(@moonpod.IoBudgetExceeded(..)),
  )
  assert_eq(session.used_bytes(), 7)
}

///|
test "denied attempts consume call slots and are audited" {
  let policy = @moonpod.Policy::new(
    ["fs.read"],
    read_roots=["/safe"],
    max_calls=1,
  )
  let session = @moonpod.Session::new(policy)
  ignore(
    session.authorize(@moonpod.ReadFile(path="/outside", estimated_bytes=0)),
  )
  assert_true(
    session.authorize(@moonpod.ReadFile(path="/safe/file", estimated_bytes=0))
    is @moonpod.Deny(@moonpod.CallBudgetExceeded(limit=1)),
  )
  let log = session.audit_log()
  assert_eq(log.length(), 2)
  assert_eq(log[0].sequence, 1)
  assert_eq(log[1].operation.tool_name(), "fs.read")
  assert_eq(session.remaining_calls(), 0)
  assert_eq(session.remaining_bytes(), 1048576)
  log.clear()
  assert_eq(session.audit_log().length(), 2)
}

///|
test "rejects negative byte estimates" {
  let policy = @moonpod.Policy::new(["custom"])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session.authorize(@moonpod.Invoke(tool="custom", estimated_output_bytes=-1))
    is @moonpod.Deny(@moonpod.InvalidByteEstimate(-1)),
  )
}

///|
test "invalid limits raise a typed configuration error" {
  try @moonpod.Policy::new([], max_calls=-1) catch {
    @moonpod.PolicyConfigError::InvalidLimit(name~, value~) => {
      assert_eq(name, "max_calls")
      assert_eq(value, -1)
    }
    _ => fail("unexpected configuration error")
  } noraise {
    _ => fail("expected PolicyConfigError")
  }
}
