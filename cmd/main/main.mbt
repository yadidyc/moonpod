///|
fn main {
  let args = @env.args()
  if args.length() <= 1 {
    run_text_demo()
  } else if args.length() == 2 && args[0] == "--policy-json" {
    run_json_policy(args[1])
  } else if args.length() == 3 && args[1] == "--policy-json" {
    run_json_policy(args[2])
  } else if args.length() == 4 &&
    args[0] == "--policy-json" &&
    args[2] == "--operations-json" {
    run_json_batch(args[1], args[3])
  } else if args.length() == 5 &&
    args[1] == "--policy-json" &&
    args[3] == "--operations-json" {
    run_json_batch(args[2], args[4])
  } else {
    println(
      "Usage: moon run cmd/main [-- --policy-json <json-policy> " +
      "--operations-json <json-array>]",
    )
  }
}

///|
fn run_text_demo() -> Unit {
  let policy = @moonpod.workspace_policy("/workspace")
  let session = @moonpod.Session::new(policy)
  println("MoonPod policy demo")
  for operation in demo_operations() {
    let decision = session.authorize(operation)
    println("- \{operation.tool_name()}: \{decision.summary()}")
  }
  println(
    "attempts=\{session.attempts()}, charged_bytes=\{session.used_bytes()}",
  )
  run_generic_resource_demo()
}

///|
fn run_generic_resource_demo() -> Unit {
  let policy = try! @moonpod.Policy::new(["artifact.read"], resource_rules=[
    try! @moonpod.ResourceRule::new(
      tool="artifact.read",
      action="read",
      resource_prefix="workspace/project-a",
    ),
  ])
  let session = @moonpod.Session::new(policy)
  println("Generic resource policy demo")
  for operation in generic_resource_operations() {
    let decision = session.authorize(operation)
    println("- \{operation.tool_name()}: \{decision.summary()}")
  }
}

///|
fn run_json_policy(source : String) -> Unit {
  try {
    let policy = @moonpod.Policy::from_json(source)
    let session = @moonpod.Session::new(policy)
    for operation in demo_operations() {
      ignore(session.authorize(operation))
    }
    println(session.audit_json())
  } catch {
    _ => println("Invalid policy JSON")
  }
}

///|
fn run_json_batch(policy_source : String, operations_source : String) -> Unit {
  try {
    let policy = @moonpod.Policy::from_json(policy_source)
    let operations = @moonpod.Operation::from_json_array(operations_source)
    let session = @moonpod.Session::new(policy)
    for operation in operations {
      ignore(session.authorize(operation))
    }
    println(session.audit_json())
  } catch {
    _ => println("Invalid policy or operations JSON")
  }
}

///|
fn demo_operations() -> Array[@moonpod.Operation] {
  [
    @moonpod.ReadFile(path="/workspace/README.mbt.md", estimated_bytes=2048),
    @moonpod.WriteFile(path="/etc/passwd", bytes=12),
    @moonpod.RunCommand(
      program="moon",
      arguments=["test"],
      estimated_output_bytes=4096,
    ),
    @moonpod.Connect(host="example.com", port=443),
  ]
}

///|
fn generic_resource_operations() -> Array[@moonpod.Operation] {
  [
    @moonpod.ResourceAccess(
      tool="artifact.read",
      action="read",
      resource="workspace/project-a/report.json",
      estimated_bytes=512,
    ),
    @moonpod.ResourceAccess(
      tool="artifact.read",
      action="read",
      resource="workspace/project-b/report.json",
      estimated_bytes=512,
    ),
  ]
}
