///|
/// A minimal host-side integration: map requests to operations, authorize
/// them, and execute side effects only after an allow decision.
fn main {
  let policy = try! @moonpod.Policy::new(
    ["fs.read", "process.run", "net.connect"],
    read_roots=["/workspace"],
    protected_paths=["/workspace/.env"],
    command_rules=[
      try! @moonpod.CommandRule::new(program="moon", argument_prefix=["test"]),
    ],
    network_rules=[
      try! @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[443]),
    ],
    max_io_bytes=4096,
  )
  let session = @moonpod.Session::new(policy)
  let requests : Array[@moonpod.Operation] = [
    @moonpod.ReadFile(path="/workspace/src/main.mbt", estimated_bytes=128),
    @moonpod.ReadFile(path="/workspace/.env", estimated_bytes=32),
    @moonpod.RunCommand(
      program="moon",
      arguments=["test"],
      estimated_output_bytes=256,
    ),
    @moonpod.RunCommand(
      program="moon",
      arguments=["publish"],
      estimated_output_bytes=256,
    ),
    @moonpod.Connect(host="api.example.com", port=443),
  ]
  println("MoonPod host integration")
  for request in requests {
    let decision = session.authorize(request)
    println("- \{request.tool_name()}: \{decision.summary()}")
    if decision.is_allowed() {
      println("  host action: would execute")
    } else {
      println("  host action: blocked")
    }
  }
  println("audit records:")
  println(session.audit_jsonl())
}
