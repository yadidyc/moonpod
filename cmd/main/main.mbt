///|
fn main {
  let policy = @moonpod.workspace_policy("/workspace")
  let session = @moonpod.Session::new(policy)
  let operations = [
    @moonpod.ReadFile(path="/workspace/README.mbt.md", estimated_bytes=2048),
    @moonpod.WriteFile(path="/etc/passwd", bytes=12),
    @moonpod.RunCommand(program="moon", estimated_output_bytes=4096),
    @moonpod.Connect(host="example.com", port=443),
  ]
  println("MoonPod policy demo")
  for operation in operations {
    let decision = session.authorize(operation)
    println("- \{operation.tool_name()}: \{decision.summary()}")
  }
  println(
    "attempts=\{session.attempts()}, charged_bytes=\{session.used_bytes()}",
  )
}
