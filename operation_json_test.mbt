///|
fn decode_operation(source : String) -> @moonpod.Operation raise {
  try @moonpod.Operation::from_json(source) catch {
    _ => fail("operation JSON should decode")
  } noraise {
    operation => operation
  }
}

///|
test "operation JSON codecs round trip built-in and generic operations" {
  let operations : Array[@moonpod.Operation] = [
    @moonpod.ReadFile(path="/workspace/src/main.mbt", estimated_bytes=12),
    @moonpod.WriteFile(path="/workspace/out.txt", bytes=7),
    @moonpod.Connect(host="api.example.com", port=443),
    @moonpod.RunCommand(
      program="moon",
      arguments=["test", "--target", "all"],
      estimated_output_bytes=2048,
    ),
    @moonpod.Invoke(tool="calendar.read", estimated_output_bytes=64),
    @moonpod.ResourceAccess(
      tool="artifact.read",
      action="read",
      resource="workspace/project-a/report.json",
      estimated_bytes=128,
    ),
  ]
  for operation in operations {
    assert_eq(decode_operation(operation.to_json()), operation)
  }
}

///|
test "operation JSON codecs reject malformed and unknown fields" {
  try @moonpod.Operation::from_json("[]") catch {
    @moonpod.OperationJsonError::ExpectedObject => ()
    _ => fail("an operation must be a JSON object")
  } noraise {
    _ => fail("an array should not decode as an operation")
  }
  try @moonpod.Operation::from_json("{\"tool\":\"fs.read\"}") catch {
    @moonpod.OperationJsonError::MissingField(name) => assert_eq(name, "path")
    _ => fail("missing operation fields should be reported")
  } noraise {
    _ => fail("missing operation fields should fail")
  }
  try
    @moonpod.Operation::from_json(
      "{\"tool\":\"fs.read\",\"path\":\"/workspace/a\",\"estimated_bytes\":1,\"extra\":true}",
    )
  catch {
    @moonpod.OperationJsonError::UnknownField(name) => assert_eq(name, "extra")
    _ => fail("unknown operation fields should be rejected")
  } noraise {
    _ => fail("unknown operation fields should fail")
  }
}

///|
test "operation JSON codecs decode ordered batches" {
  let operations = @moonpod.Operation::from_json_array(
    "[{\"tool\":\"net.connect\",\"host\":\"api.example.com\",\"port\":443},{\"tool\":\"calendar.read\",\"estimated_output_bytes\":2}]",
  )
  assert_eq(operations.length(), 2)
  assert_true(
    operations[0] is @moonpod.Connect(host="api.example.com", port=443),
  )
  assert_true(
    operations[1]
    is @moonpod.Invoke(tool="calendar.read", estimated_output_bytes=2),
  )
  try @moonpod.Operation::from_json_array("{}") catch {
    @moonpod.OperationJsonError::ExpectedArray => ()
    _ => fail("a batch must be a JSON array")
  } noraise {
    _ => fail("an object should not decode as a batch")
  }
}
