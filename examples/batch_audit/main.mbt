///|
/// A library integration that loads the versioned JSON policy and evaluates a
/// batch before handing append-only records to a log sink.
fn main {
  let policy_source = "{\"schema_version\":1,\"allowed_tools\":[\"fs.read\",\"net.connect\"],\"read_roots\":[\"/workspace\"],\"network_rules\":[{\"host\":\"api.example.com\",\"allowed_ports\":[443]}]}"
  let operations_source = "[{\"tool\":\"fs.read\",\"path\":\"/workspace/README.md\",\"estimated_bytes\":128},{\"tool\":\"net.connect\",\"host\":\"api.example.com\",\"port\":443},{\"tool\":\"net.connect\",\"host\":\"api.example.com\",\"port\":22}]"
  let policy = try! @moonpod.Policy::from_json(policy_source)
  let operations = try! @moonpod.Operation::from_json_array(operations_source)
  let session = @moonpod.Session::new(policy)
  for operation in operations {
    ignore(session.authorize(operation))
  }
  println(session.audit_jsonl())
}
