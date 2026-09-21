///|
/// Errors returned while decoding a JSON policy document.
pub(all) suberror PolicyJsonError {
  InvalidJson
  ExpectedObject
  MissingField(String)
  InvalidField(String)
  UnsupportedSchemaVersion(Int)
  UnknownField(String)
  InvalidPolicy
} derive(Debug, Eq)

///|
/// Builds a policy from a JSON document.
///
/// The document must declare `"schema_version": 1`. Unknown fields are
/// rejected so a typo cannot silently weaken a policy. `allowed_tools` is
/// required; other array fields default to empty and numeric limits use the
/// same defaults as `Policy::new`.
pub fn Policy::from_json(source : String) -> Policy raise PolicyJsonError {
  let value = @json.parse(source) catch {
    _ => raise PolicyJsonError::InvalidJson
  }
  let fields = json_object(value)
  ensure_known_fields(
    fields,
    [
      "schema_version", "allowed_tools", "read_roots", "write_roots", "protected_paths",
      "network_rules", "command_rules", "resource_rules", "tool_quotas", "max_calls",
      "max_operation_bytes", "max_io_bytes", "approval_required_tools",
    ],
    "",
  )
  let schema_version = required_int(fields, "schema_version")
  if schema_version != 1 {
    raise PolicyJsonError::UnsupportedSchemaVersion(schema_version)
  }
  let allowed_tools = required_string_array(fields, "allowed_tools")
  let read_roots = optional_string_array(fields, "read_roots")
  let write_roots = optional_string_array(fields, "write_roots")
  let protected_paths = optional_string_array(fields, "protected_paths")
  let approval_required_tools = optional_string_array(
    fields, "approval_required_tools",
  )
  let network_rules = []
  for value in optional_array(fields, "network_rules") {
    let rule_fields = json_object(value)
    ensure_known_fields(rule_fields, ["host", "allowed_ports"], "network_rules")
    let host = required_string(rule_fields, "host")
    let allowed_ports = required_int_array(rule_fields, "allowed_ports")
    let rule = NetworkRule::new(host~, allowed_ports~) catch {
      _ => raise PolicyJsonError::InvalidField("network_rules")
    }
    network_rules.push(rule)
  }
  let command_rules = []
  for value in optional_array(fields, "command_rules") {
    let rule_fields = json_object(value)
    ensure_known_fields(
      rule_fields,
      ["program", "argument_prefix"],
      "command_rules",
    )
    let program = required_string(rule_fields, "program")
    let argument_prefix = required_string_array(rule_fields, "argument_prefix")
    let rule = CommandRule::new(program~, argument_prefix~) catch {
      _ => raise PolicyJsonError::InvalidField("command_rules")
    }
    command_rules.push(rule)
  }
  let resource_rules = []
  for value in optional_array(fields, "resource_rules") {
    let rule_fields = json_object(value)
    ensure_known_fields(
      rule_fields,
      ["tool", "action", "resource_prefix"],
      "resource_rules",
    )
    let tool = required_string(rule_fields, "tool")
    let action = required_string(rule_fields, "action")
    let resource_prefix = required_string(rule_fields, "resource_prefix")
    let rule = ResourceRule::new(tool~, action~, resource_prefix~) catch {
      _ => raise PolicyJsonError::InvalidField("resource_rules")
    }
    resource_rules.push(rule)
  }
  let tool_quotas = []
  for value in optional_array(fields, "tool_quotas") {
    let quota_fields = json_object(value)
    ensure_known_fields(quota_fields, ["tool", "max_calls"], "tool_quotas")
    let tool = required_string(quota_fields, "tool")
    let max_calls = required_int(quota_fields, "max_calls")
    let quota = ToolQuota::new(tool~, max_calls~) catch {
      _ => raise PolicyJsonError::InvalidField("tool_quotas")
    }
    tool_quotas.push(quota)
  }
  let max_calls = optional_int(fields, "max_calls", 100)
  let max_operation_bytes = optional_int(fields, "max_operation_bytes", 1048576)
  let max_io_bytes = optional_int(fields, "max_io_bytes", 1048576)
  Policy::new(
    allowed_tools,
    read_roots~,
    write_roots~,
    protected_paths~,
    network_rules~,
    command_rules~,
    tool_quotas~,
    max_calls~,
    max_operation_bytes~,
    max_io_bytes~,
    approval_required_tools~,
    resource_rules~,
  ) catch {
    _ => raise PolicyJsonError::InvalidPolicy
  }
}

///|
fn ensure_known_fields(
  fields : Map[String, Json],
  known : Array[String],
  context : String,
) -> Unit raise PolicyJsonError {
  for name, _ in fields {
    if !known.contains(name) {
      let full_name = if context == "" { name } else { context + "." + name }
      raise PolicyJsonError::UnknownField(full_name)
    }
  }
}

///|
fn json_object(value : Json) -> Map[String, Json] raise PolicyJsonError {
  match value {
    Json::Object(fields) => fields
    _ => raise PolicyJsonError::ExpectedObject
  }
}

///|
fn required_json(
  fields : Map[String, Json],
  name : String,
) -> Json raise PolicyJsonError {
  match fields.get(name) {
    Some(value) => value
    None => raise PolicyJsonError::MissingField(name)
  }
}

///|
fn required_string(
  fields : Map[String, Json],
  name : String,
) -> String raise PolicyJsonError {
  match required_json(fields, name) {
    Json::String(value) => value
    _ => raise PolicyJsonError::InvalidField(name)
  }
}

///|
fn optional_string_array(
  fields : Map[String, Json],
  name : String,
) -> Array[String] raise PolicyJsonError {
  match fields.get(name) {
    None => []
    Some(value) => json_string_array(value, name)
  }
}

///|
fn required_string_array(
  fields : Map[String, Json],
  name : String,
) -> Array[String] raise PolicyJsonError {
  json_string_array(required_json(fields, name), name)
}

///|
fn json_string_array(
  value : Json,
  name : String,
) -> Array[String] raise PolicyJsonError {
  match value {
    Json::Array(values) => {
      let result = []
      for item in values {
        match item {
          Json::String(text) => result.push(text)
          _ => raise PolicyJsonError::InvalidField(name)
        }
      }
      result
    }
    _ => raise PolicyJsonError::InvalidField(name)
  }
}

///|
fn optional_array(
  fields : Map[String, Json],
  name : String,
) -> Array[Json] raise PolicyJsonError {
  match fields.get(name) {
    None => []
    Some(Json::Array(values)) => values
    Some(_) => raise PolicyJsonError::InvalidField(name)
  }
}

///|
fn required_int_array(
  fields : Map[String, Json],
  name : String,
) -> Array[Int] raise PolicyJsonError {
  match required_json(fields, name) {
    Json::Array(values) => {
      let result = []
      for value in values {
        result.push(json_int(value, name))
      }
      result
    }
    _ => raise PolicyJsonError::InvalidField(name)
  }
}

///|
fn optional_int(
  fields : Map[String, Json],
  name : String,
  default : Int,
) -> Int raise PolicyJsonError {
  match fields.get(name) {
    None => default
    Some(value) => json_int(value, name)
  }
}

///|
fn required_int(
  fields : Map[String, Json],
  name : String,
) -> Int raise PolicyJsonError {
  json_int(required_json(fields, name), name)
}

///|
fn json_int(value : Json, name : String) -> Int raise PolicyJsonError {
  match value {
    Json::Number(number, ..) => {
      let integer = number.to_int()
      if integer.to_double() == number {
        integer
      } else {
        raise PolicyJsonError::InvalidField(name)
      }
    }
    _ => raise PolicyJsonError::InvalidField(name)
  }
}

///|
/// Serializes a session summary and its audit events as JSON.
pub fn Session::audit_json(self : Session) -> String {
  let output = StringBuilder()
  output.write_string("{\n  \"attempts\": ")
  output.write_string(self.attempts().to_string())
  output.write_string(",\n  \"used_bytes\": ")
  output.write_string(self.used_bytes().to_string())
  output.write_string(",\n  \"remaining_calls\": ")
  output.write_string(self.remaining_calls().to_string())
  output.write_string(",\n  \"remaining_bytes\": ")
  output.write_string(self.remaining_bytes().to_string())
  output.write_string(",\n  \"events\": [")
  let first = Ref(true)
  for event in self.audit_log() {
    if first.val {
      first.val = false
    } else {
      output.write_char(',')
    }
    output.write_string("\n    ")
    append_audit_event_json(output, event)
  }
  if !first.val {
    output.write_char('\n')
    output.write_string("  ")
  }
  output.write_string("]\n}")
  output.to_string()
}

///|
fn append_audit_event_json(output : StringBuilder, event : AuditEvent) -> Unit {
  output.write_string("{\"sequence\": ")
  output.write_string(event.sequence.to_string())
  output.write_string(", \"operation\": ")
  output.write_string(event.operation.to_json())
  output.write_string(", \"decision\": ")
  append_json_string(output, event.decision.summary())
  output.write_string(", \"charged_bytes\": ")
  output.write_string(event.charged_bytes.to_string())
  output.write_char('}')
}

///|
fn append_operation_json(output : StringBuilder, operation : Operation) -> Unit {
  match operation {
    ReadFile(path~, estimated_bytes~) => {
      output.write_string("{\"tool\": \"fs.read\", \"path\": ")
      append_json_string(output, path)
      output.write_string(", \"estimated_bytes\": ")
      output.write_string(estimated_bytes.to_string())
      output.write_char('}')
    }
    WriteFile(path~, bytes~) => {
      output.write_string("{\"tool\": \"fs.write\", \"path\": ")
      append_json_string(output, path)
      output.write_string(", \"bytes\": ")
      output.write_string(bytes.to_string())
      output.write_char('}')
    }
    Connect(host~, port~) => {
      output.write_string("{\"tool\": \"net.connect\", \"host\": ")
      append_json_string(output, host)
      output.write_string(", \"port\": ")
      output.write_string(port.to_string())
      output.write_char('}')
    }
    RunCommand(program~, arguments~, estimated_output_bytes~) => {
      output.write_string("{\"tool\": \"process.run\", \"program\": ")
      append_json_string(output, program)
      output.write_string(", \"arguments\": [")
      let first = Ref(true)
      for argument in arguments {
        if first.val {
          first.val = false
        } else {
          output.write_string(", ")
        }
        append_json_string(output, argument)
      }
      output.write_string("], \"estimated_output_bytes\": ")
      output.write_string(estimated_output_bytes.to_string())
      output.write_char('}')
    }
    Invoke(tool~, estimated_output_bytes~) => {
      output.write_string("{\"tool\": ")
      append_json_string(output, tool)
      output.write_string(", \"estimated_output_bytes\": ")
      output.write_string(estimated_output_bytes.to_string())
      output.write_char('}')
    }
    ResourceAccess(tool~, action~, resource~, estimated_bytes~) => {
      output.write_string("{\"tool\": ")
      append_json_string(output, tool)
      output.write_string(", \"action\": ")
      append_json_string(output, action)
      output.write_string(", \"resource\": ")
      append_json_string(output, resource)
      output.write_string(", \"estimated_bytes\": ")
      output.write_string(estimated_bytes.to_string())
      output.write_char('}')
    }
  }
}

///|
fn append_json_string(output : StringBuilder, value : String) -> Unit {
  output.write_char('"')
  for char in value {
    match char {
      '"' => output.write_string("\\\"")
      '\\' => output.write_string("\\\\")
      '\b' => output.write_string("\\b")
      '\f' => output.write_string("\\f")
      '\n' => output.write_string("\\n")
      '\r' => output.write_string("\\r")
      '\t' => output.write_string("\\t")
      _ => {
        let code = char.to_int()
        if code < 0x20 {
          output.write_string("\\u00")
          output.write_char(hex_digit(code / 16))
          output.write_char(hex_digit(code % 16))
        } else {
          output.write_char(char)
        }
      }
    }
  }
  output.write_char('"')
}

///|
fn hex_digit(value : Int) -> Char {
  match value {
    0 => '0'
    1 => '1'
    2 => '2'
    3 => '3'
    4 => '4'
    5 => '5'
    6 => '6'
    7 => '7'
    8 => '8'
    9 => '9'
    10 => 'a'
    11 => 'b'
    12 => 'c'
    13 => 'd'
    14 => 'e'
    15 => 'f'
    _ => '0'
  }
}
