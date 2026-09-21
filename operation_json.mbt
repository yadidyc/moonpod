///|
/// Errors returned while decoding an operation JSON document.
pub(all) suberror OperationJsonError {
  InvalidJson
  ExpectedObject
  ExpectedArray
  MissingField(String)
  InvalidField(String)
  UnknownField(String)
} derive(Debug, Eq)

///|
/// Serializes an operation using the same object shape as audit events.
pub fn Operation::to_json(self : Operation) -> String {
  let output = StringBuilder()
  append_operation_json(output, self)
  output.to_string()
}

///|
/// Decodes an operation object emitted by `Operation::to_json`.
///
/// The `tool` field selects one of the built-in operations. Unknown tools with
/// `estimated_output_bytes` decode as `Invoke`; objects with `action` and
/// `resource` decode as `ResourceAccess`.
pub fn Operation::from_json(
  source : String,
) -> Operation raise OperationJsonError {
  let value = @json.parse(source) catch {
    _ => raise OperationJsonError::InvalidJson
  }
  operation_from_json_value(value)
}

///|
/// Decodes a JSON array of operations in input order.
pub fn Operation::from_json_array(
  source : String,
) -> Array[Operation] raise OperationJsonError {
  let value = @json.parse(source) catch {
    _ => raise OperationJsonError::InvalidJson
  }
  match value {
    Json::Array(values) => {
      let operations = []
      for value in values {
        operations.push(operation_from_json_value(value))
      }
      operations
    }
    _ => raise OperationJsonError::ExpectedArray
  }
}

///|
fn operation_from_json_value(
  value : Json,
) -> Operation raise OperationJsonError {
  let fields = operation_json_object(value)
  let tool = operation_required_string(fields, "tool")
  match tool {
    "fs.read" => {
      operation_ensure_known(fields, ["tool", "path", "estimated_bytes"])
      Operation::ReadFile(
        path=operation_required_string(fields, "path"),
        estimated_bytes=operation_required_int(fields, "estimated_bytes"),
      )
    }
    "fs.write" => {
      operation_ensure_known(fields, ["tool", "path", "bytes"])
      Operation::WriteFile(
        path=operation_required_string(fields, "path"),
        bytes=operation_required_int(fields, "bytes"),
      )
    }
    "net.connect" => {
      operation_ensure_known(fields, ["tool", "host", "port"])
      Operation::Connect(
        host=operation_required_string(fields, "host"),
        port=operation_required_int(fields, "port"),
      )
    }
    "process.run" => {
      operation_ensure_known(fields, [
        "tool", "program", "arguments", "estimated_output_bytes",
      ])
      Operation::RunCommand(
        program=operation_required_string(fields, "program"),
        arguments=operation_required_string_array(fields, "arguments"),
        estimated_output_bytes=operation_required_int(
          fields, "estimated_output_bytes",
        ),
      )
    }
    _ =>
      if operation_has_field(fields, "action") ||
        operation_has_field(fields, "resource") {
        operation_ensure_known(fields, [
          "tool", "action", "resource", "estimated_bytes",
        ])
        Operation::ResourceAccess(
          tool~,
          action=operation_required_string(fields, "action"),
          resource=operation_required_string(fields, "resource"),
          estimated_bytes=operation_required_int(fields, "estimated_bytes"),
        )
      } else {
        operation_ensure_known(fields, ["tool", "estimated_output_bytes"])
        Operation::Invoke(
          tool~,
          estimated_output_bytes=operation_required_int(
            fields, "estimated_output_bytes",
          ),
        )
      }
  }
}

///|
fn operation_json_object(
  value : Json,
) -> Map[String, Json] raise OperationJsonError {
  match value {
    Json::Object(fields) => fields
    _ => raise OperationJsonError::ExpectedObject
  }
}

///|
fn operation_required_json(
  fields : Map[String, Json],
  name : String,
) -> Json raise OperationJsonError {
  match fields.get(name) {
    Some(value) => value
    None => raise OperationJsonError::MissingField(name)
  }
}

///|
fn operation_required_string(
  fields : Map[String, Json],
  name : String,
) -> String raise OperationJsonError {
  match operation_required_json(fields, name) {
    Json::String(value) => value
    _ => raise OperationJsonError::InvalidField(name)
  }
}

///|
fn operation_required_string_array(
  fields : Map[String, Json],
  name : String,
) -> Array[String] raise OperationJsonError {
  match operation_required_json(fields, name) {
    Json::Array(values) => {
      let result = []
      for value in values {
        match value {
          Json::String(text) => result.push(text)
          _ => raise OperationJsonError::InvalidField(name)
        }
      }
      result
    }
    _ => raise OperationJsonError::InvalidField(name)
  }
}

///|
fn operation_required_int(
  fields : Map[String, Json],
  name : String,
) -> Int raise OperationJsonError {
  match operation_required_json(fields, name) {
    Json::Number(number, ..) => {
      let integer = number.to_int()
      if integer.to_double() == number {
        integer
      } else {
        raise OperationJsonError::InvalidField(name)
      }
    }
    _ => raise OperationJsonError::InvalidField(name)
  }
}

///|
fn operation_has_field(fields : Map[String, Json], name : String) -> Bool {
  fields.get(name) is Some(_)
}

///|
fn operation_ensure_known(
  fields : Map[String, Json],
  known : Array[String],
) -> Unit raise OperationJsonError {
  for name, _ in fields {
    if !known.contains(name) {
      raise OperationJsonError::UnknownField(name)
    }
  }
}
