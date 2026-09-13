///|
/// Narrows this policy by intersecting its permissions with `restriction`.
///
/// Allow-lists and path roots are intersected. Protected paths and approval
/// requirements are combined, while numeric limits take the stricter value.
/// A rule present in only one policy cannot grant a permission absent from the
/// other policy.
pub fn Policy::restrict(self : Policy, restriction : Policy) -> Policy {
  {
    allowed_tools: intersect_strings(
      self.allowed_tools,
      restriction.allowed_tools,
    ),
    read_roots: intersect_path_roots(self.read_roots, restriction.read_roots),
    write_roots: intersect_path_roots(self.write_roots, restriction.write_roots),
    protected_paths: union_strings(
      self.protected_paths,
      restriction.protected_paths,
    ),
    network_rules: intersect_network_rules(
      self.network_rules,
      restriction.network_rules,
    ),
    command_rules: intersect_command_rules(
      self.command_rules,
      restriction.command_rules,
    ),
    tool_quotas: intersect_tool_quotas(
      self.tool_quotas,
      restriction.tool_quotas,
    ),
    approval_required_tools: union_strings(
      self.approval_required_tools,
      restriction.approval_required_tools,
    ),
    max_calls: minimum(self.max_calls, restriction.max_calls),
    max_operation_bytes: minimum(
      self.max_operation_bytes,
      restriction.max_operation_bytes,
    ),
    max_io_bytes: minimum(self.max_io_bytes, restriction.max_io_bytes),
  }
}

///|
fn intersect_strings(
  left : Array[String],
  right : Array[String],
) -> Array[String] {
  let result = []
  for value in left {
    if right.contains(value) && !result.contains(value) {
      result.push(value)
    }
  }
  result
}

///|
fn union_strings(left : Array[String], right : Array[String]) -> Array[String] {
  let result = []
  for value in left {
    if !result.contains(value) {
      result.push(value)
    }
  }
  for value in right {
    if !result.contains(value) {
      result.push(value)
    }
  }
  result
}

///|
fn intersect_path_roots(
  left : Array[String],
  right : Array[String],
) -> Array[String] {
  let result = []
  for left_root in left {
    guard normalize_path(left_root) is Some(normalized_left) else { continue }
    for right_root in right {
      guard normalize_path(right_root) is Some(normalized_right) else {
        continue
      }
      let narrower = if normalized_left == normalized_right ||
        path_is_within(normalized_left, [normalized_right]) {
        Some(normalized_left)
      } else if path_is_within(normalized_right, [normalized_left]) {
        Some(normalized_right)
      } else {
        None
      }
      match narrower {
        Some(root) if !result.contains(root) => result.push(root)
        _ => ()
      }
    }
  }
  result
}

///|
fn intersect_network_rules(
  left : Array[NetworkRule],
  right : Array[NetworkRule],
) -> Array[NetworkRule] {
  let result = []
  for left_rule in left {
    for right_rule in right {
      if left_rule.host == right_rule.host {
        let ports = intersect_ints(
          left_rule.allowed_ports,
          right_rule.allowed_ports,
        )
        if ports.length() > 0 {
          result.push({ host: left_rule.host, allowed_ports: ports, })
        }
      }
    }
  }
  result
}

///|
fn intersect_ints(left : Array[Int], right : Array[Int]) -> Array[Int] {
  let result = []
  for value in left {
    if right.contains(value) && !result.contains(value) {
      result.push(value)
    }
  }
  result
}

///|
fn intersect_command_rules(
  left : Array[CommandRule],
  right : Array[CommandRule],
) -> Array[CommandRule] {
  let result = []
  for left_rule in left {
    for right_rule in right {
      if left_rule.program == right_rule.program {
        let left_prefix = left_rule.argument_prefix
        let right_prefix = right_rule.argument_prefix
        let prefix = if left_prefix.length() == 0 && right_prefix.length() == 0 {
          Some([])
        } else if left_prefix.length() == 0 || right_prefix.length() == 0 {
          None
        } else if left_prefix.length() >= right_prefix.length() &&
          left_prefix.starts_with(right_prefix) {
          Some(left_prefix.copy())
        } else if right_prefix.length() >= left_prefix.length() &&
          right_prefix.starts_with(left_prefix) {
          Some(right_prefix.copy())
        } else {
          None
        }
        match prefix {
          Some(argument_prefix) =>
            result.push({ program: left_rule.program, argument_prefix, })
          None => ()
        }
      }
    }
  }
  result
}

///|
fn intersect_tool_quotas(
  left : Array[ToolQuota],
  right : Array[ToolQuota],
) -> Array[ToolQuota] {
  let tools = []
  for quota in left {
    if !tools.contains(quota.tool) {
      tools.push(quota.tool)
    }
  }
  for quota in right {
    if !tools.contains(quota.tool) {
      tools.push(quota.tool)
    }
  }
  let result = []
  for tool in tools {
    match minimum_tool_quota(tool, left, right) {
      Some(max_calls) => result.push({ tool, max_calls, })
      None => ()
    }
  }
  result
}

///|
fn minimum_tool_quota(
  tool : String,
  left : Array[ToolQuota],
  right : Array[ToolQuota],
) -> Int? {
  let mut limit : Int? = None
  for quota in left {
    if quota.tool == tool {
      limit = match limit {
        Some(current) => Some(minimum(current, quota.max_calls))
        None => Some(quota.max_calls)
      }
    }
  }
  for quota in right {
    if quota.tool == tool {
      limit = match limit {
        Some(current) => Some(minimum(current, quota.max_calls))
        None => Some(quota.max_calls)
      }
    }
  }
  limit
}

///|
fn minimum(left : Int, right : Int) -> Int {
  if left < right {
    left
  } else {
    right
  }
}
