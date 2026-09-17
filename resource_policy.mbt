///|
/// A reusable rule for a tool's action on a resource namespace.
///
/// `resource_prefix` uses slash-separated identifiers. A request matches when
/// its resource is exactly the prefix or is a descendant below that prefix.
/// This makes the same rule useful for plugin IDs, service paths, workspace
/// objects, and other host-defined resource names.
pub struct ResourceRule {
  tool : String
  action : String
  resource_prefix : String
} derive(Debug, Eq)

///|
/// Creates a validated resource rule.
pub fn ResourceRule::new(
  tool~ : String,
  action~ : String,
  resource_prefix~ : String,
) -> ResourceRule raise PolicyConfigError {
  if tool == "" {
    raise PolicyConfigError::EmptyResourceRuleTool
  }
  if action == "" {
    raise PolicyConfigError::EmptyResourceRuleAction
  }
  if resource_prefix == "" {
    raise PolicyConfigError::EmptyResourceRulePrefix
  }
  { tool, action, resource_prefix, }
}

///|
fn ResourceRule::matches(
  self : ResourceRule,
  tool : String,
  action : String,
  resource : String,
) -> Bool {
  self.tool == tool &&
  self.action == action &&
  (
    resource == self.resource_prefix ||
    resource.has_prefix(self.resource_prefix + "/")
  )
}
