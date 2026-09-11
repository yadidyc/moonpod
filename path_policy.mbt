///|
/// Normalizes portable lexical paths without touching the host filesystem.
/// Going above the lexical root is rejected.
fn normalize_path(raw : String) -> String? {
  let path = raw.replace_all(old="\\", new="/")
  guard path != "" else { return None }
  let absolute = path.has_prefix("/")
  let parts : Array[String] = []
  for part in path.split("/") {
    let segment = part.to_owned()
    match segment {
      "" | "." => ()
      ".." => if parts.pop() is None { return None }
      _ => parts.push(segment)
    }
  }
  if parts.length() == 0 {
    if absolute {
      Some("/")
    } else {
      None
    }
  } else {
    let joined = parts.iter().join("/")
    if absolute {
      Some("/" + joined)
    } else {
      Some(joined)
    }
  }
}

///|
fn path_is_within(path : String, roots : Array[String]) -> Bool {
  guard normalize_path(path) is Some(candidate) else { return false }
  for raw_root in roots {
    guard normalize_path(raw_root) is Some(root) else { continue }
    if root == "/" && candidate.has_prefix("/") {
      return true
    }
    if candidate == root || candidate.has_prefix(root + "/") {
      return true
    }
  }
  false
}
