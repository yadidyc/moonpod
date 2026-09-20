///|
/// Normalizes portable lexical paths without touching the host filesystem.
/// Going above the lexical root is rejected. Drive-letter and UNC paths use
/// ASCII case folding; POSIX and relative paths remain case sensitive.
fn normalize_path(raw : String) -> String? {
  let path = raw.replace_all(old="\\", new="/")
  guard path != "" else { return None }
  let drive_absolute = path.length() >= 3 &&
    path[1] == ':' &&
    path[2] == '/' &&
    ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
  if path.length() >= 2 && path[1] == ':' && !drive_absolute {
    return None
  }
  let unc = path.has_prefix("//")
  let absolute = !drive_absolute && !unc && path.has_prefix("/")
  let root_depth = if drive_absolute { 1 } else if unc { 2 } else { 0 }
  let parts : Array[String] = []
  for part in path.split("/") {
    let segment = part.to_owned()
    match segment {
      "" | "." => ()
      ".." => {
        if parts.length() <= root_depth {
          return None
        }
        ignore(parts.pop())
      }
      _ => parts.push(segment)
    }
  }
  if unc && parts.length() < 2 {
    None
  } else if drive_absolute && parts.length() == 1 {
    Some((parts[0] + "/").to_lower())
  } else if parts.length() == 0 {
    if absolute {
      Some("/")
    } else {
      None
    }
  } else {
    let joined = parts.iter().join("/")
    let normalized = if unc {
      Some("//" + joined)
    } else if absolute {
      Some("/" + joined)
    } else {
      Some(joined)
    }
    match normalized {
      Some(value) if drive_absolute || unc => Some(value.to_lower())
      _ => normalized
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
    let drive_root = root.length() == 3 && root[1] == ':' && root[2] == '/'
    if drive_root && candidate.has_prefix(root) {
      return true
    }
    if candidate == root || candidate.has_prefix(root + "/") {
      return true
    }
  }
  false
}

///|
fn path_is_allowed(
  path : String,
  roots : Array[String],
  protected_paths : Array[String],
) -> Bool {
  path_is_within(path, roots) && !path_is_within(path, protected_paths)
}
