///|
test "generic resource rules authorize scoped actions" {
  let policy = @moonpod.Policy::new(["calendar.read", "storage.write"], resource_rules=[
    @moonpod.ResourceRule::new(
      tool="calendar.read",
      action="read",
      resource_prefix="tenant/acme",
    ),
    @moonpod.ResourceRule::new(
      tool="storage.write",
      action="write",
      resource_prefix="bucket/reports",
    ),
  ])
  let session = @moonpod.Session::new(policy)
  assert_true(
    session
    .authorize(
      @moonpod.ResourceAccess(
        tool="calendar.read",
        action="read",
        resource="tenant/acme/2026-09-17",
        estimated_bytes=10,
      ),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ResourceAccess(
        tool="calendar.read",
        action="write",
        resource="tenant/acme/2026-09-17",
        estimated_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.ResourceNotAllowed(..)),
  )
  assert_true(
    session.authorize(
      @moonpod.ResourceAccess(
        tool="storage.write",
        action="write",
        resource="bucket/reports-private",
        estimated_bytes=0,
      ),
    )
    is @moonpod.Deny(@moonpod.ResourceNotAllowed(..)),
  )
}

///|
test "generic resource rules survive JSON loading and restriction" {
  let policy = @moonpod.Policy::from_json(
    (
      #|{
      #|  "schema_version": 1,
      #|  "allowed_tools": ["plugin.invoke"],
      #|  "resource_rules": [
      #|    {
      #|      "tool": "plugin.invoke",
      #|      "action": "run",
      #|      "resource_prefix": "plugin/reports"
      #|    }
      #|  ]
      #|}
    ),
  )
  let restriction = @moonpod.Policy::new(["plugin.invoke"], resource_rules=[
    @moonpod.ResourceRule::new(
      tool="plugin.invoke",
      action="run",
      resource_prefix="plugin/reports/monthly",
    ),
  ])
  let session = @moonpod.Session::new(policy.restrict(restriction))
  assert_true(
    session
    .authorize(
      @moonpod.ResourceAccess(
        tool="plugin.invoke",
        action="run",
        resource="plugin/reports/monthly/summary.json",
        estimated_bytes=1,
      ),
    )
    .is_allowed(),
  )
  assert_true(
    session.authorize(
      @moonpod.ResourceAccess(
        tool="plugin.invoke",
        action="run",
        resource="plugin/reports/daily/summary.json",
        estimated_bytes=1,
      ),
    )
    is @moonpod.Deny(@moonpod.ResourceNotAllowed(..)),
  )
}
