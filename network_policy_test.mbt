///|
test "allows only configured host and port pairs" {
  let rule = @moonpod.NetworkRule::new(host="api.example.com", allowed_ports=[
    443,
  ])
  let policy = @moonpod.Policy::new(["net.connect"], network_rules=[rule])
  let session = @moonpod.Session::new(policy)

  assert_true(
    session
    .authorize(@moonpod.Connect(host="api.example.com", port=443))
    .is_allowed(),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="api.example.com", port=22))
    is @moonpod.Deny(@moonpod.PortNotAllowed(host="api.example.com", port=22)),
  )
  assert_true(
    session.authorize(@moonpod.Connect(host="evil.example", port=443))
    is @moonpod.Deny(@moonpod.HostNotAllowed("evil.example")),
  )
}
