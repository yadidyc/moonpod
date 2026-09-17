// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "yadidyc/moonpod"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/yadidyc/moonpod"

license = "Apache-2.0"

keywords = [ "policy", "audit", "plugin", "workflow", "agent" ]

preferred_target = "wasm"

description = "A transport-neutral resource policy and audit engine for MoonBit hosts"

import {
  "doffice/moonpermit@0.1.1",
}
