module github.com/TeoSlayer/pilotprotocol

go 1.25.3

require (
	github.com/expr-lang/expr v1.17.8
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/sys v0.44.0 // indirect

require github.com/pilot-protocol/app-store v0.0.0

replace github.com/pilot-protocol/app-store => ../app-store

replace github.com/pilot-protocol/app-store/integration => ../app-store/integration

require (
	github.com/coder/websocket v1.8.14
	github.com/pilot-protocol/trustedagents v0.0.0
	golang.org/x/net v0.54.0
)

replace github.com/pilot-protocol/trustedagents => ../trustedagents

require github.com/pilot-protocol/skillinject v0.0.0

replace github.com/pilot-protocol/skillinject => ../skillinject

require github.com/pilot-protocol/webhook v0.0.0

replace github.com/pilot-protocol/webhook => ../webhook

require github.com/pilot-protocol/eventstream v0.0.0

replace github.com/pilot-protocol/eventstream => ../eventstream

require github.com/pilot-protocol/dataexchange v0.0.0

replace github.com/pilot-protocol/dataexchange => ../dataexchange

require github.com/pilot-protocol/updater v0.0.0

replace github.com/pilot-protocol/updater => ../updater
