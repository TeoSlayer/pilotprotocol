module github.com/TeoSlayer/pilotprotocol

go 1.25.10

require (
	github.com/coder/websocket v1.8.14
	github.com/pilot-protocol/app-store v0.1.0
	github.com/pilot-protocol/beacon v0.1.0
	github.com/pilot-protocol/common v0.4.4
	github.com/pilot-protocol/dataexchange v0.1.0
	github.com/pilot-protocol/eventstream v0.1.0
	github.com/pilot-protocol/handshake v0.1.0
	github.com/pilot-protocol/nameserver v0.1.0
	github.com/pilot-protocol/policy v0.1.0
	github.com/pilot-protocol/rendezvous v0.1.0
	github.com/pilot-protocol/runtime v0.1.0
	github.com/pilot-protocol/skillinject v0.1.0
	github.com/pilot-protocol/trustedagents v0.1.0
	github.com/pilot-protocol/webhook v0.1.0
)

require (
	github.com/expr-lang/expr v1.17.8 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/pilot-protocol/beacon => ../beacon

replace github.com/pilot-protocol/dataexchange => ../dataexchange

replace github.com/pilot-protocol/eventstream => ../eventstream

replace github.com/pilot-protocol/gateway => ../gateway

replace github.com/pilot-protocol/nameserver => ../nameserver

replace github.com/pilot-protocol/policy => ../policy

replace github.com/pilot-protocol/rendezvous => ../rendezvous

replace github.com/pilot-protocol/skillinject => ../skillinject

replace github.com/pilot-protocol/trustedagents => ../trustedagents

replace github.com/pilot-protocol/webhook => ../webhook

replace github.com/pilot-protocol/app-store => ../app-store

replace github.com/pilot-protocol/updater => ../updater

replace github.com/pilot-protocol/common => ../common

replace github.com/pilot-protocol/handshake => ../handshake

replace github.com/pilot-protocol/runtime => ../runtime

replace github.com/pilot-protocol/libpilot => ../libpilot
