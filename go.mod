module github.com/TeoSlayer/pilotprotocol

go 1.25.10

require (
	github.com/coder/websocket v1.8.14
<<<<<<< HEAD
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
=======
	github.com/pilot-protocol/app-store v1.0.1-beta.1
	github.com/pilot-protocol/beacon v0.2.3-0.20260529143248-4f632d9c0953
	github.com/pilot-protocol/common v0.4.3
	github.com/pilot-protocol/dataexchange v0.2.1-beta.1
	github.com/pilot-protocol/eventstream v0.2.2
	github.com/pilot-protocol/handshake v0.2.1-0.20260529034908-6f286b1fa5c8
	github.com/pilot-protocol/nameserver v0.2.1
	github.com/pilot-protocol/policy v0.2.1
	github.com/pilot-protocol/rendezvous v0.2.2-0.20260529153356-45c9d2195c20
	github.com/pilot-protocol/runtime v0.3.1-0.20260529034924-948bcb891b24
	github.com/pilot-protocol/skillinject v0.2.2-0.20260529041510-e36bc173e7e7
	github.com/pilot-protocol/trustedagents v0.2.3-beta.3
	github.com/pilot-protocol/webhook v0.2.1-0.20260529034934-0d9094bbdede
>>>>>>> 20c941f (fix(daemon): satisfy daemonapi.Daemon contract after common@v0.4.3 bump)
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


replace github.com/pilot-protocol/handshake => ../handshake

replace github.com/pilot-protocol/runtime => ../runtime

replace github.com/pilot-protocol/libpilot => ../libpilot
