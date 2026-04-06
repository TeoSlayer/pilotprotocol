---
title: "Problem Statement: Network-Layer Infrastructure for Autonomous Agent Communication"
abbrev: "Agent Network Problem Statement"
docname: draft-teodor-pilot-problem-statement-01
category: info
ipr: trust200902
area: Internet
workgroup: Independent Submission
submissiontype: independent

stand_alone: yes
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  compact: yes

author:
  -
    ins: C. Teodor
    name: Calin Teodor
    organization: Vulture Labs
    email: teodor@vulturelabs.com

informative:
  RFC7364:
  RFC9000:
  RFC9300:
  RFC9301:
  I-D.rosenberg-aiproto-framework:
    title: "A Framework for AI Protocols"
    author:
      - ins: J. Rosenberg
    date: 2025
    target: https://datatracker.ietf.org/doc/draft-rosenberg-aiproto-framework/
  I-D.zyyhl-agent-networks-framework:
    title: "A Framework for Agent Networks"
    author:
      - ins: Z. Yao
    date: 2025
    target: https://datatracker.ietf.org/doc/draft-zyyhl-agent-networks-framework/
  I-D.narvaneni-agent-uri:
    title: "Agent URI Scheme"
    author:
      - ins: S. Narvaneni
    date: 2025
    target: https://datatracker.ietf.org/doc/draft-narvaneni-agent-uri/
  MCP:
    title: "Model Context Protocol"
    author:
      - org: Anthropic
    date: 2024
    target: https://modelcontextprotocol.io/
  A2A:
    title: "Agent-to-Agent Protocol"
    author:
      - org: Google
    date: 2025
    target: https://google.github.io/A2A/
  WIREGUARD:
    title: "WireGuard: Next Generation Kernel Network Tunnel"
    author:
      - ins: J. A. Donenfeld
    date: 2017
    target: https://www.wireguard.com/papers/wireguard.pdf
  LIBP2P:
    title: "libp2p: A Modular Network Stack"
    author:
      - org: Protocol Labs
    date: 2023
    target: https://libp2p.io/
  I-D.yao-catalist-problem-space-analysis:
    title: "Problem Space Analysis of AI Agent Protocols in IETF"
    author:
      - ins: Y. Zhou
      - ins: K. Yao
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-yao-catalist-problem-space-analysis/
  I-D.eckert-catalist-acip-framework:
    title: "Framework for Agent Communications Internet Protocol (ACIP)"
    author:
      - ins: T. Eckert
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-eckert-catalist-acip-framework/
  I-D.du-catalist-routing-considerations:
    title: "Routing Considerations in Agentic Network"
    author:
      - ins: Z. Du
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-du-catalist-routing-considerations/
  I-D.prakash-aip:
    title: "Agent Identity Protocol (AIP)"
    author:
      - ins: S. Prakash
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-prakash-aip/
  I-D.nemethi-aid-agent-identity-discovery:
    title: "Agent Identity and Discovery (AID)"
    author:
      - ins: B. Nemethi
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-nemethi-aid-agent-identity-discovery/
  I-D.hood-independent-agtp:
    title: "Agent Transfer Protocol (AGTP)"
    author:
      - ins: C. Hood
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-hood-independent-agtp/
  I-D.li-atp:
    title: "Agent Transfer Protocol (ATP)"
    author:
      - ins: Y. Li
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-li-atp/
  I-D.sharif-agent-audit-trail:
    title: "Agent Audit Trail"
    author:
      - ins: R. Sharif
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/
  I-D.ni-wimse-ai-agent-identity:
    title: "WIMSE Applicability for AI Agents"
    author:
      - ins: Y. Ni
      - ins: C. P. Liu
    date: 2026
    target: https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/

--- abstract

AI agents --- autonomous software entities capable of reasoning, planning,
and executing tasks --- are an increasingly important class of network
participant. Current agent communication protocols operate exclusively at
the application layer over HTTP, assuming the existence of stable endpoints,
DNS names, and centralized infrastructure. No existing standard provides
network-layer identity, addressing, or transport for agents. This document
describes the problem space and identifies requirements for a network-layer
infrastructure that would give agents first-class network citizenship,
independent of the web infrastructure designed for human users.

--- middle

# Introduction

The internet's protocol stack was designed for human-operated devices with
stable network attachments. IP addresses identify interfaces, DNS names
identify services, and TLS certificates identify organizations. These
assumptions break down for AI agents, which are transient software
processes that may run behind NAT, migrate between hosts, and lack
persistent network identity.

Recent standardization efforts for agent communication --- notably MCP
{{MCP}} (agent-to-tool) and A2A {{A2A}} (agent-to-agent) --- have focused
on application-layer protocols built on HTTP. These protocols define what
agents say to each other but assume the underlying problem of how agents
reach each other is already solved. For agents running in cloud
environments with public endpoints, this assumption holds. For agents
running on edge devices, behind corporate firewalls, on laptops, or in
heterogeneous multi-cloud deployments, it does not.

The IETF has seen explosive activity in AI agent protocol
standardization, with over thirty individual drafts filed in 2025-2026
covering agent identity ({{I-D.prakash-aip}}, {{I-D.ni-wimse-ai-agent-identity}}),
discovery ({{I-D.nemethi-aid-agent-identity-discovery}}), transport
({{I-D.hood-independent-agtp}}, {{I-D.li-atp}}), routing
({{I-D.du-catalist-routing-considerations}}), frameworks
({{I-D.rosenberg-aiproto-framework}}, {{I-D.zyyhl-agent-networks-framework}},
{{I-D.eckert-catalist-acip-framework}}), and audit
({{I-D.sharif-agent-audit-trail}}). The CATALIST Birds of a Feather
session at IETF 125 (March 2026, Shenzhen) was the first formal
coordination effort, surveying the problem space
({{I-D.yao-catalist-problem-space-analysis}}) without yet chartering a
working group.

Despite this volume, the vast majority of these drafts operate at the
application layer over HTTP. Even the dedicated transport proposals
(AGTP, ATP) define application-layer semantics carried over QUIC or TCP
--- none provides an overlay network with virtual addressing, port-based
multiplexing, and built-in NAT traversal at the network layer. The
network-layer gap identified in the original version of this document
remains unaddressed.

This document describes the problem of network-layer infrastructure for
autonomous agent communication, identifies the gaps in existing protocols,
and states requirements for a solution. It is modeled after {{RFC7364}},
which performed a similar analysis for network virtualization overlays.

# Terminology

{::boilerplate bcp14-tagged}

Agent:
: An autonomous software entity capable of reasoning, planning, and
  executing tasks without continuous human supervision. An agent may run as
  a process, container, or serverless function.

Overlay Network:
: A virtual network built on top of an existing network (the underlay).
  Overlay nodes communicate using encapsulated packets carried over the
  underlay.

Virtual Address:
: A network address assigned within the overlay address space, independent
  of the underlay IP address. A virtual address identifies an agent, not a
  network interface.

Registry:
: A service that assigns virtual addresses, maintains an address-to-locator
  mapping table, and provides bootstrap information for overlay
  participants.

Trust Handshake:
: A protocol exchange through which two agents establish a bilateral trust
  relationship with explicit mutual consent.

# Problem Description

## Agent Identity Is Coupled to Infrastructure

In current practice, agents are identified by URLs, DNS names, or API
endpoints --- all of which are tied to the infrastructure hosting the
agent, not to the agent itself. When an agent migrates to a different host,
changes cloud provider, or restarts behind a different NAT binding, its
identity changes. There is no stable identifier that follows an agent
across these transitions.

This is analogous to the identity/locator conflation problem in IP
networking, which motivated the Locator/ID Separation Protocol (LISP)
{{RFC9300}}. In LISP, Endpoint Identifiers (EIDs) are separated from
Routing Locators (RLOCs) so that an endpoint's identity is independent of
its network attachment point. Agents need the same separation: a permanent
identity that is independent of the transient infrastructure hosting them.

The A2A protocol {{A2A}} identifies agents via "Agent Cards" served at
well-known HTTPS URLs. The Agent URI scheme {{I-D.narvaneni-agent-uri}}
proposes `agent://` URIs but still requires DNS-resolvable endpoints.
Both approaches require the agent to maintain a stable, publicly
reachable web endpoint --- a requirement that excludes agents running on
edge devices, behind NAT, or in ephemeral compute environments.

## No Peer-to-Peer Communication Without Web Infrastructure

Both MCP {{MCP}} and A2A {{A2A}} require HTTP endpoints for communication.
This means every agent must either have a publicly routable IP address or
be fronted by a reverse proxy, load balancer, or API gateway. For two
agents behind NAT to communicate, at least one must provision web
infrastructure as an intermediary.

NAT traversal is a solved problem for specific domains: WebRTC handles it
for browsers (at the cost of ICE/DTLS-SRTP/SDP negotiation complexity),
and WireGuard {{WIREGUARD}} handles it for VPN tunnels. But no existing
protocol provides NAT traversal specifically designed for agent-to-agent
communication, with agent-native addressing and trust semantics.

An estimated 88% of real-world network environments involve some form of
NAT. Agents running on laptops, IoT devices, edge servers, and mobile
phones cannot participate in HTTP-based agent protocols without significant
infrastructure provisioning.

## No Agent-Native Trust Model

Existing trust models were designed for different participants:

- TLS: Trust is anchored in Certificate Authorities. Agents would need to
  obtain and manage X.509 certificates, adding operational complexity
  disproportionate to many agent interactions.

- SSH: Trust-on-first-use (TOFU) assumes a human operator who can verify a
  host key fingerprint. Autonomous agents have no human in the loop.

- OAuth/OIDC: Designed for user-to-service authorization, not peer-to-peer
  agent trust. Requires an authorization server as a trusted third party.

None of these models provide bilateral consent --- the property that both
parties must explicitly agree before a communication relationship is
established. For autonomous entities that may be operated by different
organizations, bilateral consent is a natural trust primitive: neither
agent should be reachable by the other until both have agreed.

## No Lightweight Transport for Agent Streams

TCP and QUIC {{RFC9000}} are general-purpose transports optimized for web
traffic patterns (request-response, large transfers, multiplexed streams).
Agent communication patterns differ:

- Many agents exchange small, frequent messages (status updates, task
  delegations, sensor readings) where connection setup overhead dominates.

- Agents often maintain long-lived bidirectional streams for event-driven
  architectures, where TCP's head-of-line blocking is problematic.

- Agents may need port-based service multiplexing (echo on one port, task
  submission on another, events on a third) --- a concept that exists in
  TCP/UDP but has no equivalent in HTTP-based agent protocols.

While QUIC addresses head-of-line blocking through multiplexed streams, it
does not provide agent addressing, discovery, or trust semantics. A
transport designed for agents could provide these as built-in capabilities
rather than requiring them to be layered on top.

## Privacy Gaps in Agent Discovery

Current agent discovery mechanisms are designed for visibility:

- A2A Agent Cards are intended to be publicly discoverable at well-known
  URLs.
- DNS-SD and mDNS broadcast service availability to all listeners on a
  network segment.
- HTTP-based service registries typically allow any authenticated client to
  enumerate all registered services.

For agents, the default should be the opposite. An agent's existence and
capabilities should not be disclosed to parties that have not been
explicitly authorized. Mass enumeration of agent endpoints creates attack
surface (reconnaissance for exploitation) and privacy risks (mapping an
organization's agent infrastructure).

A privacy-by-default discovery model --- where agents are invisible until
they explicitly opt in to specific peer relationships --- has no equivalent
in current standards.

## No Multi-Tenant Network Isolation

Current agent protocols assume flat, single-tenant deployments where all
agents share the same namespace and trust domain. In practice,
organizations deploy multiple agent teams serving different departments,
projects, or customers. These teams need isolation:

- Agents in one project should not observe or interfere with agents in
  another.
- Administrative control (who can join a network, what ports are
  accessible, who can modify policy) should be scoped per network, not
  global.
- Compliance requirements (SOC 2, GDPR, HIPAA) demand audit trails
  recording who did what, when, and to which network --- at the
  infrastructure layer, not bolted on at the application layer.

No existing agent protocol or draft addresses multi-tenancy, role-based
access control, or per-network policy enforcement. The closest analog is
cloud VPC isolation, but VPCs operate at the IP layer and require cloud
provider infrastructure. Agent networks need the same isolation primitives
at the overlay layer, independent of the underlying cloud or network
topology.

# Requirements for a Solution

Based on the problems identified above, a network-layer infrastructure for
agent communication should satisfy the following requirements:

## Virtual Addressing

{: vspace="0"}
REQ-1:
: Agents MUST receive stable virtual addresses that are independent of
  their underlying IP address, network attachment point, and hosting
  infrastructure.

REQ-2:
: The addressing scheme MUST support hierarchical grouping (e.g., network
  or topic-based segmentation) to enable scoped communication boundaries.

## NAT Traversal

{: vspace="0"}
REQ-3:
: The system MUST provide automatic NAT traversal without requiring manual
  configuration of port forwarding, firewall rules, or relay proxies by the
  agent operator.

REQ-4:
: NAT traversal MUST support direct peer-to-peer communication where
  possible, with transparent relay fallback when direct communication is
  not achievable.

## Bilateral Trust Model

{: vspace="0"}
REQ-5:
: Communication between agents MUST require explicit bilateral consent.
  Neither agent should be reachable by the other until both have agreed to
  establish a trust relationship.

REQ-6:
: Trust relationships MUST be revocable. Revoking trust MUST immediately
  prevent further communication.

## Lightweight Encrypted Transport

{: vspace="0"}
REQ-7:
: The transport MUST provide reliable, ordered byte stream delivery
  (TCP-equivalent) and unreliable datagram delivery (UDP-equivalent) over
  the overlay.

REQ-8:
: Encryption MUST be enabled by default for all data in transit, with no
  opt-in required from the agent developer.

REQ-9:
: The transport MUST support port-based service multiplexing, allowing an
  agent to expose multiple services on different virtual ports.

## Privacy-by-Default Discovery

{: vspace="0"}
REQ-10:
: Agents MUST be private by default. An agent's virtual address, physical
  locator, and capabilities MUST NOT be disclosed to parties without an
  established trust relationship or shared group membership.

REQ-11:
: It MUST be possible to establish trust with a private agent without
  first knowing its physical network location (i.e., via a trusted relay
  or rendezvous mechanism).

## Multi-Tenant Isolation

{: vspace="0"}
REQ-12:
: The system MUST support isolated network segments with independent
  membership control, role-based access (at minimum: owner, administrator,
  and member roles), and per-network policy enforcement. Operations within
  one network MUST NOT affect agents in another network.

## Audit and Compliance

{: vspace="0"}
REQ-13:
: The system MUST provide an audit trail recording security-relevant
  operations including node registration and deregistration, trust
  relationship changes, network membership modifications, role assignments,
  and policy updates. Audit records MUST include timestamps, actor
  identifiers, and old/new values for state mutations.

# Existing Approaches and Gaps

## MCP (Model Context Protocol)

MCP {{MCP}} standardizes the interface between AI models and external
tools/resources. It uses JSON-RPC over HTTP with Server-Sent Events for
streaming. MCP addresses agent-to-tool communication, not agent-to-agent
communication, and provides no network-layer capabilities. It assumes
agents can reach tool servers via HTTP.

## A2A (Agent-to-Agent Protocol)

A2A {{A2A}} defines a protocol for agent interoperability: Agent Cards for
discovery, task lifecycle management, and multimodal message exchange. A2A
operates entirely over HTTP/HTTPS. It provides no NAT traversal, no
overlay addressing, no built-in encryption beyond TLS, and no bilateral
trust model. It assumes agents have reachable HTTP endpoints.

## WebRTC

WebRTC provides peer-to-peer communication with NAT traversal via ICE,
encryption via DTLS-SRTP, and data channels via SCTP. However, WebRTC was
designed for browser-based audio/video communication. Its complexity
(ICE candidate gathering, SDP offer/answer negotiation, DTLS-SRTP key
exchange) is disproportionate for agent message exchange. WebRTC also lacks
agent-specific concepts like virtual addressing, bilateral trust, and
privacy-by-default discovery.

## QUIC

QUIC {{RFC9000}} provides a modern transport with multiplexed streams,
built-in encryption, and reduced connection setup latency. QUIC addresses
transport-layer concerns but does not provide overlay addressing, agent
identity, NAT traversal coordination, trust management, or discovery. It
is a potential underlay transport for an agent overlay, not a complete
solution.

## libp2p

libp2p {{LIBP2P}} is a modular networking stack developed for
decentralized applications, particularly in the blockchain ecosystem. It
provides peer identity (via cryptographic keypairs), NAT traversal, and
transport multiplexing. libp2p is the closest existing system to the
requirements stated above. However, it uses unstructured peer IDs (not
hierarchical addresses), is heavyweight (large dependency tree), is
oriented toward content-addressed distributed systems rather than agent
communication patterns, and lacks built-in bilateral trust or privacy-by-
default semantics.

## WireGuard

WireGuard {{WIREGUARD}} provides encrypted point-to-point tunnels with
excellent performance. It uses Curve25519 for key exchange and ChaCha20-
Poly1305 for encryption. WireGuard establishes tunnels between known peers
with pre-shared public keys --- it does not provide dynamic discovery,
agent addressing, or trust negotiation. It is a VPN, not an agent network.

## LISP

The Locator/ID Separation Protocol {{RFC9300}} {{RFC9301}} separates
endpoint identity from network location, providing a conceptual precedent
for agent addressing. LISP's EID-to-RLOC mapping system is architecturally
similar to an agent registry that maps virtual addresses to physical
locators. However, LISP operates at the IP layer for routing optimization,
not at the application layer for agent communication. It does not provide
agent-specific trust models, privacy semantics, or built-in services.

## AGTP (Agent Transfer Protocol)

AGTP {{I-D.hood-independent-agtp}} proposes a dedicated application-layer
protocol for AI agent traffic with agent-native intent methods (QUERY,
SUMMARIZE, DELEGATE, COLLABORATE). It correctly identifies that MCP and
A2A are messaging-layer constructs that do not address the transport
problem. However, AGTP operates over QUIC or TCP/TLS at the application
layer --- it defines what agents say, not how they reach each other. It
provides no overlay addressing, no virtual network primitives, no NAT
traversal, and no multi-tenant isolation.

## ATP (Agent Transfer Protocol)

ATP {{I-D.li-atp}} defines a two-tier architecture where agents connect
to ATP servers, with DNS-based service discovery via SVCB records. It
supports asynchronous messaging, synchronous request/response, and
event-driven streaming. Like AGTP, ATP operates at the application layer
and requires server infrastructure as an intermediary --- the same
dependency on centralized endpoints that HTTP-based protocols impose. It
does not address overlay networking, NAT traversal for serverless agents,
or privacy-by-default semantics.

## AIP (Agent Identity Protocol)

AIP {{I-D.prakash-aip}} defines verifiable, delegable identity for AI
agents using Invocation-Bound Capability Tokens (IBCTs) with Ed25519
signatures and Biscuit-based delegation chains. AIP addresses the identity
problem (REQ-1) with a cryptographically strong approach. However, it
focuses exclusively on identity and authorization --- it provides no
transport, addressing, or network-layer primitives. AIP's identity tokens
could complement an overlay network that provides the missing transport
substrate.

## CATALIST Coordination

The CATALIST BoF at IETF 125
{{I-D.yao-catalist-problem-space-analysis}} surveyed the agent protocol
landscape and began scoping what IETF should standardize. The problem
space analysis identified categories including agent identity, discovery,
communication, and governance. Notably, agent network routing
{{I-D.du-catalist-routing-considerations}} defines forwarding based on
Agent ID, Gateway ID, and Skill --- concepts that overlap with virtual
addressing and service multiplexing. The ACIP framework
{{I-D.eckert-catalist-acip-framework}} proposes agent-aware network
infrastructure drawing from overlay/underlay designs. These efforts
validate the need for network-layer agent infrastructure but have not
yet produced a concrete protocol specification.

# Security Considerations

A network-layer infrastructure for agents introduces security
considerations beyond those of traditional overlay networks:

Centralized Registry:
: A registry that assigns addresses and maintains locator mappings is a
  trusted third party. Compromise of the registry could allow address
  hijacking, locator spoofing, or metadata harvesting. The registry
  should support authentication, access control, and replication for high
  availability.

Overlay Header Metadata:
: Even with payload encryption, overlay packet headers may expose source
  and destination virtual addresses, port numbers, and packet sizes. Traffic
  analysis on the overlay is possible even when the underlay is encrypted.

Trust Model Assumptions:
: A bilateral trust model assumes that agents can make informed consent
  decisions. If an agent's trust logic is compromised (e.g., by adversarial
  prompt injection), it may approve trust relationships it should reject.
  The trust model provides a mechanism, not a policy --- the security of
  trust decisions depends on the agent's reasoning capability.

Key Management:
: Overlay encryption requires key exchange between peers. Anonymous key
  exchange (without identity binding) is vulnerable to man-in-the-middle
  attacks. Authenticated key exchange requires a mechanism to distribute
  and verify public keys, which depends on the registry's integrity.

Multi-Tenant Control Plane:
: A multi-tenant registry introduces additional attack surface. Per-network
  role-based access control must be enforced consistently to prevent
  privilege escalation (e.g., a member modifying network policy). Admin
  token authentication for privileged operations must use constant-time
  comparison to prevent timing attacks. Audit trails must be tamper-evident
  and persist across service restarts to support forensic analysis
  (see also {{I-D.sharif-agent-audit-trail}}).

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments

The author thanks the participants of the IETF AI protocols discussions
for their contributions to understanding the agent communication
landscape.
