# Security Policy

## Supported Versions

Security fixes are issued against the latest minor release. Older releases
are not patched; please upgrade to the current version to receive fixes.

| Version | Supported |
| ------- | --------- |
| 1.8.x   | Yes       |
| < 1.8   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Send the report privately to **`founders@pilotprotocol.network`**. Please
include:

- A description of the issue and its impact.
- Steps to reproduce (proof-of-concept, affected commands, sample traffic).
- The commit or release version you tested against.
- Any suggested mitigation or fix.

## What to Expect

- We aim to acknowledge reports within **3 business days**.
- We will keep you informed while we investigate and develop a fix.
- Once a fix is released, we will publish an advisory crediting the
  reporter (unless you prefer to remain anonymous).
- We do not currently operate a paid bug-bounty program. Responsible
  disclosures are acknowledged in release notes.

## Scope

In scope:

- Core protocol (`pkg/` and `cmd/` in this repository)
- Rendezvous server, daemon, `pilotctl`, gateway, updater
- Published SDKs (`sdk/node`, `sdk/python`)

Out of scope:

- Denial-of-service through sheer traffic volume without a protocol flaw
- Vulnerabilities in third-party dependencies that do not affect Pilot's
  attack surface (report those upstream)
- Social-engineering, phishing, or physical attacks
