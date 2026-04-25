# Shipped Networks

All 64 first-class networks deployed by `.github/workflows/apply-networks.yml`
to the production registry at `34.71.57.205:9000`.

Each blueprint lives at `configs/networks/<name>.json` and is round-tripped
through provisioning at test time
(`pkg/registry/provision_configs_test.go::TestShippedNetworkBlueprintsLoadAndValidate`).

## Open-data networks (30, IDs 44–73)

Open-join, **default-allow**, full inter-agent communication: any peer
can connect/dial/datagram any other peer, on any port, with no tag
required. Anyone can `pilotctl network join <id>` without a token and
talk freely with anyone else in the network.

| Network | Domain |
|---|---|
| `science` | Primary-source research datasets and scientific endpoints |
| `geo` | Geocoding, routes, places, elevation, timezones, IP-to-country |
| `reference` | Dictionaries, trivia, colors, advice and assorted utility lookups |
| `health` | Clinical trials, drug safety, epidemiology and biomedical data |
| `government` | Civic, regulatory and government records across jurisdictions |
| `news` | News feeds, current events and real-time event streams |
| `finance` | Markets, crypto, FX rates and financial instruments |
| `dev` | Developer platforms, package registries and code ecosystems |
| `transit` | Public-transit schedules, real-time arrivals and network status |
| `sports` | Live scores, fixtures, standings and statistics |
| `academic` | Scholarly literature and bibliographic metadata |
| `language` | Translation, NLP, dictionaries and linguistic corpora |
| `security` | CVEs, certificate transparency, DNS and threat intelligence |
| `food` | Food, recipes, nutrition and beverages |
| `entertainment` | Games, anime, public-domain media and fandom lookups |
| `knowledge` | Structured-knowledge lookups and factual reference |
| `flights` | Live aircraft tracking, airport metadata and aviation weather |
| `weather` | Weather forecasts, historical climate and marine conditions |
| `traffic` | Urban transport, bike-share and city mobility feeds |
| `vehicles` | Vehicle identifiers, recalls, complaints and model lookups |
| `gov-finance` | Government economic and financial records |
| `economics` | Macroeconomic indicators and global reference data |
| `climate` | Carbon intensity, grid mix and climate-system data |
| `packages` | Package-registry metadata across language ecosystems |
| `culture` | Museum catalogs and cultural-heritage collections |
| `data` | General open-data catalogs and country references |
| `books` | Book search and public-domain library catalogs |
| `music` | Music metadata, catalogs and lyrics |
| `space` | Space and astronomy feeds |
| `nature` | Biodiversity observations and species sightings |

## Reputation / membership policies (33)

Programmable expr_policy networks demonstrating different membership
and trust dynamics:

| Network | Mechanic |
|---|---|
| `anti-camping` | Evict idle peers below activity floor |
| `aristocracy` | Asymmetric privilege — high-score nodes can dial low-score; reverse denied |
| `burnout` | Cap reputation accumulation; force cooldown after burst |
| `cold-shoulder` | Deny traffic from peers with negative score |
| `cooling-off` | Outbound block during a fresh-peer settling window |
| `dunbar-150` | Hard 150-peer cap with prune+fill maintenance |
| `first-in-first-out` | Prune in join order |
| `forgiveness` | Per-cycle violation decay |
| `gift-economy` | Mutual reputation increment on round-trip |
| `golden-hour` | One-time reputation bonus for newcomers |
| `gossip-tax` | Reputation drain on rumor traffic |
| `grudge-match` | Persistent negative scoring across restarts |
| `half-life` | Exponential reputation decay |
| `high-trust-society` | Per-cycle prune + fill against trust-link target |
| `karma-ledger` | Per-cycle karma tick |
| `last-in-first-out` | Prune in reverse-join order |
| `lottery` | Random eviction at cycle |
| `meritocracy` | Rank by score; gate at threshold |
| `meritocracy-rating` | Score-based rating surface |
| `mutual-admiration` | Member-only gate after reputation handshake |
| `old-guard` | Age-weighted privilege |
| `ostracism` | Evict low-score peers |
| `pay-it-forward` | Forwarder reward on chained interactions |
| `rotating-chairs` | Periodic prune+fill rotation |
| `seniority` | Privilege after seniority threshold accrued |
| `small-circle` | Trim+fill toward 50-peer target |
| `stable-state` | Cap fluctuations, hold steady member count |
| `sybil-gauntlet` | Multi-stage gate against fresh peers |
| `tithe` | Reputation contribution clipped per cycle |
| `trust-decay` | Prune trust links above 100 by score |
| `two-strikes` | Evict after second policy violation |
| `vouching-chain` | Direct trust grant; transitive walk pending |
| `whale-hunt` | Privilege via reputation harpoon (score 600+) |

## Reference networks (1)

| Network | Purpose |
|---|---|
| `data-exchange-policy` | Canonical service-tag pattern; inspiration for the 30 open-data nets above |

## Deployment

`apply-networks.yml` runs on every push touching `configs/networks/*.json`.
It:

1. Detects added/modified/deleted JSON files via `git diff HEAD~1 HEAD`.
2. Validates each via `pilotctl policy validate`.
3. Provisions each via `pilotctl provision <file> -json` against
   `PILOT_REGISTRY=34.71.57.205:9000` using `PILOT_ADMIN_TOKEN`.
4. Deletes removed networks via `pilotctl deprovision <name> -json`.

A manual `workflow_dispatch` re-applies every `*.json` file (no diff).
