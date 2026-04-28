# Analytics

The website ships GA4 (`G-EEWEKT0GW5`, loaded in `src/components/BaseHead.astro`)
plus a small custom event layer in `src/scripts/analytics.ts` driven by
`data-*` attributes on call sites. There is no per-page glue — to track a
new behavior, add the appropriate attribute and the engine will pick it up.

## When to add an event

Only when the result will be looked at on a dashboard. Every event in the
taxonomy below is a maintenance commitment — it has to stay aligned with
the call site that triggers it and with the dashboard that consumes it.
Twelve events is the budget; we cap at ~15 before we start removing.

If you find yourself adding an event "just in case," stop. The point is
deciding what to ship next based on real signal, not collecting telemetry
for its own sake.

## Event taxonomy

### Click events

| Event                  | Triggered by                                              | Key params                                            |
| ---------------------- | --------------------------------------------------------- | ----------------------------------------------------- |
| `cta_click`            | Click on `[data-track="cta_click"]`                       | `target`, `location`                                  |
| `nav_click`            | Click on `[data-track="nav_click"]`                       | `target`                                              |
| `outbound_click`       | Click on `<a>` to a host outside `*.pilotprotocol.network`| `target` (host), `href`                               |
| `modal_open`           | Click on `[data-track="modal_open"]`                      | `target` (modal id)                                   |
| `modal_close`          | OSI modal closed (any path)                               | `target`, `via=escape \| backdrop \| button`          |
| `external_doc_click`   | Click on a `/docs/*` link from a `/blog/*` page           | `target` (docs path)                                  |

### Engagement

| Event                  | Triggered by                                              | Key params                                            |
| ---------------------- | --------------------------------------------------------- | ----------------------------------------------------- |
| `section_view`         | `[data-track-section]` ≥ 50% in viewport, once per page   | `target` (section name)                               |
| `section_dwell`        | Section exits viewport (or pagehide), > 250 ms            | `target`, `duration_ms`                               |
| `scroll_depth`         | Page reaches 25 / 50 / 75 / 100% scroll                   | `value`                                               |
| `page_active_time`     | `pagehide`, accumulated visible time, > 1 s               | `duration_ms`                                         |
| `live_chip_hover`      | Hover dwell on `[data-track-hover]` chip past threshold   | `target`                                              |
| `network_viz_engage`   | Hover dwell on the network viz past threshold             | (none)                                                |
| `blog_post_read`       | Scroll past 75% of `[data-track-read]` article            | `slug`                                                |
| `install_command_copy` | User copies text inside `[data-track-copy]`               | `command`                                             |

### Friction

| Event                  | Triggered by                                              | Key params                                            |
| ---------------------- | --------------------------------------------------------- | ----------------------------------------------------- |
| `web_vital`            | LCP / CLS / TTFB measured (LCP and CLS report on pagehide)| `name`, `value` (CLS is `× 1000` to keep an integer)  |
| `dead_click`           | Click that hit no link, no button, no `[data-track]`      | `location` (section or pathname), `target` (tag name) |

The bottom three rows are part of the budget but the engine doesn't fire
them yet. Wire them when we have a dashboard slot for the data.

## Adding a tracked behavior

Every behavior is a `data-*` attribute on the call site — no JS edits needed.

### Click events

```html
<a href="/docs/getting-started"
   data-track="cta_click"
   data-track-target="install"
   data-track-location="hero">
  Install in one line →
</a>
```

The `data-track` value is the GA4 event name itself (snake_case). `target`
and `location` ride along as event params. Use one of the canonical event
names from the taxonomy table — adding a new event name means adding a row
to the table.

### Outbound link tracking

Nothing to do — any `<a>` whose host is not `pilotprotocol.network` (or the
current host) auto-fires `outbound_click`. Internal anchors are ignored.
`mailto:`, `tel:`, `javascript:` and other non-http URLs are skipped.

### Section visibility

```html
<section id="thesis" data-track-section="thesis">…</section>
```

Fires `section_view` with `target=thesis` the first time the section is
≥ 50% in viewport on a given page load.

### Copy-to-clipboard

```html
<div data-track-copy="install.sh">
  $ curl -fsSL https://pilotprotocol.network/install.sh | sh
</div>
```

When the user copies any text whose selection anchor is inside the wrapper,
fires `install_command_copy` with `command="install.sh"`.

### Hover dwell

```html
<div data-track-hover="network_viz_engage" data-track-hover-threshold-ms="1500">
```

Starts a timer on `mouseenter`, fires once after the threshold (default
`1500`). Cancelled by `mouseleave`. Cap is per page-load — won't fire twice.

## Where things live

- `src/components/BaseHead.astro` — GA4 boot + `import '../scripts/analytics.ts'`
- `src/scripts/analytics.ts` — the entire engine (single file, no deps)
- This document — the canonical taxonomy reference

## How to verify locally

1. `npm run dev`
2. Open `http://localhost:4321/` (or whatever port Astro picks)
3. DevTools → Console: paste
   ```js
   window.dataLayer = window.dataLayer || [];
   const orig = window.gtag;
   window.gtag = (...args) => { console.log('gtag', ...args); orig?.(...args); };
   ```
4. Click around, scroll, hover, copy. Each tracked behavior should log a
   `gtag event <name> { ... }` line. If something doesn't log, the call
   site is missing its `data-*` attribute.

## Read access for dashboards

The GA4 data lives in property `530680522`. For programmatic access (Looker
Studio, scripts, CI), use the service-account key at
`~/.config/gcp-keys/ga-reader-key.json`. Don't commit it.

## Privacy & consent

Two layers ship today:

1. **GA4** (loaded sitewide, no banner). IP anonymization on, no PII, no
   cross-site identifiers. The custom events above carry only the params
   the docs declare — no free-form text, no form contents, no path-with-PII.
2. **PostHog** (opt-in, gated on the consent banner). Session recordings
   and heatmaps. Only loads when the user clicked **Allow** on the banner
   in `src/components/ConsentBanner.astro`. Loaded with
   `person_profiles: 'never'` (anonymous mode), `maskAllInputs: true`, and
   any element marked `[data-private]` is masked in recordings.

The banner shows once per device (persisted in `localStorage` as
`pilot-analytics-consent` ∈ `accepted | declined`). Cleared the
choice? The banner reappears on next visit.

PostHog only initialises when **both** conditions hold:
- `localStorage['pilot-analytics-consent'] === 'accepted'`, AND
- `PUBLIC_POSTHOG_KEY` is defined (set in your `.env` or Cloudflare Pages
  environment vars).

If the key is unset, the consent banner is decorative — clicking Allow does
nothing harmful, just no recordings happen. To turn PostHog on for real:

```bash
# Sign up at https://posthog.com/, create a project, copy the API key.
# Then in the Cloudflare Pages project settings:
PUBLIC_POSTHOG_KEY=phc_xxxxxxxxxxxxxxxxxxxxxx
PUBLIC_POSTHOG_HOST=https://us.i.posthog.com   # or eu.i.posthog.com
```

To turn it off: unset the env var. The banner can stay; without a key,
nothing loads.
