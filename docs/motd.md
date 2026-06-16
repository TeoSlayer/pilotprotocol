# Message of the day (MOTD)

The message-of-the-day mechanism shows a short, centrally-managed banner
ahead of **every** `pilotctl` command, for one UTC calendar day at a time.
It is used for network-wide notices: maintenance windows, incident updates,
breaking-change heads-ups.

```
$ pilotctl info
Message of the day: overlay maintenance 22:00 UTC — expect ~5min blips

<normal pilotctl info output>
```

When no message is active for the current UTC day, output is unchanged.
Messages are managed centrally by the Pilot Protocol team; there is nothing
to configure on a client to receive them.

## Design

Two rules drive the design:

1. **`pilotctl` must stay fast and never call the network or the daemon just
   to render the banner.**
2. **The daemon must not make an on-demand call when a command runs.**

So the work is split:

- The **daemon** is the only component that touches the network. A background
  loop (`motdPollLoop`) fetches the feed every `--motd-interval` (default
  15m), selects the entry dated for the current UTC day, holds it in memory,
  and **mirrors** it to `~/.pilot/motd.json`.
- **`pilotctl`** reads only that local mirror — one file read — and
  re-validates the UTC day on read, so a stale mirror (e.g. the daemon was
  offline across midnight) never shows yesterday's message.

```
 central feed  ──poll──►  pilot-daemon  ──mirror──►  ~/.pilot/motd.json
  (managed by the         (only net I/O)              (the local variable)
   Pilot team)                                            │ read (no net, no IPC)
                                                          ▼
                          pilotctl <any command> ──► prepends banner
```

No new binary ships: the poll is a goroutine inside `pilot-daemon`, modelled
on the existing skill-reconciler loop.

## Output behaviour

- **Text mode:** the banner is prepended to stdout as
  `Message of the day: <text>` followed by a blank line, then the normal
  command output.
- **`--json` mode:** no text is prepended (it would break parsing). Instead
  the standard envelope carries a top-level `important_update` field:

  ```json
  { "status": "ok", "data": { ... }, "important_update": "overlay maintenance 22:00 UTC" }
  ```

  The same field is added to error envelopes. The daemon also surfaces the
  current value as `motd` in `pilotctl info`.

## Configuration

`pilot-daemon` flags (also settable via `pilotctl daemon start`):

| Flag | Default | Meaning |
|------|---------|---------|
| `--motd-feed-url <url>` | the central feed URL | feed location; **empty disables** polling entirely |
| `--motd-interval <dur>` | `15m` | how often to re-fetch |
| `$PILOT_MOTD_URL` | — | env override for the feed URL |

The mirror lives next to the daemon identity (normally `~/.pilot/motd.json`),
which is where `pilotctl` looks.

## Semantics

- **UTC days.** A message is active only on its UTC calendar day. `pilotctl`
  re-checks the day on read, so a message never lingers past its UTC day.
- **Self-clearing.** When the active message is withdrawn, the mirror is
  cleared within one poll interval and the banner disappears on its own.
- **Fail-safe.** Non-2xx responses and parse errors are non-fatal: the daemon
  keeps its last good mirror and logs at debug level. An unknown
  `schema_version` is rejected rather than mis-parsed.
