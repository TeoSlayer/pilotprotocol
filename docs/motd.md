# Message of the day (MOTD)

The message-of-the-day mechanism shows a short, operator-published banner
ahead of **every** `pilotctl` command, for one UTC calendar day at a time.
It is used for network-wide notices: maintenance windows, incident updates,
breaking-change heads-ups.

```
$ pilotctl info
Message of the day: overlay maintenance 22:00 UTC — expect ~5min blips

<normal pilotctl info output>
```

When no message is published for the current UTC day, output is unchanged.

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
 pilot-motd repo (motd.json)  ──poll──►  pilot-daemon  ──mirror──►  ~/.pilot/motd.json
   the "DB": one JSON file                (only net I/O)              (the local variable)
                                                                          │ read (no net, no IPC)
                                                                          ▼
                                          pilotctl <any command> ──► prepends banner
```

No new binary ships: the poll is a goroutine inside `pilot-daemon`, modelled
on the existing skill-reconciler loop.

## The feed (the "DB")

The source of truth is a single static JSON file published from the
[`pilot-motd`](https://github.com/pilot-protocol/pilot-motd) repository and
served raw from its default branch:

```
https://raw.githubusercontent.com/pilot-protocol/pilot-motd/main/motd.json
```

Schema (`schema_version: 1`):

```json
{
  "schema_version": 1,
  "messages": [
    { "date": "2026-06-15", "text": "overlay maintenance 22:00 UTC", "id": "maint-0615" }
  ]
}
```

- `date` is a **UTC** calendar day (`YYYY-MM-DD`). A message is active only on
  that day. Future-dated entries are ignored until their day arrives, so you
  can schedule ahead.
- Keep at most one entry per day. If several share a day, the first non-blank
  one wins.

### Posting and clearing

Committing to `pilot-motd` is the whole workflow — every daemon picks the
change up on its next poll (raw GitHub CDN cache is a few minutes).

- **Post:** add/replace today's entry in `messages`.
- **Clear:** remove today's entry, set its `text` to `""`, or commit an empty
  `{"schema_version":1,"messages":[]}`. Any of these clears the banner within
  one poll interval — committing an empty MOTD updates the value just like
  posting one does.

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
| `--motd-feed-url <url>` | the `pilot-motd` raw URL | feed location; **empty disables** polling entirely |
| `--motd-interval <dur>` | `15m` | how often to re-fetch |
| `$PILOT_MOTD_URL` | — | env override for the feed URL |

The mirror lives next to the daemon identity (normally `~/.pilot/motd.json`),
which is where `pilotctl` looks.
