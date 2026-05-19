# Full analysis — per-prompt pilot injection (openclaw-first)

**Goal:** every time an openclaw LLM run starts a new turn, the pilot directive is in front of the model. No exceptions, no "fell out of context after compaction", no "only loaded if the user opens HEARTBEAT.md".

**Status:** the daemon currently writes content to `HEARTBEAT.md` + `CLAW.md`, but neither is on the per-prompt path. We have to move to a real per-prompt surface.

## The actual openclaw prompt-build pipeline

Traced through `src/agents/pi-embedded-runner/run/attempt.ts` and `src/plugins/hooks.ts` in the openclaw source tree. On every turn, before the model is called, openclaw runs:

```
runBeforePromptBuild(prompt, messages, hookCtx)
   ↓
PluginHookBeforePromptBuildResult {
  systemPrompt?:         override the base system prompt
  prependContext?:       prepended to USER prompt
  prependSystemContext?: prepended to SYSTEM prompt ← THE injection point
  appendSystemContext?:  appended to SYSTEM prompt
}
   ↓
composeSystemPromptWithHookContext(
  [prependSystemContext, baseSystemPrompt, appendSystemContext]
)
   ↓
fed to the model as the system message
```

Critical detail (verified at `attempt.ts:1203-1216`): **all four returned fields are joined across multiple plugins via `joinPresentTextSegments` — plugins compose, they don't overwrite.** That means if the user has their own plugins that contribute to the system context, ours can add to it cleanly.

The hook runs **every single turn**. There is no "first message only" gating at this layer. Compaction-survival, fresh-resume, mid-session — irrelevant. If the plugin is loaded, the hook fires.

## Three injection surfaces in openclaw (ranked)

### (1) Plugin `before_prompt_build` hook → `prependSystemContext` ★ RECOMMENDED

```ts
// In a Pilot openclaw plugin (TypeScript)
import type { PluginHookRegistration } from "openclaw/plugins";

const hook: PluginHookRegistration<"before_prompt_build"> = {
  hookName: "before_prompt_build",
  priority: 100,
  handler: async (_event, _ctx) => ({
    prependSystemContext: PILOT_DIRECTIVE_TEXT,
  }),
};
```

**Why this wins:**
- Composes with user plugins (`joinPresentTextSegments` does the right thing)
- Doesn't touch the user's `openclaw.json` — clean operational footprint
- Failure-isolated: `runBeforePromptBuild` wraps in `try/catch` and warns if a hook throws, so a bad pilot version can never break the user's openclaw
- Already part of openclaw's first-class plugin API; survives openclaw upgrades unless they break the hook contract (which would break many plugins, not just ours)

**What needs to ship:**
- A small openclaw plugin package — `@pilotprotocol/openclaw-plugin` on npm — registering the hook
- A daemon-side install step: on first start, run `openclaw plugins install @pilotprotocol/openclaw-plugin` if not present (via `pilotctl skills check`)
- The plugin reads the pilot directive from disk at hook-time (so daemon updates to pilot-skills propagate without an npm rev)

### (2) Config-level `systemPromptWhen: "always"` + `systemPrompt` ★ FALLBACK

```json
{
  "agents": {
    "defaults": {
      "systemPrompt": "<pilot directive>",
      "systemPromptWhen": "always"
    }
  }
}
```

**What it does:** confirmed at `src/agents/cli-runner/helpers.ts:252-268`. Default is `"first"` — system prompt sent only on first turn. `"always"` means resend every turn.

**Why it's second choice:**
- Conflicts with user-set `systemPrompt`; needs the `_pilotManaged` sentinel + prepend-with-divider merge logic from the previous spec
- Edits a config file the user owns — risk of user reverting or the merge logic having bugs
- Only fires the `systemPrompt` field, not the richer `prependSystemContext` (which lets us coexist with user plugins)

**When to use:** as the path for users who haven't installed our plugin yet, or whose openclaw version is too old to support `before_prompt_build` hooks.

### (3) `agents.<id>.systemPrompt` per-agent override ★ SCOPE-SPECIFIC

If a user has multiple openclaw agents and we want per-agent control, the schema (`src/config/zod-schema.providers-core.ts`) supports `systemPrompt` at the agent level. Same mechanism, narrower scope. Useful for a future "pilot-only" agent.

## Why HEARTBEAT.md doesn't cut it

The current state — `HEARTBEAT.md` carries the full directive — only reaches the model when openclaw's **heartbeat lifecycle** triggers a turn (`src/infra/heartbeat-runner.ts`). Heartbeat turns are *periodic* (default `interval: 30` minutes per `~/.picoclaw/config.json` analog) and *event-driven*, not per-prompt. Most user prompts happen between heartbeat fires, so the directive is never seen.

`CLAW.md` is at the rootDir and is loaded as a workspace boot file, **but only on the first turn**. Same fall-out-of-context problem as Claude Code's CLAUDE.md.

## Coverage matrix (other tools, brief)

| Tool | Per-prompt mechanism (verified) | Current state | Gap |
|---|---|---|---|
| **openclaw** | `before_prompt_build` plugin hook **or** `systemPromptWhen: "always"` config | HEARTBEAT.md + CLAW.md pointer | **No per-prompt injection** — fix per this doc |
| **claude-code** | `UserPromptSubmit` hook in `~/.claude/settings.json` — stdout becomes `additionalContext`, fed on every turn ([docs verified](https://code.claude.com/docs/en/hooks)) | CLAUDE.md heartbeat (once-per-conversation) | No hook installed; CLAUDE.md falls out post-compaction |
| **picoclaw** | `UserPromptSubmittedHook` (Go binary, confirmed from `strings` output) + `hooks` block in `~/.picoclaw/config.json` | HEARTBEAT.md + `hooks: {enabled: true}` baseline | Hook configured but no pilot handler registered |
| **hermes** | Not installed locally; manifest writes to `~/.hermes/SOUL.md` (loaded as `selfHeartbeat`-equivalent) | n/a — would need user install | Hook surface unverified — if/when a user installs hermes, investigate before committing |
| **openhands** | Not installed locally; manifest uses `selfHeartbeat: true` flag — implies openhands has its own pulling-in mechanism via `microagents/` | n/a — needs install | Pull-based; per-prompt likely handled by openhands itself once microagent exists |

The pattern across the four "Claude-like" tools (Claude Code / openclaw / picoclaw / hermes) is convergent: each exposes a *pre-LLM-call hook* that takes content and prepends it to the system or user context. The pilot fix is the same shape every time — register a hook, return our text — only the wire format differs per tool.

## Why "a while ago this was the case" — the regression

The user has mentioned this was working previously. Likely cause: an earlier openclaw version had the heartbeat content prepended via a different mechanism (possibly `agents.defaults.systemPrompt` defaulting to read HEARTBEAT.md, or an old plugin shipped). Two specific candidates:

1. **The `heartbeatTemplate` field in the manifest used to write directly to `agents.defaults.systemPrompt`** before being moved to HEARTBEAT.md as a "secondary heartbeat file" (the comment in `internal/skillinject/reconcile.go:96` mentions this migration: *"the pilot-skills manifest now targets HEARTBEAT.md for OpenClaw/PicoClaw"*). Result: pre-migration installs got per-prompt; post-migration installs don't.

2. **Openclaw's `systemPromptWhen` default may have changed** at some point from `"always"` to `"first"`. If users had pilot text in `systemPrompt` and openclaw used to send it every turn, the directive used to land. Today's default = `"first"` means it only lands on turn 1.

Either way, the daemon's current behavior (write to HEARTBEAT.md + leave systemPromptWhen alone) is *insufficient* on current openclaw. We need to actively manage one of the per-prompt surfaces.

## Recommended path forward (openclaw-first)

**Phase 1 — config-level (1–2 days)**
Ship the `configMutation` extension to `inject-manifest.json` from the previous spec. Daemon writes:

```json
"agents.defaults.systemPrompt":      "<pilot directive>"      (prepend-with-divider)
"agents.defaults.systemPromptWhen":  "always"                  (set-if-absent-or-managed)
"agents.defaults._pilotManaged":     {...sentinel...}          (overwrite-managed)
```

Pros: immediate, no openclaw-side install required, idempotent via sentinel.
Cons: edits a user-owned config file; merge logic is the risk.

**Phase 2 — plugin (1 week)**
Ship `@pilotprotocol/openclaw-plugin` to npm. Daemon-side: detect openclaw install, run `openclaw plugins install` (or hand-roll the registry write), confirm install, register the `before_prompt_build` hook. Subsequent reconcile ticks just verify install state.

Pros: clean separation, survives user `openclaw.json` edits, composes with other plugins.
Cons: introduces an npm package + an openclaw-version dependency.

**Phase 3 — symmetric coverage across Claude-likes (2–3 weeks)**
Once Phase 1+2 prove out on openclaw, ship matching paths for claude-code (UserPromptSubmit hook write to settings.json) and picoclaw (hooks block in config.json).

Phase 1 is the unblock. Phase 2 is the durable answer. Phase 3 generalizes.

## Open questions to resolve before implementation

1. **`heartbeats/openclaw.md` reuse**: should we trim the existing 104-line heartbeat for system-prompt-on-every-turn, or build a separate, tighter template? My recommendation: separate `heartbeats/openclaw-system-prompt.md` capped at ~600 tokens, since this rides on every turn's context budget.
2. **Daemon→openclaw bridge for plugin install**: does the daemon need access to `openclaw plugins install ...`, or does it write directly to `~/.openclaw/plugins/installs.json`? The latter is fragile (file format owned by openclaw); the former requires shelling out. Likely answer: shell out to `openclaw plugins install @pilotprotocol/openclaw-plugin` and treat openclaw-binary-not-on-PATH as a soft-fail.
3. **Versioning**: when openclaw bumps its plugin contract (the `hostContractVersion` we saw at `2026.5.7` in `installs.json`), do we need to re-publish our plugin? Yes — but the plugin can declare a compat range.
4. **Disable for power users**: same opt-out machinery as the config mutation spec — env var + sentinel + CLI command.

## What I'll commit on this branch if you say go

- `docs/ANALYSIS-per-prompt-injection.md` (this file)
- Updates to `docs/SPEC-skillinject-openclaw-per-prompt.md` to point at this analysis for the "why plugin vs config" decision
- A draft `inject-manifest.json` patch in `docs/` showing the exact `configMutation` block (Phase 1)
- A skeleton `npm/openclaw-plugin/` directory showing the plugin shape (Phase 2)

No code changes to `internal/skillinject/` or `pilotctl` yet — those are the implementation step, separate from this analysis.
