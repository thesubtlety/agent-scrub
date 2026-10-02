<p align="center">
  <img src="assets/logo.png" width="112" alt="Agent Scrub">
</p>
<h1 align="center">Agent Scrub</h1>
<p align="center">Find and remove secrets your AI coding agents left on disk.</p>

Claude Code, Codex, Cursor, etc. keep durable local histories, and secrets can wind up sitting there in
plaintext after the coding session is over. I found API keys in my AI coding-agent histories, so I built a
scrubber.

AI coding tools keep your prompts, transcripts, and tool output on your Mac — often with API keys and tokens
sitting in plaintext. Agent Scrub finds them and redacts them in place. Everything stays local; nothing is
uploaded.

<p align="center">
  <img src="assets/image.png" width="760" alt="Agent Scrub showing an AWS secret access key redacted across 6 copies in Codex history">
</p>

Covers **Claude Code, Codex, Gemini CLI, Cursor, GitHub Copilot, Windsurf, Cody, Cline, Aider, Continue, and
Pi** (and any VS Code fork sharing the same chat store).

## What it scans — and what it won't touch

Agent Scrub only reads each agent's **conversation history**: prompts, transcripts, tool output, and saved
memory. It never scans the tools' **config or credential files** — Codex `auth.json`, Continue `config.yaml`,
a project `.env`, editor secret storage, and the like are marked off-limits and are never read or rewritten.

That distinction is the whole safety model: a key in a transcript is a *leaked copy*. The agent authenticates
from its config, not from its chat log, so removing the copy clears the exposure without breaking the tool.
Agent Scrub only redacts these leaked copies — never a live credential a tool needs to run.

Want to know how dangerous a key you found actually is — what it can reach if someone else has it? Point it at
[geiger](https://github.com/puck-security/geiger), a read-only blast-radius triage for leaked credentials.

## Install

macOS 14 or later.

**Download (easiest).** Grab the latest `AgentScrub-*.zip` from
[Releases](../../releases/latest), unzip it, then in Terminal:

```sh
xattr -dr com.apple.quarantine AgentScrub.app
open AgentScrub.app
```

The app is unsigned, so macOS quarantines it on download — the `xattr` line clears that. (Or right-click the
app → **Open** → **Open**.) The release build is universal, so it runs on both Apple Silicon and Intel.

**Build from source.** Needs Xcode 16 (Swift 6):

```sh
./tools/app/bundle.sh
open .build/AgentScrub.app
```

## Permissions

On first run macOS asks for two things:

- **Keychain** — Agent Scrub keeps a random per-install key in your login Keychain and uses it to fingerprint
  secrets, so its own database never stores their plaintext. Allow it (choose *Always Allow* to stop repeat
  prompts). It only touches its own Keychain item.
- **Files** — Agent Scrub reads your agents' history to scan it. macOS gates file access, so you'll get a
  prompt (it may name Documents / Desktop / Downloads). Allow it, or it can't scan or redact.

Either way, nothing leaves your Mac.

## Use

It lives in the menu bar, scans on launch, and keeps up as your history changes.

- **Overview** — what's found, by type / project / app, plus lifetime totals.
- **Discovered secrets** — each secret and where its copies live. Reveal the value, decode a JWT, and:
  - **Redact now** — overwrite it in your files with a `[REDACTED:…]` marker.
  - **Always redact** — do that automatically every time it reappears.
  - **Not a secret** / **Keep** — dismiss or keep it.
- **Coverage** — anything that couldn't be read, and why; exclude folders you don't want scanned.

Redaction rewrites real files and can't be undone. It re-checks and re-parses every change, and skips files
an agent is actively writing (those retry once the session ends). It can't pull back copies already sent to
a provider or sitting in a backup.

## Command line

`hgctl` scripts the same actions — `scan`, `redact`, `verify`, `policy`, `enforce`. Every write is a dry run
unless you pass `--yes`.

```sh
swift run hgctl scan
```

## Your data

Everything stays on your Mac — Agent Scrub never makes a network connection.

Its state lives in `~/Library/Application Support/History Guard` (findings and your keep/redact decisions),
its key in your login Keychain, and excluded folders in preferences. To remove it completely: delete the app,
that folder, and the `io.adversis.history-guard` Keychain item.

## Develop

```sh
swift build && swift test
```

Tagging a release (`git tag v1.0.0 && git push --tags`) builds the universal `.app` and publishes it to
GitHub Releases via CI.
