# CLAUDE.md

Context for Claude Code sessions working in this repository.

## What this is

A personal fork of [chenyg0911/webssh-go](https://github.com/chenyg0911/webssh-go)
— a small, single-file Go web SSH client (`golang.org/x/crypto/ssh` +
`gorilla/websocket` + `pkg/sftp`, an embedded HTML/JS frontend). Built by
and for one person (leogama), for one machine: it will eventually run on
their personal VPS (`leogama.xyz`) and take over the `ssh.leogama.xyz`
subdomain, letting them open a browser terminal to *other* personal
machines using a private key stored on the VPS — never typed into the
browser, no persistent session needed.

This repo is consumed as a source dependency by a separate, private
repository — `leogama/vps-toolkit` — whose `apps/webssh/setup.sh` clones
this repo's `single-user` branch and compiles it. That repo also carries
the fuller deployment story (systemd unit, Caddy reverse proxy + auth,
`/srv` layout conventions, `PLANS.md`'s "WebSSH (ssh.leogama.xyz,
apps/webssh)" section) — this repo's own scope is just the Go/JS/HTML
source itself.

## My goals for this project (leogama, the owner)

Two goals, in order, and both matter — don't optimize away either one:

1. **A tool I'll actually use.** Very simple, occasional-use browser SSH
   client. Not a daily driver, not multi-user, no accounts beyond whatever
   Caddy's Basic Auth does in front of it on the VPS. The one feature that
   actually matters: the private key lives on the server, not typed in
   through the UI each time. The file browser (SFTP list/upload/download)
   is a genuinely useful bonus, worth keeping.

2. **Learning Go and network programming, hands-on, on real code I'll keep
   using.** This is deliberately *not* "hand me a finished, secure app" —
   it's "help me modify a real single-file program, one understandable
   piece at a time." When something is broken or insecure, the default
   move is to **flag it clearly and explain it, not silently fix it** —
   fixing it is often the next exercise. Don't do large, sweeping rewrites
   in one pass; small, explained, reviewable commits are much more valuable
   to me here than an efficient diff. When you do touch code, prefer
   comments that teach (what a stdlib call actually does, why a pattern is
   shaped the way it is) over comments that just restate what's obvious
   from the code.

## Branches

- **`single-user`** — the stable/deployable branch. This is what
  `vps-toolkit`'s `setup.sh` actually builds. Currently sits at the last
  upstream commit before upstream's own multi-user/SQLite rewrite (that
  rewrite added nothing this single-admin setup needs, since Caddy's own
  auth already covers "who's allowed in" — don't reintroduce app-level
  multi-user auth here).
- **`dev`** — active work happens here. Merge into `single-user` only once
  a round of changes is working and worth deploying — don't merge
  half-finished exploration.

## Known, deliberately-not-yet-fixed issues

Both flagged with a comment at their exact spot in `main.go` (as of the
"document main.go" commit on `dev`). Don't fix either without it being
asked for explicitly — they're intended as guided learning exercises, not
oversights to clean up on sight:

- `CheckOrigin` on the websocket upgrader (`var upgrader = ...`) accepts
  any origin. Combined with sitting behind Caddy's `basic_auth` (browsers
  replay cached Basic Auth credentials across origins), this is a real CSRF
  angle on the terminal endpoint. The eventual fix is checking the Origin
  header against the app's own expected origin.
- `HostKeyCallback: ssh.InsecureIgnoreHostKey()` in `handleWebSocket`
  means outbound SSH connections never verify the target machine's
  identity. The eventual fix is pinning each connection's expected host
  key (trust-on-first-use, or configured up front), not this blanket
  bypass.

**Don't deploy this somewhere it's reachable with a real key configured
until at least the CheckOrigin issue is addressed.**

## Secrets

Never commit real values for `WEBSSH_ENCRYPTION_KEY`, private keys, or
`connections.json` (already gitignored) — this fork has no separate
SECURITY.md, but the same rule from `vps-toolkit` applies: secrets live in
environment variables and root-owned files on the actual box, never in git
history, not even as "just a test value."

## Conventions carried over from vps-toolkit

- Caddy handles TLS and Basic Auth in front of this app — this program
  itself should keep speaking plain HTTP with no auth of its own (already
  done: see the "strip login/session auth and TLS/cert handling" commit).
- Native/simple before clever: this is a good project for straightforward,
  well-commented stdlib usage, not for reaching for extra dependencies or
  abstractions the current single-file shape doesn't need.
