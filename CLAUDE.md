# CLAUDE.md

> This is the `cce-authenticator` crate, inside the larger **`cce` Cargo workspace** —
> read `../cce-compositor/WORKSPACE.md` first for the multi-repo layout, the
> standalone-build rule, `ccebuild`, and the `cce-ui` toolkit. This file covers only
> what is specific to this crate.

`cce-authenticator` **is the cce session's polkit authentication agent.** It is not a
demo or a convenience: before it shipped, the session had no agent registered at all,
so *every* `pkexec` in the desktop failed instantly and silently — settings-app sysfs
writes, bluetooth power, storage backup, package updates. The only visible symptom was
optimistic UIs quietly reverting. If this crate is broken or its unit is down, that is
the failure you get back, and nothing prints to the screen to say so.

The whole crate is one `src/main.rs` implementing the `cce-ui` `Application` trait.

## Two modes

- **No args — agent mode.** Registers `org.freedesktop.PolicyKit1.AuthenticationAgent`
  at `/org/cce/AuthenticatorAgent` for this login session and serves requests until
  SIGTERM, when it unregisters. Shipped as `cce-polkit-agent.service`
  (`WantedBy=graphical-session.target`). That unit name predates this implementation —
  it was Soteria's, kept across the swap so the user's `systemctl --user enable`
  carried over.
- **`--standalone` / `-s`** — the window on its own, no D-Bus, authenticating against
  PAM (`PAM_SERVICE`) and fprintd directly. This is the test vehicle; see Verifying.

**A native cce-ui window is load-bearing, not a preference.** The interim agent
(Soteria, GTK) put up a dialog that never took keyboard focus under `cce-fx`, so it
sat there accepting nothing until polkit timed it out — "window disappeared by
itself". Native windows get normal map-focus. If a foreign toolkit's dialog ever needs
to work here, that focus path is the thing to debug.

The session id comes from `XDG_SESSION_ID`, then `/proc/self/sessionid`, then logind's
`GetSessionByPID` — three sources because user units live *outside* the login session
and inherit no session id. `startcce`'s `systemctl --user import-environment` list had
to learn `XDG_SESSION_ID` for the first source to exist at all. Soteria hard-required
that variable and crash-looped 26 times without it; this agent only prefers it, which
is why the fallbacks are worth keeping.

## How a request flows

polkitd calls `BeginAuthentication` on the tokio/zbus thread; the GUI runs
`cce_ui::engine::run` on the **main** thread, one window at a time, so requests hand
off over an mpsc channel and **queue**. Four statics are that seam:

- `ACTIVE_REQUEST` — the request the window being built belongs to. Its presence *is*
  polkit mode (`polkit_mode = active_req.is_some()`), and taking it is how success is
  reported exactly once.
- `ACTIVE_SENDER` — the running window's message sender, for D-Bus-initiated cancels.
- `COOKIES` — the active cookie plus pending cancellations. See Cancellation.

Inside a request the agent drives `/usr/lib/polkit-1/polkit-agent-helper-1 <user>
<cookie>`: it writes the password to the helper's stdin, and a reader thread turns the
helper's stdout protocol (`PAM_PROMPT_ECHO_OFF`, `PAM_PROMPT_ECHO_ON`,
`PAM_ERROR_MSG`, `PAM_TEXT_INFO`) into `AppMessage`s. The **exit status is the
verdict** — there is no success line to parse.

**The helper runs one PAM conversation and exits**, so a retry is a new process, not
another write to the old stdin (which is a closed pipe the moment it fails). That is
what `spawn_helper` and `RETRIES` exist for; the bound is not politeness, it stops a
helper that fails *instantly* — a cookie polkitd no longer recognises — from spawning
in a tight loop.

## Two invariants worth stating outright

**Simulation must never be reachable under a live request.** A simulated success sends
`Ok(())` to polkitd, which *grants the privileged action* having checked no credential
at all. `CCE_AUTH_SIMULATE` once did exactly that, because the guard only disabled
simulation when the variable was *absent*. It is now gated on the unsafe state — a
request is in flight — rather than on how simulation was asked for, and the password
and fingerprint paths exclude it again on `polkit_mode` instead of trusting the flag.
Keep that shape: gate on the dangerous condition, not on an allowlist of the ways in.

**Cancellations are recorded for every cookie, then consumed by their owner.** Because
requests queue, a `CancelAuthentication` can name a cookie whose window has not opened
yet, or one that is still starting and has no `ACTIVE_SENDER` to deliver to. The
handler therefore records unconditionally and *then* tries to deliver; the main loop
claims the cookie and checks for a record before opening a window, and `new()` checks
again once a sender exists. A single active-cookie slot got all three orderings wrong
and stranded dialogs. The crate's one test locks those orderings in.

## Verifying (the safe envelope is narrow)

- **`--standalone` spawned in the shadow session** (`cce-shadow spawn env
  CCE_AUTH_SIMULATE=1 …`) touches no polkit D-Bus and is the only way to exercise the
  window end to end without a prompt. `CCE_AUTH_SIMULATE=1` drives the auto-success
  path there (2s success, 1s exit).
- **Never live-test `pkexec` from the shadow session** — the D-Bus *system* bus is
  shared, so the prompt lands on the real screen.
- **Never run `polkit-agent-helper-1` by hand.** It drives real PAM: it can light up
  the fingerprint reader and trip `pam_faillock`, which has locked this machine out
  before. The helper and retry paths are consequently code-verified only.
- Agent health: `systemctl --user status cce-polkit-agent`, and the journal should say
  `Successfully registered`. `RUST_LOG=info` (set by the unit) narrates every request.

## Build

`make install` → `ccebuild install --no-build cce-authenticator`, which installs the
binary *and* `cce-polkit-agent.service`. Never hand-list binaries in the Makefile —
`cargo metadata` already knows them. This directory is its own git repository with a
fetch-only origin; committing locally is publishing, via gitsite. `Cargo.lock` is
gitignored here, so it needs no refresh when dependencies change.
