# Limitations

Approved known limitations and deferrals. Reviewers: read this first, and don't raise these again.

### On systemd 229 and older, some mount paths are written wrong
- Kind: known limitation
- What the operator sees: on systemd 229 and older (CentOS/RHEL 7's 219, Ubuntu 16.04's 229), a
  `--requires-mounts-for` path holding `%`, `"` or `\` is written into `RequiresMountsFor=` in a form those
  versions read as a different path: they keep 1.64's `%%` and its backslash escapes as they are. The unit then
  does not wait for that mount. 1.63 wrote such a path unchanged, which those versions read correctly. Paths
  with spaces work there too.
- Why: those versions neither expand `%` specifiers nor unescape in `RequiresMountsFor=` (systemd 219's
  `config_parse_unit_requires_mounts_for` splits on whitespace and quotes, nothing more); newer ones (239 and
  later) do both, and 1.64 writes for them. Writing per systemd version would mean detecting the version, for
  an end-of-life systemd and a mount path that holds one of these three characters.
- Revisit when: someone runs firewatcher on such a systemd with such a mount path.
- Approved: 2026-11-01, the user chose "Known limitation (Recommended)".

### While the events receiver is down, each alert waits one timeout before ntfy
- Kind: known limitation
- What the operator sees: with `events_url` set and its receiver not answering (the host down, its packets
  dropped), each alert (only `always_notify` captures fall back to ntfy) is pushed one `ntfy_timeout` late (10 s by default; twice that for a capture that
  overflows), because firewatcher tries the POST first and pushes to ntfy only when it fails. No alert is lost.
- Why: the POST and the push run one after the other. A separate short timeout, or skipping the POST for a while
  after a failure, would shorten the wait at the cost of a second setting or of state; a few seconds' delay while
  the receiver is down was judged acceptable.
- Revisit when: the delay matters in practice (a burst of alerts while the receiver is down).
- Approved: 2026-11-01, the user chose "Known limitation".

### A URL whose password starts with digits and a `/` shows those digits as the port
- Kind: known limitation
- What the operator sees: in a URL such as `http://u:2024/<rest>@h/e` (a `user:password` whose password starts
  with digits followed by `/`), the text up to the `/` is a valid host and port (`u`, port 2024), so firewatcher
  accepts it and its log lines show `http://u:2024`: the leading digits of the password appear as the port, and the
  request goes to host `u`. The same holds for a password that starts with `/`, `?` or `#` (`http://usr:/…@h/e`
  goes to host `usr`). Because such a URL reads as a host and port, firewatcher gives it no user:password warning.
- Why: such a URL is valid as written; refusing it would mean refusing an `@` in a URL's path, which valid LLM URLs
  use. Credentials in a URL are never sent anyway (README: use `events_token`, `token` or `api_key`).
- Revisit when: a way to tell such a URL from a real host and path appears, or someone hits it.
- Approved: 2026-11-01, the user ticked "fw: digits shown as port". The no-warning sentence added 2026-11-04, the user: "Add it to the wording".

### A purge for free space syncs every filesystem, so a hung NFS share can stall reading
- Kind: deferred
- What the operator sees: right after firewatcher deletes old months to stay above `--min-free-percent`, it calls
  `sync`, which writes every filesystem on the host. If some hard-mounted NFS share is not answering and holds unwritten
  data, that `sync` waits until its server comes back, and firewatcher reads no log lines meanwhile. It happens only
  after such a purge, on a host with such a share.
- Why: found during the 1.68 simplify pass (2026-11-14), after the 1.68 scope was set; present since 1.61.
- Revisit when: 1.69. Plan: sync only the filesystem the folder is on, with syncfs(2) through ctypes as hpcp's
  `_syncfs` does, and skip the sync where syncfs is missing (a filesystem that then shows freed space late costs a move
  to the fallback folder when one is set, or dropped writes for the rest of that capture when not, never the floor, as
  today).

### A failed `systemctl` step after the install's writes leaves the config and the unit, and a rerun puts the flags on ExecStart
- Kind: deferred
- What the operator sees: `--install-service` checks and renders everything before it writes, but `daemon-reload` and
  `enable --now` run after the writes. When one of them fails, the install prints "systemctl ... failed (exit N)", returns
  that code, and leaves `firewatcher.conf` (mode 0600) and the unit in place. The same command run again finds the config,
  so it renders the command-line flags onto the unit's `ExecStart` instead of into the config. The ntfy URL, a secret like
  a password, is then in the world-readable unit (the run prints a warning for it). A clean install keeps `ExecStart` to
  `--config <path>`. 1.67 does the same.
- Why: found by the 1.68 final review (2026-11-15); the 1.68 change moved only the checks and the rendering before the
  first write. Not worse than 1.67.
- Revisit when: 1.69. Plan: when `daemon-reload` or `enable --now` fails after this run created the config, remove the
  config and the unit this run wrote (it created the config with `O_EXCL`, so it is sure the file is its own), so the
  rerun is a clean install. A config that existed before the run stays, and so does a unit this run replaced rather than created.

### The journal replay treats a whole second as context when the saved line is no longer in the journal
- Kind: deferred
- What the operator sees: at a restart, firewatcher reads the journal back from the saved position. When the journal holds
  fewer lines of the saved second than the saved line number says (the journal file that held the start of that second
  was rotated away while firewatcher was stopped), the saved line is never found. Every line that follows it in that
  second is replayed as context only and never matched, so a line in it that matches a pattern opens no capture. The
  next second's lines are matched as usual. The README says that when unsure, firewatcher reads a line again rather than
  skip it; this case skips. Rare: it needs that second's lines split over a rotation. 1.67 does the same.
- Why: found by the 1.68 final review (2026-11-15). The replay ends at the saved line, found by its number in the second
  and its digest; it has no rule for a line number that cannot be reached.
- Revisit when: 1.69. Plan: end the replay at the first line of the saved second whose digest matches when the count
  cannot reach the saved number (a line read again is the safe mistake), and test it with a journal that lost the start of
  the second.

### On Python 3.6 under a C locale, a service given a non-ASCII path dies when it writes there
- Kind: deferred
- What the operator sees: firewatcher run by hand, or from a hand-written config, on Python 3.6 under a C locale with a
  non-ASCII output folder, log file or note stops with `UnicodeEncodeError` at the first capture or at start. An install
  no longer writes such a path (1.68 refuses it, exit 2), and Python 3.7 and later are not affected. 1.67 does the same.
- Why: Python 3.6 reads non-ASCII bytes under a C locale as undecodable text, which its file calls then cannot encode.
  Found by the 1.68 final review (2026-11-15, F2).
- Revisit when: 1.69. Plan: give such values to the file calls as their bytes, as the local branch `superseded-local-1.61`
  did with `_as_utf8` (kept as the tag `archive/superseded-local-1.61`), or stop and say to run under a UTF-8 locale.

### A command-line `--tail-lines ''` reaches `tail -n ''`, which the config file's empty value does not
- Kind: deferred
- What the operator sees: `firewatcher --tail-lines '' ...` (also `--tail_lines ''`, and a unit that carries it) starts
  `tail -n ''`, which exits with "invalid number of lines"; firewatcher then ends ("Processed 0 lines") and, under
  systemd, restarts in a loop. Following the journal with no saved position fails the same way (`journalctl` answers "Failed to parse --lines=''"). An empty `tail_lines =` in the config file is ignored, as an unset value. 1.67 does the same.
- Why: found by the 1.68 final review (2026-11-15). The command-line value is used as given, while the config loader skips
  an empty one.
- Revisit when: 1.69. Plan: treat an empty `--tail-lines` as unset in the argument parser, the way the config file does.
