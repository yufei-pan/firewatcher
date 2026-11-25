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
  dropped), each alert (only `always_notify` captures fall back to ntfy) is pushed one `ntfy_timeout` late (10 s by
  default; 5 s for a capture that overflows the analysis queue), because firewatcher tries the POST first and pushes
  to ntfy only when it fails. Other captures are not pushed then; they stay in the capture folder and the journal.
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

### After a boot with the clock far behind, a restart does not read the lines logged before the clock was corrected
- Kind: known limitation
- What the operator sees: when the journal lost the saved line (as a volatile journal does at a reboot), a restart
  reads from `--capture-time` (300 s by default) before the saved line; lines logged while firewatcher was stopped
  and stamped earlier than that are not read. That needs a boot whose hardware clock was more than `--capture-time`
  behind and was corrected before firewatcher started. 1.68 did the same, and was worse (it skipped the whole
  second it could not find).
- Why: where the saved line is gone, firewatcher can only go by time, and so does journalctl: a cursor from another
  boot lands by its time (tested on systemd 219, 2026-11-23). Where the saved line is still there (a persistent
  journal), a clock set back does not change where the resume starts; the age of the position (`--resume-max`) is
  judged by the clock, and one that looks older than that is read by time, as when the saved line is gone.
- Revisit when: an operator hits it. The route then: a fallback that reads by boot instead of by time.
- Approved: chief's decision C224, 2026-11-24 (the user made the chief session their desk on 2026-11-14 and let it
  decide where it judges they would pick the option nine times in ten; not the user's words, and the user may
  reverse it): "(a) known limitation" with one README line. The user did not ask for it; 1.69's reviews found it.

### After a reboot, the lines the old boot logged after firewatcher stopped are not read
- Kind: deferred
- What the operator sees: on systemd 252 and later (Debian 12 and 13, EL9, Ubuntu 24.04), with a persistent
  journal, a restart after a reboot reads on from the first entry of the new boot. What the old boot logged between
  firewatcher's stop and its end (a failed unmount, an I/O error during shutdown) is never matched. systemd 219 to
  249 read it. Since 1.67.
- Why: from systemd 252 on, `journalctl --follow` shows only the newest boot, with `--cursor` and with `--since`
  (measured 2026-11-25 on 252, 255, 257 and 259; 219, 239 and 249 show every boot). No option lifts it on every
  version.
- Plan (1.71): read the lines logged while stopped without `--follow`, from the saved entry to the journal's end,
  then follow from the last entry read, dropping it as a restart drops the saved entry. The context before the saved
  entry is read in the same pass, from a cursor found by reading back from the saved entry (entry "After a restart,
  the context before the saved entry can lack its last lines" below). The same change adds one test
  that runs the real journalctl (on a journal written with systemd-journal-remote, skipped where that is missing; the
  same change makes CI's ubuntu-24.04 jobs install it, which they do not today): lines equal journalctl's, the entry
  found with 30 entries after it, the entry gone, two boots. No test in the suite runs a real journalctl today, and
  the fake one is only as right as its author.
- Revisit when: 1.71.

### After a restart, the context before the saved entry can lack its last lines
- Kind: deferred
- What the operator sees: the lines read again before the saved entry, as context for a capture opened soon after a
  restart, end early in two cases. When the clock was ahead and was set back inside the `--capture-time` window, the
  context ends at the first line stored after the saved entry's second. When the window holds more than the read gets
  through in 30 seconds (about 4 to 6 million lines on the hosts measured, far above journald's default rate limit),
  the context ends where that read stopped, without the window's last lines. No line is skipped or matched again by
  this; 1.69 matched the first case's lines again and read the whole window before matching. Since 1.70.
- Why: 1.70 reads the context forward from a time, which keeps no entry in memory, but starts and stops by time.
- Plan (1.71): the change of the entry above, which reads in journal order. Read back from the saved entry for the
  cursor where the context starts, no further than `--buffer-max-mb` holds; then read forward from that cursor without
  `--follow`: the lines before the saved entry refill the context, the saved entry is dropped, the rest are matched,
  and the follow starts after the last entry read. No time stop, no separate 30-second read remains.
- Revisit when: 1.71.

### After a restart, a journalctl that does not answer the look matches the window again
- Kind: deferred
- What the operator sees: when journalctl fails, or prints nothing within 30 seconds, as firewatcher looks for the
  saved entry at a restart, firewatcher reads by time as if the entry were gone: every line from `--capture-time`
  before it is matched again, so an incident of that window is captured and pushed a second time. No line is
  skipped. 1.69 kept its saved position in that case. Since 1.70.
- Why: 1.70 treats "no answer" as "gone", because without the first entry it cannot tell.
- Plan (1.71): with the change of the two entries above: when the look gets no answer, read on from the saved
  entry without the context, as 1.69 kept its position, with a real-journalctl test of a cursor the journal lost.
- Revisit when: 1.71.
