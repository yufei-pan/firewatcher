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
  and stamped earlier than that are not read. That needs the clock set back by more than `--capture-time` while
  firewatcher was stopped, and firewatcher started with the clock no more than a minute behind the saved line: most
  often a boot whose hardware clock was that far behind and was corrected before firewatcher started; a clock set
  back by hand does it too (shown without a reboot on systemd 219 to 257, 2026-11-25). Started while the clock is
  still more than a minute behind the saved line, firewatcher takes the position for one from the future and reads
  only the last `--tail-lines` lines. 1.68 did the same, and was worse (it skipped the whole second it could not find).
- Why: where the saved line is gone, firewatcher can only go by time, and so does journalctl: a cursor from another
  boot lands by its time (tested on systemd 219, 2026-11-23). Where the saved line is still there (a persistent
  journal), a clock set back does not change where the resume starts; the age of the position (`--resume-max`) is
  judged by the clock, and one that looks older than that is read by time, as when the saved line is gone.
- Revisit when: an operator hits it. The route then: a fallback that reads by boot instead of by time.
- Approved: chief's decision C224, 2026-11-24 (the user made the chief session their desk on 2026-11-14 and let it
  decide where it judges they would pick the option nine times in ten; not the user's words, and the user may
  reverse it): "(a) known limitation" with one README line. The user did not ask for it; 1.69's reviews found it.

### A stop while a compression run's `tar` writes leaves its `.partial` archive behind
- Kind: deferred (1.73)
- What the operator sees: when firewatcher is stopped (or crashes) while it compresses a month, the output folder keeps
  `YYYY-MM.tar.xz.PID.partial`, as large as the archive tar had written so far, up to the whole archive. It counts
  as that month, so it takes that space until a purge (delete-after months, or the free-space floor) removes it. The
  month's own folder is untouched, and the next run compresses it again. 1.71 the same.
- Why: the compression runs in a daemon thread and removes its `.partial` file only when tar returns; a stop ends the
  process first, and the next process has another pid, so it never writes or removes that file.
- Plan (1.73): when a compression run starts, remove a `YYYY-MM[.N].tar.xz.PID.partial` in the folder whose pid no
  longer runs (a name only firewatcher makes, which `_month_of` already recognises); a test with a stale file and one
  whose pid runs. The other way, ending tar and removing the file on the stop path, was left out: it adds a wait to
  every stop, and a crash would still leave the file.
- Revisit when: 1.73, started right after 1.72 is released.
