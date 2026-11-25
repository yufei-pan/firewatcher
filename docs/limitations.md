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

### A stop signal another thread takes waits for the next line
- Kind: deferred
- What the operator sees: rarely, a SIGTERM or SIGINT sent to firewatcher's process alone (`kill`) is acted on only
  when the main thread next wakes: at the next log line, or with a capture open at its next sync or position save, at
  the latest the end of its `--capture-time` window. The kernel hands a process's signal to any of its threads, and
  one taken by another thread (the log reader, the notifier, a compression run) wakes none of the main thread's
  waits. Seen once in about 1,000 stops in tests (systemd 252 under load, 2026-11-25). The trigger found: on Python
  3.10 and later, a stop sent to firewatcher alone while a thread starts a process (the follow at the handover after
  a restart's backlog read, once per restart; a compression run's `tar`). `systemctl stop` signals journalctl too,
  whose end wakes firewatcher. Since 1.58, which added those threads.
- Why: blocking the stop signals in those threads, the usual cure, is inherited by the processes they start: the
  thread that reads the log starts journalctl, which could then not be stopped (tried in 1.71's build: a journalctl
  that thread had started ignored the stop, and firewatcher's exit waited for it).
- Plan (1.72): one design check, with the entry below, of how a stop reaches the loop: a stop that sets a flag the loop
  checks and that wakes its wait, or the two routes: the threads block the stop signals and start their processes with
  them unblocked, or the main thread waits on a wakeup descriptor (`signal.set_wakeup_fd`) beside its read; then a test
  that hands a stop to each thread.
- Revisit when: 1.72.

### A stop that lands while a busy capture is read can hang, or be ignored and lose one line
- Kind: deferred
- What the operator sees: while a capture is open and lines arrive fast (a burst, or the lines logged while stopped
  after a restart), about 1 stop in 100 goes wrong in one of two ways (tests on Python 3.6, 3.11 and 3.13,
  2026-11-25). It hangs after "Exiting." until the unit's `TimeoutStopSec` kills firewatcher, so the last position is
  not saved and up to a second of lines is read again at the next start. Or it is ignored: the log says "Error
  reading line: cannot release un-acquired lock", one line already read is neither matched nor captured, and
  firewatcher runs on until its journalctl ends or a second signal. Since 1.58, which added the reader thread.
- Why: a stop is raised as an exception wherever the main thread is, Python's lock code is not safe against that, and
  the loop takes the broken lock for a read error.
- Plan (1.72): with the entry above: a stop sets a flag that the loop checks and that wakes its wait, and is no
  longer an exception in the main thread; then a test that stops a busy capture a few hundred times.
- Revisit when: 1.72.
