# firewatcher

Watch a log stream (journald, syslog, or any file) for incident patterns, then persist a window of surrounding messages to a durable location — including a network filesystem — so the record survives even if the machine later dies.

The watcher reads the journal with `journalctl --follow` when journald runs on the host (or its journal files are there, such as a host journal mounted into a container). Otherwise it follows `/var/log/syslog`, then `/var/log/messages`, even when `journalctl` is installed; `--log-file` picks a file. With no syslog file either, it falls back to `journalctl`. Running the daemon does not require systemd; only `--install-service` / `--uninstall-service` do.

Everything but [resuming after a restart](#resuming-after-a-restart) works with every source: the compressed context before a match, leaving out context already captured, the free-space floor, SIGHUP reload, and LLM analysis and pushes. Resuming needs the journal; with a log file, firewatcher reads the last `--tail-lines` lines at every start, as before.

## Install

```bash
pip install firewatcher
```

From a clone of this repository:

```bash
pip install .
```

Requires **Python 3.6+**. No third-party runtime dependencies.

## Quick start

```bash
firewatcher /etc/firewatcher/patterns.d
firewatcher -t 300 -o /var/log/captured_messages/ /etc/firewatcher/patterns.d
```

A directory argument loads every non-hidden pattern file inside it. Files ending in `.regex` are compiled as regular expressions. Any other pattern file is treated as fnmatch (bash-like) substrings, with `*` added on both ends. Lines starting with `#` are comments; to match text that starts with `#`, such as the kernel's `#PF:`, write `[#]PF:` in a plain file or `\#PF:` in a `.regex` file. Matching is case-sensitive; for a case-insensitive pattern, put it in a `.regex` file with `(?i)` in front.

`firewatcher` exits with an error when no pattern loads, for example when a pattern path is mistyped or every regex is invalid, instead of running while matching nothing.

`--install-service` seeds `/etc/firewatcher/patterns.d` with example patterns when it holds no pattern file. The `examples/` directory in the source tree is not installed onto `PATH` by `pip install`; copy the pattern files from a clone, or let `--install-service` write them.

On a match, `firewatcher` writes:

- a per-incident capture under `{output-folder}/{YYYY-MM}/…`
- a line in `{output-folder}/journal.log`

Live capture is written as lines arrive, so a copy can already be on another filesystem if the host then disappears. Each captured line is flushed as it is written, and the capture file is fsynced at most once a second and when the capture closes, so a host crash loses at most about the last second of it.

A capture holds the whole `--capture-time` window before its match, so on a busy host one capture can be tens of megabytes; a lower `--capture-time` or `--buffer-max-mb` keeps captures smaller.

When a capture opens, lines of its window that an earlier capture of the same run already holds are left out, with a note naming that file and how many lines it holds. In an error storm, where each capture opens right after the last one closes, that saves writing the same context again and again; lines that no capture holds are always written. Such a capture is not complete on its own: its LLM excerpt and push see the note, not the lines in the earlier file. A capture that moved to the fallback folder, or lost lines on the way, is never pointed to: later captures write its lines again.

A capture ends `--capture-time` seconds after its last matching line, or `--capture-time-max` seconds (default 3600) after it opened, whichever comes first, so a pattern that keeps repeating still produces a finished capture, and its analysis and push, at least once an hour. A later match starts a new capture.

If the output folder cannot be written (a full disk, a read-only remount, an NFS server that returns errors), the capture continues under `--fallback-folder` (default `/var/lib/firewatcher/captured_messages/`), starting with every line written since the last successful fsync and a note naming the file it moved from. That capture is listed in the fallback folder's own `journal.log`, and the fallback folder is compressed and pruned like the output folder. If no folder can be written, `firewatcher` keeps running, logs the error, and still hands the incident to the notifier.

Put the fallback folder on a different filesystem from the output folder. The default is under `/var/lib`, which shares a disk with `/var/log` on most systems, so it covers a failed NFS output folder but not a full local disk.

The fallback needs the failure to come back as an error. On an NFS mount with the default `hard` option, writes to an unreachable server wait instead of failing, and `firewatcher` waits with them. To fall back instead, mount the output folder with `soft` (or `softerr`) and a short `timeo`.

`firewatcher` finishes the open capture on SIGINT and on SIGTERM. A second SIGTERM ends it at once.

SIGHUP reloads the pattern files and the `--always-notify` files from the paths given at startup, so after editing `/etc/firewatcher/patterns.d/`, run `sudo systemctl reload firewatcher`. The new patterns apply from the next log line, and the journal says how many loaded. If no watch pattern loads, the old ones stay and the error is logged. The config file and other settings are not re-read; restart for those. In a terminal, SIGHUP keeps its usual meaning (the terminal went away) and ends `firewatcher`. Two SIGHUPs close together reload once.

### Resuming after a restart

When firewatcher follows the journal (not a log file), it saves how far it has read in `--position-file` (default `/var/lib/firewatcher/journal.position`): about once a second while lines arrive or a capture is open (the open capture is fsynced first, so a saved position never covers capture lines that are not on disk), as soon as a match opens a capture, and when it stops. After a restart it reads on from there instead of the last `--tail-lines` lines; after a crash or `kill -9`, that can be up to about a second before the last line it read. Each save is fsynced before it replaces the old one, so a hard reset or power loss leaves the last or the previous position, never an empty file. Lines logged while it was stopped, such as during a reboot, are still matched, and an incident it already captured is not captured again. The `--capture-time` seconds before the saved line are read again only to refill the context kept before a match. At most `--resume-max` seconds (default 3600) are read back, so after a longer stop only the last hour is matched.

To tell where it stopped, firewatcher reads the journal with `journalctl -o short-iso`, so journal lines in captures carry the year and time zone: `2026-10-23T17:52:41+00:00 host sshd[812]: …` instead of `Oct 23 17:52:41 host sshd[812]: …`. Lines logged while firewatcher was stopped arrive all at once. A capture opened by one of them takes its context from the `--capture-time` before that line by the time each line was logged, and holds the lines after it as they are read, up to `--capture-line-count-max`.

The position is the second of the last line read, its place in that second, and a digest of it. When unsure, firewatcher reads a line again rather than skip it: identical lines logged in one second, and lines that journald stored in another order than the one they show, can be captured again after a restart, and when the journal no longer holds the saved line (its file was rotated away while firewatcher was stopped, or a crash or reboot lost it), every line from `--capture-time` before it is matched, and no further back than `--resume-max`. One case can skip lines: if the journal lost the saved line, or lines before it in its second, and holds a later one of that second with the same text, the replay can end there and the lines between are not matched ([limitations](https://github.com/yufei-pan/firewatcher/blob/master/docs/limitations.md#a-restart-after-the-journal-lost-the-saved-line-can-skip-lines-that-follow-it)). A failed save is logged once, and a restart then reads again from the last position saved. If the clock is set back after a save by up to a minute (a boot with a wrong hardware clock) and the journal still holds the saved line, the lines after it are still matched, even when they are stamped before the saved second. A position more than a minute ahead of the clock is ignored, and the last `--tail-lines` lines are read. After a reboot that lost the saved line, lines stamped more than `--capture-time` before it (a boot whose clock was far behind until corrected) are not read ([limitations](https://github.com/yufei-pan/firewatcher/blob/master/docs/limitations.md#after-a-boot-with-the-clock-far-behind-a-restart-does-not-read-the-lines-logged-before-the-clock-was-corrected)).

Only one firewatcher uses a position file at a time: another one started with the same file, such as a test run in a terminal with the default settings, reads the last `--tail-lines` lines and saves nothing. An empty `--position-file` turns resuming off, and so does a journalctl that does not accept `-o short-iso` and `--since=@`, which firewatcher checks at start.

### Disk and memory limits

firewatcher keeps the filesystems it writes captures to above `--min-free-percent` free (default 1%, counted as `df` does, so the root-reserved blocks are left alone). It asks the filesystem when a capture opens, about once a second, and before its own writes could come within 64 KiB of the floor (at least every 8 MiB), fsyncing first so an NFS server counts every byte; a line that would cross that margin is not written there. firewatcher's own writes never take the disk past the floor; another program filling it between two checks can.

Near the floor, firewatcher may delete its own oldest months in that folder, so a new incident can be recorded, under these rules:

- **What:** only what firewatcher itself creates: `YYYY-MM` folders, `YYYY-MM[.N].tar.xz` archives, and their `.partial` files, each of the kind it should be (a folder, or a regular file). A month counts as a whole.
- **Never:** the current month, the month being written, a month with anything in it changed in the last day (another firewatcher may be writing there), a month being compressed, or a month with another filesystem mounted inside it.
- **How much:** only as many months as it takes, counted by their size on disk, and nothing at all if deleting every one of them still could not make room. That happens when something else filled the disk, and then the history is kept.
- **How often:** at most once per `--purge-interval` per folder (default an hour), so a disk that something else keeps filling drains firewatcher's history slowly. A purge that could not help is not tried again for five minutes (or the interval, if shorter). Each deletion is logged.

After deleting, firewatcher syncs that filesystem alone (syncfs; none on macOS, where APFS shows freed space at once) and reads the free space again. A filesystem that shows freed space late costs a move to the fallback folder, never the floor. If there is still no room, the capture moves to the fallback folder with a note, or, with no folder left, stops being written, which is logged; the incident is still pushed. Compression keeps to the floor too: a month whose archive could cross it is left uncompressed for now. Purging and compression never wait for each other, so log reading never waits for `tar`. `--delete-after-months 0` means nothing is deleted by age; the floor can still delete the oldest months. Set `--min-free-percent 0` to turn all of this off.

Memory is bounded too. The `--capture-time` seconds before a match are kept compressed (zlib, about 3 times smaller for a busy host's varied lines) within `--buffer-max-mb` (default 16 MiB); past it the oldest lines are dropped, and the capture says so. The newest lines, up to 256 KiB before they are compressed, are always kept, so the buffer can go over the limit by about that much. A line longer than 1 MiB is read and matched in pieces, so a pattern split across a 1 MiB boundary is missed.

Monthly directories are compressed on a background thread, so log reading never waits for `tar`. Each month becomes `YYYY-MM.tar.xz` holding `YYYY-MM/…`. The directory is removed only after `tar` succeeds and the archive and its folder are synced to disk; if a sync fails, the month stays and is archived again later, nothing lost. An existing archive is never overwritten: the new one becomes `YYYY-MM.1.tar.xz`, and so on.

## systemd service

```bash
sudo firewatcher --install-service
sudo firewatcher --print-unit
sudo firewatcher --uninstall-service
```

`--install-service` writes `/etc/systemd/system/firewatcher.service`, creates the output directory, seeds `/etc/firewatcher/patterns.d/` with example patterns **only if it holds no pattern file**, writes `/etc/firewatcher/firewatcher.conf` **only if that file is missing**, then `systemctl daemon-reload && systemctl enable --now firewatcher`. It checks first, and writes nothing (exit 2) for a unit name systemd cannot load or a path or value that is not UTF-8. If writing the unit or a `systemctl` step fails (or `systemctl` cannot be run), it removes the config and the unit it created, puts back a unit it replaced as it was, and disables a unit it enabled, so the same command can run again. The output folder and the example patterns stay.

`systemctl reload firewatcher` reloads the pattern files without a restart; see SIGHUP above.

Capture files follow the process umask. A systemd service defaults to `UMask=0022`, so captures are readable by every local user, while the journal they copy from is normally readable only by root and the `adm`/`systemd-journal` groups. On a host with untrusted local users, add `UMask=0027` to the unit, for example with `systemctl edit firewatcher`.

If systemd is not available, `--install-service` and `--uninstall-service` print a warning and exit. `--print-unit` still works so you can copy the unit elsewhere.

Useful flags:

| Flag | Description |
|------|-------------|
| `--unit-name NAME` | Unit name (default: `firewatcher`) |
| `--requires-mounts-for PATH` | Add `RequiresMountsFor=` (repeat for NFS/remote output). Each path is made absolute and normalized as text (`.`, `..`, `//`, a trailing `/`; symlinks are not followed, as systemd follows none), quoted for you when it has spaces, quotes or backslashes, and refused if it has a newline or is not UTF-8 (systemd cannot read either back there). On systemd 229 and older (EL7), a path with `%`, `"` or `\` is read as a different path ([limitations](https://github.com/yufei-pan/firewatcher/blob/master/docs/limitations.md#on-systemd-229-and-older-some-mount-paths-are-written-wrong)) |
| `--no-enable` | Write the unit and reload, but do not enable or start it |

```bash
sudo firewatcher --install-service -o /mnt/logs/captured_messages \
  --requires-mounts-for /mnt/logs/captured_messages \
  /etc/firewatcher/patterns.d
```

## Options

| Flag | Description |
|------|-------------|
| `pattern_file …` | Pattern files or directories |
| `--log-file` | Log file to follow (default: the journal when journald runs, else `/var/log/syslog`, else `/var/log/messages`) |
| `-t`, `--capture-time` | Seconds of context after a match (default: 300) |
| `--capture-time-max` | Longest one capture may run, in seconds (default: 3600; 0 = no limit) |
| `-o`, `--output-folder` | Where to write captures (default: `/var/log/captured_messages/`) |
| `--fallback-folder` | Where a capture continues when the output folder cannot be written (default: `/var/lib/firewatcher/captured_messages/`; `''` disables) |
| `--tail-lines` | Lines to start with (default: 20; `+N` from line N, not with journalctl). Not used when the journal resumes from a saved position |
| `--filter-only` | Filter existing logs only (`cat` instead of `tail -F`, or `journalctl` without `--follow`). Windows are measured in read time, not log time, and existing logs are read far faster than they were written, so `-t` and `--capture-time-max` barely limit a capture: it usually runs to `--capture-line-count-max` lines or the end of the input |
| `--compress-after-months` | Tar.xz monthly dirs after N months (default: 3) |
| `--delete-after-months` | Delete `YYYY-MM` dirs after N months (default: 0 = never by age; the free-space floor can still delete the oldest months) |
| `--capture-line-count-max` | Max lines written after a match (default: 10000). The lines before it are bounded by `-t` and `--buffer-max-mb` |
| `--buffer-max-mb` | Memory, in MiB, for the lines kept before a match, compressed (default: 16). The oldest are dropped past it |
| `--min-free-percent` | Free-space floor, 0–50%, for the filesystems captures go to (default: 1; 0 disables). See [Disk and memory limits](#disk-and-memory-limits) |
| `--purge-interval SEC` | Least time between two deletions of old months in one folder for free space (default: 3600; 0: no wait) |
| `--position-file PATH` | Where firewatcher saves how far it read the journal, so a restart resumes there (default: `/var/lib/firewatcher/journal.position`; `''` disables). See [Resuming after a restart](#resuming-after-a-restart) |
| `--resume-max SEC` | Most seconds of journal read back at start: lines logged while stopped, and context before them (default: 3600; 0: none) |
| `--config PATH` | INI config file. Default: `/etc/firewatcher/firewatcher.conf` when that file exists. An explicit path must exist |
| `--llm` / `--no-llm` | Enable or disable LLM analysis of each finished capture |
| `--llm-base-url URL` | OpenAI-compatible API root, such as `http://127.0.0.1:11434/v1` |
| `--llm-model NAME` | Model name |
| `--llm-timeout SEC` | LLM HTTP timeout (default: 60) |
| `--llm-max-bytes N` | Capture bytes sent to the model (default: 48000) |
| `--llm-notes TEXT` | A short note about this host, sent to the model with each capture (default: none; `''` clears a note set in the config). See [LLM analysis and notifications](#llm-analysis-and-notifications) |
| `--notify` / `--no-notify` | Enable or disable ntfy pushes |
| `--ntfy-url URL` | ntfy topic URL, such as `https://ntfy.sh/mytopic` |
| `--ntfy-priority N` | ntfy priority 1–5 (default: 4) |
| `--ntfy-timeout SEC` | Worker ntfy timeout (default: 10). A full analysis queue uses 5 seconds |
| `--always-notify PATH` | Pattern file or directory (repeatable). A capture with a matched line that also matches one of these is pushed even when the LLM says not to notify |
| `--install-service` | Install and enable a systemd unit |
| `--print-unit` | Print that unit and exit |
| `--uninstall-service` | Disable and remove the unit |
| `-V`, `--version` | Show version and exit |

`--tail_lines`, `--filter_only`, `--no-filter_only` and `--capture_line_count_max` are still accepted with underscores.

## Config file

Runtime settings live in an INI file. Explicit command-line flags override the file. Built-in defaults apply when neither sets a value. A missing default file is ignored. `--uninstall-service` does not read the file.

A commented example with all supported settings is in [`examples/firewatcher.conf`](https://github.com/yufei-pan/firewatcher/blob/master/examples/firewatcher.conf). Copy it to `/etc/firewatcher/firewatcher.conf`, or use `firewatcher --config /path/to/firewatcher.conf`.

```ini
[watch]
patterns = /etc/firewatcher/patterns.d
capture_time = 300
capture_time_max = 3600
output_folder = /var/log/captured_messages/
fallback_folder = /var/lib/firewatcher/captured_messages/
filter_only = false

[llm]
enabled = false
base_url = http://127.0.0.1:11434/v1
model = llama3.1
timeout = 60
max_bytes = 48000
notes = loop/dm devices from pytest and OOMs in capped test containers are expected

[notify]
enabled = false
ntfy_url = https://ntfy.sh/firewatcher-myhost-REPLACE_ME
priority = 4
timeout = 10
events_url =
events_token =
always_notify =
```

`patterns` and `always_notify` are one path per line, or comma-separated. Positional pattern arguments replace the `patterns` list.

Out-of-range values stop `firewatcher` at startup: a negative time or count, `capture_time` over 7 days or `capture_time_max` over 30 days, `min_free_percent` outside 0–50, `purge_interval` or `resume_max` over 30 days, `buffer_max_mb` outside 1–65536, a timeout of 0 or less or over a day, or an ntfy priority outside 1–5. So does an LLM, ntfy or events URL that is not `http://` or `https://`, has spaces, or whose server part is not a host name or a bracketed IPv6 address with an optional port (0–65535), as firewatcher reads it by its own strict rule. A `user:password` in a URL is never sent; one that would make the URL read two ways is refused, with [one exception](https://github.com/yufei-pan/firewatcher/blob/master/docs/limitations.md#a-url-whose-password-starts-with-digits-and-a--shows-those-digits-as-the-port).

`api_key` under `[llm]` and `token` under `[notify]` are not command-line flags. `FIREWATCHER_LLM_API_KEY` and `FIREWATCHER_NTFY_TOKEN` override them when set. `events_token` under `[notify]` is likewise config-only, overridden by `FIREWATCHER_EVENTS_TOKEN`. `--install-service` creates `/etc/firewatcher/firewatcher.conf` with mode `0600` only when it is missing, and the unit runs `firewatcher --config` that path. An existing file is left as it is. Flags passed to a later install are appended on `ExecStart` so they override the file.

Generated configs include explanatory comments above each setting. When no ntfy URL is supplied, a new config gets `https://ntfy.sh/firewatcher-<hostname>-<random>`, with a 12-character URL-safe base64 suffix (72 random bits, no padding). The hostname is sanitized and shortened as needed to keep the topic within 64 characters. Explicit URLs are preserved, and reinstalling leaves an existing config and topic unchanged. Notifications still default to off; subscribe to the generated topic in ntfy, then set `[notify] enabled = true`. When copying the example above, replace its topic with your own.

## LLM analysis and notifications

Both features default off.

- Notifications on, LLM off: every finished capture is pushed. The title is `{hostname}: {pattern}`.
- LLM on, notifications off: the model writes a title, summary, and notify decision. The report is appended to the capture file and logged. Nothing is pushed.
- Both on: a push is sent only when the model sets `notify` to true.
- With `[notify] events_url` set, the events service judges instead and firewatcher's LLM is off; see [Sending captures to an events service](#sending-captures-to-an-events-service).
- If the LLM request times out, returns an HTTP error, or is not the expected JSON, and notifications are on, firewatcher still pushes, using the generated title.
- No request firewatcher makes (the LLM, ntfy or the events service) follows a redirect: a 3xx answer is a failure, logged as `HTTP 301 from <server> (redirect, not followed)` with only the server, so the request and its token never go on to another host. A failed ntfy push is logged as `ntfy failed`; a failed LLM request falls back as above.

The capture window closes even when no further log lines arrive. Analysis runs on a background worker so log following stays live. The queue holds four captures. When the queue is full, that incident skips the model and, if notifications are on, the capture thread sends the generated-title push itself.

A capture that fits in `max_bytes` (default 48000) is sent whole. A bigger one is cut around the line that opened it: the header, then the lines just before the match (a quarter of the budget), the lines just after it (half), and the end of the capture (a quarter), each cut marked `[... N bytes skipped ...]`. Room one side does not need goes to the other. The pieces are read separately, so a large capture is never loaded into memory whole.

Any user or program on the host can write log lines, and those lines reach the model. The request marks the matched line and the excerpt as untrusted data between `BEGIN`/`END` lines that carry a random token, and the system prompt tells the model never to follow instructions inside them. That makes it harder for a log line to talk the model out of notifying, but cannot rule it out. For incidents that must always reach you, list patterns under `[notify] always_notify` (or `--always-notify`): when a line that matched a watch pattern also matches one of them, the capture is pushed even if the model says not to notify. That push uses the generated title and the line that matched, followed by the model's summary, since log text can steer the summary as well. If no always_notify pattern loads, firewatcher logs an error and keeps capturing without it; `--always-notify ''` clears a list set in the config. Only the line that opened the capture and later lines that matched a watch pattern while it was open count. Other lines in the window do not, and neither do matches from an earlier capture that appear as context. The capture's color codes are removed before it is sent to the model.

`[llm] notes` (or `--llm-notes TEXT`; `note` also works as the key, and `--llm-notes ''` clears a note set in the config) is a short note about this host, for example `loop/dm devices from pytest and /tmp/claude-*/scratchpad and OOMs in capped test containers are expected`. It is sent with every capture as `Operator notes about this host: ...`, outside the untrusted `BEGIN`/`END` block, and the system prompt tells the model that notes describe what is normal there. Any run of whitespace in it, newlines included, becomes one space. Given to `--install-service` while the config exists, the note goes on the unit's `ExecStart`, like any flag given there: local users can read it, and it overrides the config until the unit is reinstalled. Set it in the config to keep it private.

The ntfy topic URL is not printed at startup or in error messages, since on a public ntfy server whoever knows the topic can subscribe to it. Only the server is shown. Keep the topic in the config file (mode `0600`) rather than on the command line: `--ntfy-url` shows in the process list, and when the config already exists, `--install-service --ntfy-url` puts it on the unit's `ExecStart`, which any user can read. `--install-service` warns when that happens.

### Sending captures to an events service

Set `[notify] events_url` to an `http://` or `https://` URL (empty means off) and firewatcher POSTs every finished capture, with an excerpt of it, to that service as JSON, with `Content-Type: application/json`. If `events_token` is set (or `FIREWATCHER_EVENTS_TOKEN`), it is sent as `Authorization: Bearer <token>`. The service can be a log dashboard, a webhook relay, or anything that accepts the POST; the timeout is `[notify] timeout`.

The receiver judges. With `events_url` set, firewatcher's own LLM analysis is off whatever `[llm] enabled` says: no capture goes to the model, nothing is appended to the capture file, and `[llm] base_url` and `model` are not checked at startup. The only judgment left at the source is the rule-based floor, `always_notify`. The fields:

| Field | Meaning |
| --- | --- |
| `source` | always `firewatcher` |
| `version` | the firewatcher version |
| `host` | the host name |
| `pattern` | the pattern that opened the capture |
| `title`, `body` | what a fallback ntfy push would carry: the generated title `{hostname}: {pattern}`, and the `always_notify` line or the matched line followed by the capture path |
| `push` | whether firewatcher itself counts the capture as worth an alert: the same as `always_notify` |
| `always_notify` | an `always_notify` pattern matched |
| `excerpt` | the capture, cut the same way as for the model when it is too big, and at most 16384 characters once JSON-encoded, so the whole event stays well under 64 KiB; `""` when the capture could not be saved or is gone |
| `path` | the capture file, or `null` when it could not be saved |
| `time` | when the event was sent (ISO 8601 with the UTC offset): after the capture window, not when the line matched |

Captures are posted whatever `push` says, so the service sees them all. Any 2xx answer means the service has the capture, and then nothing goes to ntfy. Anything else (a refused connection, a timeout, a TLS error, a redirect, a 4xx or 5xx) is logged as `event post failed`, and then only `always_notify` captures are pushed to ntfy (when notifications are on), with the generated title and the line that matched. Other captures stay in the capture folder and the journal (`event post failed: ...; not pushed (not always_notify)`). While the service does not answer, each push goes out one timeout late ([limitations](https://github.com/yufei-pan/firewatcher/blob/master/docs/limitations.md#while-the-events-receiver-is-down-each-alert-waits-one-timeout-before-ntfy)). `events_url` also works without `[notify] enabled`; a failed POST then only logs. Like the ntfy topic, the URL is shown only as its server, and the token is never logged. A `user:password` in a URL (events, ntfy or LLM) is not sent: use `events_token` (`token` under `[notify]` for ntfy, `api_key` under `[llm]` for the model). firewatcher warns at startup when one is there, naming the setting (`Warning: notify.ntfy_url holds a user:password, ...`) but never its value.

Lines firewatcher writes back to the journal are a single physical line containing `firewatcher-self`, so a summary that quotes `panic` or `I/O error` does not start another capture. In journalctl and syslog output, firewatcher recognizes its own lines by the identifier field after the timestamp and host (`firewatcher[PID]:`), not by text elsewhere in the line, so a process or user name chosen to look like firewatcher cannot hide a kernel or daemon message. Lines in other formats are checked for `firewatcher-self` or `firewatcher[PID]:` anywhere. The capture files themselves stay in the log stream's original format.


## Upgrading to 1.69 from 1.68

Nothing to change under a UTF-8 or C locale. What is different:

- After deleting old months to keep the free-space floor, firewatcher syncs only that filesystem (none on macOS), so a hard-mounted NFS share that is not answering, other than the one the captures are on, no longer stalls log reading. 1.68 synced every filesystem.
- When writing the unit, `daemon-reload` or `enable --now` fails, `--install-service` removes the config and the unit it created, puts back a unit it replaced as it was, and disables a unit it enabled, so the same command can run again. 1.68 left them, and the rerun put the command-line flags, the ntfy URL among them, on the unit's `ExecStart`. A config that does not fit on the disk is the same kind of failure; 1.68 wrote part of it and went on.
- At a restart, firewatcher first finds the saved line in the journal as it is now. When the journal lost the start of that second, the lines after the saved one are still matched; when it lost the line itself, every line from `--capture-time` before it is matched (no further back than `--resume-max`). 1.68 replayed them as context only, and with the clock set back by up to a minute, every line stamped before the saved second.
- `--tail-lines ''` is as if the flag were not given (the config's `tail_lines`, else 20), as an empty `tail_lines` in the config is. 1.68 passed it on, and `tail` or `journalctl` exited at once.
- Under a locale that is neither UTF-8 nor C (such as `en_US.ISO-8859-1`), a non-ASCII path in the config now names the file by its UTF-8 bytes, and a pattern file is read as UTF-8, where 1.68 used the locale's encoding for both: rename such a folder or file to its UTF-8 name, and save a pattern file as UTF-8 (one that is not is skipped, with a message). `--install-service` refuses a path or note typed there in the locale's own encoding (exit 2); 1.68 wrote it.
- On Python 3.6 under a C locale, non-ASCII paths (from the config, the command line or the unit), matched log lines and pattern files no longer stop firewatcher with `UnicodeEncodeError` or go unread, and `--install-service` writes a non-ASCII path or note given there as UTF-8, where 1.68 refused it. `--print-unit` writes the unit as UTF-8 in every locale (1.68 stopped on a non-ASCII `--requires-mounts-for` path) and refuses a value that is not UTF-8 (exit 2), which 1.68 printed or stopped on. On any Python, a path that is not UTF-8 no longer stops it at the first capture.

## Upgrading to 1.68 from 1.67

Nothing to change. What is different:

- `--install-service` refuses a unit name systemd cannot load, and a path or value that is not UTF-8, before it writes anything (exit 2). 1.67 could write the config first and then stop with a traceback, or install a unit under a name systemd skips. A blank `--unit-name` now means `firewatcher`, as an empty one did.
- `systemctl enable --now` and `disable --now` get `--` before the unit name, so a name starting with `-` works.
- On Python 3.6 under a C locale, `--install-service` refuses a non-ASCII path or note given on the command line (exit 2, nothing written) and says to run under a UTF-8 locale; 1.67 stopped there with `UnicodeEncodeError`. 1.69 installs it.
- The package declares its license as the SPDX expression `GPL-3.0-or-later` when built with setuptools 77 or later.
- `--uninstall-service --unit-name` with a path (`a/b`) now prints a message and exits 2; 1.67 stopped with a traceback. It still takes any other name an older firewatcher may have installed.
- Dead code and duplicated rules are gone; nothing else an operator sees changed.

## Development

```bash
pip install -r requirements-dev.txt
pytest
pytest --cov=firewatcher --cov-fail-under=95 --cov-report=term-missing
```

## Author

Yufei Pan (pan@zopyr.us)

## License

GPL-3.0-or-later
