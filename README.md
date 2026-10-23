# firewatcher

Watch a log stream (journald, syslog, or any file) for incident patterns, then persist a window of surrounding messages to a durable location — including a network filesystem — so the record survives even if the machine later dies.

The watcher prefers `journalctl --follow` when `journalctl` is on PATH. On hosts without journald it falls back to `/var/log/syslog`, then `/var/log/messages`, or `--log-file`. Running the daemon does not require systemd; only `--install-service` / `--uninstall-service` do.

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

`--install-service` seeds `/etc/firewatcher/patterns.d` with example patterns when that directory is empty. The `examples/` directory in the source tree is not installed onto `PATH` by `pip install`; copy the pattern files from a clone, or let `--install-service` write them.

On a match, `firewatcher` writes:

- a per-incident capture under `{output-folder}/{YYYY-MM}/…`
- a line in `{output-folder}/journal.log`

Live capture is written as lines arrive, so a copy can already be on another filesystem if the host then disappears. Each captured line is flushed as it is written, and the capture file is fsynced at most once a second and when the capture closes, so a host crash loses at most about the last second of it.

A capture ends `--capture-time` seconds after its last matching line, or `--capture-time-max` seconds (default 3600) after it opened, whichever comes first, so a pattern that keeps repeating still produces a finished capture, and its analysis and push, at least once an hour. A later match starts a new capture.

If the output folder cannot be written (a full disk, a read-only remount, an NFS server that returns errors), the capture continues under `--fallback-folder` (default `/var/lib/firewatcher/captured_messages/`), starting with every line written since the last successful fsync and a note naming the file it moved from. That capture is listed in the fallback folder's own `journal.log`, and the fallback folder is compressed and pruned like the output folder. If no folder can be written, `firewatcher` keeps running, logs the error, and still hands the incident to the notifier.

Put the fallback folder on a different filesystem from the output folder. The default is under `/var/lib`, which shares a disk with `/var/log` on most systems, so it covers a failed NFS output folder but not a full local disk.

The fallback needs the failure to come back as an error. On an NFS mount with the default `hard` option, writes to an unreachable server wait instead of failing, and `firewatcher` waits with them. To fall back instead, mount the output folder with `soft` (or `softerr`) and a short `timeo`.

`firewatcher` finishes the open capture on SIGINT and on SIGTERM. A second SIGTERM ends it at once.

Monthly directories are compressed on a background thread, so log reading never waits for `tar`. Each month becomes `YYYY-MM.tar.xz` holding `YYYY-MM/…`. The directory is removed only after `tar` succeeds and the archive is synced to disk. An existing archive is never overwritten: the new one becomes `YYYY-MM.1.tar.xz`, and so on.

## systemd service

```bash
sudo firewatcher --install-service
sudo firewatcher --print-unit
sudo firewatcher --uninstall-service
```

`--install-service` writes `/etc/systemd/system/firewatcher.service`, creates the output directory, seeds `/etc/firewatcher/patterns.d/` with example patterns **only if that directory is empty**, writes `/etc/firewatcher/firewatcher.conf` **only if that file is missing**, then `systemctl daemon-reload && systemctl enable --now firewatcher`.

If systemd is not available, `--install-service` and `--uninstall-service` print a warning and exit. `--print-unit` still works so you can copy the unit elsewhere.

Useful flags:

| Flag | Description |
|------|-------------|
| `--unit-name NAME` | Unit name (default: `firewatcher`) |
| `--requires-mounts-for PATH` | Add `RequiresMountsFor=` (repeat for NFS/remote output) |
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
| `--log-file` | Log file to follow (default: journalctl / syslog / messages) |
| `-t`, `--capture-time` | Seconds of context after a match (default: 300) |
| `--capture-time-max` | Longest one capture may run, in seconds (default: 3600; 0 = no limit) |
| `-o`, `--output-folder` | Where to write captures (default: `/var/log/captured_messages/`) |
| `--fallback-folder` | Where a capture continues when the output folder cannot be written (default: `/var/lib/firewatcher/captured_messages/`; `''` disables) |
| `--tail-lines` | Lines to start with (default: 20; `+N` from line N, not with journalctl) |
| `--filter-only` | Filter existing logs only (`cat` instead of `tail -F`, or `journalctl` without `--follow`). Windows are measured in read time, not log time, and existing logs are read far faster than they were written, so `-t` and `--capture-time-max` barely limit a capture: it usually runs to `--capture-line-count-max` lines or the end of the input |
| `--compress-after-months` | Tar.xz monthly dirs after N months (default: 3) |
| `--delete-after-months` | Delete `YYYY-MM` dirs after N months (default: 0 = never) |
| `--capture-line-count-max` | Max lines before/after a match (default: 10000). Also caps how many recent lines are held in memory |
| `--config PATH` | INI config file. Default: `/etc/firewatcher/firewatcher.conf` when that file exists. An explicit path must exist |
| `--llm` / `--no-llm` | Enable or disable LLM analysis of each finished capture |
| `--llm-base-url URL` | OpenAI-compatible API root, such as `http://127.0.0.1:11434/v1` |
| `--llm-model NAME` | Model name |
| `--llm-timeout SEC` | LLM HTTP timeout (default: 60) |
| `--llm-max-bytes N` | Capture bytes sent to the model (default: 48000) |
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

A commented example with all supported settings is in [`examples/firewatcher.conf`](examples/firewatcher.conf). Copy it to `/etc/firewatcher/firewatcher.conf`, or use `firewatcher --config /path/to/firewatcher.conf`.

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

[notify]
enabled = false
ntfy_url = https://ntfy.sh/firewatcher-myhost-REPLACE_ME
priority = 4
timeout = 10
always_notify =
```

`patterns` and `always_notify` are one path per line, or comma-separated. Positional pattern arguments replace the `patterns` list.

Out-of-range values stop `firewatcher` at startup: a negative time or count, `capture_time` over 7 days or `capture_time_max` over 30 days, a timeout of 0 or less or over a day, an ntfy priority outside 1–5, or an LLM or ntfy URL that does not start with `http://` or `https://` or that contains spaces.

`api_key` under `[llm]` and `token` under `[notify]` are not command-line flags. `FIREWATCHER_LLM_API_KEY` and `FIREWATCHER_NTFY_TOKEN` override them when set. `--install-service` creates `/etc/firewatcher/firewatcher.conf` with mode `0600` only when it is missing, and the unit runs `firewatcher --config` that path. An existing file is left as it is. Flags passed to a later install are appended on `ExecStart` so they override the file.

Generated configs include explanatory comments above each setting. When no ntfy URL is supplied, a new config gets `https://ntfy.sh/firewatcher-<hostname>-<random>`, with a 12-character URL-safe base64 suffix (72 random bits, no padding). The hostname is sanitized and shortened as needed to keep the topic within 64 characters. Explicit URLs are preserved, and reinstalling leaves an existing config and topic unchanged. Notifications still default to off; subscribe to the generated topic in ntfy, then set `[notify] enabled = true`. When copying the example above, replace its topic with your own.

## LLM analysis and notifications

Both features default off.

- Notifications on, LLM off: every finished capture is pushed. The title is `{hostname}: {pattern}`.
- LLM on, notifications off: the model writes a title, summary, and notify decision. The report is appended to the capture file and logged. Nothing is pushed.
- Both on: a push is sent only when the model sets `notify` to true.
- If the LLM request times out, returns an HTTP error, or is not the expected JSON, and notifications are on, firewatcher still pushes, using the generated title.

The capture window closes even when no further log lines arrive. Analysis runs on a background worker so log following stays live. The queue holds four captures. When the queue is full, that incident skips the model and, if notifications are on, the capture thread sends the generated-title push itself.

Any user or program on the host can write log lines, and those lines reach the model. The request marks the matched line and the excerpt as untrusted data between `BEGIN`/`END` lines that carry a random token, and the system prompt tells the model never to follow instructions inside them. That makes it harder for a log line to talk the model out of notifying, but cannot rule it out. For incidents that must always reach you, list patterns under `[notify] always_notify` (or `--always-notify`): when a line that matched a watch pattern also matches one of them, the capture is pushed even if the model says not to notify. That push uses the generated title and the line that matched, followed by the model's summary, since log text can steer the summary as well. If no always_notify pattern loads, firewatcher logs an error and keeps capturing without it; `--always-notify ''` clears a list set in the config. Only the line that opened the capture and later lines that matched a watch pattern while it was open count. Other lines in the window do not, and neither do matches from an earlier capture that appear as context. The capture's color codes are removed before it is sent to the model.

The ntfy topic URL is not printed at startup or in error messages, since on a public ntfy server whoever knows the topic can subscribe to it. Only the server is shown. Keep the topic in the config file (mode `0600`) rather than on the command line: `--ntfy-url` shows in the process list, and when the config already exists, `--install-service --ntfy-url` puts it on the unit's `ExecStart`, which any user can read. `--install-service` warns when that happens.

Lines firewatcher writes back to the journal are a single physical line containing `firewatcher-self`, so a summary that quotes `panic` or `I/O error` does not start another capture. In journalctl and syslog output, firewatcher recognizes its own lines by the identifier field after the timestamp and host (`firewatcher[PID]:`), not by text elsewhere in the line, so a process or user name chosen to look like firewatcher cannot hide a kernel or daemon message. Lines in other formats are checked for `firewatcher-self` or `firewatcher[PID]:` anywhere. The capture files themselves stay in the log stream's original format.


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
