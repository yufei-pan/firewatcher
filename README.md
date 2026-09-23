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

A directory argument loads every non-hidden pattern file inside it. Files ending in `.regex` are compiled as regular expressions. Any other pattern file is treated as fnmatch (bash-like) substrings, with `*` added on both ends.

`--install-service` seeds `/etc/firewatcher/patterns.d` with example patterns when that directory is empty. The `examples/` directory in the source tree is not installed onto `PATH` by `pip install`; copy the pattern files from a clone, or let `--install-service` write them.

On a match, `firewatcher` writes:

- a per-incident capture under `{output-folder}/{YYYY-MM}/…`
- a line in `{output-folder}/journal.log`

Live capture is written as lines arrive, so a copy can already be on another filesystem if the host then disappears.

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
| `-o`, `--output-folder` | Where to write captures (default: `/var/log/captured_messages/`) |
| `--tail_lines` | Lines to start with (default: 20; `+N` from line N, not with journalctl) |
| `--filter_only` | Filter existing logs only (`cat` instead of `tail -F`, or `journalctl` without `--follow`) |
| `--compress-after-months` | Tar.xz monthly dirs after N months (default: 3) |
| `--delete-after-months` | Delete `YYYY-MM` dirs after N months (default: 0 = never) |
| `--capture_line_count_max` | Max lines before/after a match (default: 10000) |
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
| `--install-service` | Install and enable a systemd unit |
| `--print-unit` | Print that unit and exit |
| `--uninstall-service` | Disable and remove the unit |
| `-V`, `--version` | Show version and exit |

## Config file

Runtime settings live in an INI file. Explicit command-line flags override the file. Built-in defaults apply when neither sets a value. A missing default file is ignored. `--uninstall-service` does not read the file.

A commented example with all supported settings is in [`examples/firewatcher.conf`](examples/firewatcher.conf). Copy it to `/etc/firewatcher/firewatcher.conf`, or use `firewatcher --config /path/to/firewatcher.conf`.

```ini
[watch]
patterns = /etc/firewatcher/patterns.d
capture_time = 300
output_folder = /var/log/captured_messages/
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
```

`patterns` is one path per line, or comma-separated. Positional pattern arguments replace that list.

`api_key` under `[llm]` and `token` under `[notify]` are not command-line flags. `FIREWATCHER_LLM_API_KEY` and `FIREWATCHER_NTFY_TOKEN` override them when set. `--install-service` creates `/etc/firewatcher/firewatcher.conf` with mode `0600` only when it is missing, and the unit runs `firewatcher --config` that path. An existing file is left as it is. Flags passed to a later install are appended on `ExecStart` so they override the file.

Generated configs include explanatory comments above each setting. When no ntfy URL is supplied, a new config gets `https://ntfy.sh/firewatcher-<hostname>-<random>`, with a 12-character URL-safe base64 suffix (72 random bits, no padding). The hostname is sanitized and shortened as needed to keep the topic within 64 characters. Explicit URLs are preserved, and reinstalling leaves an existing config and topic unchanged. Notifications still default to off; subscribe to the generated topic in ntfy, then set `[notify] enabled = true`. When copying the example above, replace its topic with your own.

## LLM analysis and notifications

Both features default off.

- Notifications on, LLM off: every finished capture is pushed. The title is `{hostname}: {pattern}`.
- LLM on, notifications off: the model writes a title, summary, and notify decision. The report is appended to the capture file and logged. Nothing is pushed.
- Both on: a push is sent only when the model sets `notify` to true.
- If the LLM request times out, returns an HTTP error, or is not the expected JSON, and notifications are on, firewatcher still pushes, using the generated title.

The capture window closes even when no further log lines arrive. Analysis runs on a background worker so log following stays live. The queue holds four captures. Notify-only jobs run ahead of jobs that still need the model. When the queue is full, that incident skips the model and, if notifications are on, the capture thread sends the generated-title push itself.

Lines firewatcher writes back to the journal are a single physical line containing `firewatcher-self`, so a summary that quotes `panic` or `I/O error` does not start another capture. The capture files themselves stay in the log stream's original format.


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
