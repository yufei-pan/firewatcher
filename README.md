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

`--install-service` seeds `/etc/firewatcher/patterns.d` with example patterns when that directory is empty. The `examples/` directory in the source tree is not installed onto `PATH` by `pip install`; copy those files from a clone, or let `--install-service` write them.

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

`--install-service` writes `/etc/systemd/system/firewatcher.service`, creates the output directory, seeds `/etc/firewatcher/patterns.d/` with example patterns **only if that directory is empty**, then `systemctl daemon-reload && systemctl enable --now firewatcher`.

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
| `--install-service` | Install and enable a systemd unit |
| `--print-unit` | Print that unit and exit |
| `--uninstall-service` | Disable and remove the unit |
| `-V`, `--version` | Show version and exit |


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
