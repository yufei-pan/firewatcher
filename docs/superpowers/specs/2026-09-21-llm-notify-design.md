# LLM analysis and ntfy notifications

After a capture window closes, firewatcher can ask an OpenAI-compatible LLM whether the incident is worth a human look, and can push that result through ntfy. Both features default off. The tool stays one file, Python 3.6+, and stdlib-only (`urllib`, `configparser`, `syslog`, `queue`, `threading`).

## When work runs

Work starts when a capture window closes (`_end_capture`, including shutdown while a file is still open). The opening match only writes the incident file.

A pending log read runs on a dedicated reader thread so the capture deadline can expire even when the source produces no more lines. At most one read is outstanding; after a timeout the same read is retained for the next window.

One background worker starts only when LLM analysis or notification is enabled. Queue depth is 4. A job that does not need the LLM is ordered ahead of a job that does. If the queue is full, that incident skips the LLM; when notification is on, the capture thread sends a generated-title push with a 5-second timeout.

On a normal exit the still-open capture is enqueued and the worker is joined for one LLM timeout plus one ntfy timeout. The unit's `TimeoutStopSec` is that sum plus 15 seconds (at least 30) so systemd does not kill the process during the join.

## Toggles

- LLM off, notify off: unchanged.
- LLM off, notify on: every finished capture is pushed with a generated title.
- LLM on, notify off: analyze, append the report to the capture file, journal it, no push.
- LLM on, notify on: push only when the model sets `notify` true.

Fail-open: a timeout, HTTP error, or unparseable model output still pushes when notification is on. The generated title is `{hostname}: {pattern}`, one line, about 120 characters. The body is the matched line plus the capture path.

## LLM and ntfy

`POST {base_url}/chat/completions` with stdlib `urllib`. `base_url` is the API root, for example `https://api.openai.com/v1` or `http://127.0.0.1:11434/v1`.

The system prompt demands one JSON object and nothing else: `title`, `summary`, and `notify`. `notify` is true only when a person should look soon. The prompt forbids inventing hosts, times, or causes absent from the excerpt.

The excerpt is the capture file, capped at `max_bytes` (default 48000): the match header, then the tail. Timeout default 60 seconds. A success or a failure note is appended to that capture file.

ntfy is `POST` to the topic URL. The body is the summary, or the matched line when there is no summary, plus the capture path, cut to 4096 bytes. `Title` is one line, about 200 characters. `Priority` defaults to 4. `Authorization: Bearer` is set only when a token is present. The worker timeout defaults to 10 seconds.

## Journal and self-filter

`syslog.openlog('firewatcher', LOG_PID)`. Every record is one physical line: newlines become ` / `, and the line contains `firewatcher-self`. Stdout gets one short status line with the same marker, not the raw summary.

- info: analysis summary, or the model declined to notify
- warning: push sent, or analysis skipped because the queue was full
- err: LLM error, or ntfy error

`_is_own_log_line` returns true when the line contains `firewatcher-self`. The existing `firewatcher[pid]:` check and script-path check stay. Capture files remain `journalctl` short format. A line like `firewatcher:` with no pid and no marker is still not treated as ours.

## Config file

INI via `configparser` with interpolation disabled. Default path `/etc/firewatcher/firewatcher.conf`. A missing default file is silent and built-in defaults apply. `--config PATH` is required to exist.

Sections:

- `[watch]`: `patterns`, `log_file`, `capture_time`, `output_folder`, `tail_lines`, `filter_only`, `compress_after_months`, `delete_after_months`, `capture_line_count_max`
- `[llm]`: `enabled`, `base_url`, `model`, `api_key`, `timeout`, `max_bytes`
- `[notify]`: `enabled`, `ntfy_url`, `token`, `priority`, `timeout`

`patterns` is one path per line, or comma-separated.

Precedence for ordinary settings: explicit CLI, then config, then built-in default. Argparse defaults are unset so an omitted flag is not an override. Positional pattern files replace `patterns` from the config. Tri-state pairs `--llm` / `--no-llm`, `--notify` / `--no-notify`, and `--filter_only` / `--no-filter_only` can override the file in either direction.

`api_key` and `token` have no CLI flag. `FIREWATCHER_LLM_API_KEY` and `FIREWATCHER_NTFY_TOKEN` override the file when set. After the merge, enabled LLM requires `base_url` and `model`; enabled notify requires `ntfy_url`.

Install actions stay CLI-only: `--install-service`, `--print-unit`, `--uninstall-service`, `--unit-name`, `--requires-mounts-for`, `--no-enable`. `--uninstall-service` does not read the config file.

`--install-service` creates the config only when it is missing (mode `0600`), using built-in defaults plus watch, LLM, and notify options passed on that command. An existing file is not rewritten. `ExecStart` is `firewatcher --config <path>`. When the file already existed, explicit flags from that install are appended on `ExecStart` so they override the file. Later edits to a config the unit points at take effect on restart.

## Tests

No network; mock `urlopen`. Cover the toggle matrix, fail-open on HTTP errors and bad JSON, marker filtering, newline flattening, queue overflow, missing default config, missing explicit `--config`, CLI overriding a file value, env overriding the two secrets, startup refusals, and the unit file's `--config` plus appended overrides.

Version `1.58`.

Out of scope: rate limits, a second notification backend, a model-chosen severity, and changing capture-file format.
