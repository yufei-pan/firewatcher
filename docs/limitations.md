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

### A restart after the journal lost the saved line can skip lines that follow it
- Kind: deferred
- What the operator sees: when the journal lost the saved line, or lines before it in its second (a rotated file, a crash or a reboot), but still holds a later line of that second with the same text, the replay can end at that twin. The lines between the lost line and the twin were not read before the stop, and on the restart they are read as context only, not matched. 1.68 did the same. A message logged several times in one second is the usual twin.
- Also the replay's own stop: it ends at the first line shown later than the saved second, as in 1.68 (the 30 s distance rule collects the saved second for `locate` only). journalctl orders lines by the time journald stored them, so a line stored before the saved one and shown a second later ends the replay there, and the lines stored from it up to the saved one, read before the stop, match again: a second capture and push of an incident, never a skip.
- Why: the position holds the second of the saved line, its number in that second and a digest of its text, and a twin has the same digest and can have the same number. The replay stops on a time shown in the lines, which is not the order the lines come in.
- Plan (1.70), one change to `locate` and `replay_time` together, tested against a journalctl that orders lines by the time they were stored:
  - Save the digest of the line before the saved one as well, number lines within a run of lines with the same stamp (as `saw()` and, since 1.69, `_journal_second` do), and take a line as the saved one only where its number and the digest of its line before agree; otherwise treat the saved line as lost and read the window again. A burst of identical lines has identical lines before it, so the number tells them apart where the digest cannot.
  - Where `locate` found the saved line, end the replay at that line (counted among all lines of its second, as `replay_time` counts) and not at the first line shown later, up to JOURNAL_STAMP_SKEW seconds past the saved second; where it could not tell, end as now, at the first line shown later (a later end there would skip lines).
- Revisit when: 1.70.

### A restart that read past a long stall says the journal no longer holds the last line
- Kind: deferred
- What the operator sees: when journald stored a line shown more than 30 seconds (JOURNAL_STAMP_SKEW) away before the saved line (a stall of the host longer than any gap seen outside two stalls of 370 and 458 s), `locate` stops reading there, does not reach the saved line, and the note says "The journal no longer holds the last line read", though it does. Every line from `--capture-time` before the saved second is matched again, a second capture and push of the last incident, never a skip.
- Why: `_journal_second` returns only the lines it collected, so `locate` cannot tell a stop at a far line from the end of the journal.
- Plan (1.70): `_journal_second` says that it stopped at a far line, and `locate` writes a note of its own ("stopped reading at a line N seconds from the saved second; matching every line from ...").
- Revisit when: 1.70.

### `--print-unit` does not run the install's checks of the unit name and the config text
- Kind: deferred
- What the operator sees: `--print-unit --unit-name 'a b'` prints a unit and exits 0, where `--install-service` refuses the name (exit 2); a config text the install would refuse (not UTF-8) is never rendered by `--print-unit`. It refuses a value that is not UTF-8 in the unit itself, as the install does. 1.68 did the same.
- Why: the install runs its checks in `install_service`; the print path calls `render_unit_file` only.
- Plan (1.70): one function runs the checks and renders the unit and the config text, and both commands call it.
- Revisit when: 1.70.

### A dangling symlink at the unit path is written through, and its target is kept when the install fails
- Kind: deferred
- What the operator sees: with a dangling symlink at `/etc/systemd/system/firewatcher.service`, `--install-service` writes the unit at the link's target (the open follows the link), and a step that fails afterwards leaves that file, naming the config the clean-up removed. Older than 1.69.
- Why: the clean-up counts a path that exists as a link as a unit that was there before, and keeps nothing of it to put back.
- Plan (1.70): a path that is a link (`os.path.lexists`) but no file (`os.path.isfile`) counts as created, and a failure removes what the install wrote through it.
- Revisit when: 1.70.

### A byte-order mark at the start of a pattern file stays in its first pattern
- Kind: deferred
- What the operator sees: a pattern file saved with a UTF-8 byte-order mark (some Windows editors do) has U+FEFF at the start of its first pattern, which then never matches, with no message. Older than 1.69.
- Why: pattern files are read as `utf-8`, which keeps the mark.
- Plan (1.70): read them as `utf-8-sig`.
- Revisit when: 1.70.
