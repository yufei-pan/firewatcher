# firewatcher: progress

Open work lives here and nowhere else (RULES, "Long work: the progress file"). Edit rows in place, in the commit that changes the work.

## Goal
- 2026-11-05, for every cas tool: "we improve the cas scripts iteratively. feel free to add scope / tasks if when doing some work, you noticed some other thing that can be improved with cas scripts." (the user; no goal for this repo alone is written in the repo)

## Open work

### Next version, 1.69 (no written plan: the entries of kind "deferred" with "Revisit when: 1.69" in docs/limitations.md)
- **The 1.69 deferrals.** State: not started; after the cas usage order of 2026-11-15 allows. Where: docs/limitations.md: a purge's whole-host `sync` (plan: `syncfs` on the folder, as hpcp's `_syncfs`; since 1.61); a failed `systemctl` step after the install's writes leaves the config and unit, and a rerun puts the flags (the ntfy URL among them) on ExecStart; the journal replay when the saved line is gone; a command-line `--tail-lines ''`; a service on Python 3.6 under a C locale given a non-ASCII path (plan: the branch's `_as_utf8`, kept as tag `archive/superseded-local-1.61`). Also docs the 1.68 fix round's second opinion found, none worse than 1.67: the README's clock sentence and the replay entry when the saved line is gone and the clock was set back; the `--tail-lines ''` entry's opening names `tail` where the default source is `journalctl`; the Python 3.6 entry and README:247 name a log file and a note, where only an output folder stops the service; README:94's "only if that directory is empty" (the code seeds when it holds no pattern file); shorter README rule list and 3.6 bullet, no line count. From: the 1.68 reviews (deferrals, not asked).

### Standing rows
- **Deferred work** is in `docs/limitations.md` (entries of kind "deferred"); each names when it is revisited. The file holds three known limitations and the 1.69 deferrals (row above).

## Standing decisions
The user's rulings on how the cas repos are worked, one line each; a line changes only on the user's word. The cas monorepo's CLAUDE.md holds the same list, with how to reach the test machines.
- Deferrals (2026-11-05): "please do not ask me about features you think should defer to next version anymore. instead, note them down and after getting the current version done, start the next version right away. only ask me to approve things that are going into limitations that we do not have plans to fix it any time soon."
- The release gate (2026-11-09): "releasing a new version gate is only if it does not make an existing issue worse. even if the fix does not completely resolve the problem, if it makes the result more tolerable, we shall not gate it for release because there are still issues."
- Review before upload (2026-10-18): "commit and push is fine but when packaging, please follow the rule that need a code review before uvpack / upload to pypi".
- A test that passed only on a rerun (2026-11-06, "Green with a warning (Recommended)"): CI stays green with a warning, and "Before any upload, every such test still needs a written cause either way."
- Release pushes (2026-11-10, "Release OK covers it (Recommended)"): an OK for a release covers its push of main, the version tag and the GitHub release.
- Tests (2026-11-12, "Core per release, full at roll-up (Recommended)"): CI's own command on Python 3.14 and 3.11 in Docker before each release; the full gate (every Python in CI, macOS, EL7 on Python 3.11) before a Monday roll-up pin moves.
- CentOS 7 (2026-11-04): "for centos 7, which is already EOL, we only target all the last packages released for it. this also includes EPEL which is also in archive right now."
- EL8 (2026-11-05): "yes rocky 8 it is. let's also only test on them when you think test on real kernel is needed."
- macOS (2026-11-11): tests run on the user's own always-on Mac, as a standard user made for them, never with sudo.

## Questions waiting for the user
- None.

## Closed
- 1.68 (tag v1.68, the merge of feat/168, released 2026-11-15): the simplify pass (code 3,227 to 3,084 lines before the new checks, behaviour unchanged); the three install checks from `superseded-local-1.61` (unit names systemd cannot load are refused before anything is written; `--` before the unit name to `systemctl`; a value that is not UTF-8, escaped bytes included, refused with a message that shows no secret); the SPDX license; Python 3.11 in CI; the folder-fsync note in the README only. Final review (F1: a 3.6 C-locale non-ASCII install crashed its service; refused instead), fix round 1 (f689115 to 682adfb), re-review release, docs d3d7a9b and d29ec45.
- Operator notes for the LLM, and quoting of `;` and newlines in unit arguments (parts of the branch above): done in 1.63 (5b77876, c12fd4d).
- `RequiresMountsFor=` paths quoted, normalized as text and refused when not UTF-8 (parts of the branch above): done in 1.64 (4fd4139 to 628cafa).
- The LLM excerpt built around the match (the branch's `_excerpt_window`): landed another way, as master's `_capture_excerpt`, in 1.61 and 1.62 (dd503c0, 7122885).
