# firewatcher: progress

Open work lives here and nowhere else (RULES, "Long work: the progress file"). Edit rows in place, in the commit that changes the work.

## Goal
- 2026-11-05, for every cas tool: "we improve the cas scripts iteratively. feel free to add scope / tasks if when doing some work, you noticed some other thing that can be improved with cas scripts." (the user; no goal for this repo alone is written in the repo)

## Open work

### firewatcher 1.70 (no written plan: the entries of kind "deferred" naming 1.70 in docs/limitations.md, each with its plan)
- **Resuming, a design check first:** weigh resuming by journal cursor (journalctl 219 has `--after-cursor` and `--cursor`) before adding saved state; it settles the A-6 entry (a restart after the journal lost the saved line, or lines before it in its second, with a twin line; and the rare views where 1.69 reads a line again that 1.68 found exactly) and the entry "A restart where a line shown far later was stored first says the journal no longer holds the last line". State: the design check runs (2026-11-23). From: 1.69's reviews (2026-11-23), deferrals, not asked.
- **`--print-unit` runs the install's checks; a dangling symlink at the unit path; a byte-order mark at the start of a pattern file** (the last two older than 1.69). State: not started. From: 1.69's reviews (2026-11-23), deferrals, not asked.

### Standing rows
- **Deferred work** is in `docs/limitations.md` (entries of kind "deferred"); each names when it is revisited. The file holds three known limitations and the 1.70 deferrals (rows above).

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
- **Q1 (1.69): after a boot with the clock far behind, lines logged before the clock was corrected are not read: a known limitation?** What the operator sees: at a restart firewatcher reads the journal from `--capture-time` (300 s by default) before the saved line; lines logged while it was stopped and stamped earlier than that are not read. That needs a boot whose hardware clock was more than `--capture-time` behind and was corrected before firewatcher started, and a journal that lost the saved line (as a volatile journal does at a reboot). 1.68 does the same, and was worse (it skipped the whole second it could not find). Why not fix: journalctl seeks by timestamp; reading from a journal cursor or a boot id instead is a redesign of how firewatcher resumes. Revisit when an operator hits it, or resuming moves to journal cursors. It would also get one README line. Options: **(a) known limitation (recommended)**; (b) a design of resuming by journal cursor, in a later version (planned work, so a deferral instead). What waits on it: nothing in 1.69 (it ships either way; the entry is written once you answer). Your words it touches: none.

## Closed
- 1.69 (tag v1.69, the merge of feat/169 4ed6eb7, released 2026-11-23): a purge syncs only the purged folder's filesystem (none on macOS, measured); a failed install undoes what it did (removes the config and unit it created, puts back a replaced unit, disables only what it enabled, reloads; systemd 219 too); a restart finds the saved line in the journal as it is now (never ending its replay later than 1.68's rule; measured on a real journal's normal and stalled seconds); `--tail-lines ''` as if not given; Python 3.6 under a C locale handles non-ASCII paths, lines and pattern files; an LLM reply with a lone surrogate keeps its verdict; the macOS test fix. Build bfw169, final review fr169f (Fable high: fix first), fix round f169f, re-review rr169f, fix round f169g, re-review rr169g (the step back: the restart's numbering removed), fix round f169h, re-review rr169h, last round f169i; suites 524 on 3.14, 3.12, 3.11, 3.9 and 3.6, EL7 518, the Mac 509 (at e379c34), first runs; PyPI wheel c0d787a5 and sdist a6de2935 match the build; GitHub release v1.69; master's CI green (run 45265211378). cas-toolbox pins it after its full gate.
- 1.68 (tag v1.68, the merge of feat/168, released 2026-11-15): the simplify pass (code 3,227 to 3,084 lines before the new checks, behaviour unchanged); the three install checks from `superseded-local-1.61` (unit names systemd cannot load are refused before anything is written; `--` before the unit name to `systemctl`; a value that is not UTF-8, escaped bytes included, refused with a message that shows no secret); the SPDX license; Python 3.11 in CI; the folder-fsync note in the README only. Final review (F1: a 3.6 C-locale non-ASCII install crashed its service; refused instead), fix round 1 (f689115 to 682adfb), re-review release, docs d3d7a9b and d29ec45.
- Operator notes for the LLM, and quoting of `;` and newlines in unit arguments (parts of the branch above): done in 1.63 (5b77876, c12fd4d).
- `RequiresMountsFor=` paths quoted, normalized as text and refused when not UTF-8 (parts of the branch above): done in 1.64 (4fd4139 to 628cafa).
- The LLM excerpt built around the match (the branch's `_excerpt_window`): landed another way, as master's `_capture_excerpt`, in 1.61 and 1.62 (dd503c0, 7122885).
