# firewatcher: progress

Open work lives here and nowhere else (RULES, "Long work: the progress file"). Edit rows in place, in the commit that changes the work.

## Goal
- 2026-11-05, for every cas tool: "we improve the cas scripts iteratively. feel free to add scope / tasks if when doing some work, you noticed some other thing that can be improved with cas scripts." (the user; no goal for this repo alone is written in the repo)

## Open work

### Next release, 1.68 (no written plan; the 1.67 release notes name the first item)
- **Built, paused before its review (2026-11-14, at the user's ask):** branch feat/168 (worktree firewatcher-168) at 3522c89, 13 commits on c66d984: the simplify pass (code 3,227 to 3,084 lines before the new checks), every row below, version 1.68 and the notes draft. Suites green on Python 3.14, 3.11, 3.9 and 3.6 (470 passed), coverage 97.82%. Next on resume: the final review (and its second opinion), then the release.
- **Declare the license as an SPDX expression in `setup.py`.** State: built (db6648a), waiting for review. Where: `setup.py` on master effe920 still passes `license='GPLv3+'` and the `License :: OSI Approved ...` classifier. Copy the conditional from multiSSH3's `setup.py`: setuptools 77 or later gets `license_expression='GPL-3.0-or-later'` and no license classifier; older ones (all a Python 3.6 install has) get the free-text license and the classifier. `MANIFEST.in` already ships `LICENSE`. From: the 1.67 release notes, "What is planned next": "The license metadata as an SPDX expression, as the other cas tools have it".
- **Add Python 3.11 to the GitHub CI matrix.** State: built (426b4d5), waiting for review. Where: `.github/workflows/test.yml`, matrix `["3.9", "3.12", "3.14"]` plus the Python 3.6 container; add `"3.11"` in the commit of the release push. The 3.12 entry runs the coverage step (`--cov-fail-under=95`) and every other version the plain test step, so `"3.11"` takes the plain step as the file is written. From: the user, 2026-11-12: "Add 3.11 to CI (Recommended)", for every repo's next release.

### Install hardening left on a local branch (no written plan)
- **Unit-name and text checks that never reached master.** State: ported on feat/168 (9e031b1, c777391, a80a561), waiting for review; delete the branch below once 1.68 is released. Plan was: port these three checks to master in 1.68 (a deferral: each fixes a real failure, and the code exists). Where: local branch `superseded-local-1.61`, tip 1a86195, 20 commits on a18ec97, not pushed to GitHub. The released 1.61 and 1.62 came from other builds (PRs #1 and #2), and 1.63 and 1.64 rebuilt parts of this branch; the parts below exist only on the branch (`_check_new_unit_name`, `_strict_utf8`, `_as_utf8`, `_write_private_file`):
  - `--install-service` checks the unit name (characters systemd loads, at most 255, `@` only with a name before it and an instance after it) and renders the unit and config before it writes anything, so a refused install leaves no config behind. On master, `install_service` writes the config first and then calls `unit_filename()`, whose `ValueError` for a name such as `a/b` nothing catches: a leftover config and a traceback (read in the code, not run).
  - `systemctl enable --now` gets `--` before the unit name on the branch; master passes the name bare, so a name starting with `-` reads as an option.
  - A value or path that is not valid UTF-8 (argv bytes the locale could not decode) is refused with a message that shows no value; master writes the config with a strict UTF-8 encode, which raises `UnicodeEncodeError` for it. Master already refuses such paths for `--requires-mounts-for` (1.64).
  From: the main session's local work of 2026-10-27. The branch is the only copy: keep it until the port lands.

- **The 1.67 notes point to docs/limitations.md for a failed folder fsync** (the next run writes `YYYY-MM.1.tar.xz`), but the file has no such entry; README line 84 describes it. State: built (bb80c09): said in the README only. Where: in 1.68, say it in the README only, or write an entry (a known limitation needs the user's OK first). From: the 2026-11-14 progress sweep.

### The simplify pass (no written plan)
- **Simplify and drop dead weight, as the other cas tools had.** State: built on feat/168 (15d04c4, 3152324, 7b3a214, 3e09d1e), waiting for review; no item needed the user. Where: remove what no operator needs (dead code, guards for states that cannot happen, extra layers), behaviour unchanged, reviewed like a release. From: the user, 2026-10-23: "maybe we should go through the repos after this round, then simplify and drop any stuff that are dead weight?"; for firewatcher, simple-iotest and tsvz-rs, "Run it on all three (Recommended)", 2026-11-14.

### Next version, 1.69 (no written plan)
- **A purge's whole-host `sync` can hang on a hung hard-mounted NFS share and stop log reading** (since 1.61). State: not started; a deferred entry in docs/limitations.md on feat/168. Plan: `syncfs(2)` on the folder, as hpcp's `_syncfs` does. From: found by the 1.68 simplify pass, 2026-11-14 (a deferral, not asked).

### Standing rows
- **Deferred work** is in `docs/limitations.md` (entries of kind "deferred"); each names when it is revisited. The file holds three known limitations and no deferred entry today.

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
- Operator notes for the LLM, and quoting of `;` and newlines in unit arguments (parts of the branch above): done in 1.63 (5b77876, c12fd4d).
- `RequiresMountsFor=` paths quoted, normalized as text and refused when not UTF-8 (parts of the branch above): done in 1.64 (4fd4139 to 628cafa).
- The LLM excerpt built around the match (the branch's `_excerpt_window`): landed another way, as master's `_capture_excerpt`, in 1.61 and 1.62 (dd503c0, 7122885).
