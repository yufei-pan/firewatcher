# firewatcher: progress

Open work lives here and nowhere else (RULES, "Long work: the progress file"). Edit rows in place, in the commit that changes the work.

## Goal
- 2026-11-05, for every cas tool: "we improve the cas scripts iteratively. feel free to add scope / tasks if when doing some work, you noticed some other thing that can be improved with cas scripts." (the user; no goal for this repo alone is written in the repo)

## Open work

### Next release, 1.68 (no written plan; the 1.67 release notes name the first item)
- **Declare the license as an SPDX expression in `setup.py`.** State: not started. Where: `setup.py` on master effe920 still passes `license='GPLv3+'` and the `License :: OSI Approved ...` classifier. Copy the conditional from multiSSH3's `setup.py`: setuptools 77 or later gets `license_expression='GPL-3.0-or-later'` and no license classifier; older ones (all a Python 3.6 install has) get the free-text license and the classifier. `MANIFEST.in` already ships `LICENSE`. From: the 1.67 release notes, "What is planned next": "The license metadata as an SPDX expression, as the other cas tools have it".
- **Add Python 3.11 to the GitHub CI matrix.** State: not started. Where: `.github/workflows/test.yml`, matrix `["3.9", "3.12", "3.14"]` plus the Python 3.6 container; add `"3.11"` in the commit of the release push. The 3.12 entry runs the coverage step (`--cov-fail-under=95`) and every other version the plain test step, so `"3.11"` takes the plain step as the file is written. From: the user, 2026-11-12: "Add 3.11 to CI (Recommended)", for every repo's next release.

### Install hardening left on a local branch (no written plan)
- **Unit-name and text checks that never reached master.** State: not started; port these three checks to master in 1.68 (a deferral: each fixes a real failure, and the code exists). Where: local branch `superseded-local-1.61`, tip 1a86195, 20 commits on a18ec97, not pushed to GitHub. The released 1.61 and 1.62 came from other builds (PRs #1 and #2), and 1.63 and 1.64 rebuilt parts of this branch; the parts below exist only on the branch (`_check_new_unit_name`, `_strict_utf8`, `_as_utf8`, `_write_private_file`):
  - `--install-service` checks the unit name (characters systemd loads, at most 255, `@` only with a name before it and an instance after it) and renders the unit and config before it writes anything, so a refused install leaves no config behind. On master, `install_service` writes the config first and then calls `unit_filename()`, whose `ValueError` for a name such as `a/b` nothing catches: a leftover config and a traceback (read in the code, not run).
  - `systemctl enable --now` gets `--` before the unit name on the branch; master passes the name bare, so a name starting with `-` reads as an option.
  - A value or path that is not valid UTF-8 (argv bytes the locale could not decode) is refused with a message that shows no value; master writes the config with a strict UTF-8 encode, which raises `UnicodeEncodeError` for it. Master already refuses such paths for `--requires-mounts-for` (1.64).
  From: the main session's local work of 2026-10-27. The branch is the only copy: keep it until the port lands.

- **The 1.67 notes point to docs/limitations.md for a failed folder fsync** (the next run writes `YYYY-MM.1.tar.xz`), but the file has no such entry; README line 84 describes it. State: not started. Where: in 1.68, say it in the README only, or write an entry (a known limitation needs the user's OK first). From: the 2026-11-14 progress sweep.

### Standing rows
- **Deferred work** is in `docs/limitations.md` (entries of kind "deferred"); each names when it is revisited. The file holds three known limitations and no deferred entry today.

## Questions waiting for the user
- None.

## Closed
- Operator notes for the LLM, and quoting of `;` and newlines in unit arguments (parts of the branch above): done in 1.63 (5b77876, c12fd4d).
- `RequiresMountsFor=` paths quoted, normalized as text and refused when not UTF-8 (parts of the branch above): done in 1.64 (4fd4139 to 628cafa).
- The LLM excerpt built around the match (the branch's `_excerpt_window`): landed another way, as master's `_capture_excerpt`, in 1.61 and 1.62 (dd503c0, 7122885).
