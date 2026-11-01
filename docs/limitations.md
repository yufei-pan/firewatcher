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
