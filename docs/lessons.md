# Lessons

What this project's past changes taught us. Read all of this before changing an API, a format or an
agreed behaviour here. For the full story of a line, find the entry with the same date and name in
`lessons-full.md`.

When one has to change, add the full entry to `lessons-full.md` and one line here, newest last, in the
same commit as the change. Keep this file under 20 KB: at the cap, merge lines before adding.

- **2026-10-27 firewatcher: the model's excerpt is built from where the events are, not from the file's ends**: when a record must be cut to a budget, record where its important parts are while writing it, cut around those, and keep the end where outcomes show. A budget split must never shrink a piece when the budget grows (a superseded attempt that did kept producing new edge cases).
- **2026-10-27 firewatcher: --requires-mounts-for paths are normalized as text, never resolved on disk**: when you write a value into another program's file format, test what that program reads back for each odd input, against the real program. Transform the value only as the reading program would (here as text, like systemd), never by consulting state that may be absent or hung at the time you write.
- **2026-11-03 firewatcher 1.65: the verdict moved to the receiver**: when a pipeline gains a smarter stage downstream, move the judgment there whole, and keep only the rule-based floor (`always_notify`) at the source.
- **2026-11-03 firewatcher 1.65: a URL is parsed once, by our own strict rule**: when a value is both used for requests and written to logs, parse it once with our own strict rule that behaves the same on every runtime, not a lenient library parser. Record what that refuses that used to be accepted, as the entry above does.
- **2026-11-14 firewatcher 1.68: --install-service checks and renders everything before it writes**: an install that writes several files checks and renders all of them, by the rules of the program that will read each one, before writing any, so a refusal leaves nothing behind; a step that fails after the writes (a systemctl call) still leaves them, and a half-done install is state that changes what the next install does.
- **2026-11-23 firewatcher 1.69: the service reads non-ASCII paths in any locale, so the install no longer refuses them**: when a value is refused only because a later reader cannot handle it, fix the reader and drop the refusal: the refusal moves the failure to every other way the value reaches that reader.
- **2026-11-23 firewatcher 1.69: the replay finds the saved line in the journal as it is now**: a position counted within a log that another program trims is checked against the log as it is now before it is trusted; when it cannot be found, read again rather than skip.
