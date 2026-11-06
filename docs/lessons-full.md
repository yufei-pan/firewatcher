# Lessons: full entries

Why this project's APIs, formats and agreed behaviours had to change. `lessons.md` has one line per
entry: read that first, and look entries up here by date and name rather than reading this whole. New
entries go last, in the same commit as the change:

```markdown
## YYYY-MM-DD <short name>
- Changed: ...
- Why we had to change: ...
- Original design was wrong because: ...
- Lesson: ...
```

## 2026-10-27 firewatcher: the model's excerpt is built from where the events are, not from the file's ends
- Changed: the excerpt of a large capture sent to the LLM is the header, the lines before the match, the lines after it and the end of the capture, located by byte offsets capture_messages records as it writes (GitHub 1.61/1.62 of 2026-10-23, first published to PyPI as 1.63). 1.60 sent the first 2 KB and the last ~46 KB.
- Why we had to change: captures hold 5 minutes before and after the match, so in 35 of 49 captures on one server in October the matched event was in the gap and the model judged an incident it never saw. Keeping the end matters too: on 2026-10-23 a failed backup's retry succeeded in the last minutes of the capture, and that is what kept the model from pushing.
- Original design was wrong because: it cut by position (start and end) a record whose important part sits at a known place in the middle, and it located nothing by what the writer already knew (where it wrote the match).
- Lesson: when a record must be cut to a budget, record where its important parts are while writing it, cut around those, and keep the end where outcomes show. A budget split must never shrink a piece when the budget grows (a superseded attempt that did kept producing new edge cases).

## 2026-10-27 firewatcher: --requires-mounts-for paths are normalized as text, never resolved on disk
- Changed: in 1.64 each `--requires-mounts-for` path is made absolute and normalized as text (`.`, `..`, `//`, a trailing `/`), from its bytes, and quoted with `%` doubled. A path with a newline or carriage return, or one that is not UTF-8, is refused before anything is installed. Before, the path was written raw. Symlinks are not followed and the file system is not touched.
- Why we had to change: systemd splits an unquoted path at spaces, expands `%`, and ignores relative and unnormalized paths. So a unit could wait on the wrong mount, or on none, and start before an NFS share was up, with only a warning in the journal.
- Original design was wrong because: it passed operator text into a file with its own syntax (unit-file quoting, specifiers, path rules) as if it were plain text, and nothing checked what systemd read back. Two later attempts were wrong as well. Refusing `..` broke input that was accepted before. Resolving with realpath could follow a symlink off the remote share, hang on a dead hard-NFS mount, trigger automounts, and make the result depend on what was mounted at install time.
- Lesson: when you write a value into another program's file format, test what that program reads back for each odd input, against the real program. Transform the value only as the reading program would (here as text, like systemd), never by consulting state that may be absent or hung at the time you write.

## 2026-11-03 firewatcher 1.65: the verdict moved to the receiver
- Changed: with `[notify] events_url` set, every finished capture is POSTed as JSON (with an excerpt of up to 16 KiB) and firewatcher's own LLM analysis is off, whatever `[llm] enabled` says; a startup line says so. The event's `push` is the rule-based floor, `always_notify`. `model_notify` stays in the event, always `null`. A 2xx answer means the receiver has the capture and nothing goes to ntfy. When the POST fails, only `always_notify` captures are pushed to ntfy; the others stay in the capture folder and the journal.
- Why we had to change: the first events_url design (before 1.65 was released) kept firewatcher's own LLM judging the push, and housekeepd followed it, so behaviour stayed the same while events_url was new. Once housekeepd had its own triage, with the host's tools and history, there were two judges, two verdicts, double LLM traffic, and an outside LLM service saw every capture.
- Original design was wrong because: it kept the judgment at the sender after a better-informed stage existed downstream.
- Lesson: when a pipeline gains a smarter stage downstream, move the judgment there whole, and keep only the rule-based floor (`always_notify`) at the source.

## 2026-11-03 firewatcher 1.65: a URL is parsed once, by our own strict rule
- Changed: one strict check (`_is_http_url`) decides whether an LLM, ntfy or events URL is usable. The request and every log line use only what that check matched; a `user:password` is stripped and never sent or logged, and a URL is shown only as its server (`scheme://host[:port]`). Before 1.65 the check only needed an `http://` or `https://` start with no whitespace or control characters. Now firewatcher also stops at startup for: a server part that is not a host name (no `/`, `?`, `#`, `@`, `[`, `]`, `:` or `%`) or a bracketed IPv6 address, followed by an optional port of up to 5 digits (0 to 65535), judged also after Unicode NFKC normalization; a `user:password` that holds a `/`, `?` or `#`; and a URL with a `user:password` and another `@` later in its path, query or fragment. A URL without `user:password` may still hold an `@` in its path. With events_url set, a bad `[llm]` URL no longer stops firewatcher, since the LLM does not run.
- Why we had to change: a password holding an `@` before a `/`, `?` or `#` left the text between them as the host, and the host is logged. Review took five fix rounds on this check (credentials in requests and logs, unparseable URLs echoed, a password holding an `@`), and the last one replaced the library's view of the authority with our own check that gives the same answer on every Python.
- Original design was wrong because: it used a lenient library parser for a value that is both sent in requests and written to logs, and the old check accepted nearly anything with an http prefix.
- Lesson: when a value is both used for requests and written to logs, parse it once with our own strict rule that behaves the same on every runtime, not a lenient library parser. Record what that refuses that used to be accepted, as the entry above does.
