import datetime
import io
import json
import os
import re
import signal
import subprocess
import sys
import time
import zlib

import pytest

import firewatcher as fw
from conftest import ROOT, Clock, ScriptedPopen, fake_exists, incident_logs, patch_popen, use_journal

# --- resuming the journal after a restart ---

T = 1_800_000_000  # 2027-01-15T08:00:00Z


def cursor(offset, text):
    """The cursor of the entry stored at T + offset with that text (one entry per pair)."""
    n = zlib.crc32(('%d %s' % (T + offset, text)).encode())
    return 's=%s;i=%x;b=%s;m=%x;t=%x;x=%016x' % ('a' * 32, n, 'b' * 32, n, (T + offset) * 1000000, n)


def entry(offset, text, when=None):
    """journalctl -o export of the entry stored at T + offset (or at when, a time of its own) with that MESSAGE."""
    stored = T + offset if when is None else when
    fields = [('__CURSOR', cursor(offset, text) if when is None else cursor(when - T, text)),
              ('__REALTIME_TIMESTAMP', '%d' % (stored * 1000000)), ('_HOSTNAME', 'host'), ('SYSLOG_IDENTIFIER', 'app'),
              ('_PID', '1'), ('MESSAGE', text)]
    return b''.join(('%s=%s\n' % pair).encode() for pair in fields) + b'\n'


def jline(offset, text, when=None):
    """The line firewatcher writes for that entry."""
    stored = T + offset if when is None else when
    return '%s host app[1]: %s\n' % (fw._ExportReader(None).stamp(stored), text)


class ExportStdout(object):
    """journalctl -o export, an entry at a time: each event is an entry's bytes, (bytes, seconds the clock moves
    first), an exception to raise, or a float to sleep that many seconds first."""

    def __init__(self, events, clock=None):
        self.events = list(events)
        self.clock = clock
        self.buffer = io.BytesIO()

    def _fill(self):
        while self.buffer.tell() == len(self.buffer.getvalue()):
            if not self.events:
                return False
            event = self.events.pop(0)
            if isinstance(event, tuple):
                event, dt = event
                if self.clock is not None:
                    self.clock.t += dt
            if isinstance(event, float):
                time.sleep(event)
                continue
            if isinstance(event, BaseException):
                raise event
            self.buffer = io.BytesIO(event)
        return True

    def readline(self, size=-1):
        return self.buffer.readline(size) if self._fill() else b''

    def read(self, size=-1):
        return self.buffer.read(size) if self._fill() else b''


def export_popen(monkeypatch, events, clock=None):
    popen = ScriptedPopen([])
    popen.stdout = ExportStdout(events, clock=clock)
    return patch_popen(monkeypatch, popen)


def save_position(path, offset, text):
    path.write_text(json.dumps({'cursor': cursor(offset, text), 'time': T + offset}))


def run(tmp_path, monkeypatch, events, position, capture_time=60, **kwargs):
    export_popen(monkeypatch, events)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    out = tmp_path / 'out'
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=capture_time, output_folder=str(out),
                        compress_after_months=0, delete_after_months=0, journal_position=position, **kwargs)
    return out


def saved(tmp_path):
    return json.loads((tmp_path / 'journal.position').read_text())


def test_no_saved_position_reads_the_last_lines(tmp_path):
    position = fw.JournalPosition(str(tmp_path / 'none'), tail_lines='20', now=T)
    assert position.since is None and position.cursor is None
    assert 'No journal position saved' in position.note
    command = ['journalctl', '--all', '--no-pager', '--lines=20', '--follow']
    assert position.journal_command(command) == ['journalctl', '--output=export', '--all', '--no-pager', '--lines=20', '--follow']


def test_resume_max_zero_reads_nothing_back(tmp_path):
    path = tmp_path / 'journal.position'
    save_position(path, 0, 'x')
    position = fw.JournalPosition(str(path), resume_max=0, now=T + 5)
    assert position.since == T + 5 and position.cursor is None


def test_saw_saves_once_per_interval_and_round_trips(tmp_path, monkeypatch):
    path = tmp_path / 'state' / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(0, 'a'), T, 100.0)
    # a save covers only lines already handled, so 'a' is saved when the next line comes
    assert not path.exists()
    position.saw(cursor(0, 'b'), T, 100.5)
    assert json.loads(path.read_text())['cursor'] == cursor(0, 'a')
    position.saw(cursor(0, 'c'), T, 101.0)
    assert json.loads(path.read_text())['cursor'] == cursor(0, 'a')
    position.saw(cursor(1, 'd'), T + 1, 101.5)
    assert json.loads(path.read_text()) == {'cursor': cursor(0, 'c'), 'time': T}
    position.save()
    assert json.loads(path.read_text()) == {'cursor': cursor(1, 'd'), 'time': T + 1}
    assert not [name for name in os.listdir(str(path.parent)) if name.endswith('.tmp')]
    # a restart finds 'd' and reads back to it as context
    calls = []
    monkeypatch.setattr(fw, '_journal_holds', lambda journalctl, c: calls.append(c) or True)
    again = fw.JournalPosition(str(path), context_time=60, now=T + 5)
    assert calls == [cursor(1, 'd')] and again.cursor == cursor(1, 'd') and again.context_since == T + 1 - 60


def test_every_save_syncs_the_file_before_the_rename(tmp_path, monkeypatch):
    # XFS does not flush a file's data when it is renamed over another; after a hard reset an unsynced
    # position could come back empty. Every save, periodic or at exit, must sync first.
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    events, synced, renamed = [], [], []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append('fsync')
        synced.append(os.fstat(fd).st_ino)
        real_fsync(fd)

    def replace(a, b):
        events.append('replace')
        renamed.append(os.stat(a).st_ino)
        real_replace(a, b)

    monkeypatch.setattr(fw.os, 'fsync', fsync)
    monkeypatch.setattr(fw.os, 'replace', replace)
    position.saw(cursor(0, 'a'), T, 100.0)
    position.saw(cursor(0, 'b'), T, 100.5)
    assert events == ['fsync', 'replace']
    position.saw(cursor(1, 'c'), T + 1, 101.5)
    assert events == ['fsync', 'replace'] * 2
    position.changed = True
    position.save()
    assert events == ['fsync', 'replace'] * 3
    assert json.loads(path.read_text())['cursor'] == cursor(1, 'c')
    # the file that is renamed over the old position is the one that was synced, not its folder
    assert synced == renamed and len(set(synced)) == 3


def test_save_survives_a_filesystem_without_fsync(tmp_path, monkeypatch):
    def unsupported(fd):
        raise OSError(fw.errno.EINVAL, 'Invalid argument')

    monkeypatch.setattr(fw.os, 'fsync', unsupported)
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(0, 'a'), T, 100.0)
    position.save(100.0)
    assert json.loads(path.read_text())['time'] == T
    assert not position.save_failed


def test_an_fsync_error_that_is_not_a_missing_feature_is_a_failed_save(tmp_path, monkeypatch, capsys):
    def broken(fd):
        raise OSError(fw.errno.EIO, 'Input/output error')

    monkeypatch.setattr(fw.os, 'fsync', broken)
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(0, 'a'), T, 100.0)
    position.save(100.0)
    # not reported as saved: the position stays due, nothing replaces the old file, no half-written file is left
    assert position.save_failed and position.changed and not path.exists()
    assert os.listdir(str(tmp_path)) == []
    assert 'Input/output error' in capsys.readouterr().out


def test_a_failed_save_is_retried_while_the_journal_is_quiet_and_logged_once_per_failure_streak(tmp_path, monkeypatch, capsys):
    failing = [True]
    real_fsync = os.fsync

    def fsync(fd):
        if failing[0]:
            raise OSError(fw.errno.EIO, 'Input/output error')
        real_fsync(fd)

    monkeypatch.setattr(fw.os, 'fsync', fsync)
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(0, 'a'), T, 100.0)
    position.save(100.0)
    position.save(101.0)  # no new entry: the position is still due
    assert capsys.readouterr().out.count('cannot save the journal position') == 1
    failing[0] = False
    position.save(102.0)
    assert json.loads(path.read_text()) == {'cursor': cursor(0, 'a'), 'time': T}
    assert not position.save_failed
    # a failure after a success is a new streak, and is logged again
    position.saw(cursor(1, 'b'), T + 1, 102.5)
    failing[0] = True
    position.save(103.0)
    assert capsys.readouterr().out.count('cannot save the journal position') == 1
    assert json.loads(path.read_text())['cursor'] == cursor(0, 'a')


def test_a_stop_inside_the_save_of_saw_does_not_take_back_the_line_before(tmp_path):
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(0, 'A'), T, 100.0)
    position.save(100.0)
    position.saw(cursor(1, 'B'), T + 1, 100.5)  # B is handled in full

    def stop():
        raise KeyboardInterrupt  # where SIGTERM lands: in the capture or position fsync of this save

    position.before_save = stop
    with pytest.raises(KeyboardInterrupt):
        position.saw(cursor(2, 'C'), T + 2, 101.5)  # C is in flight
    position.unsee()  # what capture_messages does for the line in flight
    position.before_save = None
    position.save()
    # B was handled, so the restart must not read it again
    assert json.loads(path.read_text())['cursor'] == cursor(1, 'B')


def test_save_without_a_new_entry_writes_nothing(tmp_path, monkeypatch):
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.save()
    assert not path.exists()
    position.saw(cursor(0, 'a'), T, 100.0)
    position.save(100.0)
    writes = []
    monkeypatch.setattr(fw.os, 'replace', lambda a, b: writes.append(b))
    position.saw(cursor(0, 'a'), T, 100.5)  # another line of the same entry
    position.save(102.0)
    assert writes == []


def test_save_failure_is_logged_once_and_retried(tmp_path, capsys):
    blocker = tmp_path / 'blocker'
    blocker.write_text('a file where a folder should be')
    position = fw.JournalPosition(str(blocker / 'journal.position'), now=T)
    position.saw(cursor(0, 'a'), T, 100.0)
    position.saw(cursor(1, 'b'), T + 1, 101.0)
    assert capsys.readouterr().out.count('cannot save the journal position') == 1
    blocker.unlink()
    position.save(102.0)
    assert json.loads((blocker / 'journal.position').read_text())['time'] == T + 1
    assert not position.save_failed


def test_capture_matches_only_lines_after_the_saved_entry(tmp_path, monkeypatch):
    path = tmp_path / 'journal.position'
    save_position(path, 0, 'HIT before the restart')
    monkeypatch.setattr(fw, '_journal_holds', lambda journalctl, c: True)
    monkeypatch.setattr(fw, '_journal_context', lambda journalctl, c, since, until: iter([
        (T - 20, jline(-20, 'context line')), (T, jline(0, 'HIT before the restart'))]))
    position = fw.JournalPosition(str(path), context_time=60, now=T + 10)
    out = run(tmp_path, monkeypatch, [entry(0, 'HIT before the restart'), entry(5, 'logged while stopped'),
                                      entry(6, 'HIT after the restart')], position)
    logs = incident_logs(out)
    assert len(logs) == 1
    text = logs[0].read_text()
    assert 'Matched line:    %s' % jline(6, 'HIT after the restart').strip() in text
    # the lines read back are the context before the match; the saved entry is not read again
    assert text.index('context line') < text.index('HIT before the restart') < text.index('logged while stopped')
    assert text.count('HIT before the restart') == 1
    assert saved(tmp_path) == {'cursor': cursor(6, 'HIT after the restart'), 'time': T + 6}


def test_the_first_followed_entry_is_kept_when_it_is_not_the_saved_one(tmp_path, monkeypatch):
    # The saved entry was vacuumed between the look for it and the follow: journalctl starts at the entry after it,
    # which has not been read.
    path = tmp_path / 'journal.position'
    save_position(path, 0, 'saved')
    monkeypatch.setattr(fw, '_journal_holds', lambda journalctl, c: True)
    monkeypatch.setattr(fw, '_journal_context', lambda journalctl, c, since, until: iter(()))
    position = fw.JournalPosition(str(path), context_time=60, now=T + 10)
    out = run(tmp_path, monkeypatch, [entry(5, 'new, first followed'), entry(6, 'HIT second')], position)
    assert jline(5, 'new, first followed') in incident_logs(out)[0].read_text()
    assert saved(tmp_path)['cursor'] == cursor(6, 'HIT second')


def _main_with(monkeypatch, argv, can_resume=True):
    seen = {}

    def fake_capture(command, patterns, **kwargs):
        seen['command'] = command
        seen.update(kwargs)

    monkeypatch.setattr(fw, 'capture_messages', fake_capture)
    use_journal(monkeypatch)
    monkeypatch.setattr(fw, '_journal_can_resume', lambda journalctl: can_resume)
    assert fw.main(argv) == 0
    return seen


def test_main_resumes_the_journal_by_default(tmp_path, monkeypatch, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    seen = _main_with(monkeypatch, [str(pat)])
    assert seen['command'][:2] == ['journalctl', '--output=export']
    assert seen['journal_position'].path == fw.DEFAULT_POSITION_FILE
    assert 'No journal position saved' in capsys.readouterr().out


@pytest.mark.parametrize('argv, can_resume, note', [
    (['--position-file', ''], True, None),
    (['--filter-only'], True, None),
    ([], False, 'cannot resume from a saved position'),
])
def test_main_reads_the_last_lines_without_resuming(tmp_path, monkeypatch, capsys, argv, can_resume, note):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    seen = _main_with(monkeypatch, argv + [str(pat)], can_resume)
    assert seen['journal_position'] is None
    assert '--output=export' not in seen['command'] and '--lines=20' in seen['command']
    if note:
        assert note in capsys.readouterr().out


def test_a_host_without_journald_tails_syslog_without_resuming(tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_capture(command, patterns, **kwargs):
        seen['command'] = command
        seen.update(kwargs)

    def no_probe(journalctl):
        raise AssertionError('journalctl probed on a host without journald')

    monkeypatch.setattr(fw, 'capture_messages', fake_capture)
    monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists(syslog=True))
    monkeypatch.setattr(fw, '_journal_can_resume', no_probe)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    assert fw.main([str(pat)]) == 0
    assert seen['command'] == ['tail', '-n', '20', '-F', '/var/log/syslog']
    assert seen['journal_position'] is None
    # the pattern reload works whatever the source
    assert seen['reload_patterns']()[0] == {'fnmatch': {'*HIT*'}}
    assert 'journal position' not in capsys.readouterr().out


def test_journal_can_resume_probes_journalctl(tmp_path):
    ok = tmp_path / 'ok'
    ok.write_text('#!/bin/sh\nexit 0\n')
    old = tmp_path / 'old'
    old.write_text('#!/bin/sh\necho "Unknown output format" >&2\nexit 1\n')
    for script in (ok, old):
        script.chmod(0o755)
    assert fw._journal_can_resume(str(ok))
    assert not fw._journal_can_resume(str(old))
    assert not fw._journal_can_resume(str(tmp_path / 'missing'))


FAKE_JOURNALCTL = r'''#!%s
"""Prints journal.jsonl (one {"stored": seconds, "text": ...} per line, in the order stored) as journalctl -o export:
from the entry at --cursor=C (where the journal no longer holds it, from the first entry stored at or after its time,
as journalctl lands), backwards with --reverse, from --since=@N, or the last --lines=N; then, with --follow, waits.
Like journalctl 219 and 239 to 252 from --cursor, --follow without --no-tail or --lines=N prints only the first 10
entries of its start (the fake does it from --since too, which is stricter)."""
import os, re, sys, time, zlib
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, 'calls.txt'), 'a') as f:
    f.write(' '.join(sys.argv[1:]) + '\n')
args = sys.argv[1:]
if '--lines=0' in args:
    sys.exit(0)
import json
entries = []
for line in open(os.path.join(here, 'journal.jsonl')):
    e = json.loads(line)
    n = zlib.crc32(('%%d %%s' %% (e['stored'], e['text'])).encode())
    e['cursor'] = 's=%%s;i=%%x;b=%%s;m=%%x;t=%%x;x=%%016x' %% ('a' * 32, n, 'b' * 32, n, e['stored'] * 1000000, n)
    entries.append(e)
for arg in args:
    if arg.startswith('--cursor='):
        c = arg[len('--cursor='):]
        m = re.search(r';t=([0-9a-f]+);', c)
        if not m:
            sys.stderr.write('Failed to seek to cursor: Invalid argument\n')
            sys.exit(1)
        at = next((n for n, e in enumerate(entries) if e['cursor'] == c), None)
        if at is None:
            at = next((n for n, e in enumerate(entries) if e['stored'] * 1000000 >= int(m.group(1), 16)), len(entries))
        entries = list(reversed(entries[:at + 1])) if '--reverse' in args else entries[at:]
    if arg.startswith('--since=@'):
        since = int(arg[len('--since=@'):])
        entries = [e for n, e in enumerate(entries) if n >= next((k for k, x in enumerate(entries) if x['stored'] >= since), len(entries))]
    if arg.startswith('--lines='):
        entries = entries[-int(arg[len('--lines='):]):]
if '--follow' in args and '--no-tail' not in args and not any(a.startswith('--lines=') for a in args):
    entries = entries[:10]
out = sys.stdout.buffer
for e in entries:
    for name, value in (('__CURSOR', e['cursor']), ('__REALTIME_TIMESTAMP', '%%d' %% (e['stored'] * 1000000)),
                        ('_HOSTNAME', 'host'), ('SYSLOG_IDENTIFIER', 'app'), ('_PID', '1')):
        out.write(('%%s=%%s\n' %% (name, value)).encode())
    text = e['text'].encode('utf-8')
    out.write(b'MESSAGE\n' + len(text).to_bytes(8, 'little') + text + b'\n\n')
out.flush()
if '--follow' in args:
    time.sleep(600)
'''


class Daemon(object):
    """firewatcher as a daemon on a journald host, reading a fake journalctl (FAKE_JOURNALCTL, its journal.jsonl beside
    it) and saving its position, until done() or 20 seconds, then stopped with SIGTERM."""

    def __init__(self, tmp_path):
        self.bin_dir = tmp_path / 'bin'
        self.bin_dir.mkdir()
        fake = self.bin_dir / 'journalctl'
        fake.write_text(FAKE_JOURNALCTL % sys.executable)
        fake.chmod(0o755)
        self.journal = self.bin_dir / 'journal.jsonl'
        self.now = int(time.time())
        self.pat = tmp_path / 'p.txt'
        self.pat.write_text('HIT\n')
        self.conf = tmp_path / 'empty.conf'
        self.conf.write_text('')
        self.out = tmp_path / 'out'
        self.position_file = tmp_path / 'journal.position'
        self.env = dict(os.environ, PATH='%s%s%s' % (self.bin_dir, os.pathsep, os.environ.get('PATH', '')))

    def write(self, *entries):
        """The journal as it is now: (offset from now, text) pairs, in the order journald stored them."""
        self.journal.write_text(''.join(json.dumps({'stored': self.now + offset, 'text': text}) + '\n' for offset, text in entries))

    def line(self, offset, text):
        return jline(0, text, when=self.now + offset)

    def run_until(self, done):
        proc = subprocess.Popen(
            # as on a journald host, whatever runs on the machine running the tests
            [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import firewatcher as fw; '
             'fw._journald_present = lambda: True; sys.exit(fw.main(sys.argv[2:]))', str(ROOT),
             '--config', str(self.conf), '-o', str(self.out), '-t', '60',
             '--fallback-folder', '', '--position-file', str(self.position_file), str(self.pat)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
            env=self.env,
        )
        try:
            deadline = time.time() + 20
            while not done() and time.time() < deadline:
                time.sleep(0.05)
            proc.send_signal(signal.SIGTERM)
            output, _ = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        assert proc.returncode == 0, output
        return output

    def saved(self):
        try:
            return json.loads(self.position_file.read_text())
        except (OSError, ValueError):
            return {}

    def captured(self, count, text, saved):
        # The capture shows a line before the loop marks it handled, so the saved position is waited for too.
        logs = incident_logs(self.out)
        return len(logs) == count and text in logs[-1].read_text() and self.saved().get('time') == saved

    def calls(self):
        return (self.bin_dir / 'calls.txt').read_text().splitlines()


def test_a_restarted_daemon_matches_only_what_it_has_not_read(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    first_journal = [(-40, 'quiet'), (-30, 'HIT first'), (-20, 'after the first')]
    daemon.write(*first_journal)
    first = daemon.run_until(lambda: daemon.captured(1, 'after the first', now - 20))
    assert 'No journal position saved' in first
    assert daemon.saved()['time'] == now - 20
    daemon.write(*first_journal + [(-10, 'logged while stopped'), (-5, 'HIT second')])
    second = daemon.run_until(lambda: daemon.captured(2, 'HIT second', now - 5))
    assert 'Resuming the journal after' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    text = logs[1].read_text()
    assert 'Matched line:    %s' % line(-5, 'HIT second').strip() in text
    # read back as context only, so 'HIT first' did not open a capture of its own, and the saved entry is there once
    assert 'logged while stopped' in text and text.count('after the first') == 1 and 'HIT first' in text
    assert daemon.saved()['time'] == now - 5
    calls = daemon.calls()
    assert any('--lines=20' in call for call in calls)
    # one look for the saved entry, one read of the context before it, and the follow from it
    look = [call for call in calls if '--reverse' in call]
    assert len(look) == 1 and '--follow' not in look[0] and '--cursor=%s' % cursor(now - 20 - T, 'after the first') in look[0]
    back = [call for call in calls if '--since=@' in call and '--follow' not in call and '--lines=0' not in call]
    assert back == ['--all --no-pager --quiet --output=export --since=@%d' % (now - 20 - 60)]
    follow = [call for call in calls if '--follow' in call and '--cursor=' in call]
    assert len(follow) == 1 and '--no-tail' in follow[0] and '--lines' not in follow[0]


@pytest.mark.parametrize('journal_keeps_the_saved_entry', [True, False])
def test_a_restart_reads_a_backlog_longer_than_journalctls_follow_default_at_once(tmp_path, journal_keeps_the_saved_entry):
    # journalctl 219 and 239 to 252 print only 10 entries of a --follow from a cursor and wait for the journal to
    # change, unless --no-tail is given: the match after 30 other entries would wait.
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    first_journal = [(-100, 'quiet'), (-90, 'HIT first'), (-80, 'saved')]
    daemon.write(*first_journal)
    daemon.run_until(lambda: daemon.captured(1, 'saved', now - 80))
    backlog = [(-70 + i, 'filler %02d' % i) for i in range(30)] + [(-5, 'HIT late')]
    daemon.write(*(first_journal if journal_keeps_the_saved_entry else []) + backlog)
    second = daemon.run_until(lambda: daemon.captured(2, 'HIT late', now - 5))
    assert ('Resuming the journal after' if journal_keeps_the_saved_entry else 'Cannot find the last entry') in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    assert 'Matched line:    %s' % line(-5, 'HIT late').strip() in logs[1].read_text()


def test_a_restart_after_the_journal_lost_the_saved_entry_matches_every_line_of_the_window(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.write((-40, 'HIT first'), (-20, 'last line read'))
    daemon.run_until(lambda: daemon.captured(1, 'last line read', now - 20))
    # While stopped, the journal file that held it was rotated away; a match was logged after it.
    daemon.write((-15, 'HIT logged while stopped'), (-5, 'later'))
    second = daemon.run_until(lambda: daemon.captured(2, 'later', now - 5))
    assert 'Cannot find the last entry read before the stop' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    assert 'Matched line:    %s' % line(-15, 'HIT logged while stopped').strip() in logs[1].read_text()
    assert any('--since=@%d' % (now - 20 - 60) in call and '--no-tail' in call and '--follow' in call for call in daemon.calls())


def test_a_restart_with_a_position_file_of_1_69_matches_every_line_of_the_window(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.write((-30, 'HIT before the upgrade'), (-10, 'HIT after it'))
    daemon.position_file.write_text(json.dumps({'time': now - 20, 'line': 1, 'sha1': 'f' * 40}))
    second = daemon.run_until(lambda: daemon.captured(1, 'HIT after it', now - 10))
    assert 'Cannot find the last entry read before the stop' in second
    assert not any('--cursor' in call for call in daemon.calls())
    assert 'Matched line:    %s' % line(-30, 'HIT before the upgrade').strip() in incident_logs(daemon.out)[0].read_text()


def test_a_restart_on_a_journal_without_the_saved_entry_and_a_clock_set_back_matches_every_line(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.write((-40, 'HIT first'), (-20, 'last line read'))
    daemon.run_until(lambda: daemon.captured(1, 'last line read', now - 20))
    # A reboot with a volatile journal (CentOS 7's default) lost the saved entry, and the clock came back behind it.
    daemon.write((-50, 'booted with the clock behind'), (-49, 'HIT after the reboot'))
    second = daemon.run_until(lambda: len(incident_logs(daemon.out)) == 2 and daemon.saved().get('time') == now - 49)
    assert 'Cannot find the last entry read before the stop' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    assert 'Matched line:    %s' % line(-49, 'HIT after the reboot').strip() in logs[1].read_text()


def test_journal_holds_looks_for_the_saved_entry(tmp_path):
    daemon = Daemon(tmp_path)
    daemon.write((-100, 'too old'), (-50, 'context'), (-20, 'saved'), (-10, 'after'))
    journalctl = str(daemon.bin_dir / 'journalctl')
    assert fw._journal_holds(journalctl, cursor(daemon.now - 20 - T, 'saved'))
    # an entry the journal no longer holds: journalctl lands on another one
    assert not fw._journal_holds(journalctl, cursor(daemon.now - 30 - T, 'gone'))
    # a cursor journalctl cannot seek to
    assert not fw._journal_holds(journalctl, 's=x')
    assert not fw._journal_holds(str(tmp_path / 'missing'), cursor(0, 'x'))


def test_journal_context_reads_forward_from_since_through_the_saved_entry(tmp_path):
    daemon = Daemon(tmp_path)
    daemon.write((-100, 'too old'), (-50, 'context'), (-20, 'saved'), (-20, 'stored in the same second, after it'), (-10, 'after'))
    journalctl = str(daemon.bin_dir / 'journalctl')
    now = daemon.now
    got = list(fw._journal_context(journalctl, cursor(now - 20 - T, 'saved'), now - 60, now - 20))
    assert got == [(now - 50, daemon.line(-50, 'context')), (now - 20, daemon.line(-20, 'saved'))]
    assert not (tmp_path / 'bin' / 'calls.txt').read_text().count('--follow')
    assert list(fw._journal_context(str(tmp_path / 'missing'), cursor(0, 'x'), 0, T)) == []


def test_journal_context_stops_before_an_entry_stored_after_the_saved_second_when_the_saved_entry_never_shows(tmp_path):
    # a clock set back: the order journalctl prints is not the order of the stored times
    daemon = Daemon(tmp_path)
    daemon.write((-50, 'context'), (-30, 'a later entry'), (-10, 'another'))
    journalctl = str(daemon.bin_dir / 'journalctl')
    now = daemon.now
    got = list(fw._journal_context(journalctl, cursor(now - 40 - T, 'not there'), now - 60, now - 40))
    assert got == [(now - 50, daemon.line(-50, 'context'))]


def _stalling_journalctl(tmp_path, entries):
    """A journalctl that touches started, prints entries (export bytes), and then stalls."""
    export = tmp_path / 'export.bin'
    export.write_bytes(b''.join(entries))
    stub = tmp_path / 'journalctl'
    stub.write_text('#!/bin/sh\ntouch %s\ncat %s\nexec sleep 30\n' % (tmp_path / 'started', export))
    stub.chmod(0o755)
    return str(stub)


def test_journal_context_stopped_early_ends_journalctl(tmp_path):
    # a stop (SIGTERM) while the context is read: the loop is left, and the generator with it
    export = tmp_path / 'export.bin'
    export.write_bytes(entry(-50, 'context') + entry(-40, 'more'))
    stub = tmp_path / 'journalctl'
    stub.write_text('#!/bin/sh\necho $$ > %s\ncat %s\nexec sleep 30\n' % (tmp_path / 'pid', export))
    stub.chmod(0o755)
    context = fw._journal_context(str(stub), cursor(0, 'x'), T - 60, T)
    assert next(context) == (T - 50, jline(-50, 'context'))
    pid = int((tmp_path / 'pid').read_text())
    started = time.time()
    context.close()
    assert time.time() - started < 10  # killed, not waited for
    with pytest.raises(OSError):
        os.kill(pid, 0)


def test_journal_holds_is_bounded_by_the_probe_timeout(tmp_path, monkeypatch):
    stub = _stalling_journalctl(tmp_path, [])
    monkeypatch.setattr(fw, 'JOURNAL_PROBE_TIMEOUT', 0.5)
    started = time.time()
    assert not fw._journal_holds(stub, cursor(0, 'x'))
    assert time.time() - started < 10
    assert (tmp_path / 'started').exists()  # journalctl ran, and it was the timer that ended the wait


def test_journal_context_cut_off_by_the_probe_timeout_keeps_what_it_read(tmp_path, monkeypatch):
    stub = _stalling_journalctl(tmp_path, [entry(-50, 'context')])
    monkeypatch.setattr(fw, 'JOURNAL_PROBE_TIMEOUT', 0.5)
    started = time.time()
    assert list(fw._journal_context(stub, cursor(0, 'x'), T - 60, T)) == [(T - 50, jline(-50, 'context'))]
    assert time.time() - started < 10
    assert (tmp_path / 'started').exists()


def test_a_match_that_opens_a_capture_saves_the_position_at_once(tmp_path, monkeypatch):
    # After the first line's save (the periodic one is due at the start), the next periodic save is an hour away,
    # however slow the disk's fsync is: only the saves that come with the capture's open and the exit follow.
    monkeypatch.setattr(fw, 'POSITION_SAVE_INTERVAL', 3600)
    saves = []

    class Recording(fw.JournalPosition):
        def save(self, now=None):
            if self.changed:
                saves.append(self.last_cursor)
            super().save(now)

    position = Recording(str(tmp_path / 'journal.position'), now=T)
    run(tmp_path, monkeypatch, [entry(0, 'quiet'), entry(0, 'HIT one'), entry(0, 'HIT two'), entry(0, 'after')], position)
    # the first line, the match that opened the capture (not the one that extended it), and the last line at exit
    assert saves == [cursor(0, 'quiet'), cursor(0, 'HIT one'), cursor(0, 'after')]


def test_the_context_read_back_is_not_kept_in_memory(tmp_path, monkeypatch):
    # After a restart that follows a busy window, the lines before the saved entry go straight into the bounded
    # context buffer: 1.70 first kept the whole read back, which cost 200 MB for 300,000 lines for the life of the process.
    import tracemalloc
    daemon = Daemon(tmp_path)
    count = 40000
    text = 'worker %d: request %d failed: connection reset by peer (attempt 3 of 5), retrying in 250 ms'
    daemon.write(*[(-50, text % (i % 64, i)) for i in range(count)] + [(-10, 'saved')])
    journalctl = str(daemon.bin_dir / 'journalctl')
    path = tmp_path / 'journal.position'
    path.write_text(json.dumps({'cursor': cursor(daemon.now - 10 - T, 'saved'), 'time': daemon.now - 10}))
    main = ScriptedPopen([])
    main.stdout = ExportStdout([])
    real_popen = subprocess.Popen
    monkeypatch.setattr(fw.subprocess, 'Popen', lambda argv, *a, **k: real_popen(argv, *a, **k) if argv[0] == journalctl else main)
    pat = tmp_path / 'p.txt'
    pat.write_text('NEVER\n')
    tracemalloc.start()
    try:
        # from the construction on, whichever step holds the lines
        position = fw.JournalPosition(str(path), context_time=60, now=daemon.now, journalctl=journalctl)
        assert position.cursor is not None
        fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                            compress_after_months=0, delete_after_months=0, journal_position=position)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # a list of the lines read back is about 8 MB at this size (more while it is built); the buffer holds them compressed
    assert peak < 4 * 1024 * 1024, peak


def test_lines_read_back_keep_their_age_in_the_context(tmp_path, monkeypatch):
    now = int(time.time())
    path = tmp_path / 'journal.position'
    path.write_text(json.dumps({'cursor': cursor(0, 'the saved line'), 'time': now - 10}))
    monkeypatch.setattr(fw, '_journal_holds', lambda journalctl, c: True)
    monkeypatch.setattr(fw, '_journal_context', lambda journalctl, c, since, until: iter([
        (now - 250, 'too old for the window\n'), (now - 30, 'recent\n'), (now - 10, 'the saved line\n')]))
    position = fw.JournalPosition(str(path), context_time=300)
    out = run(tmp_path, monkeypatch, [entry(0, 'HIT', when=now - 1)], position)
    text = incident_logs(out)[0].read_text()
    assert 'recent' in text and 'the saved line' in text
    assert 'too old for the window' not in text


def test_a_line_that_crashes_the_loop_is_not_read_again(tmp_path, monkeypatch):
    position = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T)
    real_append = fw.ContextBuffer.append

    def append(self, read_time, seq, line):
        if 'poison' in line:
            raise RuntimeError('a bug this line sets off')
        return real_append(self, read_time, seq, line)

    monkeypatch.setattr(fw.ContextBuffer, 'append', append)
    with pytest.raises(RuntimeError):
        run(tmp_path, monkeypatch, [entry(0, 'fine'), entry(1, 'poison'), entry(2, 'never read')], position)
    assert saved(tmp_path) == {'cursor': cursor(1, 'poison'), 'time': T + 1}


def _quiet_after(events, path, expected):
    """A stdout that serves export events, then stays quiet, polling for up to 5 s until the position file holds
    the cursor `expected` before it ends; the polls are returned."""
    class QuietStdout(ExportStdout):
        def __init__(self):
            super().__init__(events)
            self.seen = []

        def _fill(self):
            if super()._fill():
                return True
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    seen = json.loads(path.read_text())['cursor']
                except (OSError, ValueError):
                    seen = None
                self.seen.append(seen)
                if seen == expected:
                    break
                time.sleep(0.01)
            return False
    return QuietStdout()


def _run_quiet(tmp_path, monkeypatch, stdout):
    monkeypatch.setattr(fw.os, 'fsync', lambda fd: None)  # a slow disk must not decide this test
    monkeypatch.setattr(fw, 'CAPTURE_SYNC_INTERVAL', 0.05)
    monkeypatch.setattr(fw, 'POSITION_SAVE_INTERVAL', 0.05)
    popen = ScriptedPopen([])
    popen.stdout = stdout
    patch_popen(monkeypatch, popen)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0,
                        journal_position=fw.JournalPosition(str(tmp_path / 'journal.position'), now=T))


def test_a_quiet_journal_during_a_capture_still_saves_the_position(tmp_path, monkeypatch):
    path = tmp_path / 'journal.position'
    stdout = _quiet_after([entry(0, 'HIT one'), entry(0, 'HIT two')], path, cursor(0, 'HIT two'))
    _run_quiet(tmp_path, monkeypatch, stdout)
    # 'HIT two' only extended the open capture, so no save came with it: the quiet wait saved it
    assert stdout.seen[-1] == cursor(0, 'HIT two')


def test_a_line_synced_on_commit_has_its_position_saved_while_the_journal_is_quiet(tmp_path, monkeypatch):
    # The line is read after the capture's sync interval, so the commit syncs it and nothing is left pending:
    # only the position's own deadline wakes the read.
    path = tmp_path / 'journal.position'
    stdout = _quiet_after([entry(0, 'HIT one'), 0.2, entry(0, 'HIT two')], path, cursor(0, 'HIT two'))
    _run_quiet(tmp_path, monkeypatch, stdout)
    assert stdout.seen[-1] == cursor(0, 'HIT two')


def test_a_position_save_never_covers_capture_lines_that_are_not_synced(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    monkeypatch.setattr(fw.os, 'fsync', lambda fd: None)
    events = []
    real_write, real_sync = fw.CaptureFile.write, fw.CaptureFile.sync

    def write(self, text):
        events.append('write')
        return real_write(self, text)

    def sync(self, now=None):
        events.append('sync')
        return real_sync(self, now)

    monkeypatch.setattr(fw.CaptureFile, 'write', write)
    monkeypatch.setattr(fw.CaptureFile, 'sync', sync)
    unsynced_at_save = []

    class Recording(fw.JournalPosition):
        def save(self, now=None):
            covers = self.changed
            super().save(now)
            if covers:
                # a write after the last sync would be on disk only by luck when the position reaches it
                tail = events[len(events) - events[::-1].index('sync'):] if 'sync' in events else events
                unsynced_at_save.append('write' in tail)

    # The capture opens at t, 'a' and 'b' are written within the sync interval, and 'c' comes after the
    # position's interval: its saw() saves a and b, which the capture has not synced yet.
    export_popen(monkeypatch, [(entry(0, 'HIT'), 0), (entry(0, 'a'), 0.25), (entry(0, 'b'), 0.25), (entry(1, 'c'), 0.75),
                               (entry(1, 'd'), 0)], clock=clock)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=600, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0,
                        journal_position=Recording(str(tmp_path / 'journal.position'), now=T))
    assert len(unsynced_at_save) >= 2
    assert not any(unsynced_at_save)


def test_a_carriage_return_in_a_message_cannot_start_a_line_of_its_own(tmp_path, monkeypatch):
    # journalctl --all passes a bare CR through; lines end only at \n, and the position comes from the entry
    position = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T)
    out = run(tmp_path, monkeypatch, [entry(0, 'before'), entry(1, 'x\r2026-13-01T00:00:00Z HIT poison'), entry(2, 'after')],
              position)
    assert saved(tmp_path) == {'cursor': cursor(2, 'after'), 'time': T + 2}
    logs = incident_logs(out)
    # one line, the CR in it as it came (read_text would turn it into a line break)
    assert len(logs) == 1 and b'app[1]: x\r2026-13-01T00:00:00Z HIT poison' in logs[0].read_bytes()


def _stopped_run(tmp_path, monkeypatch, events, stop_at=None, **kwargs):
    position = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T)
    real_write = fw.CaptureFile.write

    def write(self, text):
        if stop_at is not None and stop_at in text:
            raise KeyboardInterrupt  # where SIGINT or SIGTERM would land
        return real_write(self, text)

    monkeypatch.setattr(fw.CaptureFile, 'write', write)
    run(tmp_path, monkeypatch, events, position, **kwargs)
    monkeypatch.setattr(fw.CaptureFile, 'write', real_write)
    return saved(tmp_path)['cursor']


def test_a_stop_while_a_line_is_handled_reads_it_again(tmp_path, monkeypatch):
    events = [entry(0, 'HIT'), entry(0, 'post-1'), entry(1, 'post-2'), entry(1, 'post-3')]
    assert _stopped_run(tmp_path, monkeypatch, events, stop_at='post-2') == cursor(0, 'post-1')


def test_a_stop_between_lines_keeps_the_last_one_read(tmp_path, monkeypatch):
    events = [entry(0, 'HIT'), entry(0, 'post-1'), KeyboardInterrupt()]
    assert _stopped_run(tmp_path, monkeypatch, events) == cursor(0, 'post-1')


def test_a_stop_after_a_match_is_captured_does_not_capture_it_again(tmp_path, monkeypatch):
    class StopAtOpen(fw.JournalPosition):
        stopped = False

        def save(self, now=None):
            if self.changed and not self.stopped:
                self.stopped = True
                raise KeyboardInterrupt  # lands as the capture that holds the match is saved
            super().save(now)

    run(tmp_path, monkeypatch, [entry(0, 'HIT'), entry(0, 'post-1')], StopAtOpen(str(tmp_path / 'journal.position'), now=T))
    assert saved(tmp_path)['cursor'] == cursor(0, 'HIT')


def test_a_stop_after_a_line_is_written_does_not_read_it_again(tmp_path, monkeypatch):
    real_end = fw._end_capture
    calls = []

    def stop_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt  # lands as the line cap ends the capture, after post-2 is written
        return real_end(*args, **kwargs)

    monkeypatch.setattr(fw, '_end_capture', stop_once)
    events = [entry(0, 'HIT'), entry(0, 'post-1'), entry(0, 'post-2'), entry(1, 'post-3')]
    run(tmp_path, monkeypatch, events, fw.JournalPosition(str(tmp_path / 'journal.position'), now=T), capture_line_count_max=1)
    assert saved(tmp_path)['cursor'] == cursor(0, 'post-2')


def test_save_never_follows_a_link_planted_where_the_file_is_written(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('keep me')
    path = tmp_path / 'journal.position'
    (tmp_path / ('journal.position.%d.tmp' % os.getpid())).symlink_to(victim)
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(0, 'a'), T, 100.0)
    position.save()
    assert victim.read_text() == 'keep me'
    assert json.loads(path.read_text())['time'] == T
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.endswith('.tmp')) == ['journal.position.%d.tmp' % os.getpid()]


def test_lines_logged_while_stopped_keep_their_own_time_as_context(tmp_path, monkeypatch):
    # 40 minutes of backlog, one line a minute, read in the same instant; then a match in it
    base = int(time.time()) - 2400
    events = [entry(0, 'backlog %02d' % i, when=base + 60 * i) for i in range(30)]
    events.append(entry(0, 'HIT in the backlog', when=base + 60 * 30 - 30))
    out = run(tmp_path, monkeypatch, events, fw.JournalPosition(str(tmp_path / 'journal.position')), capture_time=120)
    text = incident_logs(out)[0].read_text()
    # the two minutes before the match, by the time each line was stored
    assert re.findall(r'backlog (\d+)', text) == ['28', '29']
    assert 'Logs since %s' % datetime.datetime.fromtimestamp(base + 60 * 30 - 30 - 120).isoformat() in text


def test_a_second_firewatcher_does_not_share_the_journal_position(tmp_path, monkeypatch, capsys):
    import fcntl
    held = os.open(fw.DEFAULT_POSITION_FILE + '.lock', os.O_RDWR | os.O_CREAT)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        pat = tmp_path / 'p.txt'
        pat.write_text('HIT\n')
        seen = _main_with(monkeypatch, [str(pat)])
        assert seen['journal_position'] is None and '--output=export' not in seen['command']
        assert 'Another firewatcher is using the journal position' in capsys.readouterr().out
    finally:
        os.close(held)
    # once it is free, and after a run that used it, the next run takes it
    assert _main_with(monkeypatch, [str(pat)])['journal_position'] is not None
    assert _main_with(monkeypatch, [str(pat)])['journal_position'] is not None


def test_a_position_folder_that_cannot_be_made_still_runs(tmp_path, monkeypatch):
    blocker = tmp_path / 'blocker'
    blocker.write_text('a file where a folder should be')
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    seen = _main_with(monkeypatch, ['--position-file', str(blocker / 'journal.position'), str(pat)])
    assert seen['journal_position'] is not None
