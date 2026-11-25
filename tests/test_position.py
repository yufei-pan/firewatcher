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


BOOT = 'b' * 32


def cursor(offset, text, boot=BOOT):
    """The cursor of the entry stored at T + offset with that text (one entry per pair), in that boot."""
    n = zlib.crc32(('%d %s' % (T + offset, text)).encode())
    return 's=%s;i=%x;b=%s;m=%x;t=%x;x=%016x' % ('a' * 32, n, boot, n, (T + offset) * 1000000, n)


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

    def close(self):
        pass


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


class FakeProc(object):
    """A journalctl process: its stdout (an ExportStdout) and the exit status wait() gives."""

    def __init__(self, stdout, status):
        self.stdout = stdout
        self.status = status
        self.killed = self.terminated = False

    def kill(self):
        self.killed = True

    def terminate(self):
        self.terminated = True

    def wait(self):
        return self.status


class FakeJournalctl(object):
    """subprocess.Popen in place of journalctl: what each run prints (ExportStdout events) and its exit status, by the
    kind of run: 'cursor' (the read from the saved entry), 'reverse', 'since', 'follow' (from a cursor or a time) and
    'first' (the follow of a first start, --lines=N). calls holds every command line, procs every (kind, FakeProc)."""

    def __init__(self, monkeypatch, **runs):
        self.runs = runs
        self.calls = []
        self.procs = []
        monkeypatch.setattr(fw.subprocess, 'Popen', self.popen)

    def popen(self, argv, *args, **kwargs):
        self.calls.append(list(argv))
        if '--reverse' in argv:
            kind = 'reverse'
        elif '--follow' in argv:
            kind = 'first' if any(word.startswith('--lines=') for word in argv) else 'follow'
        elif any(word.startswith('--since=') for word in argv):
            kind = 'since'
        else:
            kind = 'cursor'
        events, status = self.runs.get(kind, ([], 0))
        proc = FakeProc(ExportStdout(events), status)
        self.procs.append((kind, proc))
        return proc

    def kinds(self):
        return [kind for kind, _proc in self.procs]

    def proc(self, kind):
        return [proc for k, proc in self.procs if k == kind][-1]


FOLLOW = ['journalctl', '--all', '--no-pager', '--lines=20', '--follow']


def resume(tmp_path, monkeypatch, position, capture_time=60, now=None, **runs):
    """capture_messages on the journal through FakeJournalctl(runs), from position, with the clock stopped at now when
    given; the output folder and the fake."""
    journalctl = FakeJournalctl(monkeypatch, **runs)
    if now is not None:
        monkeypatch.setattr(fw.time, 'time', lambda: now)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    out = tmp_path / 'out'
    fw.capture_messages(FOLLOW, fw.load_patterns([str(pat)]), capture_time=capture_time, output_folder=str(out),
                        compress_after_months=0, delete_after_months=0, journal_position=position)
    return out, journalctl


def saved_at(tmp_path, offset, text, context_time=60, now=T + 10):
    """A JournalPosition read from a file that holds the entry stored at T + offset with that text."""
    path = tmp_path / 'journal.position'
    save_position(path, offset, text)
    return fw.JournalPosition(str(path), context_time=context_time, now=now)


def test_no_saved_position_reads_the_last_lines(tmp_path, monkeypatch, capsys):
    position = fw.JournalPosition(str(tmp_path / 'none'), tail_lines='20', now=T)
    assert position.since is None and position.cursor is None
    assert 'No journal position saved' in position.note
    out, journalctl = resume(tmp_path, monkeypatch, position, first=([entry(0, 'HIT one')], 0))
    assert journalctl.calls == [['journalctl', '--output=export', '--all', '--no-pager', '--lines=20', '--follow']]
    assert len(incident_logs(out)) == 1 and 'No journal position saved' in capsys.readouterr().out


def test_the_constructor_only_reads_the_file(tmp_path, monkeypatch):
    def no_journalctl(*args, **kwargs):
        raise AssertionError('journalctl started before the capture loop')

    monkeypatch.setattr(fw.subprocess, 'Popen', no_journalctl)
    position = saved_at(tmp_path, 0, 'saved')
    assert position.cursor == cursor(0, 'saved') and position.context_since == T - 60 and position.note is None


def test_the_saved_entry_first_resumes_after_it_with_the_lines_before_it_as_context(tmp_path, monkeypatch, capsys):
    position = saved_at(tmp_path, 0, 'HIT before the restart')
    out, journalctl = resume(
        tmp_path, monkeypatch, position,
        cursor=([entry(0, 'HIT before the restart'), entry(5, 'logged while stopped'), entry(6, 'HIT after the restart')], 0),
        reverse=([entry(0, 'HIT before the restart'), entry(-20, 'context line'), entry(-61, 'before the window')], 0),
        follow=([entry(6, 'HIT after the restart'), entry(7, 'followed')], 0))
    logs = incident_logs(out)
    assert len(logs) == 1
    text = logs[0].read_text()
    assert 'Matched line:    %s' % jline(6, 'HIT after the restart').strip() in text
    # the lines read back are the context before the match, the saved entry's own line among them, once; the last entry
    # read is dropped where the follow starts
    assert text.index('context line') < text.index('HIT before the restart') < text.index('logged while stopped') < text.index('followed')
    # (the line that opened the capture is in its header too)
    assert text.count('HIT before the restart') == 1 and text.count('HIT after the restart') == 2
    assert 'before the window' not in text
    assert saved(tmp_path) == {'cursor': cursor(7, 'followed'), 'time': T + 7}
    cursor_read, reverse, follow = journalctl.calls
    assert cursor_read == ['journalctl', '--output=export', '--all', '--no-pager', '--cursor=' + cursor(0, 'HIT before the restart')]
    assert reverse[-2:] == ['--cursor=' + cursor(0, 'HIT before the restart'), '--reverse'] and '--follow' not in reverse
    assert follow == ['journalctl', '--output=export', '--all', '--no-pager', '--cursor=' + cursor(6, 'HIT after the restart'),
                      '--no-tail', '--follow']
    # the read back ended once it passed the window's start
    assert journalctl.proc('reverse').killed
    note = [line for line in capsys.readouterr().out.splitlines() if line.startswith('Resuming the journal after %s, ' % (
        datetime.datetime.fromtimestamp(T).isoformat()))]
    assert len(note) == 1 and note[0].endswith(' seconds ago, with 2 lines of context from up to 60 seconds before it.')


@pytest.mark.parametrize('cursor_read', [
    ([entry(3, 'HIT logged after it, first')], 0),  # the journal lands on the entry after the one it lost
    ([], 0),  # nothing at or after it
])
def test_a_journal_that_lost_the_saved_entry_is_read_by_time(tmp_path, monkeypatch, capsys, cursor_read):
    position = saved_at(tmp_path, 0, 'saved')
    # the clock as when the position was read: the journal's answer decides, at the time it comes
    out, journalctl = resume(tmp_path, monkeypatch, position, now=T + 10, cursor=cursor_read,
                             since=([entry(-30, 'HIT in the window'), entry(3, 'HIT logged after it, first')], 0),
                             follow=([entry(3, 'HIT logged after it, first'), entry(4, 'later')], 0))
    assert journalctl.kinds() == ['cursor', 'since', 'follow']
    if cursor_read[0]:
        assert journalctl.proc('cursor').killed  # not read to its end
    assert journalctl.calls[1][-1] == '--since=@%d' % (T - 60) and '--follow' not in journalctl.calls[1]
    assert journalctl.calls[2][-3:] == ['--cursor=' + cursor(3, 'HIT logged after it, first'), '--no-tail', '--follow']
    text = incident_logs(out)[0].read_text()
    # every line of the window is matched, none twice
    assert 'Matched line:    %s' % jline(-30, 'HIT in the window').strip() in text
    assert text.count('HIT logged after it, first') == 1 and 'later' in text
    assert 'Cannot find the last entry read before the stop' in capsys.readouterr().out


def test_a_read_by_time_with_no_entry_follows_from_that_time(tmp_path, monkeypatch):
    position = saved_at(tmp_path, 0, 'saved')
    out, journalctl = resume(tmp_path, monkeypatch, position, now=T + 10, cursor=([], 0), since=([], 0),
                             follow=([entry(20, 'HIT new')], 0))
    assert journalctl.kinds() == ['cursor', 'since', 'follow']
    assert journalctl.calls[2][-3:] == ['--since=@%d' % (T - 60), '--no-tail', '--follow']
    assert len(incident_logs(out)) == 1


@pytest.mark.parametrize('status', [1, -9])
def test_a_journalctl_that_fails_before_its_first_entry_ends_the_run_with_the_position_kept(tmp_path, monkeypatch, capsys, status):
    position = saved_at(tmp_path, 0, 'saved')
    before = (tmp_path / 'journal.position').read_text()
    out, journalctl = resume(tmp_path, monkeypatch, position, cursor=([], status),
                             since=([entry(-30, 'HIT in the window')], 0), follow=([entry(20, 'HIT new')], 0))
    # no answer is not "gone": nothing is read by time, and the next start reads from the same entry
    assert journalctl.kinds() == ['cursor']
    assert (tmp_path / 'journal.position').read_text() == before
    assert incident_logs(out) == []
    printed = capsys.readouterr().out
    assert 'journalctl ended with status %d before its first entry' % status in printed and 'Process ended.' in printed


def test_the_follow_keeps_its_first_entry_when_it_is_not_the_last_one_read(tmp_path, monkeypatch):
    # From systemd 252 on, a follow from an entry of an older boot does not print it, and starts with the running boot's
    # entries; the same when the last entry read was vacuumed before the follow started.
    position = saved_at(tmp_path, 0, 'saved')
    out, journalctl = resume(tmp_path, monkeypatch, position, cursor=([entry(0, 'saved'), entry(2, 'old boot, last')], 0),
                             reverse=([entry(0, 'saved')], 0),
                             follow=([entry(5, 'new boot, first followed'), entry(6, 'HIT second')], 0))
    assert journalctl.calls[-1][-3:] == ['--cursor=' + cursor(2, 'old boot, last'), '--no-tail', '--follow']
    assert jline(5, 'new boot, first followed') in incident_logs(out)[0].read_text()
    assert saved(tmp_path)['cursor'] == cursor(6, 'HIT second')


def test_a_read_cut_in_the_middle_of_an_entry_ends_the_run_and_the_next_start_resumes_from_the_last_whole_one(tmp_path, monkeypatch, capsys):
    # A journalctl that ends with a failure part-way (it died, or a stop signal reached it alone) ends the run as a
    # follow that dies does, not with a follow from where it stopped: the lost stop is then not waited out. 1.71 as
    # first built followed on, and was still running a unit's stop timeout after the signal.
    position = saved_at(tmp_path, 0, 'saved')
    out, journalctl = resume(tmp_path, monkeypatch, position,
                             cursor=([entry(0, 'saved'), entry(1, 'HIT one'), entry(2, 'two'), entry(3, 'HIT three')[:40]], 3),
                             reverse=([entry(0, 'saved')], 0), follow=([entry(9, 'never read')], 0))
    assert journalctl.kinds() == ['cursor', 'reverse']
    assert 'journalctl ended with status 3 while reading on from the saved position.' in capsys.readouterr().out
    assert len(incident_logs(out)) == 1 and saved(tmp_path) == {'cursor': cursor(2, 'two'), 'time': T + 2}
    # the next start reads from that entry: the cut one whole, once, and what follows
    again = fw.JournalPosition(str(tmp_path / 'journal.position'), context_time=60, now=T + 10)
    out, journalctl = resume(tmp_path, monkeypatch, again,
                             cursor=([entry(2, 'two'), entry(3, 'HIT three'), entry(4, 'four')], 0),
                             reverse=([entry(2, 'two')], 0), follow=([entry(5, 'five')], 0))
    assert journalctl.calls[-1][-3:] == ['--cursor=' + cursor(4, 'four'), '--no-tail', '--follow']
    text = incident_logs(out)[-1].read_text()
    assert text.count('HIT three') == 2 and 'four' in text and 'five' in text  # in its header too
    assert saved(tmp_path)['cursor'] == cursor(5, 'five')


@pytest.mark.parametrize('stalled', ['cursor', 'reverse'])
def test_a_stop_while_journalctl_is_waited_for_or_the_context_read_back_ends_as_a_stop_in_the_loop_does(tmp_path, monkeypatch, capsys, stalled):
    # SIGINT (as the unit sends) or SIGTERM lands while the read from the saved entry gives nothing yet, or while the
    # lines before it are read back: "Exiting.", journalctl ended and the saved position as it was, as in the loop.
    # 1.70's first fix round read the context before the try that holds the loop, so the stop came out of
    # capture_messages as a traceback (exit 1 on Python 3.6).
    position = saved_at(tmp_path, 0, 'saved')
    before = (tmp_path / 'journal.position').read_text()
    runs = {'cursor': ([KeyboardInterrupt()], 0) if stalled == 'cursor' else ([entry(0, 'saved'), entry(5, 'never read')], 0),
            'reverse': ([entry(0, 'saved'), entry(-20, 'context line'), KeyboardInterrupt()], 0)}
    try:
        _out, journalctl = resume(tmp_path, monkeypatch, position, **runs)
    except KeyboardInterrupt:
        pytest.fail('a stop at the start came out of capture_messages')
    assert 'Exiting.' in capsys.readouterr().out
    assert journalctl.kinds() == (['cursor'] if stalled == 'cursor' else ['cursor', 'reverse'])
    assert journalctl.proc('cursor').terminated
    if stalled == 'reverse':
        assert journalctl.proc('reverse').killed
    assert (tmp_path / 'journal.position').read_text() == before


def test_a_stop_during_the_handover_starts_no_follow(tmp_path, monkeypatch):
    position = saved_at(tmp_path, 0, 'saved')
    source = fw._JournalSource(position, FOLLOW)
    journalctl = FakeJournalctl(monkeypatch, cursor=([entry(0, 'saved')], 0))
    source.open(fw.ContextBuffer(60, 1 << 20))
    source.terminate()
    assert source.readline() == '' and journalctl.kinds() == ['cursor', 'reverse']
    # a stop that comes while the follow starts ends it at once
    source = fw._JournalSource(position, FOLLOW)
    source.stopped = True
    source._start(['--cursor=' + cursor(0, 'saved'), '--no-tail'], skip=cursor(0, 'saved'))
    assert journalctl.procs[-1][1].terminated


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
    # a restart reads on from 'd', and back from it as context
    again = fw.JournalPosition(str(path), context_time=60, now=T + 5)
    assert again.cursor == cursor(1, 'd') and again.context_since == T + 1 - 60


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
    # the file that is renamed over the old position is the one that was synced, not its folder (not also that the
    # three files differ: ext4 gives a freed inode to the next temp file)
    assert synced == renamed


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
    # the follow command of a first start; capture_messages reads on from the position
    assert seen['command'] == ['journalctl', '--all', '--no-pager', '--lines=20', '--follow']
    assert seen['journal_position'].path == fw.DEFAULT_POSITION_FILE
    # where it resumes is said once the journal has answered, after the "Monitoring" line
    assert 'No journal position saved' not in capsys.readouterr().out


def test_a_stop_while_the_start_up_check_waits_exits_cleanly(tmp_path, monkeypatch, capsys):
    def stopped(journalctl):
        raise KeyboardInterrupt  # SIGINT, as the unit sends, while a slow journalctl is waited for

    monkeypatch.setattr(fw, 'capture_messages', lambda *a, **k: pytest.fail('read the journal after a stop'))
    use_journal(monkeypatch)
    monkeypatch.setattr(fw, '_journal_can_resume', stopped)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    try:
        assert fw.main([str(pat)]) == 0
    except KeyboardInterrupt:
        pytest.fail('a stop during the start-up check came out of main')
    assert 'Exiting.' in capsys.readouterr().out
    # the position file's lock is let go
    assert _main_with(monkeypatch, [str(pat)])['journal_position'] is not None


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


def test_a_slow_answer_to_the_start_up_check_still_counts_and_is_noted_once(tmp_path, monkeypatch, capsys):
    # 1.70 gave the check 30 s and then turned resuming off for the run: the lines logged while stopped were not matched.
    slow = tmp_path / 'slow'
    slow.write_text('#!/bin/sh\nsleep 1\nexit 0\n')
    slow.chmod(0o755)
    monkeypatch.setattr(fw, 'JOURNAL_WAIT_NOTE', 0.2)
    assert fw._journal_can_resume(str(slow))
    assert capsys.readouterr().out.count('Still waiting for journalctl after') == 1
    # an answer in time gives no line
    monkeypatch.setattr(fw, 'JOURNAL_WAIT_NOTE', 30)
    assert fw._journal_can_resume(str(slow))
    assert 'Still waiting' not in capsys.readouterr().out


FAKE_JOURNALCTL = r'''#!%s
"""Prints journal.jsonl (one {"stored": seconds, "text": ..., "boot": id or absent} per line, in the order stored)
as journalctl -o export: from the entry at --cursor=C (where the journal no longer holds it, from the first entry stored
at or after its time, as journalctl lands, and nothing with --reverse), backwards with --reverse, from --since=@N, or the
last --lines=N; then, with --follow, waits. Like journalctl 219 and 239 to 252 from --cursor, --follow without --no-tail
or --lines=N prints only the first 10 entries of its start (the fake does it from --since too, which is stricter). Like
journalctl 252 and later, --follow shows only the newest boot. With cut.txt beside it holding N, a read without --follow
or --reverse prints N entries and half of the next, and exits 3."""
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
    e.setdefault('boot', 'b' * 32)
    e['cursor'] = 's=%%s;i=%%x;b=%%s;m=%%x;t=%%x;x=%%016x' %% ('a' * 32, n, e['boot'], n, e['stored'] * 1000000, n)
    entries.append(e)
newest_boot = entries[-1]['boot'] if entries else None
for arg in args:
    if arg.startswith('--cursor='):
        c = arg[len('--cursor='):]
        m = re.search(r';t=([0-9a-f]+);', c)
        if not m:
            sys.stderr.write('Failed to seek to cursor: Invalid argument\n')
            sys.exit(1)
        at = next((n for n, e in enumerate(entries) if e['cursor'] == c), None)
        if at is not None:
            entries = list(reversed(entries[:at + 1])) if '--reverse' in args else entries[at:]
        elif '--reverse' in args:
            entries = []
        else:
            entries = entries[next((n for n, e in enumerate(entries) if e['stored'] * 1000000 >= int(m.group(1), 16)), len(entries)):]
    if arg.startswith('--since=@'):
        since = int(arg[len('--since=@'):])
        entries = [e for n, e in enumerate(entries) if n >= next((k for k, x in enumerate(entries) if x['stored'] >= since), len(entries))]
    if arg.startswith('--lines='):
        entries = entries[-int(arg[len('--lines='):]):]
if '--follow' in args:
    entries = [e for e in entries if e['boot'] == newest_boot]
    if '--no-tail' not in args and not any(a.startswith('--lines=') for a in args):
        entries = entries[:10]
cut = None
if '--follow' not in args and '--reverse' not in args and os.path.exists(os.path.join(here, 'cut.txt')):
    cut = int(open(os.path.join(here, 'cut.txt')).read())
out = sys.stdout.buffer
for k, e in enumerate(entries):
    data = b''
    for name, value in (('__CURSOR', e['cursor']), ('__REALTIME_TIMESTAMP', '%%d' %% (e['stored'] * 1000000)),
                        ('_HOSTNAME', 'host'), ('SYSLOG_IDENTIFIER', 'app'), ('_PID', '1')):
        data += ('%%s=%%s\n' %% (name, value)).encode()
    text = e['text'].encode('utf-8')
    data += b'MESSAGE\n' + len(text).to_bytes(8, 'little') + text + b'\n\n'
    if cut is not None and k == cut:
        out.write(data[:len(data) // 2])
        out.flush()
        sys.exit(3)
    out.write(data)
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
        """The journal as it is now: (offset from now, text) pairs, or (offset, text, boot), in the order journald stored
        them; the boot is BOOT unless given."""
        self.journal.write_text(''.join(json.dumps(dict({'stored': self.now + entry[0], 'text': entry[1]}, **(
            {'boot': entry[2]} if len(entry) > 2 else {}))) + '\n' for entry in entries))

    def cursor(self, offset, text, boot=BOOT):
        return cursor(self.now + offset - T, text, boot)

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
        self.proc = proc
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

    def reads(self):
        """The journalctl runs after the start-up check of the last run, in order."""
        calls = self.calls()
        return calls[len(calls) - calls[::-1].index(next(c for c in calls[::-1] if '--lines=0' in c)):]

    def following(self):
        """The last run has started its follow (the reads before it are done)."""
        try:
            return any('--follow' in call for call in self.reads())
        except (OSError, StopIteration):
            return False

    def wrap(self, script):
        """Put a shell script before the fake: "$@" are journalctl's arguments, and $FAKE the fake to run."""
        (self.bin_dir / 'journalctl').rename(str(self.bin_dir / 'journalctl.fake'))
        wrapper = self.bin_dir / 'journalctl'
        wrapper.write_text('#!/bin/sh\nFAKE=%s/journalctl.fake\n%s\nexec $FAKE "$@"\n' % (self.bin_dir, script))
        wrapper.chmod(0o755)

    def unwrap(self):
        (self.bin_dir / 'journalctl.fake').replace(str(self.bin_dir / 'journalctl'))


def test_a_restarted_daemon_matches_only_what_it_has_not_read(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    first_journal = [(-40, 'quiet'), (-30, 'HIT first'), (-20, 'after the first')]
    daemon.write(*first_journal)
    first = daemon.run_until(lambda: daemon.captured(1, 'after the first', now - 20))
    assert 'No journal position saved' in first
    assert daemon.saved()['time'] == now - 20
    daemon.write(*first_journal + [(-10, 'logged while stopped'), (-5, 'HIT second')])
    second = daemon.run_until(lambda: daemon.captured(2, 'HIT second', now - 5) and daemon.following())
    # said once the journal has answered, after the settings
    assert second.index('Monitoring') < second.index('Resuming the journal after')
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    text = logs[1].read_text()
    assert 'Matched line:    %s' % line(-5, 'HIT second').strip() in text
    # read back as context only, so 'HIT first' did not open a capture of its own, and the saved entry is there once
    assert 'logged while stopped' in text and text.count('after the first') == 1 and 'HIT first' in text
    assert daemon.saved()['time'] == now - 5
    assert any('--lines=20' in call for call in daemon.calls())
    # the read from the saved entry without --follow, the read back from it, and the follow from the last entry read
    saved_entry, last = daemon.cursor(-20, 'after the first'), daemon.cursor(-5, 'HIT second')
    assert daemon.reads() == ['--output=export --all --no-pager --cursor=%s' % saved_entry,
                              '--all --no-pager --quiet --output=export --cursor=%s --reverse' % saved_entry,
                              '--output=export --all --no-pager --cursor=%s --no-tail --follow' % last]


def test_a_restart_after_a_reboot_reads_what_the_old_boot_logged_after_the_stop(tmp_path):
    # From systemd 252 on, a follow shows only the newest boot (the fake does so too): 1.67 to 1.70 followed from the
    # saved entry and never matched what the old boot logged between firewatcher's stop and its end.
    daemon = Daemon(tmp_path)
    now = daemon.now
    old = 'c' * 32
    first_journal = [(-60, 'HIT before the stop', old), (-50, 'saved', old)]
    daemon.write(*first_journal)
    daemon.run_until(lambda: daemon.captured(1, 'saved', now - 50))
    daemon.write(*first_journal + [(-40, 'HIT during shutdown', old), (-39, 'HIT unmount failed', old), (-20, 'booted'),
                                   (-10, 'HIT in the new boot'), (-5, 'later')])
    second = daemon.run_until(lambda: daemon.saved().get('time') == now - 5)
    assert 'Resuming the journal after' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    text = logs[1].read_text()
    # each read once (the line that opened the capture is in its header too)
    assert 'Matched line:    %s' % daemon.line(-40, 'HIT during shutdown').strip() in text
    assert [text.count(match) for match in ('HIT during shutdown', 'HIT unmount failed', 'HIT in the new boot')] == [2, 1, 1]


def test_a_restart_whose_read_is_cut_part_way_ends_the_run_and_the_next_start_resumes_exactly(tmp_path):
    # The read without --follow ends in the middle of an entry (a journalctl that died, or that a stop signal reached
    # alone): the run ends, as a follow that dies does, with the position at the last whole entry. 1.71 as first built
    # followed on from there, and a stop whose signal firewatcher itself had lost was waited out to the unit's timeout.
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    first_journal = [(-100, 'quiet'), (-90, 'HIT first'), (-80, 'saved')]
    daemon.write(*first_journal)
    daemon.run_until(lambda: daemon.captured(1, 'saved', now - 80))
    backlog = [(-79, 'HIT read')] + [(-50 + i, 'filler %02d' % i) for i in range(30)] + [(-5, 'HIT late')]
    daemon.write(*first_journal + backlog)
    (daemon.bin_dir / 'cut.txt').write_text('2')  # the saved entry, 'HIT read', and half of 'filler 00'
    second = daemon.run_until(lambda: daemon.proc.poll() is not None)
    assert 'journalctl ended with status 3 while reading on from the saved position.' in second and 'Process ended.' in second
    assert 'Traceback' not in second and not any('--follow' in call for call in daemon.reads())
    assert daemon.saved() == {'cursor': daemon.cursor(-79, 'HIT read'), 'time': now - 79}
    assert len(incident_logs(daemon.out)) == 2 and 'HIT read' in incident_logs(daemon.out)[1].read_text()
    # the next start reads on from that entry: each line after it once, the cut one whole
    (daemon.bin_dir / 'cut.txt').unlink()
    third = daemon.run_until(lambda: daemon.captured(3, 'HIT late', now - 5))
    assert 'Resuming the journal after' in third
    text = incident_logs(daemon.out)[2].read_text()
    assert 'Matched line:    %s' % line(-5, 'HIT late').strip() in text
    assert [text.count(line(-50 + i, 'filler %02d' % i)) for i in range(30)] == [1] * 30
    # the entry it was cut after is not matched again: no capture of its own (captured() counts three)
    assert len(incident_logs(daemon.out)) == 3


def test_a_follow_that_starts_with_more_than_ten_entries_waiting_prints_them_at_once(tmp_path):
    # journalctl 219 and 239 to 252 print only the first 10 entries of a follow from a cursor, and then wait for the
    # journal to change, unless it has --no-tail (the fake does so too): the 31 entries logged between the end of the
    # read without --follow and the start of the follow must all be read.
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    first_journal = [(-100, 'quiet'), (-90, 'HIT first'), (-80, 'saved')]
    daemon.write(*first_journal)
    daemon.run_until(lambda: daemon.captured(1, 'saved', now - 80))
    daemon.write(*first_journal + [(-79, 'HIT read')])
    later = [(-50 + i, 'filler %02d' % i) for i in range(30)] + [(-5, 'HIT late')]
    (daemon.bin_dir / 'later.jsonl').write_text(''.join(json.dumps({'stored': now + at, 'text': text}) + '\n' for at, text in later))
    # the entries are logged as the follow starts
    daemon.wrap('case " $* " in *" --follow "*) cat "$(dirname "$FAKE")/later.jsonl" >> "$(dirname "$FAKE")/journal.jsonl" ;; esac')
    second = daemon.run_until(lambda: daemon.captured(2, 'HIT late', now - 5))
    assert 'Resuming the journal after' in second
    text = incident_logs(daemon.out)[1].read_text()
    assert 'Matched line:    %s' % line(-79, 'HIT read').strip() in text
    assert [text.count(line(-50 + i, 'filler %02d' % i)) for i in range(30)] == [1] * 30 and 'HIT late' in text
    assert daemon.reads()[-1] == '--output=export --all --no-pager --cursor=%s --no-tail --follow' % daemon.cursor(-79, 'HIT read')


def test_a_restart_after_the_journal_lost_the_saved_entry_matches_every_line_of_the_window(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.write((-40, 'HIT first'), (-20, 'last line read'))
    daemon.run_until(lambda: daemon.captured(1, 'last line read', now - 20))
    # While stopped, the journal file that held it was rotated away; a match was logged after it.
    daemon.write((-15, 'HIT logged while stopped'), (-5, 'later'))
    second = daemon.run_until(lambda: daemon.captured(2, 'later', now - 5) and daemon.following())
    assert 'Cannot find the last entry read before the stop' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    assert 'Matched line:    %s' % line(-15, 'HIT logged while stopped').strip() in logs[1].read_text()
    # the journal lands on the entry after the lost one: that read ends at once, the window is read by time
    assert daemon.reads() == ['--output=export --all --no-pager --cursor=%s' % daemon.cursor(-20, 'last line read'),
                              '--output=export --all --no-pager --since=@%d' % (now - 20 - 60),
                              '--output=export --all --no-pager --cursor=%s --no-tail --follow' % daemon.cursor(-5, 'later')]


def test_a_restart_with_a_position_file_of_1_69_matches_every_line_of_the_window(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.write((-30, 'HIT before the upgrade'), (-10, 'HIT after it'))
    daemon.position_file.write_text(json.dumps({'time': now - 20, 'line': 1, 'sha1': 'f' * 40}))
    second = daemon.run_until(lambda: daemon.captured(1, 'HIT after it', now - 10))
    assert 'Cannot find the last entry read before the stop' in second
    assert daemon.reads()[0] == '--output=export --all --no-pager --since=@%d' % (now - 20 - 60)
    assert 'Matched line:    %s' % line(-30, 'HIT before the upgrade').strip() in incident_logs(daemon.out)[0].read_text()


@pytest.mark.parametrize('failure', ['exit 1', 'kill -9 $$'])
def test_a_journalctl_that_fails_on_the_read_from_the_saved_entry_ends_the_run_and_the_next_start_resumes_exactly(tmp_path, failure):
    daemon = Daemon(tmp_path)
    now = daemon.now
    journal = [(-40, 'HIT in the window'), (-20, 'saved'), (-10, 'HIT after')]
    daemon.write(*journal)
    daemon.position_file.write_text(json.dumps({'cursor': daemon.cursor(-20, 'saved'), 'time': now - 20}))
    before = daemon.position_file.read_text()
    daemon.wrap('case " $* " in *" --cursor="*" --reverse "*|*" --follow "*) ;; *" --cursor="*) %s ;; esac' % failure)
    output = daemon.run_until(lambda: daemon.proc.poll() is not None)
    assert 'journalctl ended with status' in output and 'Process ended.' in output and 'Traceback' not in output
    assert daemon.position_file.read_text() == before and incident_logs(daemon.out) == []
    daemon.unwrap()
    second = daemon.run_until(lambda: daemon.captured(1, 'HIT after', now - 10))
    assert 'Resuming the journal after' in second
    # the window's match is context, not a capture of its own
    assert len(incident_logs(daemon.out)) == 1


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


@pytest.mark.parametrize('stalled', ['the read from the saved entry', 'the read back'])
def test_a_stop_signal_while_journalctl_is_waited_for_at_a_restart_exits_cleanly(tmp_path, stalled):
    # A real SIGTERM and real processes: the journalctl reading from the saved entry prints nothing, or the one reading
    # back prints one entry, and stalls. The stop must end firewatcher with exit 0 (run_until asserts it), the position
    # as it was, and that journalctl with it.
    daemon = Daemon(tmp_path)
    now = daemon.now
    daemon.write((-50, 'context'), (-10, 'saved'), (-5, 'HIT after'))
    daemon.position_file.write_text(json.dumps({'cursor': daemon.cursor(-10, 'saved'), 'time': now - 10}))
    before = daemon.position_file.read_text()
    stall = 'echo $$ > %s/stalled.pid; exec sleep 30' % daemon.bin_dir
    if stalled == 'the read back':
        daemon.wrap('case " $* " in *" --reverse "*) $FAKE "$@" | head -c 200; %s ;; esac' % stall)
    else:
        daemon.wrap('case " $* " in *" --reverse "*|*" --follow "*) ;; *" --cursor="*) %s ;; esac' % stall)
    output = daemon.run_until(lambda: (daemon.bin_dir / 'stalled.pid').exists())
    assert 'Exiting.' in output and 'Traceback' not in output and 'Resuming' not in output
    assert daemon.position_file.read_text() == before
    pid = int((daemon.bin_dir / 'stalled.pid').read_text())
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            break
        time.sleep(0.05)
    with pytest.raises(OSError):
        os.kill(pid, 0)


def test_a_slow_journalctl_at_a_restart_is_waited_for_and_noted_once(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fw, 'JOURNAL_WAIT_NOTE', 0.2)
    position = saved_at(tmp_path, 0, 'saved')
    out, journalctl = resume(tmp_path, monkeypatch, position, cursor=([0.6, entry(0, 'saved'), entry(5, 'HIT after')], 0),
                             reverse=([entry(0, 'saved')], 0))
    # the reads that answered in time give no line, then or later
    time.sleep(0.5)
    printed = capsys.readouterr().out
    assert printed.count('Still waiting for journalctl after') == 1 and 'Resuming the journal after' in printed
    assert len(incident_logs(out)) == 1 and journalctl.kinds() == ['cursor', 'reverse', 'follow']


def test_journal_before_reads_back_from_the_saved_entry_to_the_window_start(tmp_path):
    daemon = Daemon(tmp_path)
    now = daemon.now
    daemon.write((-100, 'too old'), (-50, 'context'), (-30, 'ahead and set back'), (-40, 'more'), (-20, 'saved'), (-10, 'after'))
    journalctl = str(daemon.bin_dir / 'journalctl')
    got = list(fw._journal_before(journalctl, daemon.cursor(-20, 'saved'), now - 60, now))
    # newest first, through the saved entry's own line; a time never later than the line after it
    assert got == [(now - 20, daemon.line(-20, 'saved')), (now - 40, daemon.line(-40, 'more')),
                   (now - 40, daemon.line(-30, 'ahead and set back')), (now - 50, daemon.line(-50, 'context'))]
    assert not (tmp_path / 'bin' / 'calls.txt').read_text().count('--follow')
    # an entry the journal no longer holds, and a journalctl that is not there: nothing
    assert list(fw._journal_before(journalctl, daemon.cursor(-25, 'gone'), now - 60, now)) == []
    assert list(fw._journal_before(str(tmp_path / 'missing'), cursor(0, 'x'), 0, T)) == []


def test_journal_before_takes_nothing_from_a_read_back_that_starts_elsewhere(monkeypatch):
    # journalctl 219 to 257 print nothing backwards from an entry they lost; one that landed on another would give a
    # context that does not end at the saved entry
    FakeJournalctl(monkeypatch, reverse=([entry(-5, 'another'), entry(-10, 'older')], 0))
    assert list(fw._journal_before('journalctl', cursor(0, 'saved'), T - 60, T)) == []


def test_journal_before_stopped_early_ends_journalctl(tmp_path):
    # the buffer is full, or a stop: the caller stops taking lines, and journalctl is ended
    export = tmp_path / 'export.bin'
    export.write_bytes(entry(0, 'saved') + entry(-50, 'context') + entry(-40, 'more'))
    stub = tmp_path / 'journalctl'
    stub.write_text('#!/bin/sh\necho $$ > %s\ncat %s\nexec sleep 30\n' % (tmp_path / 'pid', export))
    stub.chmod(0o755)
    lines = fw._journal_before(str(stub), cursor(0, 'saved'), T - 60, T + 10)
    assert next(lines) == (T, jline(0, 'saved'))
    pid = int((tmp_path / 'pid').read_text())
    started = time.time()
    lines.close()
    assert time.time() - started < 10  # killed, not waited for
    with pytest.raises(OSError):
        os.kill(pid, 0)


def _lines(count, start=1000.0):
    return [(start + k * 0.01, 'host app[7]: line %d %s\n' % (k, 'x' * (k % 97))) for k in range(count)]


@pytest.mark.parametrize('count, cap', [(0, 1 << 20), (1, 1 << 20), (5000, 1 << 20)])
def test_refill_under_the_cap_takes_every_line_as_append_would(count, cap):
    lines = _lines(count)
    appended = fw.ContextBuffer(1e9, cap)
    for seq, (at, line) in enumerate(lines, 1):
        appended.append(at, seq, line)
    refilled = fw.ContextBuffer(1e9, cap)
    assert refilled.refill(reversed(lines)) == count
    assert list(refilled.entries(0)) == list(appended.entries(0)) == [(at, seq, line) for seq, (at, line) in enumerate(lines, 1)]
    assert refilled.dropped_until is None and refilled.memory <= cap
    # the loop's lines go on from there
    refilled.append(2000.0, count + 1, 'next\n')
    assert list(refilled.entries(0))[-1] == (2000.0, count + 1, 'next\n') and refilled.seq_span(0) == (1, count + 1)


def test_refill_over_the_cap_keeps_the_newest_lines_and_reads_no_further():
    lines = _lines(200000)
    taken = []

    def newest_first():
        for pair in reversed(lines):
            taken.append(pair)
            yield pair

    cap = 1 << 20
    refilled = fw.ContextBuffer(1e9, cap)
    count = refilled.refill(newest_first())
    kept = list(refilled.entries(0))
    assert 0 < count == len(kept) < len(lines) and refilled.memory <= cap
    assert [line for _at, _seq, line in kept] == [line for _at, line in lines[-count:]]
    assert [seq for _at, seq, _line in kept] == list(range(1, count + 1))
    # the capture says older lines were dropped, from the newest one left out on
    assert refilled.dropped_until == lines[-count - 1][0]
    # the read back stopped at the first block that did not fit
    assert len(taken) - count <= fw.BUFFER_OPEN_MEMORY // (fw.BUFFER_LINE_OVERHEAD + sys.getsizeof(''))
    # as many lines as append keeps under the same cap, give or take a block
    appended = fw.ContextBuffer(1e9, cap)
    for seq, (at, line) in enumerate(lines, 1):
        appended.append(at, seq, line)
    assert abs(len(list(appended.entries(0))) - count) < 2000


def test_refill_keeps_its_newest_block_even_over_the_cap():
    lines = _lines(3000)
    refilled = fw.ContextBuffer(1e9, 1)
    count = refilled.refill(reversed(lines))
    assert 0 < count < len(lines) and len(refilled.blocks) == 1
    assert [line for _at, _seq, line in refilled.entries(0)] == [line for _at, line in lines[-count:]]


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


def test_the_context_read_back_is_not_kept_in_memory(tmp_path, monkeypatch, capsys):
    # After a restart that follows a busy window, the lines before the saved entry go straight into the bounded
    # context buffer: 1.70 first kept the whole read back, which cost 200 MB for 300,000 lines for the life of the process.
    import tracemalloc
    real_popen = subprocess.Popen
    daemon = Daemon(tmp_path)
    count = 40000
    text = 'worker %d: request %d failed: connection reset by peer (attempt 3 of 5), retrying in 250 ms'
    daemon.write(*[(-50, text % (i % 64, i)) for i in range(count)] + [(-10, 'saved')])
    journalctl = str(daemon.bin_dir / 'journalctl')
    path = tmp_path / 'journal.position'
    path.write_text(json.dumps({'cursor': daemon.cursor(-10, 'saved'), 'time': daemon.now - 10}))
    # the read back is the fake journalctl, a real process; the read from the saved entry gives it, and the follow nothing
    scripted = FakeJournalctl(monkeypatch, cursor=([entry(0, 'saved', when=daemon.now - 10)], 0))
    monkeypatch.setattr(fw.subprocess, 'Popen', lambda argv, *a, **k: real_popen(argv, *a, **k) if '--reverse' in argv
                        else scripted.popen(argv))
    pat = tmp_path / 'p.txt'
    pat.write_text('NEVER\n')
    tracemalloc.start()
    try:
        # from the construction on, whichever step holds the lines
        position = fw.JournalPosition(str(path), context_time=60, now=daemon.now)
        fw.capture_messages([journalctl] + FOLLOW[1:], fw.load_patterns([str(pat)]), capture_time=60,
                            output_folder=str(tmp_path / 'out'), compress_after_months=0, delete_after_months=0,
                            journal_position=position)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # the lines did reach the buffer (a read that yields nothing would pass the limit below): the context lines and the saved one
    assert 'Processed %d lines.' % (count + 1) in capsys.readouterr().out
    # measured at this size in 1.70: with the lines in the buffer, compressed, the peak is 1.4 MB; with a list of them in
    # between (as 1.70's first build had) it is 12.4 MB
    assert peak < 4 * 1024 * 1024, peak


def test_lines_read_back_keep_their_age_in_the_context(tmp_path, monkeypatch):
    now = int(time.time())
    path = tmp_path / 'journal.position'
    path.write_text(json.dumps({'cursor': cursor(now - 10 - T, 'the saved line'), 'time': now - 10}))
    position = fw.JournalPosition(str(path), context_time=300)
    out, _journalctl = resume(tmp_path, monkeypatch, position,
                              cursor=([entry(0, 'the saved line', when=now - 10)], 0),
                              reverse=([entry(0, 'the saved line', when=now - 10), entry(0, 'recent', when=now - 30),
                                        entry(0, 'too old for the window', when=now - 250)], 0),
                              follow=([entry(0, 'HIT', when=now - 1)], 0))
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
