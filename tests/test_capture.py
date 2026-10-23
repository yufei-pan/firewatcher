import collections
import os
import datetime
import re
import threading
import time

import pytest

import firewatcher as fw
from conftest import Clock, capture, incident_logs, ScriptedPopen, ScriptedStdout, patch_popen, REAL_OUTPUT_FOLDER

# --- capture loop ---

def test_capture_messages_returns_on_eof(tmp_path):
    out = capture(tmp_path, 'noise\nPANICMARK here\nmore noise\n', pattern='PANICMARK')
    logs = list(out.rglob('*.log'))
    assert logs
    text = ''.join(p.read_text() for p in logs)
    assert 'PANICMARK' in text


def test_capture_messages_default_output_folder_matches_cli():
    import inspect
    defaults = inspect.signature(fw.capture_messages).parameters
    assert defaults['output_folder'].default == REAL_OUTPUT_FOLDER
    assert REAL_OUTPUT_FOLDER == '/var/log/captured_messages/'


def test_matching_lines_count_toward_capture_cap(tmp_path):
    out = capture(tmp_path, 'HIT 1\nHIT 2\nHIT 3\nHIT 4\nHIT 5\n', capture_line_count_max=2)
    caps = incident_logs(out)
    assert caps
    text = caps[0].read_text()
    assert 'Truncated' in text or 'exceeded' in text


def test_capture_writes_journal_and_pre_match_context(tmp_path):
    out = capture(tmp_path, 'before-a\nbefore-b\nHIT now\nafter-1\n')
    journal = (out / 'journal.log').read_text()
    assert 'HIT' in journal or 'Matched' in journal or 'Captured logs' in journal
    caps = incident_logs(out)
    assert len(caps) == 1
    text = caps[0].read_text()
    assert 'before-a' in text
    assert 'before-b' in text
    assert 'HIT now' in text
    assert 'after-1' in text
    assert 'End of capture' in text
    assert datetime.datetime.now().strftime('%Y-%m') in str(caps[0])


def test_capture_skips_blank_lines_and_has_no_file_without_match(tmp_path):
    out = capture(tmp_path, '\n\n   \nno match here\n', pattern='HIT')
    assert incident_logs(out) == []
    assert not (out / 'journal.log').exists()


def test_capture_regex_pattern(tmp_path):
    out = capture(tmp_path, 'kernel: nvme0n1 timeout\n', pattern=r'nvme\d+n\d+', regex=True)
    text = incident_logs(out)[0].read_text()
    assert 'nvme0n1' in text


def test_capture_closes_window_when_time_expires(tmp_path):
    out = capture(tmp_path, 'HIT\nlater line\n', capture_time=-1)
    text = incident_logs(out)[0].read_text()
    assert 'HIT' in text
    assert 'End of capture' in text


def test_capture_utf8_replace_does_not_hang(tmp_path):
    out = capture(tmp_path, b'noise \xff\nHIT here\n', pattern='HIT')
    assert incident_logs(out)
    assert 'HIT here' in incident_logs(out)[0].read_text()


def test_capture_skips_own_syslog_lines(tmp_path):
    out = capture(
        tmp_path,
        'host firewatcher[12]: Capturing logs to /tmp/error\nkernel: real error\n',
        pattern='error',
    )
    text = incident_logs(out)[0].read_text()
    assert 'real error' in text
    matched_line = text.split('Matched line:')[1].splitlines()[0]
    assert 'real error' in matched_line
    assert 'firewatcher[12]' not in matched_line


def test_end_capture_none_is_noop(tmp_path):
    fw._end_capture(None, 0, 10)
    fw._end_capture('', 0, 10)


def test_capture_keyboardinterrupt_ends_open_window(tmp_path, monkeypatch, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    patterns = fw.load_patterns([str(pat)])
    out = tmp_path / 'out'
    popen = ScriptedPopen(['HIT now\n', KeyboardInterrupt()])
    patch_popen(monkeypatch, popen)
    fw.capture_messages(
        ['unused'], patterns,
        capture_time=60, output_folder=str(out),
        compress_after_months=0, delete_after_months=0,
    )
    assert popen.terminated
    printed = capsys.readouterr().out
    assert 'Exiting.' in printed
    logs = incident_logs(out)
    assert logs
    assert 'End of capture' in logs[0].read_text()


def test_capture_keyboardinterrupt_tolerate_terminate_error(tmp_path, monkeypatch, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    patterns = fw.load_patterns([str(pat)])
    popen = ScriptedPopen([KeyboardInterrupt()], terminate_raises=True)
    patch_popen(monkeypatch, popen)
    fw.capture_messages(
        ['unused'], patterns,
        capture_time=60, output_folder=str(tmp_path / 'out'),
        compress_after_months=0, delete_after_months=0,
    )
    assert 'Exiting.' in capsys.readouterr().out
    assert incident_logs(tmp_path / 'out') == []


def test_capture_readline_error_continues(tmp_path, monkeypatch, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    patterns = fw.load_patterns([str(pat)])
    out = tmp_path / 'out'
    popen = ScriptedPopen(['noise\n', OSError('boom'), 'HIT now\n'])
    patch_popen(monkeypatch, popen)
    fw.capture_messages(
        ['unused'], patterns,
        capture_time=60, output_folder=str(out),
        compress_after_months=0, delete_after_months=0,
    )
    assert 'Error reading line' in capsys.readouterr().out
    assert incident_logs(out)


def test_capture_subsequent_match_is_marked(tmp_path):
    out = capture(tmp_path, 'HIT 1\nHIT 2\nnoise after\n')
    text = incident_logs(out)[0].read_text()
    assert '-> HIT 2' in text
    assert 'noise after' in text


def test_capture_nonmatch_lines_can_hit_line_cap(tmp_path):
    body = 'HIT\n' + ''.join(f'line{i}\n' for i in range(5))
    out = capture(tmp_path, body, capture_line_count_max=2)
    text = incident_logs(out)[0].read_text()
    assert 'Truncated' in text or 'exceeded' in text
    assert 'line0' in text
    assert 'line4' not in text


def test_line_cap_limits_only_the_lines_after_the_match(tmp_path):
    body = ''.join(f'pre-{i}\n' for i in range(10)) + 'HIT\n' + ''.join(f'post-{i}\n' for i in range(10))
    out = capture(tmp_path, body, capture_line_count_max=3)
    text = incident_logs(out)[0].read_text()
    assert all('pre-%d' % i in text for i in range(10))
    assert 'post-2' in text and 'post-4' not in text
    assert 'Older cached in-memory lines were dropped' not in text


def test_capture_progress_every_10000_lines(tmp_path, capsys):
    body = ('x\n' * 9999) + 'HIT\n'
    capture(tmp_path, body)
    assert 'Processed 10000 lines.' in capsys.readouterr().out


def test_capture_compresses_on_unmatched_traffic(tmp_path, monkeypatch):
    calls = []
    orig = fw.Log_Compressor.startCompressLogs

    def spy(self):
        calls.append(1)
        return orig(self)

    monkeypatch.setattr(fw.Log_Compressor, 'startCompressLogs', spy)
    capture(tmp_path, 'noise-a\nnoise-b\n', pattern='HIT')
    assert len(calls) >= 3


def test_capture_drops_buffer_older_than_window(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    patterns = fw.load_patterns([str(pat)])
    out = tmp_path / 'out'
    popen = ScriptedPopen([('old-context\n', 0), ('HIT now\n', 70)], clock=clock)
    patch_popen(monkeypatch, popen)
    fw.capture_messages(
        ['unused'], patterns,
        capture_time=60, output_folder=str(out),
        compress_after_months=0, delete_after_months=0,
    )
    text = incident_logs(out)[0].read_text()
    assert 'HIT now' in text
    assert 'old-context' not in text


def test_capture_rematch_extends_window(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    patterns = fw.load_patterns([str(pat)])
    out = tmp_path / 'out'
    popen = ScriptedPopen([
        ('HIT 1\n', 0),
        ('mid\n', 50),
        ('HIT 2\n', 0),
        ('late\n', 50),
    ], clock=clock)
    patch_popen(monkeypatch, popen)
    fw.capture_messages(
        ['unused'], patterns,
        capture_time=60, output_folder=str(out),
        compress_after_months=0, delete_after_months=0,
    )
    text = incident_logs(out)[0].read_text()
    assert '-> HIT 2' in text
    assert 'late' in text


def run_scripted(tmp_path, monkeypatch, popen, **kw):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    opts = dict(capture_time=60, output_folder=str(tmp_path / 'out'), compress_after_months=0, delete_after_months=0)
    opts.update(kw)
    patch_popen(monkeypatch, popen)
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), **opts)
    return tmp_path / 'out'


def test_full_window_of_context_is_kept_past_ten_thousand_lines(tmp_path):
    body = ''.join('pre-%05d some context\n' % i for i in range(30000)) + 'HIT\n'
    text = incident_logs(capture(tmp_path, body))[0].read_text()
    assert 'pre-00000' in text and 'pre-29999' in text
    assert text.count('some context') == 30000


def test_capture_does_not_report_dropped_lines_that_aged_out(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    popen = ScriptedPopen([
        ('old-1\n', 0), ('old-2\n', 0), ('old-3\n', 0),
        ('mid\n', 70), ('HIT now\n', 0),
    ], clock=clock)
    out = run_scripted(tmp_path, monkeypatch, popen, capture_line_count_max=2)
    text = incident_logs(out)[0].read_text()
    assert 'mid' in text
    assert 'old-3' not in text
    assert 'Older cached in-memory lines were dropped' not in text


def test_idle_reads_stay_on_the_calling_thread(tmp_path, monkeypatch):
    threads = []

    class RecordingPopen(ScriptedPopen):
        def __init__(self, events):
            super().__init__(events)
            readline = self.stdout.readline

            def recording_readline(*args):
                threads.append(threading.current_thread())
                return readline(*args)

            self.stdout.readline = recording_readline

    run_scripted(tmp_path, monkeypatch, RecordingPopen(['noise\n', 'HIT now\n', 'after\n']))
    main = threading.current_thread()
    assert threads[0] is main and threads[1] is main
    assert threads[2] is not main


def test_capture_opens_the_capture_file_once(tmp_path, monkeypatch):
    opened = []
    real_open = open

    def counting_open(path, *args, **kwargs):
        opened.append(str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(fw, 'open', counting_open, raising=False)
    out = capture(tmp_path, 'HIT now\n' + ''.join(f'after-{i}\n' for i in range(20)))
    cap = str(incident_logs(out)[0])
    assert opened.count(cap) == 1
    assert 'after-19' in incident_logs(out)[0].read_text()


def test_capture_fsyncs_at_most_once_per_interval(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    synced_at = []
    monkeypatch.setattr(fw.os, 'fsync', lambda fd: synced_at.append(clock.t))
    popen = ScriptedPopen([
        ('HIT now\n', 0), ('a\n', 0.125), ('b\n', 0.25), ('c\n', 0.875),
    ], clock=clock)
    run_scripted(tmp_path, monkeypatch, popen)
    start = 1_000_000.0
    assert synced_at == [start, start + 1.25, start + 1.25]


def test_capture_fsyncs_pending_lines_when_source_goes_quiet(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'CAPTURE_SYNC_INTERVAL', 0.05)
    events = []
    monkeypatch.setattr(fw.os, 'fsync', lambda fd: events.append('fsync'))

    class QuietStdout:
        def __init__(self):
            self.lines = ['HIT now\n', 'more\n']

        def readline(self, size=-1):
            if self.lines:
                return self.lines.pop(0)
            time.sleep(0.5)
            events.append('eof')
            return ''

    popen = ScriptedPopen([])
    popen.stdout = QuietStdout()
    run_scripted(tmp_path, monkeypatch, popen)
    assert events == ['fsync', 'fsync', 'eof', 'fsync']


def test_capture_survives_filesystems_without_fsync(tmp_path, monkeypatch):
    def no_fsync(fd):
        raise OSError(22, 'Invalid argument')

    monkeypatch.setattr(fw.os, 'fsync', no_fsync)
    out = capture(tmp_path, 'HIT now\nafter\n')
    text = incident_logs(out)[0].read_text()
    assert 'after' in text
    assert 'End of capture' in text


class RecordingDispatcher:
    def __init__(self):
        self.jobs = []

    def submit(self, job):
        self.jobs.append(job)

    def close(self):
        pass


def recording_dispatcher(monkeypatch):
    dispatcher = RecordingDispatcher()
    monkeypatch.setattr(fw, '_start_dispatcher', lambda settings: dispatcher)
    return dispatcher


def journal_records(monkeypatch):
    records = []
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args: records.append(args))
    return records


# --- capture_time_max ---

def repeating_hits(clock):
    # a match every 50 s keeps a 60 s window open for as long as it repeats
    return ScriptedPopen([('HIT 1\n', 0), ('HIT 2\n', 50), ('HIT 3\n', 50), ('HIT 4\n', 50), ('tail\n', 1)], clock=clock)


def test_capture_time_max_ends_a_capture_its_pattern_keeps_extending(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = run_scripted(tmp_path, monkeypatch, repeating_hits(clock), capture_time_max=120)
    first, second = (p.read_text() for p in incident_logs(out))
    assert '-> HIT 3' in first
    assert 'HIT 4' not in first
    assert 'Capture reached capture_time_max of 120 seconds' in first
    assert 'Matched line:    HIT 4' in second
    assert 'tail' in second
    assert 'Capture reached capture_time_max' not in second


def test_capture_time_max_zero_disables_the_bound(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = run_scripted(tmp_path, monkeypatch, repeating_hits(clock), capture_time_max=0)
    (only,) = incident_logs(out)
    assert '-> HIT 4' in only.read_text()


def test_match_after_the_window_ran_out_starts_a_new_capture(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = run_scripted(tmp_path, monkeypatch, ScriptedPopen([('HIT 1\n', 0), ('HIT 2\n', 70)], clock=clock))
    first, second = (p.read_text() for p in incident_logs(out))
    assert 'HIT 2' not in first
    assert 'Matched line:    HIT 2' in second


def test_capture_time_max_default_matches_cli():
    import inspect
    defaults = inspect.signature(fw.capture_messages).parameters
    assert defaults['capture_time_max'].default == fw.DEFAULT_CAPTURE_TIME_MAX == fw.Settings().capture_time_max


# --- unwritable output folder ---

def test_unwritable_output_folder_falls_back_and_keeps_running(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    dispatcher = recording_dispatcher(monkeypatch)
    blocked = tmp_path / 'blocked'
    blocked.write_text('a file, so nothing can be created under it')
    fallback = tmp_path / 'fallback'
    capture(tmp_path, 'before\nHIT now\nafter\n', output_folder=str(blocked / 'out'), fallback_folder=str(fallback))
    (cap,) = incident_logs(fallback)
    text = cap.read_text()
    assert 'capture moved here from %s' % (blocked / 'out') in text
    for expected in ('before', 'Matched line:    HIT now', 'after', 'End of capture'):
        assert expected in text
    assert str(cap) in (fallback / 'journal.log').read_text()
    assert [job['path'] for job in dispatcher.jobs] == [str(cap)]
    assert any('cannot write capture' in record[1] for record in records)


def test_capture_with_no_writable_folder_still_reaches_the_dispatcher(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    dispatcher = recording_dispatcher(monkeypatch)
    blocked = tmp_path / 'blocked'
    blocked.write_text('a file')
    capture(tmp_path, 'HIT now\nafter\nHIT again\n', output_folder=str(blocked / 'out'))
    assert len(dispatcher.jobs) == 1
    assert dispatcher.jobs[0]['path'] is None
    assert dispatcher.jobs[0]['matched_line'] == 'HIT now'
    assert any('no writable folder with free space left' in record[1] for record in records)


class FlakyHandle:
    """A capture file that stops accepting data once a line containing BREAK is written, like a dying NFS mount."""

    def __init__(self, handle):
        self.handle = handle
        self.failing = False

    def write(self, text):
        if 'BREAK' in text:
            self.failing = True
        return self.handle.write(text)

    def flush(self):
        if self.failing:
            raise OSError(5, 'Input/output error')
        self.handle.flush()

    def fileno(self):
        return self.handle.fileno()

    def close(self):
        self.handle.close()


def test_write_error_mid_capture_continues_in_the_fallback_folder(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    dispatcher = recording_dispatcher(monkeypatch)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    real_open = open

    def flaky_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        if str(path).startswith(str(out)) and not str(path).endswith('journal.log'):
            return FlakyHandle(handle)
        return handle

    monkeypatch.setattr(fw, 'open', flaky_open, raising=False)
    capture(tmp_path, 'HIT now\nline-1\nBREAK line-2\nline-3\n', output_folder=str(out), fallback_folder=str(fallback))
    (primary,) = incident_logs(out)
    (moved,) = incident_logs(fallback)
    assert 'Matched line:    HIT now' in primary.read_text()
    text = moved.read_text()
    assert 'capture moved here from %s after a write error' % primary in text
    # lines since the last fsync are written again, so nothing between the two files is lost
    for expected in ('line-1', 'BREAK line-2', 'line-3', 'End of capture'):
        assert expected in text
    assert [job['path'] for job in dispatcher.jobs] == [str(moved)]


def test_fsync_error_moves_the_capture_with_its_unsynced_lines(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    calls = []

    def fsync(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(fw.errno.EIO, 'Input/output error')

    monkeypatch.setattr(fw.os, 'fsync', fsync)
    fallback = tmp_path / 'fallback'
    capture(tmp_path, 'before\nHIT now\nafter\n', fallback_folder=str(fallback))
    text = incident_logs(fallback)[0].read_text()
    for expected in ('after a write error', 'before', 'Matched line:    HIT now', 'after', 'End of capture'):
        assert expected in text


def test_capture_file_after_close_ignores_writes(tmp_path):
    cap = fw.CaptureFile(str(tmp_path / 'c.log'), 1.0)
    cap.write('one\n')
    cap.close()
    cap.close()
    cap.write('late\n')
    cap.commit()
    fw._end_capture(cap, 0, 10)
    assert (tmp_path / 'c.log').read_text() == 'one\n'


@pytest.mark.parametrize('where', ['trailer', 'close'])
def test_interrupted_end_of_capture_still_hands_over_the_incident(tmp_path, monkeypatch, where):
    dispatcher = RecordingDispatcher()
    cap = fw.CaptureFile(str(tmp_path / 'c.log'), 1.0)
    real_write, real_sync = cap.write, cap.sync

    def interrupted_write(text):
        if 'End of capture' in text:
            raise KeyboardInterrupt
        real_write(text)

    def interrupted_sync(now=None):
        real_sync(now)
        raise KeyboardInterrupt

    if where == 'trailer':
        cap.write = interrupted_write
    else:
        cap.sync = interrupted_sync
    with pytest.raises(KeyboardInterrupt):
        fw._end_capture(cap, 0, 10, incident={'pattern': 'HIT'}, dispatcher=dispatcher)
    assert cap.closed
    assert [job['path'] for job in dispatcher.jobs] == [str(tmp_path / 'c.log')]


def test_captures_opened_in_the_same_second_get_their_own_files(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    # the line cap ends the first capture, and the next match opens another in the same second
    popen = ScriptedPopen([('HIT 1\n', 0), ('HIT 2\n', 0), ('HIT 3\n', 0)], clock=clock)
    out = run_scripted(tmp_path, monkeypatch, popen, capture_line_count_max=0)
    caps = incident_logs(out)
    assert len(caps) == 2
    assert sorted(p.name.endswith('-1.log') for p in caps) == [False, True]
    assert sum('Matched pattern' in p.read_text() for p in caps) == 2
    journal = (out / 'journal.log').read_text()
    assert all(str(p) in journal for p in caps)


def test_fallback_folder_is_compressed_too(tmp_path, monkeypatch):
    roots = []
    real_init = fw.Log_Compressor.__init__

    def recording_init(self, logsDir, *args, **kwargs):
        roots.append(logsDir)
        real_init(self, logsDir, *args, **kwargs)

    monkeypatch.setattr(fw.Log_Compressor, '__init__', recording_init)
    fallback = tmp_path / 'fallback'
    capture(tmp_path, 'noise\n', fallback_folder=str(fallback))
    assert roots == [str(tmp_path / 'out'), str(fallback)]


# --- always_notify ---

def test_always_notify_marks_incidents_whose_matched_lines_match(tmp_path, monkeypatch):
    dispatcher = recording_dispatcher(monkeypatch)
    always = {'fnmatch': {'*I/O error*'}}
    capture(tmp_path, 'HIT first\nHIT then I/O error\nHIT again I/O error\n', always_notify_patterns=always)
    assert dispatcher.jobs[0].get('always_notify') is True
    assert dispatcher.jobs[0]['always_notify_line'] == 'HIT then I/O error'


def test_always_notify_ignores_context_lines(tmp_path, monkeypatch):
    dispatcher = recording_dispatcher(monkeypatch)
    always = {'fnmatch': {'*I/O error*'}}
    # any program can log an I/O error line; only lines that matched a watch pattern count
    capture(tmp_path, 'I/O error before\nHIT first\nI/O error after\n', always_notify_patterns=always)
    assert 'always_notify' not in dispatcher.jobs[0]


# --- shutdown ---

def test_interrupt_while_handling_a_line_still_finishes_the_capture(tmp_path, monkeypatch, capsys):
    dispatcher = recording_dispatcher(monkeypatch)

    def interrupted(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(fw.CaptureFile, 'commit', interrupted)
    popen = ScriptedPopen(['HIT now\n', 'after\n'])
    out = run_scripted(tmp_path, monkeypatch, popen)
    assert popen.terminated
    assert 'Exiting.' in capsys.readouterr().out
    assert 'End of capture' in incident_logs(out)[0].read_text()
    assert [job['matched_line'] for job in dispatcher.jobs] == ['HIT now']


def test_interrupt_while_opening_a_capture_does_not_resend_the_previous_incident(tmp_path, monkeypatch):
    dispatcher = recording_dispatcher(monkeypatch)
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    calls = []

    def hostname():
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return 'box'

    monkeypatch.setattr(fw, '_hostname', hostname)
    popen = ScriptedPopen([('HIT first\n', 0), ('HIT second\n', 70)], clock=clock)
    run_scripted(tmp_path, monkeypatch, popen)
    assert [job['matched_line'] for job in dispatcher.jobs] == ['HIT first']


def test_eof_does_not_terminate_the_reader(tmp_path, monkeypatch):
    popen = ScriptedPopen(['HIT now\n'])
    run_scripted(tmp_path, monkeypatch, popen)
    assert not popen.terminated


def test_write_that_raises_moves_the_capture(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    real_open = open

    class RaisingHandle(FlakyHandle):
        def write(self, text):
            if 'BREAK' in text:
                raise OSError(28, 'No space left on device')
            return self.handle.write(text)

    def raising_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        if str(path).startswith(str(out)) and not str(path).endswith('journal.log'):
            return RaisingHandle(handle)
        return handle

    monkeypatch.setattr(fw, 'open', raising_open, raising=False)
    capture(tmp_path, 'HIT now\nBREAK line\nlast\n', output_folder=str(out), fallback_folder=str(fallback))
    text = incident_logs(fallback)[0].read_text()
    assert 'No space left on device' in text
    assert 'BREAK line' in text
    assert 'last' in text


# --- free space ---

FULL = (10 ** 6, 10 ** 12)       # 1 MB free of 1 TB: far below a 1% floor
ROOMY = (5 * 10 ** 11, 10 ** 12)


TWO_DAYS_AGO = time.time() - 2 * 86400


def months(root, **sizes):
    """Month folders and archives under root with that many bytes each, last changed two days ago."""
    root.mkdir(parents=True, exist_ok=True)
    for name, size in sizes.items():
        name = name.replace('_', '.')
        path = root / name
        if '.' in name:
            path.write_bytes(os.urandom(size))
        else:
            path.mkdir()
            (path / 'x.log').write_bytes(os.urandom(size))
            os.utime(str(path / 'x.log'), (TWO_DAYS_AGO, TWO_DAYS_AGO))
        os.utime(str(path), (TWO_DAYS_AGO, TWO_DAYS_AGO))


class FakeDisk:
    """_free_space for paths under root: a disk of `size` bytes holding `other` bytes of something
    else plus what really is under root (or, with lag, what was there when it was made)."""

    def __init__(self, monkeypatch, root, size, other=0, lag=False):
        self.root, self.size, self.other = str(root), size, other
        self.frozen = fw._entry_stats(self.root)[0] if lag else None
        monkeypatch.setattr(fw, '_free_space', self)

    def used(self):
        return self.other + (self.frozen if self.frozen is not None else fw._entry_stats(self.root)[0])

    def headroom_at(self, floor):
        return self.size - self.used() - int(self.size * floor)

    def set_headroom(self, headroom, floor):
        """Make 'something else' use enough that the room above the floor is headroom."""
        self.other += self.headroom_at(floor) - headroom

    def __call__(self, path):
        if not str(path).startswith(self.root):
            return ROOMY
        return self.size - self.used(), self.size


def guard_for(*folders, percent=10):
    return fw.DiskGuard(percent, [fw.Log_Compressor(str(folder), 0, 0) for folder in folders])


def test_purge_deletes_only_the_oldest_months_it_needs(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    out = tmp_path / 'out'
    current = datetime.datetime.now().strftime('%Y-%m')
    months(out, **{'2020-01': 200_000, '2020-02_tar_xz': 200_000, '2020-03': 200_000})
    (out / current).mkdir()
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-100_000, 0.10)
    room = guard_for(out).headroom(str(out / current / 'hit.log'))
    assert room >= fw.MIN_HEADROOM
    assert sorted(p.name for p in out.iterdir()) == ['2020-02.tar.xz', '2020-03', current]
    assert disk.headroom_at(0.10) >= fw.MIN_HEADROOM
    assert [r[1] for r in records if 'deleting' in r[1]] == [
        'firewatcher-self deleting 2020-01 from %s to keep 10%% of the disk free' % out]


def test_purge_keeps_history_when_it_cannot_make_room(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 100_000, '2020-02': 100_000})
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-1_000_000, 0.10)  # something else filled the disk
    assert guard_for(out).headroom(str(out / '2026-10' / 'hit.log')) < fw.MIN_HEADROOM
    assert sorted(p.name for p in out.iterdir()) == ['2020-01', '2020-02']
    assert any('not writing it there' in r[1] for r in records)


def test_purge_runs_at_most_once_an_hour_per_folder(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    clock = Clock(time.time())
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 200_000, '2020-02': 200_000})
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    guard = guard_for(out)
    path = str(out / '2026-10' / 'hit.log')
    disk.set_headroom(-10_000, 0.10)
    assert guard.headroom(path) >= fw.MIN_HEADROOM
    assert sorted(p.name for p in out.iterdir()) == ['2020-02']
    clock.t += 60
    disk.set_headroom(-10_000, 0.10)  # filled again
    assert guard.headroom(path) < fw.MIN_HEADROOM
    assert (out / '2020-02').is_dir()
    clock.t += fw.DEFAULT_PURGE_INTERVAL
    assert guard.headroom(path) >= fw.MIN_HEADROOM
    assert not (out / '2020-02').exists()


def test_lagging_statvfs_costs_a_move_never_the_floor(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    synced = []
    monkeypatch.setattr(fw.os, 'sync', lambda: synced.append(1))
    out = tmp_path / 'out'
    months(out, **{'2020-01': 300_000, '2020-02': 300_000, '2020-03': 300_000})
    disk = FakeDisk(monkeypatch, out, 10_000_000, lag=True)  # never shows the deletion
    disk.set_headroom(-10_000, 0.10)
    guard = guard_for(out)
    path = str(out / '2026-10' / 'hit.log')
    # only what statvfs reports authorizes a write, so this capture moves on
    assert guard.headroom(path) < fw.MIN_HEADROOM
    assert synced == [1]
    # and the lag does not cost more history than the room needed
    assert sorted(p.name for p in out.iterdir()) == ['2020-02', '2020-03']
    assert guard.headroom(path) < fw.MIN_HEADROOM
    assert sorted(p.name for p in out.iterdir()) == ['2020-02', '2020-03']

def test_purge_only_touches_what_firewatcher_made_and_nothing_recent(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2019-10_tar_xz_123_partial': 100_000, '2019-12': 100_000, '2019-12_tar_xz': 100_000,
                   '2019-12_1_tar_xz': 100_000, '2019-12_bak': 100_000, '2019-03_csv': 100_000,
                   '2019-1': 100_000, '2019-11': 100_000})
    os.utime(str(out / '2019-11'), None)  # another firewatcher just wrote there
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-300_000, 0.10)
    guard_for(out).headroom(str(out / '2026-10' / 'hit.log'))
    assert sorted(p.name for p in out.iterdir()) == ['2019-03.csv', '2019-1', '2019-11', '2019-12.bak']


def test_month_names(tmp_path):
    assert [fw._month_of(n) for n in ('2019-12', '2019-12.tar.xz', '2019-12.3.tar.xz', '2019-12.tar.xz.99.partial')] == ['2019-12'] * 4
    assert [fw._month_of(n) for n in ('2019-1', '2019-13', '2019-12.bak', '2019-12.tar', 'journal.log', '2019-12x', '2019-12\n')] == [None] * 7


def test_one_undeletable_month_does_not_block_the_rest(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 200_000, '2020-02': 200_000})
    real_rmtree = fw.shutil.rmtree

    def rmtree(path, *args, **kwargs):
        if str(path).endswith('2020-01'):
            raise OSError(16, 'Device or resource busy')
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(fw.shutil, 'rmtree', rmtree)
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    assert guard_for(out).headroom(str(out / '2026-10' / 'hit.log')) >= fw.MIN_HEADROOM
    assert sorted(p.name for p in out.iterdir()) == ['2020-01']
    assert any('cannot delete 2020-01' in r[1] for r in records)


def test_output_folder_inside_the_fallback_purges_its_own_months(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    fallback = tmp_path / 'fw'
    out = fallback / 'out'
    months(fallback, **{'2019-01': 200_000})
    months(out, **{'2019-01': 200_000})
    disk = FakeDisk(monkeypatch, fallback, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    guard_for(out, fallback).headroom(str(out / '2026-10' / 'hit.log'))
    assert not (out / '2019-01').exists()
    assert (fallback / '2019-01').is_dir()


def test_purge_skips_the_month_being_compressed_without_waiting(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 200_000, '2020-02': 200_000})
    compressor = fw.Log_Compressor(str(out), 0, 0)
    assert compressor._claim('2020-01')  # tar is on it
    assert compressor.deleteMonth('2020-01', 'for the test') == 0
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    started = time.time()
    assert fw.DiskGuard(10, [compressor]).headroom(str(out / '2026-10' / 'hit.log')) >= fw.MIN_HEADROOM
    assert time.time() - started < 1
    assert sorted(p.name for p in out.iterdir()) == ['2020-01']

def test_compression_keeps_to_the_floor(tmp_path, monkeypatch, capsys):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 300_000})
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(200_000, 0.10)  # less than the month: its archive could cross the floor
    compressor = fw.Log_Compressor(str(out), 0, 0)
    fw.DiskGuard(10, [compressor])
    compressor.compressAfterMonths = 1
    compressor.lastProcessTime = 0
    compressor.compressLogs()
    assert sorted(p.name for p in out.iterdir()) == ['2020-01']
    assert 'Not compressing 2020-01 now' in capsys.readouterr().out


def test_unknown_free_space_is_logged_once(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    monkeypatch.setattr(fw, '_free_space', lambda path: None)
    guard = guard_for(tmp_path)
    assert guard.headroom(str(tmp_path / '2026-10' / 'a.log')) is None
    assert guard.headroom(str(tmp_path / '2026-10' / 'b.log')) is None
    assert sum('cannot read free space' in r[1] for r in records) == 1


def test_free_space_walks_up_only_past_missing_folders(tmp_path, monkeypatch):
    assert fw._free_space(str(tmp_path / 'not' / 'yet')) is not None

    def stale(path):
        raise OSError(116, 'Stale file handle')

    monkeypatch.setattr(fw.os, 'statvfs', stale)
    assert fw._free_space(str(tmp_path)) is None


def test_zero_floor_never_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, '_free_space', lambda path: (_ for _ in ()).throw(AssertionError('checked')))
    assert fw.DiskGuard(0, []).headroom(str(tmp_path / 'x.log')) is None


def test_capture_skips_a_full_output_folder_for_the_fallback(tmp_path, monkeypatch):
    records = journal_records(monkeypatch)
    dispatcher = recording_dispatcher(monkeypatch)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    monkeypatch.setattr(fw, '_free_space', lambda path: FULL if str(path).startswith(str(out)) else ROOMY)
    capture(tmp_path, 'before\nHIT now\nafter\n', output_folder=str(out), fallback_folder=str(fallback), min_free_percent=1)
    assert incident_logs(out) == []
    text = incident_logs(fallback)[0].read_text()
    assert 'because free space there fell below the floor' in text
    assert 'after' in text and 'End of capture' in text
    assert dispatcher.jobs[0]['path'] == str(incident_logs(fallback)[0])
    assert any('free space below 1%' in record[1] for record in records)


def test_capture_moves_when_its_folder_fills_up(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    full = {'out': False}
    monkeypatch.setattr(fw, '_free_space', lambda path: FULL if full['out'] and str(path).startswith(str(out)) else ROOMY)

    class FillingStdout(ScriptedStdout):
        def readline(self, size=-1):
            line = super().readline(size)
            if line.startswith('fill'):
                full['out'] = True
            return line

    popen = ScriptedPopen([])
    popen.stdout = FillingStdout([('HIT now\n', 0), ('a\n', 2), ('fill\n', 2), ('b\n', 2)], clock=clock)
    run_scripted(tmp_path, monkeypatch, popen, fallback_folder=str(fallback), min_free_percent=1)
    primary = incident_logs(tmp_path / 'out')[0].read_text()
    moved = incident_logs(fallback)[0].read_text()
    assert 'HIT now' in primary and 'a\n' in primary
    assert 'capture moved here from' in moved and 'b\n' in moved and 'End of capture' in moved


def test_fast_capture_never_runs_past_the_floor(tmp_path, monkeypatch):
    # A 1 MB filesystem with a 10% floor and 300 KB free, written far faster than the once-a-second fsync.
    journal_records(monkeypatch)
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    size, already_used = 1_000_000, 700_000

    def used():
        return already_used + sum(p.stat().st_size for p in out.rglob('*') if p.is_file())

    monkeypatch.setattr(fw, '_free_space', lambda path: (size - used(), size) if str(path).startswith(str(out)) else ROOMY)
    lines = [('HIT now\n', 0)] + [('post %04d %s\n' % (i, 'y' * 60), 0) for i in range(6000)]
    run_scripted(tmp_path, monkeypatch, ScriptedPopen(lines, clock=clock),
                 fallback_folder=str(fallback), min_free_percent=10, capture_line_count_max=20000)
    assert size - used() >= size // 10  # the floor held
    text = ''.join(p.read_text() for p in incident_logs(out) + incident_logs(fallback))
    assert 'because free space there fell below the floor' in text
    # every line once: a move for space carries nothing over
    assert sorted(re.findall(r'post (\d+)', text)) == ['%04d' % i for i in range(6000)]


def fast_capture(tmp_path, monkeypatch, lines, out_room, fallback_room=None, **kw):
    """Run lines (the first one matching) with no time passing, on a 10 MB output disk with out_room
    above a 10% floor, and a fallback disk with fallback_room (None: plenty). Returns both disks."""
    journal_records(monkeypatch)
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    out.mkdir()
    fallback.mkdir()
    disks = {}
    for name, root, room in (('out', out, out_room), ('fallback', fallback, fallback_room)):
        disk = FakeDisk(monkeypatch, root, 10_000_000)
        disk.set_headroom(room if room is not None else 5_000_000, 0.10)
        disks[name] = disk
    monkeypatch.setattr(fw, '_free_space', lambda path: (disks['out'] if str(path).startswith(str(out)) else disks['fallback'])(path))
    opts = dict(fallback_folder=str(fallback), min_free_percent=10, capture_line_count_max=50000)
    opts.update(kw)
    run_scripted(tmp_path, monkeypatch, ScriptedPopen([(line, 0) for line in lines], clock=clock), **opts)
    return disks


def test_non_ascii_capture_never_runs_past_the_floor(tmp_path, monkeypatch):
    # U+FFFD stands in for every undecodable byte and takes three bytes on disk
    lines = ['HIT now\n'] + ['post %04d %s\n' % (i, '\ufffd' * 40) for i in range(3000)]
    disks = fast_capture(tmp_path, monkeypatch, lines, out_room=200_000)
    assert disks['out'].headroom_at(0.10) >= 0
    text = ''.join(p.read_text() for p in incident_logs(tmp_path / 'out') + incident_logs(tmp_path / 'fallback'))
    assert sorted(re.findall(r'post (\d+)', text)) == ['%04d' % i for i in range(3000)]


def test_move_for_space_respects_the_fallback_floor_and_duplicates_nothing(tmp_path, monkeypatch):
    # the buffer dump alone is bigger than the output's room, and the fallback has room for only part of the rest
    lines = (['HIT first\n'] + ['pre %04d %s\n' % (i, 'x' * 90) for i in range(3000)]
             + ['HIT now\n'] + ['post %04d %s\n' % (i, 'y' * 90) for i in range(3000)])
    disks = fast_capture(tmp_path, monkeypatch, lines, out_room=150_000, fallback_room=200_000)
    assert disks['out'].headroom_at(0.10) >= 0
    assert disks['fallback'].headroom_at(0.10) >= 0
    text = ''.join(p.read_text() for p in incident_logs(tmp_path / 'out') + incident_logs(tmp_path / 'fallback'))
    for kind in ('pre', 'post'):
        found = re.findall(kind + r' (\d+)', text)
        assert len(found) == len(set(found)), kind + ' lines written twice'


def test_a_line_bigger_than_the_room_moves_the_capture_first(tmp_path, monkeypatch):
    lines = ['HIT now\n', 'small\n', 'huge ' + 'z' * 300_000 + '\n', 'after\n']
    disks = fast_capture(tmp_path, monkeypatch, lines, out_room=150_000)
    assert disks['out'].headroom_at(0.10) >= 0
    moved = incident_logs(tmp_path / 'fallback')[0].read_text()
    assert 'z' * 300_000 in moved and 'after' in moved


def test_capture_with_no_room_anywhere_is_not_saved(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    dispatcher = recording_dispatcher(monkeypatch)
    monkeypatch.setattr(fw, '_free_space', lambda path: FULL)
    out = capture(tmp_path, 'HIT now\nafter\n', min_free_percent=1)
    assert incident_logs(out) == []
    assert dispatcher.jobs[0]['path'] is None


# --- memory ---

def random_text(n):
    import base64
    return base64.b64encode(os.urandom(n * 3 // 4)).decode()[:n]


def test_buffer_drops_the_oldest_lines_past_its_memory_limit(tmp_path):
    # incompressible lines: 3 MB of them do not fit in 1 MiB
    lines = ['old-%04d %s\n' % (i, random_text(1000)) for i in range(3000)]
    # '!' never occurs in base64, so only the last line can match
    out = capture(tmp_path, ''.join(lines) + 'HIT!\n', pattern='HIT!', buffer_max_mb=1)
    (cap,) = incident_logs(out)
    text = cap.read_text()
    assert 'Older cached in-memory lines were dropped to stay within buffer_max_mb 1 MiB' in text
    assert 'old-0000 ' not in text
    assert 'old-2999 ' in text and 'Matched line:    HIT!' in text
    kept = len(re.findall(r'^old-\d{4} ', text, re.M))
    assert 1000 < kept < 1600  # base64 compresses to about 3/4, so 1 MiB holds about 1.3 MB of these


def test_buffer_keeps_the_newest_line_even_when_it_alone_is_too_big(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'MAX_LINE_CHARS', 4 * 1024 * 1024)  # read it as one line
    big = random_text(2 * 1024 * 1024)
    out = capture(tmp_path, 'old line\n' * 2000 + 'HIT! ' + big + '\n', pattern='HIT!', buffer_max_mb=1)
    (cap,) = incident_logs(out)
    text = cap.read_text()
    assert big in text


def test_context_buffer_memory_stays_bounded():
    buffer = fw.ContextBuffer(10 ** 9, 1024 * 1024)
    for seq in range(20000):
        buffer.append(float(seq), seq, 'line %d %s\n' % (seq, random_text(200)))
        assert buffer.memory <= 1024 * 1024 + fw.BUFFER_BLOCK_BYTES * 3
    newest = list(buffer.entries(0))
    assert newest[-1][1] == 19999
    assert [seq for _t, seq, _l in newest] == list(range(newest[0][1], 20000))
    assert buffer.dropped_until is not None


def test_context_buffer_ages_out_by_time_and_skips_without_decompressing(monkeypatch):
    buffer = fw.ContextBuffer(100, 64 * 1024 * 1024)
    for seq in range(5000):
        buffer.append(float(seq) / 10, seq, 'line %05d %s\n' % (seq, 'x' * 100))
    assert buffer.blocks
    entries = list(buffer.entries(400.0))
    assert entries[0][1] == 4000 and entries[-1][1] == 4999
    assert all(line.startswith('line %05d ' % seq) for _t, seq, line in entries)
    assert [seq for _t, seq, _l in buffer.entries(400.0, skip=[(4000, 4900)])][0] == 4901
    assert buffer.seq_span(400.0) == (4000, 4999)
    assert buffer.seq_span(500.0) is None
    assert fw.ContextBuffer(100, 1024).seq_span(0) is None
    real = fw.zlib.decompress
    calls = []
    monkeypatch.setattr(fw.zlib, 'decompress', lambda data: calls.append(1) or real(data))
    list(buffer.entries(0, skip=[(0, 4990)]))
    assert len(calls) <= 1  # only a block that is not wholly skipped
    buffer.seq_span(0)
    assert len(calls) <= 1
    # 500 s on, everything but the newest line has aged out
    buffer.append(1000.0, 5000, 'newest\n')
    assert [seq for _t, seq, _l in buffer.entries(0)] == [5000]

def test_overlong_lines_are_read_in_pieces(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'MAX_LINE_CHARS', 16)
    out = capture(tmp_path, 'noise\nHIT ' + 'z' * 40 + '\nafter\n')
    text = incident_logs(out)[0].read_text()
    assert 'z' * 40 in text.replace('\n', '').replace('\x1b[0m', '').replace('\x1b[91m-> ', '')
    assert 'after' in text


def test_reader_that_keeps_failing_ends_the_run(tmp_path, monkeypatch, capsys):
    popen = ScriptedPopen(['HIT now\n'] + [OSError('pipe closed')] * fw.MAX_READ_ERRORS + ['never read\n'])
    out = run_scripted(tmp_path, monkeypatch, popen)
    printed = capsys.readouterr().out
    assert 'Giving up after %d read errors in a row.' % fw.MAX_READ_ERRORS in printed
    assert popen.terminated
    text = incident_logs(out)[0].read_text()
    assert 'End of capture' in text and 'never read' not in text


def test_compression_at_startup_already_keeps_to_the_floor(tmp_path, monkeypatch, capsys):
    out = tmp_path / 'out'
    months(out, **{'2020-01': 1000})
    asked = []

    class Refusing(fw.DiskGuard):
        def can_spend(self, folder, nbytes):
            asked.append(folder)
            return False

    # synchronous, so the order is certain; the background thread starts at the same point in __init__
    fw.Log_Compressor(str(out), 1, 0, guard=Refusing(10))
    assert asked == [str(out)]
    assert (out / '2020-01').is_dir()


def test_purge_is_sized_for_what_the_caller_needs(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    monkeypatch.setattr(fw.os, 'sync', lambda: None)
    out = tmp_path / 'out'
    months(out, **{'2019-01': 30_000, '2019-02': 2_000_000, '2019-03': 2_000_000})
    disk = FakeDisk(monkeypatch, out, 100_000_000)
    disk.set_headroom(50_000, 0.10)
    room = guard_for(out).headroom(str(out / '2026-10' / 'hit.log'), need=200_000)
    assert room - 200_000 >= fw.MIN_HEADROOM
    assert sorted(p.name for p in out.iterdir()) == ['2019-03']


def test_a_purge_that_cannot_help_is_not_retried_for_every_capture(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    clock = Clock(time.time())
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 10_000})
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-1_000_000, 0.10)
    guard = guard_for(out)
    walks = []
    compressor = guard.compressors[str(out)]
    real = compressor.purgeableMonths
    monkeypatch.setattr(compressor, 'purgeableMonths', lambda keep: walks.append(1) or real(keep))
    path = str(out / '2026-10' / 'hit.log')
    for _ in range(5):
        assert guard.headroom(path) < fw.MIN_HEADROOM
    assert walks == [1]
    clock.t += fw.PURGE_RETRY
    guard.headroom(path)
    assert walks == [1, 1]
    assert (out / '2020-01').is_dir()


def test_purge_ignores_entries_of_the_wrong_kind(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2019-01': 100_000})
    (out / '2018-12').write_bytes(os.urandom(100_000))       # a file named like a month folder
    (out / '2018-11.tar.xz').mkdir()                          # a folder named like an archive
    for name in ('2018-12', '2018-11.tar.xz'):
        os.utime(str(out / name), (TWO_DAYS_AGO, TWO_DAYS_AGO))
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    guard_for(out).headroom(str(out / '2026-10' / 'hit.log'))
    assert sorted(p.name for p in out.iterdir()) == ['2018-11.tar.xz', '2018-12']


def test_a_file_still_being_written_protects_its_month(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2019-01': 100_000, '2019-02': 100_000})
    with open(str(out / '2019-01' / 'x.log'), 'ab') as handle:  # another firewatcher appending
        handle.write(b'more')
    os.utime(str(out / '2019-01'), (TWO_DAYS_AGO, TWO_DAYS_AGO))  # the folder itself looks old
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    guard_for(out).headroom(str(out / '2026-10' / 'hit.log'))
    assert sorted(p.name for p in out.iterdir()) == ['2019-01']


def test_a_month_with_another_filesystem_mounted_in_it_is_never_deleted(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2019-01': 100_000, '2019-02': 100_000})
    real = fw._entry_stats

    def mounted(path):
        size, newest, devices = real(path)
        return (size, newest, devices | {-1}) if str(path).endswith('2019-01') else (size, newest, devices)

    monkeypatch.setattr(fw, '_entry_stats', mounted)
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    guard_for(out).headroom(str(out / '2026-10' / 'hit.log'))
    assert sorted(p.name for p in out.iterdir()) == ['2019-01']
    # nor by the age-based deletion
    (out / '2019-03').mkdir()
    fw.Log_Compressor(str(out), 0, 1)
    assert (out / '2019-01').is_dir()


def test_age_based_deletion_goes_on_past_a_month_it_cannot_delete(tmp_path, monkeypatch, capsys):
    out = tmp_path / 'out'
    months(out, **{'2018-01': 1000, '2018-02': 1000})
    real_rmtree = fw.shutil.rmtree

    def rmtree(path, *args, **kwargs):
        if str(path).endswith('2018-01'):
            raise OSError(16, 'Device or resource busy')
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(fw.shutil, 'rmtree', rmtree)
    fw.Log_Compressor(str(out), 0, 1)
    assert sorted(p.name for p in out.iterdir()) == ['2018-01']
    assert 'Deleting 2018-01 failed' in capsys.readouterr().out


def test_writes_check_before_leaving_less_than_the_margin(tmp_path):
    rooms = {'a': 70_000, 'b': 10 ** 9}
    cap = fw.CaptureFile([str(tmp_path / 'a.log'), str(tmp_path / 'b.log')], 1.0,
                         headroom=lambda path, need=0: rooms[os.path.basename(path)[0]])
    cap.write('x' * 10_000 + '\n')
    cap.close()
    assert (tmp_path / 'a.log').read_text() == ''
    assert 'x' * 10_000 in (tmp_path / 'b.log').read_text()


def test_a_hard_linked_month_counts_as_freeing_nothing(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    out = tmp_path / 'out'
    months(out, **{'2019-01': 200_000})
    os.link(str(out / '2019-01' / 'x.log'), str(tmp_path / 'backup.log'))  # a backup elsewhere on the disk
    os.utime(str(out / '2019-01'), (TWO_DAYS_AGO, TWO_DAYS_AGO))
    disk = FakeDisk(monkeypatch, tmp_path, 10_000_000)
    disk.set_headroom(-10_000, 0.10)
    assert guard_for(out).headroom(str(out / '2026-10' / 'hit.log')) < fw.MIN_HEADROOM
    assert (out / '2019-01').is_dir()  # deleting it could not have made room, so it is kept


def test_purge_interval_is_a_setting(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    monkeypatch.setattr(fw.os, 'sync', lambda: None)
    clock = Clock(time.time())
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    months(out, **{'2020-01': 200_000, '2020-02': 200_000})
    disk = FakeDisk(monkeypatch, out, 10_000_000)
    guard = fw.DiskGuard(10, [fw.Log_Compressor(str(out), 0, 0)], purge_interval=120)
    path = str(out / '2026-10' / 'hit.log')
    disk.set_headroom(-10_000, 0.10)
    guard.headroom(path)
    assert sorted(p.name for p in out.iterdir()) == ['2020-02']
    disk.set_headroom(-10_000, 0.10)
    clock.t += 60
    guard.headroom(path)
    assert (out / '2020-02').is_dir()  # within the 120 s
    clock.t += 61
    guard.headroom(path)
    assert not (out / '2020-02').exists()


# --- context already in an earlier capture ---

def numbered(text, kind):
    return re.findall(r'%s-(\d+)' % kind, text)


def test_storm_capture_leaves_out_what_the_previous_one_holds(tmp_path):
    # the line cap ends the first capture; the next match opens a second within the window
    body = ''.join('ctx-%03d\n' % i for i in range(50)) + 'HIT 1\n' + ''.join('a-%03d\n' % i for i in range(20)) + 'HIT 2\n' + 'b-000\n'
    out = capture(tmp_path, body, capture_line_count_max=10)
    first, second = incident_logs(out)
    second_text = second.read_text()
    # 50 context lines, HIT 1, and a-000 to a-010 (the line that crossed the cap)
    assert '62 lines of this window are left out: they are in %s' % first in second_text
    assert numbered(second_text, 'ctx') == [] and numbered(second_text, 'a') == ['011', '012', '013', '014', '015', '016', '017', '018', '019']
    every = re.findall(r'\b((?:ctx|a)-\d+)', first.read_text() + second_text)
    assert len(every) == len(set(every)) == 70  # each line once, none lost


def test_lines_between_captures_are_kept(tmp_path, monkeypatch):
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    popen = ScriptedPopen([('HIT 1\n', 0), ('in-first\n', 1), ('gap-1\n', 70), ('gap-2\n', 1), ('HIT 2\n', 1)], clock=clock)
    out = run_scripted(tmp_path, monkeypatch, popen, capture_time=60)
    first, second = (p.read_text() for p in incident_logs(out))
    assert 'in-first' in first
    # the first capture's lines are older than the second's window, so nothing is left out
    assert 'left out' not in second
    assert 'gap-1' in second and 'gap-2' in second


def test_a_capture_leaves_out_lines_from_several_earlier_ones(tmp_path):
    body = ('one\n' + 'HIT 1\n' + ''.join('a-%d\n' % i for i in range(4))
            + 'two\n' + 'HIT 2\n' + ''.join('b-%d\n' % i for i in range(4))
            + 'three\n' + 'HIT 3\n')
    out = capture(tmp_path, body, capture_line_count_max=2)
    caps = incident_logs(out)
    third = caps[-1].read_text()
    assert 'left out: they are in %s' % caps[0] in third
    assert 'left out: they are in %s' % caps[1] in third
    joined = ''.join(p.read_text() for p in caps)
    for line in ('one', 'two', 'three', 'a-0', 'a-3', 'b-0', 'b-3'):
        assert len(re.findall(r'^%s$' % line, joined, re.M)) == 1, line


def test_lines_of_an_unsaved_capture_are_not_left_out(tmp_path, monkeypatch):
    journal_records(monkeypatch)
    blocked = tmp_path / 'blocked'
    blocked.write_text('a file')
    real_open_capture = fw._open_capture
    calls = []

    def first_one_unsaved(output_folder, *args, **kwargs):
        calls.append(1)
        folder = str(blocked / 'out') if len(calls) == 1 else output_folder
        return real_open_capture(folder, *args, **kwargs)

    monkeypatch.setattr(fw, '_open_capture', first_one_unsaved)
    body = 'ctx\n' + 'HIT 1\n' + ''.join('a-%d\n' % i for i in range(5)) + 'HIT 2\n'
    out = capture(tmp_path, body, capture_line_count_max=3)
    (only,) = incident_logs(out)
    text = only.read_text()
    assert 'left out' not in text
    assert 'ctx' in text and 'a-0' in text


# --- SIGHUP pattern reload ---

class HangupBefore(ScriptedStdout):
    """Sends the reload request just before returning a line that starts with `marker`."""

    def __init__(self, events, marker):
        super().__init__(events)
        self.marker = marker

    def readline(self, size=-1):
        line = super().readline(size)
        if isinstance(line, str) and line.startswith(self.marker):
            fw._request_reload(None, None)
        return line


def _hangup_capture(tmp_path, monkeypatch, lines, marker, **kw):
    pat = tmp_path / 'p.txt'
    pat.write_text('OLD\n')
    popen = ScriptedPopen([])
    popen.stdout = HangupBefore(lines, marker)
    patch_popen(monkeypatch, popen)
    out = tmp_path / 'out'
    fw.capture_messages(
        ['unused'], fw.load_patterns([str(pat)]),
        capture_time=60, output_folder=str(out),
        compress_after_months=0, delete_after_months=0, **kw)
    return out


def test_sighup_reload_matches_the_next_line_with_the_new_patterns(tmp_path, monkeypatch, capsys):
    new = tmp_path / 'new.txt'
    new.write_text('NEW\n')
    always = tmp_path / 'always.txt'
    always.write_text('NEW\n')
    out = _hangup_capture(tmp_path, monkeypatch, ['OLD before\n', 'NEW after\n', 'OLD again\n'], 'NEW',
                          reload_patterns=lambda: fw._load_pattern_sets([str(new)], [str(always)]))
    printed = capsys.readouterr().out
    assert 'reloaded patterns: 0 regex, 1 plain, always_notify too' in printed
    text = incident_logs(out)[0].read_text()
    assert '-> NEW after' in text
    # OLD was dropped by the reload, so a later OLD line is context, not a match
    assert '-> OLD again' not in text and 'OLD again' in text
    assert not fw._reload_requested


def test_sighup_reload_failure_keeps_the_old_patterns(tmp_path, monkeypatch, capsys):
    out = _hangup_capture(tmp_path, monkeypatch, ['quiet\n', 'OLD still watched\n'], 'quiet',
                          reload_patterns=lambda: fw._load_pattern_sets([str(tmp_path / 'gone.txt')], None))
    printed = capsys.readouterr().out
    assert 'reloading patterns failed, keeping the old ones: no usable patterns in' in printed
    assert 'OLD still watched' in incident_logs(out)[0].read_text()


def test_sighup_without_a_reloader_changes_nothing(tmp_path, monkeypatch, capsys):
    out = _hangup_capture(tmp_path, monkeypatch, ['quiet\n', 'OLD still watched\n'], 'quiet')
    printed = capsys.readouterr().out
    assert 'reloaded patterns' not in printed and 'reloading patterns' not in printed
    assert 'OLD still watched' in incident_logs(out)[0].read_text()
    assert not fw._reload_requested


def test_load_pattern_sets_drops_an_empty_always_notify_list(tmp_path, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    empty = tmp_path / 'always.txt'
    empty.write_text('# nothing yet\n')
    patterns, always = fw._load_pattern_sets([str(tmp_path)], [str(empty)])
    # the folder holds both files; the comment-only one adds nothing
    assert patterns == {'fnmatch': {'*HIT*'}}
    assert always is None
    assert 'no usable always_notify patterns' in capsys.readouterr().out


def test_lines_of_a_capture_that_moved_are_written_again(tmp_path, monkeypatch):
    # Its lines are split between two files, so the next capture writes them again rather than point at one.
    journal_records(monkeypatch)
    clock = Clock(1_000_000.0)
    monkeypatch.setattr(fw.time, 'time', clock.time)
    out = tmp_path / 'out'
    fallback = tmp_path / 'fallback'
    full = {'out': False}
    monkeypatch.setattr(fw, '_free_space', lambda path: FULL if full['out'] and str(path).startswith(str(out)) else ROOMY)

    class FillingStdout(ScriptedStdout):
        def readline(self, size=-1):
            line = super().readline(size)
            if line.startswith('fill'):
                full['out'] = True
            return line

    popen = ScriptedPopen([])
    popen.stdout = FillingStdout([('ctx\n', 0), ('HIT 1\n', 0), ('a-0\n', 0), ('fill\n', 0), ('a-1\n', 2),
                                  ('a-2\n', 0), ('a-3\n', 0), ('HIT 2\n', 0)], clock=clock)
    run_scripted(tmp_path, monkeypatch, popen, fallback_folder=str(fallback), min_free_percent=1, capture_line_count_max=3)
    assert 'a-0' in incident_logs(out)[0].read_text()
    second = [p.read_text() for p in incident_logs(fallback) if 'Matched line:    HIT 2' in p.read_text()][0]
    assert 'left out' not in second
    assert 'ctx' in second and 'a-0' in second


def test_capture_file_moved_only_after_it_held_a_file(tmp_path):
    blocked = tmp_path / 'blocked'
    blocked.write_text('a file where a folder should be')
    capture = fw.CaptureFile([str(blocked / 'x.log'), str(tmp_path / 'ok' / 'x.log')], 1.0)
    assert capture.saved and not capture.moved
    capture.write('line\n')
    capture._move_on(OSError('lost the server'))
    assert capture.moved
    capture.close()


def test_capture_file_bounds_text_kept_for_a_move(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'UNSYNCED_MAX', 1000)
    fsyncs = []
    real_fsync = fw.os.fsync
    monkeypatch.setattr(fw.os, 'fsync', lambda fd: fsyncs.append(fd) or real_fsync(fd))
    capture = fw.CaptureFile(str(tmp_path / 'x.log'), 1.0)
    for i in range(100):
        capture.write('line %03d %s\n' % (i, 'x' * 90))
        assert capture.unsynced_size <= 1000 and sum(map(len, capture.unsynced)) == capture.unsynced_size
    assert len(fsyncs) >= 9
    capture.close()
    assert (tmp_path / 'x.log').read_text().count('line ') == 100


def test_storm_captures_do_not_decompress_what_earlier_ones_hold(tmp_path, monkeypatch):
    real = fw.zlib.decompress
    calls = []
    monkeypatch.setattr(fw.zlib, 'decompress', lambda data: calls.append(1) or real(data))
    body = ''.join('HIT %05d %s\n' % (i, random_text(100)) for i in range(6000))
    out = capture(tmp_path, body, capture_line_count_max=50)
    captures = incident_logs(out)
    assert len(captures) > 100
    # at most the block still open to new lines, per capture
    assert len(calls) <= 2 * len(captures)
    every = re.findall(r'HIT (\d{5})', ''.join(p.read_text().split('Logs since', 1)[1] for p in captures))
    assert len(every) == len(set(every)) == 6000


def test_a_carriage_return_does_not_split_a_line(tmp_path):
    out = capture(tmp_path, 'x\r2000-01-01T00:00:00Z HIT that looks like its own entry\nafter\n')
    data = incident_logs(out)[0].read_bytes()
    assert b'Matched line:    x\r2000-01-01T00:00:00Z HIT' in data


def test_context_buffer_compresses_many_short_lines_early():
    buffer = fw.ContextBuffer(10 ** 9, 1024 * 1024)
    for seq in range(200000):
        buffer.append(float(seq), seq, '%d\n' % (seq % 10))
        assert buffer.lines_memory < fw.BUFFER_OPEN_MEMORY + 200
    assert buffer.memory <= 1024 * 1024 + fw.BUFFER_OPEN_MEMORY + 64 * 1024
