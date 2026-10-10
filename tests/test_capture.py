import collections
import datetime
import threading
import time

import firewatcher as fw
from conftest import Clock, capture, incident_logs, ScriptedPopen, patch_popen

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
    assert defaults['output_folder'].default == fw.DEFAULT_OUTPUT_FOLDER
    assert fw.DEFAULT_OUTPUT_FOLDER == '/var/log/captured_messages/'


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


def test_capture_skips_excess_pre_match_buffer(tmp_path):
    body = ''.join(f'pre-{i}\n' for i in range(10)) + 'HIT\n'
    out = capture(tmp_path, body, capture_line_count_max=3)
    text = incident_logs(out)[0].read_text()
    assert 'Older cached in-memory lines were dropped' in text
    assert 'pre-0' not in text
    assert 'pre-8' in text
    assert 'pre-9' in text
    assert 'HIT' in text


def test_capture_progress_every_10000_lines(tmp_path, capsys):
    body = ('x\n' * 9999) + 'HIT\n'
    capture(tmp_path, body)
    assert 'Processed 10000 lines.' in capsys.readouterr().out


def test_capture_compresses_on_unmatched_traffic(tmp_path, monkeypatch):
    calls = []
    orig = fw.Log_Compressor.compressLogs

    def spy(self):
        calls.append(1)
        return orig(self)

    monkeypatch.setattr(fw.Log_Compressor, 'compressLogs', spy)
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


def test_pre_match_buffer_is_capped_at_capture_line_count_max(tmp_path, monkeypatch):
    class RecordingDeque(collections.deque):
        peak = 0

        def append(self, item):
            super().append(item)
            RecordingDeque.peak = max(RecordingDeque.peak, len(self))

    monkeypatch.setattr(fw, 'deque', RecordingDeque)
    capture(tmp_path, ''.join(f'noise-{i}\n' for i in range(50)), capture_line_count_max=5)
    assert 0 < RecordingDeque.peak <= 5


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

            def recording_readline():
                threads.append(threading.current_thread())
                return readline()

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

        def readline(self):
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
