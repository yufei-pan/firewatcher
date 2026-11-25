"""How a stop reaches the loop: a SIGTERM or SIGINT only sets a flag, and a byte on the wakeup pipe ends the main
thread's wait for the log, whichever thread the kernel hands the signal to (1.71 and older acted on a stop another thread
took only at the next line, and a stop raised inside a busy capture's read could hang or lose a line)."""
import os
import select
import signal
import subprocess
import sys
import threading
import time

import pytest

import firewatcher as fw
from conftest import ROOT, ScriptedPopen, incident_logs, patch_popen

# firewatcher with a thread that hands the stop to the thread named by argv[2] ('another thread': to itself) once a line
# comes on stdin, so that thread takes it; or, for 'a line being handled', a stop sent while the line with LAST in it is
# handled
LAUNCH = r'''
import os, signal, sys, threading, time
sys.path.insert(0, sys.argv[1])
import firewatcher as fw
fw._journald_present = lambda: True  # as on a journald host, whatever runs on the machine running the tests
who, signum = sys.argv[2], int(sys.argv[3])
if who == 'a line being handled':
    find = fw.PatternMatcher.find
    def find_and_stop(self, line):
        if 'LAST' in line:
            os.kill(os.getpid(), signum)
            time.sleep(0.2)
        return find(self, line)
    fw.PatternMatcher.find = find_and_stop
else:
    def hand_over():
        if not sys.stdin.readline():
            return  # the test closed stdin without a word
        thread = threading.current_thread() if who == 'another thread' else next(
            t for t in threading.enumerate() if t.name == who)
        signal.pthread_kill(thread.ident, signum)
    threading.Thread(target=hand_over, name='test-hand-over', daemon=True).start()
sys.exit(fw.main(sys.argv[4:]))
'''


def start(tmp_path, who, signum, args):
    """firewatcher under LAUNCH, with a tar on PATH that takes a minute (so a compression run, and its thread, stay)."""
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir(exist_ok=True)
    tar = bin_dir / 'tar'
    tar.write_text('#!/bin/sh\necho $$ > %s\nexec sleep 60 </dev/null >/dev/null 2>&1\n' % (tmp_path / 'tar.pid'))
    tar.chmod(0o755)
    env = dict(os.environ, PYTHONUNBUFFERED='1', PATH='%s%s%s' % (bin_dir, os.pathsep, os.environ.get('PATH', '')))
    return subprocess.Popen([sys.executable, '-c', LAUNCH, str(ROOT), who, str(int(signum))] + [str(arg) for arg in args],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)


def read_until(proc, text, seconds=20):
    """firewatcher's output until it holds text."""
    seen = b''
    deadline = time.time() + seconds
    while text.encode() not in seen:
        left = deadline - time.time()
        assert left > 0 and select.select([proc.stdout], [], [], left)[0], seen.decode('utf-8', 'replace')
        block = os.read(proc.stdout.fileno(), 65536)
        assert block, 'firewatcher ended first: ' + seen.decode('utf-8', 'replace')
        seen += block
    return seen.decode('utf-8', 'replace')


def stopped(proc, seen, tmp_path, signum):
    """The rest of the output once the stop is acted on, 5 s at most (it is about 10 ms); exit 0, "Exiting." or the
    end of the run, and neither a traceback nor a read error."""
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail('a %s was not acted on within 5 s: %s' % (signal.Signals(signum).name, seen[-600:]))
    finally:
        try:
            os.kill(int((tmp_path / 'tar.pid').read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    text = seen + output.decode('utf-8', 'replace')
    assert proc.returncode == 0, text[-800:]
    assert 'Exiting.' in text and 'Traceback' not in text and 'Error reading line' not in text, text[-800:]
    return text


@pytest.mark.parametrize('capture_open', [False, True], ids=['no capture', 'capture open'])
@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT], ids=['SIGTERM', 'SIGINT'])
@pytest.mark.parametrize('who', ['MainThread', 'firewatcher-notify', 'firewatcher-compress', 'a line being handled'])
def test_a_stop_ends_the_run_at_once_whichever_thread_takes_it(tmp_path, who, signum, capture_open):
    # A log file read through tail -F, the notifier (events_url set) and a compression run (an old month, a slow tar)
    # alive, the main thread waiting for the next line: 1.71 waited for that line when another thread took the stop.
    log, out, pat, conf = tmp_path / 'app.log', tmp_path / 'out', tmp_path / 'p.txt', tmp_path / 'fw.conf'
    pat.write_text('HIT\n')
    conf.write_text('[notify]\nevents_url = http://127.0.0.1:9/e\n')
    log.write_text('one\ntwo\n' + ('HIT three\n' if capture_open else ''))
    (out / '2001-01').mkdir(parents=True)
    (out / '2001-01' / 'old.log').write_text('old\n')
    proc = start(tmp_path, who, signum, ['--config', conf, '-o', out, '-t', '300', '--fallback-folder', '',
                                         '--log-file', log, pat])
    seen = read_until(proc, 'Capturing logs' if capture_open else 'Delete logs after')
    time.sleep(0.3)  # the main thread is in its wait for the next line
    if who == 'a line being handled':
        with log.open('a') as f:
            f.write('the LAST line\n')
    else:
        proc.stdin.write(b'go\n')
        proc.stdin.flush()
    stopped(proc, seen, tmp_path, signum)
    if who == 'a line being handled' and capture_open:
        # the line being handled at the stop is finished: 1.71 dropped it and read it again after the restart
        assert 'the LAST line' in ''.join(log.read_text() for log in incident_logs(out) if log.name != 'old.log')


@pytest.mark.parametrize('signum', [signal.SIGTERM, signal.SIGINT], ids=['SIGTERM', 'SIGINT'])
def test_a_stop_ends_the_last_wait_of_a_run_that_read_its_input_to_the_end(tmp_path, signum):
    # --filter-only waits for the compressor at the end of its input; 1.71 ended there with a traceback
    log, out, pat, conf = tmp_path / 'app.log', tmp_path / 'out', tmp_path / 'p.txt', tmp_path / 'fw.conf'
    pat.write_text('HIT\n')
    conf.write_text('')
    log.write_text('one\nHIT two\n')
    (out / '2001-01').mkdir(parents=True)
    (out / '2001-01' / 'old.log').write_text('old\n')
    proc = start(tmp_path, 'MainThread', signum, ['--config', conf, '-o', out, '--fallback-folder', '', '--filter-only',
                                                  '--log-file', log, pat])
    seen = read_until(proc, 'End of capture')
    deadline = time.time() + 20
    while not (tmp_path / 'tar.pid').exists() and time.time() < deadline:
        time.sleep(0.02)
    time.sleep(0.2)
    proc.send_signal(signum)
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail('the stop did not end the wait for the compressor within 5 s')
    finally:
        try:
            os.kill(int((tmp_path / 'tar.pid').read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    text = seen + output.decode('utf-8', 'replace')
    assert proc.returncode == 0 and 'Process ended.' in text and 'Traceback' not in text, text[-800:]


# --- the wait itself ---

def _wakeup_write_end():
    """The descriptor Python writes a handled signal's number to (inside fw._stops_wake_reads())."""
    fd = signal.set_wakeup_fd(-1)
    signal.set_wakeup_fd(fd)
    return fd


@pytest.fixture
def pipe():
    """A pipe holding the bytes given, its writer left open (or closed with end=True): its read end. With late, those
    bytes come 5 s later, so a wait that a stop should have ended fails the test instead of hanging it."""
    made, timers = [], []

    def make(data=b'', end=False, late=None):
        read_end, write_end = os.pipe()
        os.write(write_end, data)
        made.append(write_end)
        if end:
            os.close(made.pop())
        elif late:
            timers.append(threading.Timer(5, os.write, (write_end, late)))
            timers[-1].start()
        reader = os.fdopen(read_end, 'rb', buffering=0)
        made.append(reader)
        return reader

    yield make
    for timer in timers:
        timer.cancel()
        timer.join()
    for each in made:
        if isinstance(each, int):
            os.close(each)
        else:
            each.close()


def test_a_stop_byte_on_the_wakeup_pipe_ends_the_wait_before_its_handler_runs(pipe):
    # the byte is there before the handler has run (another thread took the signal); a SIGHUP's byte is not a stop
    with fw._stops_wake_reads():
        os.write(_wakeup_write_end(), bytes([signal.SIGHUP]))
        assert fw._stoppable(pipe(b'a line\n')).readline() == b'a line\n'
        os.write(_wakeup_write_end(), bytes([signal.SIGHUP, signal.SIGTERM]))
        with pytest.raises(KeyboardInterrupt):
            fw._stoppable(pipe(late=b'not stopped\n')).readline()
        assert not fw._stop_requested


def test_a_stop_that_comes_with_the_end_of_the_output_wins_over_that_end(monkeypatch, pipe):
    # A unit's stop signals journalctl too: its output can end in the same instant, and the stop's byte arrive just
    # after the wait saw that end (the select below). The end then reads as the stop, not as journalctl's failure.
    real = fw.select.select

    def end_first(rlist, wlist, xlist, timeout=None):
        ready = real(rlist[:1], wlist, xlist, timeout)
        os.write(_wakeup_write_end(), bytes([signal.SIGINT]))
        return ready

    with fw._stops_wake_reads():
        monkeypatch.setattr(fw.select, 'select', end_first)
        with pytest.raises(KeyboardInterrupt):
            fw._stoppable(pipe(end=True)).read()
        monkeypatch.setattr(fw.select, 'select', real)
        # with no stop, the end is the end
        assert fw._stoppable(pipe(end=True)).read() == b''


def test_the_scope_puts_back_the_handlers_and_the_wakeup_descriptor():
    before = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    kept = signal.set_wakeup_fd(-1)
    signal.set_wakeup_fd(kept)
    with fw._stops_wake_reads():
        assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == (fw._request_stop, fw._request_stop)
        assert fw._wakeup_fd is not None and _wakeup_write_end() != kept
    assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == before
    assert fw._wakeup_fd is None and signal.set_wakeup_fd(kept) == kept


def test_request_stop_only_notes_the_stop_and_a_second_takes_the_default(pipe):
    previous = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGTERM, fw._request_stop)
        fw._request_stop(signal.SIGTERM, None)  # raises nothing: the wait for the log raises it
        assert fw._stop_requested and signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        with pytest.raises(KeyboardInterrupt):
            fw._stoppable(pipe(b'a line\n')).readline()
    finally:
        signal.signal(signal.SIGTERM, previous)


def test_an_exception_while_the_source_is_quiet_ends_the_run(tmp_path, monkeypatch, capsys):
    # A bug in what the wait runs at a deadline (here the open capture's sync) ends the run, as in 1.71; it must not
    # become a read error that the loop reads on after.
    monkeypatch.setattr(fw, 'CAPTURE_SYNC_INTERVAL', 0.05)
    real_sync = fw.CaptureFile.sync
    raised = []

    def sync(self, now=None):
        if now is None and not raised:  # the quiet wait's sync (a commit passes its time)
            raised.append(1)
            raise RuntimeError('a bug')
        return real_sync(self, now)

    monkeypatch.setattr(fw.CaptureFile, 'sync', sync)

    class Quiet(object):
        lines = ['HIT now\n', 'more\n']

        def readline(self, size=-1):
            if self.lines:
                return self.lines.pop(0)
            time.sleep(0.5)
            return ''

    popen = ScriptedPopen([])
    popen.stdout = Quiet()
    patch_popen(monkeypatch, popen)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    with pytest.raises(fw._DeadlineError) as ended:
        fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                            compress_after_months=0, delete_after_months=0)
    assert isinstance(ended.value.__cause__, RuntimeError)
    assert 'Error reading line' not in capsys.readouterr().out
    assert 'End of capture' in incident_logs(tmp_path / 'out')[0].read_text()
