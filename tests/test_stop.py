"""How a stop reaches the loop: a SIGTERM or SIGINT only sets a flag, and a byte on the wakeup pipe ends the main
thread's wait for the log, whichever thread the kernel hands the signal to (1.71 and older acted on a stop another thread
took only at the next line, and a stop raised inside a busy capture's read could hang or lose a line)."""
import os
import re
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
        # The notifier and the compressor are started when firewatcher first needs them, a few milliseconds after the
        # first line; the test allows the stop 5 s, so 4 s is the longest this waits for the thread.
        end = time.time() + 4
        while True:
            thread = threading.current_thread() if who == 'another thread' else next(
                (t for t in threading.enumerate() if t.name == who), None)
            if thread is not None or time.time() > end:
                break
            time.sleep(0.01)
        if thread is None:
            print('NO THREAD NAMED %s' % who, flush=True)
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


# The stop's own line. Every end prints "Process ended. Exiting.", so the text alone proves nothing.
EXITING = re.compile(r'^Exiting\.$', re.M)


def stopped(proc, seen, tmp_path, signum):
    """The whole output once the stop is acted on, 5 s at most (it is about 10 ms): exit 0, the line "Exiting." (a stop,
    not a journalctl that ended), and no traceback and no read error."""
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()
        pytest.fail('a %s was not acted on within 5 s: %s' % (
            signal.Signals(signum).name, (seen + output.decode('utf-8', 'replace'))[-600:]))
    finally:
        try:
            os.kill(int((tmp_path / 'tar.pid').read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    text = seen + output.decode('utf-8', 'replace')
    assert proc.returncode == 0, text[-800:]
    assert EXITING.search(text) and 'journalctl ended with status' not in text, text[-800:]
    assert 'Traceback' not in text and 'Error reading line' not in text, text[-800:]
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
    # "Capturing logs to" is the capture's open; the start-up line "Capturing logs for" comes before any capture
    seen = read_until(proc, 'Capturing logs to' if capture_open else 'Delete logs after')
    time.sleep(0.3)  # the main thread is in its wait for the next line
    if who == 'a line being handled':
        with log.open('a') as f:
            f.write('the LAST line\n')
    else:
        proc.stdin.write(b'go\n')
        proc.stdin.flush()
    text = stopped(proc, seen, tmp_path, signum)
    if capture_open:
        assert 'End of capture' in text, text[-800:]
    if who == 'a line being handled' and capture_open:
        # the line being handled at the stop is finished (1.71 dropped it)
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
    assert (tmp_path / 'tar.pid').exists(), 'the compressor never started tar: ' + seen
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


def test_request_stop_only_notes_the_stop_and_a_second_of_either_kind_takes_the_default(pipe):
    previous = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    try:
        signal.signal(signal.SIGTERM, fw._request_stop)
        signal.signal(signal.SIGINT, fw._request_stop)
        fw._request_stop(signal.SIGTERM, None)  # raises nothing: the wait for the log raises it
        assert fw._stop_requested
        assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == (signal.SIG_DFL, signal.SIG_DFL)
        with pytest.raises(KeyboardInterrupt):
            fw._stoppable(pipe(b'a line\n')).readline()
        # a stop signal that is not ours (ignored when firewatcher started, or another handler) is left as it is
        signal.signal(signal.SIGTERM, fw._request_stop)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        fw._request_stop(signal.SIGTERM, None)
        assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == (signal.SIG_DFL, signal.SIG_IGN)
    finally:
        signal.signal(signal.SIGTERM, previous[0])
        signal.signal(signal.SIGINT, previous[1])


# firewatcher on a log file, with the notifier on (so a dispatcher exists), whose clean-up waits when argv[2] is 'slow', as
# when an LLM or events call is in flight at the stop (up to llm_timeout + ntfy_timeout, 70 s by default; here 30 s, far
# past the 5 s the tests allow)
CLEANUP_LAUNCH = r"""
import sys, time
sys.path.insert(0, sys.argv[1])
import firewatcher as fw
if sys.argv[2] == 'slow':
    def close(self):
        print('Waiting for the notifier', flush=True)
        time.sleep(30)
    fw.IncidentDispatcher.close = close
sys.exit(fw.main(sys.argv[3:]))
"""


def start_on_a_log_file(tmp_path, cleanup, wrapper=()):
    """CLEANUP_LAUNCH ('slow' or 'plain'), after the wrapper command if there is one, in a process group of its own (see
    end_group)."""
    log, out, pat, conf = tmp_path / 'app.log', tmp_path / 'out', tmp_path / 'p.txt', tmp_path / 'fw.conf'
    pat.write_text('HIT\n')
    conf.write_text('[notify]\nevents_url = http://127.0.0.1:9/e\n')
    log.write_text('one\ntwo\n')
    args = ['--config', conf, '-o', out, '-t', '300', '--fallback-folder', '', '--log-file', log, pat]
    return subprocess.Popen(list(wrapper) + [sys.executable, '-c', CLEANUP_LAUNCH, str(ROOT), cleanup] +
                            [str(arg) for arg in args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONUNBUFFERED='1'), start_new_session=True)


def end_group(proc):
    """SIGKILL what is left of firewatcher and the `tail -F` it started (a test that failed must not leave either: the
    tail holds the output pipe, so the test would hang at the next read of it)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass  # none left
    proc.stdout.close()
    proc.wait()


@pytest.mark.parametrize('second', [signal.SIGTERM, signal.SIGINT], ids=['then SIGTERM', 'then SIGINT'])
@pytest.mark.parametrize('first', [signal.SIGTERM, signal.SIGINT], ids=['SIGTERM', 'SIGINT'])
def test_a_second_stop_signal_of_either_kind_ends_a_clean_up_that_waits_at_once(tmp_path, first, second):
    # `systemctl stop` (SIGINT) and then a `kill` (SIGTERM) to hurry it, or the other way round: the first 1.72 build put
    # the default action back only for the signal it had got, so the other kind was absorbed until the clean-up was done
    proc = start_on_a_log_file(tmp_path, 'slow')
    try:
        seen = read_until(proc, 'Capturing logs')
        proc.send_signal(first)
        seen += read_until(proc, 'Waiting for the notifier')
        proc.send_signal(second)
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pytest.fail('a %s after a %s did not end firewatcher within 5 s: %s' % (
                signal.Signals(second).name, signal.Signals(first).name, seen[-600:]))
    finally:
        end_group(proc)
    assert proc.returncode == -second, (proc.returncode, seen + output.decode('utf-8', 'replace'))


def _stopped_with(proc, seen, signum):
    """The output once signum has ended firewatcher (exit 0, "Exiting." on its own line), 5 s at most."""
    proc.send_signal(signum)
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        pytest.fail('a %s did not end it within 5 s: %s' % (signal.Signals(signum).name, seen[-600:]))
    text = seen + output.decode('utf-8', 'replace')
    assert proc.returncode == 0 and 'Traceback' not in text and EXITING.search(text), text[-800:]


def test_a_sigint_firewatcher_was_started_ignoring_stays_ignored(tmp_path):
    # `sh -c 'firewatcher ... & wait'`: a script's background job starts with SIGINT ignored, and a Ctrl-C on the script
    # reaches it. 1.71 left that SIGINT ignored; SIGTERM still ends firewatcher.
    proc = start_on_a_log_file(tmp_path, 'plain', wrapper=['sh', '-c', 'trap "" INT; exec "$@"', 'sh'])
    try:
        seen = read_until(proc, 'Capturing logs')
        proc.send_signal(signal.SIGINT)
        time.sleep(1)  # a stop is acted on in about 10 ms (p95 14 ms), so a second is far past it
        assert proc.poll() is None, 'the ignored SIGINT ended firewatcher: ' + seen
        _stopped_with(proc, seen, signal.SIGTERM)
    finally:
        end_group(proc)


def test_a_sigterm_firewatcher_was_started_ignoring_still_stops_it(tmp_path):
    # As in 1.71. Left ignored, SIGTERM would be inherited by the `tail -F` firewatcher starts, and terminate() could not
    # end it where tail does not leave when its output closes (macOS): firewatcher then never ended.
    proc = start_on_a_log_file(tmp_path, 'plain', wrapper=['sh', '-c', 'trap "" TERM; exec "$@"', 'sh'])
    try:
        seen = read_until(proc, 'Capturing logs')
        _stopped_with(proc, seen, signal.SIGTERM)
    finally:
        end_group(proc)


def test_an_exception_while_the_source_is_quiet_ends_the_run(tmp_path, monkeypatch, capsys):
    # A bug in what the wait runs at a deadline (here the end of the open capture, when the source has been quiet for
    # capture_time) ends the run, as in 1.71; it must not become a read error that the loop reads on after. One line and
    # the capture's own end, so no commit's fsync (whose time decides whether a sync is due) is in the way.
    real_end = fw._end_capture
    raised = []

    def end_capture(*args, **kwargs):
        if not raised:  # the quiet wait's end of the capture; the one that finishes the run after it is real
            raised.append(1)
            raise RuntimeError('a bug')
        return real_end(*args, **kwargs)

    monkeypatch.setattr(fw, '_end_capture', end_capture)

    class Quiet(object):
        lines = ['HIT now\n']

        def readline(self, size=-1):
            if self.lines:
                return self.lines.pop(0)
            time.sleep(5)  # far past the 0.3 s capture time below, so the deadline ends the wait first
            return ''

    popen = ScriptedPopen([])
    popen.stdout = Quiet()
    patch_popen(monkeypatch, popen)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    with pytest.raises(fw._DeadlineError) as ended:
        fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=0.3, output_folder=str(tmp_path / 'out'),
                            compress_after_months=0, delete_after_months=0)
    assert isinstance(ended.value.__cause__, RuntimeError)
    assert 'Error reading line' not in capsys.readouterr().out
    assert 'End of capture' in incident_logs(tmp_path / 'out')[0].read_text()
