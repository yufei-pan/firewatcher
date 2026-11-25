import contextlib
import os
import select
import sys
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import firewatcher as fw  # noqa: E402

# the real default, before the fixture below points it into each test's directory
REAL_OUTPUT_FOLDER = fw.DEFAULT_OUTPUT_FOLDER


@pytest.fixture(autouse=True)
def isolated_firewatcher_config(tmp_path, monkeypatch):
    """Keep tests off the host config, output and pattern folders, journal position, any secret environment variables, and each other's SIGHUP."""
    monkeypatch.setattr(fw, 'DEFAULT_CONFIG_PATH', str(tmp_path / 'firewatcher.conf'))
    monkeypatch.setattr(fw, 'DEFAULT_OUTPUT_FOLDER', str(tmp_path / 'captured_messages') + os.sep)
    monkeypatch.setattr(fw, 'DEFAULT_FALLBACK_FOLDER', str(tmp_path / 'fallback') + os.sep)
    monkeypatch.setattr(fw, 'DEFAULT_PATTERNS_DIR', str(tmp_path / 'patterns.d'))
    monkeypatch.setattr(fw, 'DEFAULT_POSITION_FILE', str(tmp_path / 'journal.position'))
    # no journald unless a test says so, whatever runs on the machine running the tests
    monkeypatch.setattr(fw, 'JOURNALD_SOCKET', str(tmp_path / 'journald.socket'))
    monkeypatch.setattr(fw, 'JOURNAL_DIRS', (str(tmp_path / 'journal'),))
    monkeypatch.delenv(fw.LLM_API_KEY_ENV, raising=False)
    monkeypatch.delenv(fw.NTFY_TOKEN_ENV, raising=False)
    monkeypatch.delenv(fw.EVENTS_TOKEN_ENV, raising=False)
    # a SIGHUP flag left set by one test must not reload patterns in the next, nor a stop flag stop it
    monkeypatch.setattr(fw, '_reload_requested', False)
    monkeypatch.setattr(fw, '_stop_requested', False)


@pytest.fixture(autouse=True)
def scripted_streams_through_pipes(monkeypatch):
    """firewatcher's waits for a process's output see a Feed's pipe filled as they wait on it; the feeds a test left
    open are closed after it."""
    monkeypatch.setattr(fw, 'select', types.SimpleNamespace(select=_select))
    yield
    for feed in list(_FEEDS.values()):
        feed.close()


def parse_cli(argv):
    return fw.build_parser().parse_args(argv)


def ok_systemctl(*cmd):
    class R:
        returncode = 0
    return R()


def systemctl_recorder(calls, returncode=0):
    def fake(*cmd):
        calls.append(cmd)
        class R:
            pass
        R.returncode = returncode if not callable(returncode) else returncode(cmd)
        return R()
    return fake


@contextlib.contextmanager
def file_size_limit(size):
    """A disk that fills: a file that grows past size bytes gets its first size bytes, then OSError EFBIG (Python
    ignores the SIGXFSZ the kernel sends). Keep the block short: whatever the process writes meanwhile is limited too."""
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    resource.setrlimit(resource.RLIMIT_FSIZE, (size, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))


def use_journal(monkeypatch):
    """A host with journalctl on PATH and journald running."""
    monkeypatch.setattr(fw.shutil, 'which', lambda name: '/usr/bin/journalctl' if name == 'journalctl' else None)
    monkeypatch.setattr(fw, '_journald_present', lambda: True)


def write_log(tmp_path, text, name='src.log'):
    src = tmp_path / name
    if isinstance(text, bytes):
        src.write_bytes(text)
    else:
        src.write_text(text)
    return src


def capture(tmp_path, lines, pattern='HIT', regex=False, **kw):
    pat = tmp_path / ('p.regex' if regex else 'p.txt')
    pat.write_text(pattern if pattern.endswith('\n') else pattern + '\n')
    src = write_log(tmp_path, lines)
    out = tmp_path / 'out'
    patterns = fw.load_patterns([str(pat)])
    opts = dict(
        capture_time=60,
        output_folder=str(out),
        compress_after_months=0,
        delete_after_months=0,
        capture_line_count_max=10000,
    )
    opts.update(kw)
    fw.capture_messages(['cat', str(src)], patterns, **opts)
    return out


def incident_logs(out):
    # in the order they were opened: name_SECOND.log, then name_SECOND-1.log, name_SECOND-2.log, ...
    def opened(path):
        base, _, n = path.stem.rpartition('-')
        return (str(path.parent), base, int(n)) if n.isdigit() and base.count('T') else (str(path.parent), path.stem, 0)
    return sorted((p for p in out.rglob('*.log') if p.name != 'journal.log'), key=opened)


def fake_exists(syslog=False, messages=False):
    real = os.path.exists
    def exists(path):
        if path == '/var/log/syslog':
            return syslog
        if path == '/var/log/messages':
            return messages
        return real(path)
    return exists


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = float(t)

    def time(self):
        return self.t


_FEEDS = {}  # the descriptor firewatcher reads: its Feed
_real_select = select.select


class Feed(object):
    """A scripted stream behind a real pipe, which firewatcher reads as a process's output (fileno(), close()).
    script.readline() gives what comes next: text or bytes, '' or b'' at the end, or it raises. It is asked only when
    firewatcher waits on the empty pipe, on a thread of its own, so a script that sleeps or polls (a quiet source)
    leaves firewatcher's deadlines running, and the order of lines, clock moves and exceptions is the script's. What it
    raises is raised in that wait (_select)."""

    def __init__(self, script):
        self.script = script
        self.read_fd, self.write_fd = os.pipe()
        self.raised_r, self.raised_w = os.pipe()
        self.wanted = threading.Event()
        self.asked = self.ended = self.closed = False
        self.error = None
        _FEEDS[self.read_fd] = self
        threading.Thread(target=self._feed, name='test-feed', daemon=True).start()

    def fileno(self):
        return self.read_fd

    def close(self):
        if not self.closed:
            self.closed = True
            del _FEEDS[self.read_fd]
            os.close(self.read_fd)
            os.close(self.raised_r)
            # the thread closes its own ends
            self.wanted.set()

    def ask(self):
        if not (self.asked or self.ended) and not _real_select([self.read_fd], [], [], 0)[0]:
            self.asked = True
            self.wanted.set()

    def _feed(self):
        try:
            while True:
                self.wanted.wait()
                self.wanted.clear()
                if self.closed:
                    return
                try:
                    line = self.script.readline()
                    # inside the try: a line that cannot be encoded is raised in firewatcher's wait like any other error
                    data = line.encode('utf-8', 'surrogateescape') if isinstance(line, str) else line
                except BaseException as exc:
                    self.error = exc
                    self.asked = False
                    os.write(self.raised_w, b'!')
                    continue
                if self.closed:
                    return
                if not data:
                    # the end of the output; the pipe that carries what the script raises stays open until close()
                    self.ended = True
                    os.close(self.write_fd)
                    self.write_fd = None
                    continue
                # cleared before the bytes are there, so firewatcher's next wait asks again
                self.asked = False
                while data:
                    data = data[os.write(self.write_fd, data):]
        except OSError:
            pass  # firewatcher closed its end
        finally:
            if self.write_fd is not None:
                os.close(self.write_fd)
            os.close(self.raised_w)


def _select(rlist, wlist, xlist, timeout=None):
    """select.select for firewatcher: a Feed's pipe is fed as firewatcher waits on it, and what its script raised is
    raised here, in that wait."""
    feeds = [_FEEDS[fd] for fd in rlist if fd in _FEEDS]
    if not feeds:
        return _real_select(rlist, wlist, xlist, timeout)
    for feed in feeds:
        feed.ask()
    ready, written, failed = _real_select(list(rlist) + [feed.raised_r for feed in feeds], wlist, xlist, timeout)
    for feed in feeds:
        if feed.raised_r in ready:
            os.read(feed.raised_r, 1)
            error, feed.error = feed.error, None
            raise error
    return [fd for fd in ready if fd in rlist], written, failed


class ScriptedStdout:
    """stdout.readline() script: str, BaseException, or (str_or_exc, dt) to advance clock."""

    def __init__(self, events, clock=None):
        self.events = list(events)
        self.clock = clock

    def readline(self, size=-1):
        if not self.events:
            return ''
        ev = self.events.pop(0)
        if isinstance(ev, tuple):
            ev, dt = ev
            if self.clock is not None:
                self.clock.t += dt
        if isinstance(ev, BaseException):
            raise ev
        return ev

    def close(self):
        pass


class ScriptedPopen:
    def __init__(self, events, terminate_raises=False, clock=None):
        self.stdout = ScriptedStdout(events, clock=clock)
        self.terminated = False
        self.terminate_raises = terminate_raises
        self.clock = clock

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def terminate(self):
        if self.terminate_raises:
            raise OSError('already gone')
        self.terminated = True

    def kill(self):
        self.terminated = True

    def wait(self):
        return 0


def patch_popen(monkeypatch, popen):
    """Each start of a process gives popen, whose stdout script (popen.stdout as set) is read through a pipe of its own."""
    def start(*args, **kwargs):
        popen.stdout = Feed(getattr(popen.stdout, 'script', popen.stdout))
        return popen

    monkeypatch.setattr(fw.subprocess, 'Popen', start)
    return popen
