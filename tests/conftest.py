import os
import sys
import threading
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
    monkeypatch.delenv(fw.LLM_API_KEY_ENV, raising=False)
    monkeypatch.delenv(fw.NTFY_TOKEN_ENV, raising=False)
    # a SIGHUP flag left set by one test must not reload patterns in the next
    monkeypatch.setattr(fw, '_reload_requested', threading.Event())


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


def patch_popen(monkeypatch, popen):
    monkeypatch.setattr(fw.subprocess, 'Popen', lambda *a, **k: popen)
    return popen
