"""Restarts of firewatcher on the real journalctl, reading journals written with systemd-journal-remote through
`journalctl -D`. Skipped where either program is missing, unless FIREWATCHER_REQUIRE_JOURNALCTL is set (CI), which
makes their absence a failure. With -D, journalctl 252 and later follow the folder's newest boot."""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

import pytest

from conftest import ROOT, incident_logs

JOURNALCTL = shutil.which('journalctl')
JOURNAL_REMOTE = next((path for path in ('/lib/systemd/systemd-journal-remote', '/usr/lib/systemd/systemd-journal-remote')
                       if os.access(path, os.X_OK)), None)


@pytest.fixture
def journal(tmp_path):
    if not (JOURNALCTL and JOURNAL_REMOTE):
        missing = 'journalctl' if not JOURNALCTL else 'systemd-journal-remote'
        if os.environ.get('FIREWATCHER_REQUIRE_JOURNALCTL'):
            pytest.fail('FIREWATCHER_REQUIRE_JOURNALCTL is set but %s is not installed' % missing)
        pytest.skip('%s is not installed' % missing)
    real = Journal(tmp_path)
    try:
        yield real
    finally:
        # a few journal files of 8 MB each
        shutil.rmtree(real.folder, ignore_errors=True)


class Journal(object):
    """A journal folder, the journalctl that reads it (a wrapper adding -D, first on PATH) and firewatcher runs on it.
    Entries are (seconds after the saved entry's time T, message), or (seconds, message, boot)."""

    def __init__(self, tmp_path):
        self.folder = tmp_path / 'journal'
        self.folder.mkdir()
        bin_dir = tmp_path / 'bin'
        bin_dir.mkdir()
        wrapper = bin_dir / 'journalctl'
        wrapper.write_text('#!/bin/sh\nexec %s -D %s "$@"\n' % (JOURNALCTL, self.folder))
        wrapper.chmod(0o755)
        self.env = dict(os.environ, PATH='%s%s%s' % (bin_dir, os.pathsep, os.environ.get('PATH', '')))
        self.boot = uuid.uuid4().hex
        self.old_boot = uuid.uuid4().hex
        self.T = int(time.time()) - 60
        self.monotonic = 1000000
        self.position = tmp_path / 'journal.position'
        self.out = tmp_path / 'out'
        self.pat = tmp_path / 'p.txt'
        self.pat.write_text('HIT\n')
        self.conf = tmp_path / 'empty.conf'
        self.conf.write_text('')

    def write(self, name, *entries):
        data = b''
        for entry in entries:
            at, text = entry[:2]
            self.monotonic += 1000
            data += ('__REALTIME_TIMESTAMP=%d\n__MONOTONIC_TIMESTAMP=%d\n_BOOT_ID=%s\n_HOSTNAME=h\nSYSLOG_IDENTIFIER=app\n'
                     '_PID=7\nMESSAGE=%s\n\n' % (int((self.T + at) * 1000000) + 5, self.monotonic,
                                                 entry[2] if len(entry) > 2 else self.boot, text)).encode('utf-8')
        subprocess.run([JOURNAL_REMOTE, '--output=%s' % (self.folder / name), '-'], input=data, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def entries(self):
        """(cursor, message) of every entry, in journal order."""
        out = subprocess.run(['journalctl', '--all', '--no-pager', '--quiet', '-o', 'export'], stdout=subprocess.PIPE,
                             env=self.env, check=True).stdout
        found = []
        for line in out.split(b'\n'):
            if line.startswith(b'__CURSOR='):
                found.append([line[9:].decode(), None])
            elif line.startswith(b'MESSAGE='):
                found[-1][1] = line[8:].decode('utf-8')
        return found

    def save_at(self, message):
        """The position file a stop after that entry leaves."""
        self.position.write_text(json.dumps({'cursor': next(c for c, m in self.entries() if m == message), 'time': self.T}))

    def start(self):
        return subprocess.Popen(
            [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import firewatcher as fw; '
             'fw._journald_present = lambda: True; sys.exit(fw.main(sys.argv[2:]))', str(ROOT),
             '--config', str(self.conf), '-o', str(self.out), '-t', '300', '--fallback-folder', '',
             '--position-file', str(self.position), str(self.pat)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
            env=self.env)

    def wait_for_the_end(self, proc):
        """Until the saved position is the journal's last entry (20 s at most: the runs here take about one)."""
        last = self.entries()[-1][0]
        deadline = time.time() + 20
        while time.time() < deadline and proc.poll() is None:
            try:
                if json.loads(self.position.read_text()).get('cursor') == last:
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.05)

    def stop(self, proc):
        proc.send_signal(signal.SIGTERM)
        output = proc.communicate(timeout=20)[0]
        assert proc.returncode == 0, output
        return output

    def restart(self):
        """One run: started, until it has read the journal to its end, then stopped; its output."""
        proc = self.start()
        try:
            self.wait_for_the_end(proc)
        finally:
            output = self.stop(proc)
        return output

    def captured(self):
        """The journal lines of every capture, as written, without colour or the mark of a matching line, and the
        lines that opened them."""
        lines, openers = [], []
        for log in incident_logs(self.out):
            for line in re.sub(r'\x1b\[[0-9;]*m', '', log.read_text(encoding='utf-8')).splitlines():
                if line.startswith('Matched line:'):
                    openers.append(line.split(' h app[7]: ', 1)[1])
                elif ' h app[7]: ' in line:
                    lines.append(line[3:] if line.startswith('-> ') else line)
        return lines, openers


def messages(lines):
    return [line.split(' h app[7]: ', 1)[1] for line in lines]


def test_a_restart_finds_the_saved_entry_and_matches_every_line_after_it_once(journal):
    journal.write('system.journal', *[(-295 + 10 * k, ('HIT before %d' if k == 25 else 'pre %d') % k) for k in range(30)] +
                  [(0, 'saved')] +
                  [(1 + 0.1 * k, ('HIT while stopped %d' if k % 10 == 5 else 'post %d') % k) for k in range(300)] +
                  [(31, 'HIT non-ASCII: café → ok')])
    journal.save_at('saved')
    output = journal.restart()
    assert 'Resuming the journal after' in output and 'with 31 lines of context' in output, output
    lines, openers = journal.captured()
    assert openers == ['HIT while stopped 5']
    # the 30 entries before the saved one and its own line are the context, then each line after it once, in order
    expected = [('HIT before %d' if k == 25 else 'pre %d') % k for k in range(30)] + ['saved'] + \
        [('HIT while stopped %d' if k % 10 == 5 else 'post %d') % k for k in range(300)] + ['HIT non-ASCII: café → ok']
    assert messages(lines) == expected
    # the lines as journalctl itself prints them (journalctl 219 to 252 write the offset without its colon)
    shown = subprocess.run(['journalctl', '--all', '--no-pager', '--quiet', '-o', 'short-iso'], stdout=subprocess.PIPE,
                           env=journal.env, check=True).stdout.decode('utf-8').splitlines()
    shown = [re.sub(r'^(\S+[+-]\d\d)(\d\d) ', r'\1:\2 ', line) for line in shown]
    assert lines == shown
    # the follow: entries written while it runs are read at once, and a restart with nothing new reads nothing again
    shutil.rmtree(str(journal.out))
    proc = journal.start()
    try:
        time.sleep(1.0)
        now = time.time() - journal.T
        journal.write('system.journal', *[(now + 0.001 * k, ('HIT live %d' if k % 10 == 5 else 'live %d') % k) for k in range(40)])
        journal.wait_for_the_end(proc)
    finally:
        journal.stop(proc)
    lines, openers = journal.captured()
    # after the context of the last 300 s, read back
    assert openers == ['HIT live 5'] and len(set(lines)) == len(lines)
    assert messages(lines)[-40:] == [('HIT live %d' if k % 10 == 5 else 'live %d') % k for k in range(40)]


def test_a_restart_after_a_reboot_reads_what_the_old_boot_logged_after_the_stop(journal):
    old = journal.old_boot
    journal.write('system.journal', *[(-200 + 10 * k, 'old boot %d' % k, old) for k in range(20)] +
                  [(0, 'saved', old), (1, 'HIT during shutdown', old), (2, 'HIT unmount failed', old), (3, 'old boot last', old),
                   (20, 'new boot first'), (21, 'HIT in the new boot'), (22, 'new boot more')])
    journal.save_at('saved')
    journal.restart()
    lines, openers = journal.captured()
    assert openers == ['HIT during shutdown']
    assert messages(lines)[-7:] == ['saved', 'HIT during shutdown', 'HIT unmount failed', 'old boot last', 'new boot first',
                                    'HIT in the new boot', 'new boot more']


def test_a_restart_after_the_journal_lost_the_saved_entry_reads_by_time(journal):
    journal.write('a.journal', *[(-200 + 10 * k, ('HIT in the window %d' if k == 15 else 'a %d') % k) for k in range(20)] + [(0, 'saved')])
    journal.save_at('saved')
    journal.write('b.journal', *[(50 + k, ('HIT b %d' if k % 10 == 5 else 'b %d') % k) for k in range(40)])
    (journal.folder / 'a.journal').unlink()
    output = journal.restart()
    assert 'Cannot find the last entry read before the stop' in output, output
    lines, openers = journal.captured()
    assert openers == ['HIT b 5'] and messages(lines) == [('HIT b %d' if k % 10 == 5 else 'b %d') % k for k in range(40)]


def test_a_restart_after_the_clock_was_set_back_takes_no_later_line_as_context(journal):
    # In a long journal, journalctl --since lands after the saved entry when the clock was set back after it (1.70
    # took 2,000 lines logged after the stop as context, then matched them too); the read from the saved entry is exact.
    # (the smallest of the design check's layouts, all of which landed after it on systemd 219 to 257)
    journal.write('system.journal', *[(-30000 + 0.5 * k, 'old %d' % k) for k in range(3000)] +
                  [(-290 + 10 * k, 'pre %d' % k) for k in range(29)] + [(0, 'saved')] +
                  [(-400 + 0.5 * k, ('HIT post %d' if k % 100 == 7 else 'post %d') % k) for k in range(400)])
    journal.save_at('saved')
    output = journal.restart()
    assert 'with 30 lines of context' in output, output
    lines, openers = journal.captured()
    assert openers == ['HIT post 7']
    assert messages(lines) == ['pre %d' % k for k in range(29)] + ['saved'] + \
        [('HIT post %d' if k % 100 == 7 else 'post %d') % k for k in range(400)]
