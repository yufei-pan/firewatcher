"""Restarts of firewatcher on the real journalctl, reading journals written with systemd-journal-remote through
`journalctl -D`. Skipped where either program is missing, unless FIREWATCHER_REQUIRE_JOURNALCTL is set (CI), which
makes their absence a failure. With -D, journalctl 252 and later follow the folder's newest boot."""
import collections
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

import pytest

from conftest import ROOT, incident_logs
from test_stop import EXITING, read_until

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

    def wait_for_the_end(self, proc, nudge=False):
        """Until the saved position is the journal's last entry (20 s at most: the runs here take about one); the test
        fails when it never is, or when firewatcher ends first. With nudge, an entry is written every 2 s meanwhile:
        journalctl's follow can miss the end of a burst until the journal changes again (systemd 257, 1 in 2,400 bursts
        of 40 entries without firewatcher, 2026-11-25)."""
        ends = [self.entries()[-1][0]]
        deadline = time.time() + 20
        nudged = time.time()
        while time.time() < deadline and proc.poll() is None:
            try:
                if json.loads(self.position.read_text()).get('cursor') in ends:
                    return
            except (OSError, ValueError):
                pass
            if nudge and time.time() > nudged + 2:
                nudged = time.time()
                self.write('system.journal', (nudged - self.T, 'nudge'))
                ends.append(self.entries()[-1][0])
            time.sleep(0.05)
        pytest.fail('the saved position never reached the end of the journal%s' % (
            '' if proc.poll() is None else ' (firewatcher ended with %s first)' % proc.returncode))

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
        journal.wait_for_the_end(proc, nudge=True)
    finally:
        journal.stop(proc)
    lines, openers = journal.captured()
    # after the context of the last 300 s, read back
    assert openers == ['HIT live 5'] and len(set(lines)) == len(lines)
    assert [m for m in messages(lines) if m != 'nudge'][-40:] == [('HIT live %d' if k % 10 == 5 else 'live %d') % k for k in range(40)]


def test_a_restart_after_a_reboot_reads_what_the_old_boot_logged_after_the_stop(journal):
    old = journal.old_boot
    journal.write('system.journal', *[(-200 + 10 * k, 'old boot %d' % k, old) for k in range(20)] +
                  [(0, 'saved', old), (1, 'HIT during shutdown', old), (2, 'HIT unmount failed', old), (3, 'old boot last', old),
                   (20, 'new boot first'), (21, 'HIT in the new boot'), (22, 'new boot more')])
    journal.save_at('saved')
    journal.restart()
    lines, openers = journal.captured()
    assert openers == ['HIT during shutdown']
    # the old boot's lead-up from the read back, the saved entry, and every line after it, once and in order
    assert messages(lines) == ['old boot %d' % k for k in range(20)] + [
        'saved', 'HIT during shutdown', 'HIT unmount failed', 'old boot last', 'new boot first', 'HIT in the new boot',
        'new boot more']


def test_a_restart_after_the_journal_lost_the_saved_entry_reads_by_time(journal):
    journal.write('a.journal', *[(-200 + 10 * k, ('HIT in the window %d' if k == 15 else 'a %d') % k) for k in range(20)] + [(0, 'saved')])
    journal.save_at('saved')
    # the journal keeps one entry just before the window (--capture-time, 300 s, before the saved entry) and one in it
    journal.write('c.journal', (-301, 'before the window'), (-299, 'HIT inside the window'))
    journal.write('b.journal', *[(50 + k, ('HIT b %d' if k % 10 == 5 else 'b %d') % k) for k in range(40)])
    (journal.folder / 'a.journal').unlink()
    output = journal.restart()
    assert 'Cannot find the last entry read before the stop' in output, output
    lines, openers = journal.captured()
    # the match in the window opens the capture, and the line before the window is not read
    assert openers == ['HIT inside the window']
    assert messages(lines) == ['HIT inside the window'] + [('HIT b %d' if k % 10 == 5 else 'b %d') % k for k in range(40)]


def test_a_restart_after_the_clock_was_set_back_takes_no_later_line_as_context(journal):
    # In a long journal, journalctl --since lands after the saved entry when the clock was set back after it (1.70
    # took the lines logged after the stop that it reached as context, then matched them too); the read from the saved entry
    # is exact.
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


def _children(pid):
    """The processes whose parent is pid (firewatcher's journalctls)."""
    found = []
    for name in os.listdir('/proc'):
        if name.isdigit():
            try:
                with open('/proc/%s/stat' % name) as f:
                    if int(f.read().rsplit(')', 1)[1].split()[1]) == pid:
                        found.append(int(name))
            except (OSError, ValueError, IndexError):
                pass
    return found


def _kill_all(proc, known):
    """SIGKILL firewatcher and its journalctls: the ones it has now and the ones (known) from before. They hold the
    test's pipe as their stderr, so a read of it would not end until they do."""
    for pid in (_children(proc.pid) if proc.poll() is None else []) + list(known):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def test_a_busy_capture_stopped_hundreds_of_times_loses_no_line_and_matches_none_twice(journal):
    # 200 stops at random while a backlog of 40,000 entries is read with a capture open nearly all the time (a match
    # every 1,000), in four lanes, each with its own position and captures: half sent to firewatcher alone, half as the
    # unit's stop sends them (to firewatcher, then its journalctl). 1.71 went wrong in 58 of 6,000 such stops (hung after
    # "Exiting.", or "Error reading line" and a line lost; 2026-11-25); at that rate 200 stops miss it about 1 time in 7.
    # Each stop must end with exit 0 and the line "Exiting." on its own (a stop that came with journalctl's end and was
    # taken for a journalctl that failed prints "journalctl ended with status" and no such line).
    texts = [('HIT e%d' if k % 1000 == 500 else 'e%d') % k for k in range(40000)]
    journal.write('system.journal', *[(-80 + k, 'pre %d' % k) for k in range(20)] + [(-55, 'saved')] +
                  [(-50 + 0.001 * k, text) for k, text in enumerate(texts)])
    cursors = [c for c, m in journal.entries()]
    index = dict((c, i - 21) for i, c in enumerate(cursors))
    stops, checks = [], []

    def lane(n):
        rnd = random.Random(n)
        folder = journal.folder.parent / ('lane%d' % n)
        position, out = folder / 'journal.position', folder / 'out'
        done = 0
        while done < 50:
            shutil.rmtree(str(folder), ignore_errors=True)
            out.mkdir(parents=True)
            position.write_text(json.dumps({'cursor': cursors[20], 'time': journal.T}))
            clean = True
            reached = None
            while done < 50 and reached != cursors[-1]:
                proc = subprocess.Popen(
                    [sys.executable, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import firewatcher as fw; '
                     'fw._journald_present = lambda: True; sys.exit(fw.main(sys.argv[2:]))', str(ROOT),
                     '--config', str(journal.conf), '-o', str(out), '-t', '10', '--fallback-folder', '',
                     '--position-file', str(position), str(journal.pat)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=journal.env)
                kids = []
                try:
                    seen = read_until(proc, 'Starting firewatcher')
                    time.sleep(rnd.uniform(0.12, 0.4))
                    signum = rnd.choice((signal.SIGTERM, signal.SIGINT))
                    group = rnd.random() < 0.5
                    kids = _children(proc.pid)
                    proc.send_signal(signum)
                    for pid in kids if group else []:
                        try:
                            os.kill(pid, signum)
                        except OSError:
                            pass
                    try:
                        text = seen + proc.communicate(timeout=5)[0].decode('utf-8', 'replace')
                        outcome = 'ok' if proc.returncode == 0 else 'exit %s' % proc.returncode
                    except subprocess.TimeoutExpired:
                        _kill_all(proc, kids)
                        text = seen + proc.communicate(timeout=10)[0].decode('utf-8', 'replace')
                        outcome = 'not ended within 5 s'
                finally:
                    if proc.poll() is None:  # a read_until that failed
                        _kill_all(proc, kids)
                    proc.stdout.close()
                if outcome == 'ok' and (not EXITING.search(text) or 'journalctl ended with status' in text
                                        or 'Traceback' in text or 'Error reading line' in text):
                    outcome = 'ended wrong'
                done += 1
                stops.append((outcome, signal.Signals(signum).name, 'and journalctl' if group else 'alone',
                              text[-400:] if outcome != 'ok' else ''))
                clean = clean and outcome == 'ok'
                try:
                    reached = json.loads(position.read_text())['cursor']
                except (OSError, ValueError, KeyError):
                    reached = None
            # every line from the first match to the last one the position covers is in a capture; in a pass with no
            # stop gone wrong, none was read in two captures
            hits = list(range(500, index.get(reached, -1) + 1, 1000))
            captured, read = set(), []
            for log in incident_logs(out):
                shown = re.sub(r'\x1b\[[0-9;]*m', '', log.read_text(encoding='utf-8')).splitlines()
                opener = next((line.split(' h app[7]: ', 1)[1] for line in shown if line.startswith('Matched line:')), None)
                lines = [line.split(' h app[7]: ', 1)[1] for line in shown
                         if ' h app[7]: ' in line and not line.startswith('Matched line:')]
                captured.update(lines)
                read.extend(lines[lines.index(opener):] if opener in lines else [])
            if hits:
                lost = [t for t in texts[500:hits[-1] + 1] if t not in captured]
                twice = [t for t, c in collections.Counter(read).items() if c > 1] if clean else []
                checks.append((n, lost[:3], twice[:3]))

    lanes = [threading.Thread(target=lane, args=(n,)) for n in range(4)]
    for each in lanes:
        each.start()
    for each in lanes:
        each.join()
    assert len(stops) == 200 and checks
    wrong = [stop for stop in stops if stop[0] != 'ok']
    assert not wrong, (len(wrong), wrong[:5])
    assert not [check for check in checks if check[1] or check[2]], checks
