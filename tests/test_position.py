import json
import os
import signal
import subprocess
import sys
import time

import pytest

import firewatcher as fw
from conftest import ROOT, ScriptedPopen, incident_logs, parse_cli, patch_popen

# --- resuming the journal after a restart ---

T = 1_800_000_000  # 2027-01-15T08:00:00Z


def stamp(offset=0, tz='+0000'):
    when = time.gmtime(T + offset)
    return time.strftime('%Y-%m-%dT%H:%M:%S', when) + tz


def jline(offset, text, tz='+0000'):
    return '%s host app[1]: %s\n' % (stamp(offset, tz), text)


def save_position(path, offset, ordinal, text):
    line = jline(offset, text)
    end = fw._iso_stamp(line)[1]
    path.write_text(json.dumps({'time': T + offset, 'line': ordinal, 'sha1': fw._line_digest(line, end)}))


def resumed(tmp_path, offset, ordinal, text, context_time=60, resume_max=3600, now_offset=10):
    path = tmp_path / 'journal.position'
    save_position(path, offset, ordinal, text)
    return fw.JournalPosition(str(path), resume_max, context_time, now=T + now_offset)


def replay(position, lines):
    """For each line: 'old' (context only) or 'new' (matched as usual), recording new lines like the capture loop."""
    kinds = []
    for line in lines:
        if position.replaying and position.replay_time(line) is not None:
            kinds.append('old')
        else:
            position.saw(line, T)
            kinds.append('new')
    return kinds


@pytest.mark.parametrize('text, expected', [
    ('2027-01-15T08:00:00+0000 host a: x', T),
    ('2027-01-15T10:00:00+02:00 host a: x', T),
    ('2027-01-15T01:00:00-0700 host a: x', T),
    ('2027-01-15T08:00:00.123456+0000 host a: x', T),
    ('2027-01-15T08:00:00Z host a: x', T),
])
def test_iso_stamp_reads_journalctl_short_iso(text, expected):
    when, end = fw._iso_stamp(text)
    assert when == expected
    assert text[end:] == 'host a: x'


@pytest.mark.parametrize('text', ['Jan 15 08:00:00 host a: x', '    continued', '-- Boot 0123abcd --', '2027-01-15T08:00:00+0000'])
def test_iso_stamp_rejects_other_lines(text):
    assert fw._iso_stamp(text) is None


def test_no_saved_position_reads_the_last_lines(tmp_path):
    position = fw.JournalPosition(str(tmp_path / 'none'), tail_lines='20', now=T)
    assert position.since is None and not position.replaying
    assert 'No journal position saved' in position.note
    command = ['journalctl', '--all', '--no-pager', '--lines=20', '--follow']
    assert position.journal_command(command) == ['journalctl', '--output=short-iso', '--all', '--no-pager', '--lines=20', '--follow']


@pytest.mark.parametrize('content', ['', 'not json', '[]', '{"time": 1}', '{"time": 1e30, "line": 1, "sha1": "x"}'])
def test_unreadable_position_reads_the_last_lines(tmp_path, content):
    path = tmp_path / 'journal.position'
    path.write_text(content)
    position = fw.JournalPosition(str(path), now=T)
    assert position.since is None and not position.replaying
    assert 'Cannot read the journal position' in position.note


def test_position_in_the_future_reads_the_last_lines(tmp_path):
    position = resumed(tmp_path, 3600, 1, 'x', now_offset=0)
    assert position.since is None and not position.replaying
    assert 'in the future' in position.note


def test_recent_position_resumes_with_context_before_it(tmp_path):
    position = resumed(tmp_path, 0, 1, 'x', context_time=60, now_offset=10)
    assert position.since == T - 60 and position.replaying
    assert 'Resuming the journal after' in position.note and '10 seconds ago' in position.note
    command = position.journal_command(['journalctl', '--all', '--no-pager', '--lines=20', '--follow'])
    assert command == ['journalctl', '--output=short-iso', '--all', '--no-pager', '--since=@%d' % (T - 60), '--follow']


def test_old_position_reads_back_only_resume_max(tmp_path):
    position = resumed(tmp_path, 0, 1, 'x', resume_max=600, now_offset=7200)
    assert position.since == T + 7200 - 600
    assert not position.replaying
    assert '7200 seconds old; reading the last 600 seconds' in position.note


def test_resume_max_zero_reads_nothing_back(tmp_path):
    position = resumed(tmp_path, 0, 1, 'x', resume_max=0, now_offset=5)
    assert position.since == T + 5 and not position.replaying


def test_replay_ends_right_after_the_saved_line(tmp_path):
    position = resumed(tmp_path, 0, 2, 'b')
    lines = [
        '-- Boot 0123 --\n', jline(-30, 'earlier'), jline(0, 'a'), jline(0, 'b'), '    b continued\n',
        jline(0, 'c'), jline(1, 'd'), '    d continued\n',
    ]
    assert replay(position, lines) == ['old', 'old', 'old', 'old', 'old', 'new', 'new', 'new']


def test_replayed_lines_carry_their_own_time(tmp_path):
    position = resumed(tmp_path, 0, 1, 'a')
    assert position.replay_time('-- Boot 0123 --\n') == T - 60
    assert position.replay_time(jline(-30, 'earlier')) == T - 30
    assert position.replay_time('    continued\n') == T - 30


def test_identical_lines_in_the_saved_second_are_counted(tmp_path):
    position = resumed(tmp_path, 0, 2, 'same')
    lines = [jline(0, 'same'), jline(0, 'same'), jline(0, 'same')]
    assert replay(position, lines) == ['old', 'old', 'new']
    # the run carries on counting that second where the last one stopped
    assert position.ordinal == 3


def test_a_lost_saved_line_ends_the_replay_at_the_next_second(tmp_path):
    position = resumed(tmp_path, 0, 1, 'gone')
    assert replay(position, [jline(0, 'a'), jline(0, 'b'), jline(1, 'c')]) == ['old', 'old', 'new']


def test_a_saved_line_counted_from_mid_second_is_still_found(tmp_path):
    # The last run started inside that second and saw 'c' as its first line there.
    position = resumed(tmp_path, 0, 1, 'c')
    assert replay(position, [jline(0, 'a'), jline(0, 'b'), jline(0, 'c'), jline(0, 'd')]) == ['old', 'old', 'old', 'new']


def test_a_changed_time_zone_still_finds_the_saved_line(tmp_path):
    position = resumed(tmp_path, 0, 1, 'b')
    lines = [jline(0, 'a', tz='+0200'), jline(0, 'b', tz='+0200'), jline(0, 'c', tz='+0200')]
    # same instants, written two hours ahead
    lines = [line.replace('T08:', 'T10:') for line in lines]
    assert replay(position, lines) == ['old', 'old', 'new']


def test_saw_saves_once_per_interval_and_round_trips(tmp_path):
    path = tmp_path / 'state' / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(jline(0, 'a'), 100.0)
    assert json.loads(path.read_text())['line'] == 1
    position.saw(jline(0, 'b'), 100.5)
    position.saw('    b continued\n', 100.6)
    assert json.loads(path.read_text())['line'] == 1
    position.saw(jline(0, 'c'), 101.0)
    saved = json.loads(path.read_text())
    assert saved['time'] == T and saved['line'] == 3
    position.saw(jline(1, 'd'), 101.5)
    position.save(final=True)
    assert json.loads(path.read_text())['line'] == 1
    assert not [name for name in os.listdir(str(path.parent)) if name.endswith('.tmp')]
    # a restart reads 'd' again only as context
    again = fw.JournalPosition(str(path), now=T + 5)
    assert replay(again, [jline(0, 'a'), jline(0, 'b'), jline(0, 'c'), jline(1, 'd'), jline(1, 'e')]) == ['old'] * 4 + ['new']


def test_save_without_a_new_line_writes_nothing(tmp_path):
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw('    not a journal line\n', 100.0)
    position.save(final=True)
    assert not path.exists()


def test_save_failure_is_logged_once_and_retried(tmp_path, capsys):
    blocker = tmp_path / 'blocker'
    blocker.write_text('a file where a folder should be')
    position = fw.JournalPosition(str(blocker / 'journal.position'), now=T)
    position.saw(jline(0, 'a'), 100.0)
    position.saw(jline(1, 'b'), 101.0)
    assert capsys.readouterr().out.count('cannot save the journal position') == 1
    blocker.unlink()
    position.save(102.0)
    assert json.loads((blocker / 'journal.position').read_text())['time'] == T + 1
    assert not position.save_failed


def test_capture_matches_only_lines_after_the_saved_position(tmp_path, monkeypatch):
    position = resumed(tmp_path, 0, 1, 'HIT before the restart', context_time=60)
    popen = ScriptedPopen([
        jline(-20, 'context line'),
        jline(0, 'HIT before the restart'),
        jline(5, 'logged while stopped'),
        jline(6, 'HIT after the restart'),
    ])
    patch_popen(monkeypatch, popen)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    out = tmp_path / 'out'
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(out),
                        compress_after_months=0, delete_after_months=0, journal_position=position)
    logs = incident_logs(out)
    assert len(logs) == 1
    text = logs[0].read_text()
    assert 'Matched line:    %s' % jline(6, 'HIT after the restart').strip() in text
    # the lines read again are the context before the match
    assert text.index('context line') < text.index('HIT before the restart') < text.index('logged while stopped')
    assert json.loads((tmp_path / 'journal.position').read_text())['time'] == T + 6


def _main_with(monkeypatch, argv, can_resume=True):
    seen = {}

    def fake_capture(command, patterns, **kwargs):
        seen['command'] = command
        seen.update(kwargs)

    monkeypatch.setattr(fw, 'capture_messages', fake_capture)
    monkeypatch.setattr(fw.shutil, 'which', lambda name: '/usr/bin/journalctl' if name == 'journalctl' else None)
    monkeypatch.setattr(fw, '_journal_can_resume', lambda journalctl: can_resume)
    assert fw.main(argv) == 0
    return seen


def test_main_resumes_the_journal_by_default(tmp_path, monkeypatch, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    seen = _main_with(monkeypatch, [str(pat)])
    assert seen['command'][:2] == ['journalctl', '--output=short-iso']
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
    assert '--output=short-iso' not in seen['command'] and '--lines=20' in seen['command']
    if note:
        assert note in capsys.readouterr().out


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
"""Prints journal.txt like journalctl -o short-iso, from --since=@N or the last --lines=N, then waits."""
import calendar, os, sys, time
lines = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'journal.txt')).read().splitlines(True)
args = sys.argv[1:]
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'calls.txt'), 'a') as f:
    f.write(' '.join(args) + '\n')
if '--lines=0' in args:
    sys.exit(0)
for arg in args:
    if arg.startswith('--since=@'):
        since = int(arg[len('--since=@'):])
        lines = [l for l in lines if calendar.timegm(time.strptime(l[:19], '%%Y-%%m-%%dT%%H:%%M:%%S')) >= since]
    if arg.startswith('--lines='):
        lines = lines[-int(arg[len('--lines='):]):]
sys.stdout.write(''.join(lines))
sys.stdout.flush()
time.sleep(600)
'''


def test_a_restarted_daemon_matches_only_what_it_has_not_read(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    fake = bin_dir / 'journalctl'
    fake.write_text(FAKE_JOURNALCTL % sys.executable)
    fake.chmod(0o755)
    now = int(time.time())

    def line(offset, text):
        return '%s host app[1]: %s\n' % (time.strftime('%Y-%m-%dT%H:%M:%S+0000', time.gmtime(now + offset)), text)

    journal = bin_dir / 'journal.txt'
    journal.write_text(line(-40, 'quiet') + line(-30, 'HIT first') + line(-20, 'after the first'))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    conf = tmp_path / 'empty.conf'
    conf.write_text('')
    out = tmp_path / 'out'
    position_file = tmp_path / 'journal.position'
    env = dict(os.environ, PATH='%s%s%s' % (bin_dir, os.pathsep, os.environ.get('PATH', '')))

    def run_until(done):
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / 'firewatcher.py'), '--config', str(conf), '-o', str(out), '-t', '60',
             '--fallback-folder', '', '--position-file', str(position_file), str(pat)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, env=env,
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

    def captured(count, text):
        logs = incident_logs(out)
        return len(logs) == count and text in logs[-1].read_text()

    first = run_until(lambda: captured(1, 'after the first'))
    assert 'No journal position saved' in first
    assert json.loads(position_file.read_text())['time'] == now - 20
    journal.write_text(journal.read_text() + line(-10, 'logged while stopped') + line(-5, 'HIT second'))
    second = run_until(lambda: captured(2, 'HIT second'))
    assert 'Resuming the journal after' in second
    logs = incident_logs(out)
    assert len(logs) == 2
    text = logs[1].read_text()
    assert 'Matched line:    %s' % line(-5, 'HIT second').strip() in text
    # read again as context only, so 'HIT first' did not open a capture of its own
    assert 'logged while stopped' in text and 'after the first' in text and 'HIT first' in text
    assert json.loads(position_file.read_text())['time'] == now - 5
    calls = (bin_dir / 'calls.txt').read_text().splitlines()
    assert any('--lines=20' in call for call in calls)
    assert any('--since=@%d' % (now - 20 - 60) in call for call in calls)


def test_a_match_that_opens_a_capture_saves_the_position_at_once(tmp_path, monkeypatch):
    saved = []

    class Recording(fw.JournalPosition):
        def save(self, now=None, final=False):
            if self.changed:
                saved.append(self.last_line.split(': ', 1)[1].strip())
            super().save(now, final)

    position = Recording(str(tmp_path / 'journal.position'), now=T)
    patch_popen(monkeypatch, ScriptedPopen([jline(0, 'quiet'), jline(0, 'HIT one'), jline(0, 'HIT two'), jline(0, 'after')]))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0, journal_position=position)
    # the first line, the match that opened the capture (not the one that extended it), and the last line at exit
    assert saved == ['quiet', 'HIT one', 'after']


def _now_line(offset, text):
    return '%s host app[1]: %s\n' % (time.strftime('%Y-%m-%dT%H:%M:%S+0000', time.gmtime(int(time.time()) + offset)), text)


def test_replayed_lines_keep_their_age_in_the_context(tmp_path, monkeypatch):
    path = tmp_path / 'journal.position'
    saved_line = _now_line(-10, 'the saved line')
    stamp_end = fw._iso_stamp(saved_line)[1]
    path.write_text(json.dumps({'time': fw._iso_stamp(saved_line)[0], 'line': 1, 'sha1': fw._line_digest(saved_line, stamp_end)}))
    position = fw.JournalPosition(str(path), context_time=300)
    patch_popen(monkeypatch, ScriptedPopen([_now_line(-250, 'too old for the window'), _now_line(-30, 'recent'), saved_line, _now_line(-1, 'HIT')]))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    out = tmp_path / 'out'
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(out),
                        compress_after_months=0, delete_after_months=0, journal_position=position)
    text = incident_logs(out)[0].read_text()
    assert 'recent' in text and 'the saved line' in text
    assert 'too old for the window' not in text


def test_a_line_that_crashes_the_loop_is_not_read_again(tmp_path, monkeypatch):
    position = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T)
    patch_popen(monkeypatch, ScriptedPopen([jline(0, 'fine'), jline(1, 'poison'), jline(2, 'never read')]))
    real_append = fw.ContextBuffer.append

    def append(self, read_time, seq, line):
        if 'poison' in line:
            raise RuntimeError('a bug this line sets off')
        return real_append(self, read_time, seq, line)

    monkeypatch.setattr(fw.ContextBuffer, 'append', append)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    with pytest.raises(RuntimeError):
        fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                            compress_after_months=0, delete_after_months=0, journal_position=position)
    assert json.loads((tmp_path / 'journal.position').read_text())['time'] == T + 1


def test_a_quiet_journal_during_a_capture_still_saves_the_position(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'CAPTURE_SYNC_INTERVAL', 0.05)
    path = tmp_path / 'journal.position'
    seen_while_quiet = []

    class QuietStdout:
        def __init__(self):
            self.lines = [jline(0, 'HIT one'), jline(0, 'HIT two')]

        def readline(self, size=-1):
            if self.lines:
                return self.lines.pop(0)
            time.sleep(0.5)
            seen_while_quiet.append(json.loads(path.read_text())['line'])
            return ''

    popen = ScriptedPopen([])
    popen.stdout = QuietStdout()
    patch_popen(monkeypatch, popen)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0,
                        journal_position=fw.JournalPosition(str(path), now=T))
    # 'HIT two' only extended the open capture, so no save came with it: the quiet wait saved it
    assert seen_while_quiet == [2]
