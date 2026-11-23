import datetime
import json
import os
import re
import signal
import subprocess
import sys
import time

import pytest

import firewatcher as fw
from conftest import ROOT, Clock, ScriptedPopen, fake_exists, incident_logs, parse_cli, patch_popen, use_journal

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


@pytest.mark.parametrize('text', ['Jan 15 08:00:00 host a: x', '    continued', '-- Boot 0123abcd --', '2027-01-15T08:00:00+0000',
                                  '0000-01-01T00:00:00Z x', '2027-13-01T00:00:00Z x', '2027-00-01T00:00:00Z x',
                                  '2027-02-30T00:00:00Z x', '2027-01-15T25:61:00+0000 x'])
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


# --- finding the saved line in the journal as it is at the restart ---

def fake_journalctl(tmp_path, journal):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    fake = bin_dir / 'journalctl'
    fake.write_text(FAKE_JOURNALCTL % sys.executable)
    fake.chmod(0o755)
    (bin_dir / 'journal.txt').write_text(journal)
    return str(fake)


def stored(offset, line):
    """A line of the fake journalctl's journal that journald stored at T + offset, whatever time the line shows."""
    return '@%d %s' % (T + offset, line)


def script(tmp_path, body, name='journalctl'):
    path = tmp_path / name
    path.write_text('#!%s\nimport sys, time\n%s\n' % (sys.executable, body))
    path.chmod(0o755)
    return str(path)


def located(tmp_path, ordinal, text, journalctl):
    position = resumed(tmp_path, 0, ordinal, text)
    position.locate([journalctl, '--output=short-iso', '--all', '--no-pager', '--since=@%d' % position.since, '--follow'])
    return position


def test_locate_keeps_the_saved_line_where_the_journal_still_has_it(tmp_path):
    lines = [jline(-1, 'x'), jline(0, 'a'), jline(0, 'b'), jline(0, 'c'), jline(1, 'd')]
    position = located(tmp_path, 2, 'b', fake_journalctl(tmp_path, ''.join(lines)))
    assert position.replaying and position.saved[1] == 2
    assert replay(position, lines) == ['old', 'old', 'old', 'new', 'new']
    # the saved second read once, from that second on, without --follow
    assert (tmp_path / 'bin' / 'calls.txt').read_text() == '--output=short-iso --all --no-pager --since=@%d\n' % T
    # a journal that ends inside the saved second
    other = tmp_path / 'other'
    other.mkdir()
    position = located(other, 2, 'b', fake_journalctl(other, jline(0, 'a') + jline(0, 'b')))
    assert position.replaying and position.saved[1] == 2


def test_a_journal_that_lost_the_start_of_the_saved_second_ends_the_replay_at_the_saved_line(tmp_path):
    # the saved line was the third of its second; the first two went with a rotated journal file
    position = located(tmp_path, 3, 'c', fake_journalctl(tmp_path, jline(0, 'c') + jline(0, 'HIT') + jline(1, 'd')))
    assert position.saved[1] == 1
    assert replay(position, [jline(0, 'c'), jline(0, 'HIT'), jline(1, 'd')]) == ['old', 'new', 'new']


def test_with_the_start_of_the_second_lost_identical_lines_are_read_again_never_skipped(tmp_path):
    # the saved line was the fourth of four identical lines: which one it is now cannot be told, so the first
    lines = [jline(0, 'same'), jline(0, 'same'), jline(0, 'x'), jline(1, 'y')]
    position = located(tmp_path, 4, 'same', fake_journalctl(tmp_path, ''.join(lines)))
    assert replay(position, lines) == ['old', 'new', 'new', 'new']


@pytest.mark.parametrize('journal', [
    jline(0, 'c') + jline(0, 'HIT') + jline(1, 'd'),  # the saved line went, the rest of its second stayed
    jline(0, 'a'),  # the journal ends inside the saved second, before the saved line
    jline(5, 'HIT later'),  # its whole second went
    '',  # nothing at or after it: "-- No entries --"
    jline(0, 'c') + jline(-100, 'b'),  # the clock set back after it: reading stops at the first line more than JOURNAL_STAMP_SKEW away
])
def test_a_journal_without_the_saved_line_replays_nothing(tmp_path, journal):
    position = located(tmp_path, 2, 'b', fake_journalctl(tmp_path, journal))
    assert not position.replaying
    assert 'no longer holds the last line read' in position.note
    assert replay(position, [jline(-30, 'HIT earlier'), jline(0, 'HIT')]) == ['new', 'new']


def test_a_line_shown_as_the_second_before_can_come_first_without_the_saved_line_being_lost(tmp_path):
    # journalctl seeks by the time journald stored a line and shows the time it was sent: x was sent just before the
    # second turned and stored just after, so --since=@T starts with it. 1.69 as built stopped at x, found nothing
    # of the saved second, and matched the whole --capture-time again after an ordinary restart.
    lines = [stored(0, jline(-1, 'x')), jline(0, 'a'), jline(0, 'b'), jline(0, 'c'), jline(1, 'd')]
    position = located(tmp_path, 2, 'b', fake_journalctl(tmp_path, ''.join(lines)))
    assert position.replaying and position.saved[1] == 2
    assert 'no longer holds' not in position.note
    assert replay(position, [line.partition(' ')[2] if line.startswith('@') else line for line in lines]) == \
        ['old', 'old', 'old', 'new', 'new']


def test_a_line_shown_as_the_saved_second_can_come_after_one_shown_as_the_next(tmp_path):
    # d was sent in the saved second and stored after c, which was sent in the next one
    lines = [jline(0, 'a'), stored(1, jline(1, 'c')), stored(1, jline(0, 'd'))]
    position = located(tmp_path, 1, 'd', fake_journalctl(tmp_path, ''.join(lines)))
    # the saved d was the first line of its run as the capture loop numbered it (c came before); it is there at that
    # number or after it, so the saved number stays
    assert position.replaying and position.saved[1] == 1
    assert 'no longer holds' not in position.note


def test_a_line_shown_as_the_second_before_inside_the_saved_second_does_not_end_the_replay_early(tmp_path):
    # journald stored h (sent in the second before) between lines of the saved second, as in a stall. The capture
    # loop counted the saved A as the 2nd of its run (h ended the run, B began a new one), and the journal holds an
    # earlier A: e379c34 took that one as the saved line and read h, B and A again; the replay ends as 1.68's did
    lines = [jline(0, 'A'), stored(0, jline(-1, 'h')), jline(0, 'B'), jline(0, 'A'), jline(1, 'd')]
    position = located(tmp_path, 2, 'A', fake_journalctl(tmp_path, ''.join(lines)))
    assert position.replaying and position.saved[1] == 2
    shown = [line.partition(' ')[2] if line.startswith('@') else line for line in lines]
    assert replay(position, shown) == ['old', 'old', 'old', 'old', 'new']


def test_a_journal_that_lost_lines_before_the_saved_one_skips_no_line_1_68_matched(tmp_path):
    # the capture loop read [B, A] and saved A as the 2nd of its run; B went with a rotated file, and while firewatcher
    # was stopped C, A, h (sent in the second before, stored inside it: a stall), D, A and E came. With A's text at
    # its number or after it, the replay ends where 1.68's did; a later line with A's text and number skipped C to A
    lines = [jline(0, 'A'), jline(0, 'C'), jline(0, 'A'), stored(0, jline(-1, 'h')), jline(0, 'D'), jline(0, 'A'), jline(1, 'E')]
    position = located(tmp_path, 2, 'A', fake_journalctl(tmp_path, ''.join(lines)))
    shown = [line.partition(' ')[2] if line.startswith('@') else line for line in lines]
    assert replay(position, shown) == ['old', 'old', 'old', 'new', 'new', 'new', 'new']


def test_a_saved_number_that_is_right_among_all_lines_of_the_second_is_kept(tmp_path):
    # after a resume the saved number counts all lines of the second (replay_time), whatever ends the capture loop's
    # runs: the first X is the 2nd line of its second and the 1st of its run (h ended Y's): the replay ends there,
    # and the next X is read as new, not skipped.
    lines = [jline(0, 'Y'), stored(0, jline(-1, 'h')), jline(0, 'X'), jline(0, 'X'), jline(1, 'd')]
    position = located(tmp_path, 2, 'X', fake_journalctl(tmp_path, ''.join(lines)))
    assert position.saved[1] == 2
    shown = [line.partition(' ')[2] if line.startswith('@') else line for line in lines]
    assert replay(position, shown) == ['old', 'old', 'old', 'new', 'new']


def test_a_burst_of_identical_lines_in_the_saved_second_is_found_at_the_saved_one(tmp_path):
    # the saved A was the 2nd of two identical lines, with x and d after it: the journal is as it was, so the replay
    # ends at the 2nd A, as 1.68's did, and the first A is not taken for it (a lower number would read the 2nd again)
    lines = [jline(0, 'A'), jline(0, 'A'), jline(0, 'x'), jline(1, 'd')]
    position = located(tmp_path, 2, 'A', fake_journalctl(tmp_path, ''.join(lines)))
    assert position.saved[1] == 2
    assert replay(position, lines) == ['old', 'old', 'new', 'new']


def test_one_line_lost_before_the_saved_one_is_not_made_up_for_by_a_line_after_it(tmp_path):
    # the saved b was the 2nd line of its second and the 1st went with a rotated file: the saved line is now the 1st,
    # and HIT after it is new (a number two lower would count HIT as context, a skip)
    lines = [jline(0, 'b'), jline(0, 'HIT'), jline(1, 'd')]
    position = located(tmp_path, 2, 'b', fake_journalctl(tmp_path, ''.join(lines)))
    assert replay(position, lines) == ['old', 'new', 'new']


def test_a_stall_that_stores_the_far_earlier_line_first_still_finds_the_saved_line(tmp_path):
    # journald stalled and stored a line sent 100 s before the saved second first, then the lines of that second (all
    # at T + 5): --since=@T starts with the far line. Reading stopped there in 1.69 as built, which then said the
    # journal no longer holds the saved line and matched the whole window again; 1.68 replayed up to the saved line
    lines = [stored(5, jline(-100, 'Q')), stored(5, jline(0, 'A')), stored(5, jline(0, 'T')), stored(5, jline(1, 'U'))]
    position = located(tmp_path, 2, 'T', fake_journalctl(tmp_path, ''.join(lines)))
    assert position.replaying and position.saved[1] == 2
    shown = [line.partition(' ')[2] for line in lines]
    assert replay(position, shown) == ['old', 'old', 'old', 'new']


def test_a_stalled_head_of_far_earlier_lines_does_not_hide_a_lost_saved_second(tmp_path):
    skew = fw.JOURNAL_STAMP_SKEW
    # far earlier lines and then a line far later: the read ends there, and nothing of the saved second is in it
    journal = stored(5, jline(-100, 'Q')) + stored(5, jline(-99, 'R')) + jline(skew + 1, 'S') + jline(0, 'b')
    position = located(tmp_path, 1, 'b', fake_journalctl(tmp_path, journal))
    assert not position.replaying and 'no longer holds' in position.note
    # far earlier lines to the end of the journal
    other = tmp_path / 'other'
    other.mkdir()
    position = located(other, 1, 'b', fake_journalctl(other, stored(5, jline(-100, 'Q')) + stored(5, jline(-99, 'R'))))
    assert not position.replaying and 'no longer holds' in position.note


def test_a_stalled_head_that_never_ends_is_bounded_by_the_probe_timeout(tmp_path, monkeypatch):
    # journalctl keeps writing far earlier lines: the bound is the probe's, and where it cannot tell, locate leaves the position as saved
    monkeypatch.setattr(fw, 'JOURNAL_PROBE_TIMEOUT', 1)
    head = ''.join(jline(-100, 'Q%d' % n) for n in range(3))
    journalctl = script(tmp_path, 'sys.stdout.write(%r)\nsys.stdout.flush()\ntime.sleep(600)' % head, 'endless')
    start = time.time()
    position = located(tmp_path, 3, 'c', journalctl)
    assert time.time() - start < 15
    assert position.replaying and position.saved[1] == 3


def test_a_journal_that_runs_on_far_from_the_saved_second_is_read_no_further(tmp_path):
    # the clock set back after it: a second more than JOURNAL_STAMP_SKEW away is another stretch of the journal
    skew = fw.JOURNAL_STAMP_SKEW
    for far in (skew + 1, -skew - 1):
        folder = tmp_path / ('far%d' % far)
        folder.mkdir()
        journal = jline(0, 'c') + jline(far, 'b') + jline(0, 'b')
        assert not located(folder, 1, 'b', fake_journalctl(folder, journal)).replaying
    # and one at that distance or less is read past: 16 s is the largest gap between sending and storing seen
    # outside a stall of the host (15.7 s on the host it was measured on)
    for near_by in (16, skew):
        near = tmp_path / ('near%d' % near_by)
        near.mkdir()
        assert located(near, 1, 'b', fake_journalctl(near, jline(0, 'c') + jline(near_by, 'x') + jline(0, 'b'))).replaying


def test_when_journalctl_cannot_tell_the_replay_goes_by_the_saved_number(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'JOURNAL_PROBE_TIMEOUT', 1)
    second = jline(0, 'c') + jline(0, 'HIT')
    # each in its own file: a script that is written over by the next never runs
    for journalctl in (str(tmp_path / 'missing'),
                       script(tmp_path, 'sys.stdout.write(%r)\nsys.exit(1)' % second, 'exits-1'),
                       script(tmp_path, 'sys.stdout.write(%r)\nsys.stdout.flush()\ntime.sleep(600)' % second, 'hangs')):
        start = time.time()
        position = located(tmp_path, 3, 'c', journalctl)
        assert time.time() - start < 15, journalctl
        assert position.replaying and position.saved[1] == 3, journalctl


def test_saw_saves_once_per_interval_and_round_trips(tmp_path):
    path = tmp_path / 'state' / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(jline(0, 'a'), 100.0)
    # a save covers only lines already handled, so 'a' is saved when the next line comes
    assert not path.exists()
    position.saw(jline(0, 'b'), 100.5)
    assert json.loads(path.read_text())['line'] == 1
    position.saw('    b continued\n', 100.6)
    position.saw(jline(0, 'c'), 101.0)
    assert json.loads(path.read_text())['line'] == 1
    position.saw(jline(1, 'd'), 101.5)
    saved = json.loads(path.read_text())
    assert saved['time'] == T and saved['line'] == 3
    position.save()
    assert json.loads(path.read_text())['line'] == 1
    assert not [name for name in os.listdir(str(path.parent)) if name.endswith('.tmp')]
    # a restart reads 'd' again only as context
    again = fw.JournalPosition(str(path), now=T + 5)
    assert replay(again, [jline(0, 'a'), jline(0, 'b'), jline(0, 'c'), jline(1, 'd'), jline(1, 'e')]) == ['old'] * 4 + ['new']


def test_every_save_syncs_the_file_before_the_rename(tmp_path, monkeypatch):
    # XFS does not flush a file's data when it is renamed over another; after a hard reset an unsynced
    # position could come back empty. Every save, periodic or at exit, must sync first.
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    events = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append('fsync')
        real_fsync(fd)

    def replace(a, b):
        events.append('replace')
        real_replace(a, b)

    monkeypatch.setattr(fw.os, 'fsync', fsync)
    monkeypatch.setattr(fw.os, 'replace', replace)
    position.saw(jline(0, 'a'), 100.0)
    position.saw(jline(0, 'b'), 100.5)
    assert events == ['fsync', 'replace']
    position.saw(jline(1, 'c'), 101.5)
    assert events == ['fsync', 'replace'] * 2
    position.changed = True
    position.save()
    assert events == ['fsync', 'replace'] * 3
    assert json.loads(path.read_text())['line'] == 1


def test_save_survives_a_filesystem_without_fsync(tmp_path, monkeypatch):
    def unsupported(fd):
        raise OSError(fw.errno.EINVAL, 'Invalid argument')

    monkeypatch.setattr(fw.os, 'fsync', unsupported)
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(jline(0, 'a'), 100.0)
    position.save(100.0)
    assert json.loads(path.read_text())['line'] == 1
    assert not position.save_failed


def test_a_stop_inside_the_save_of_saw_does_not_take_back_the_line_before(tmp_path):
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(jline(0, 'A'), 100.0)
    position.save(100.0)
    position.saw(jline(1, 'B'), 100.5)  # B is handled in full

    def stop():
        raise KeyboardInterrupt  # where SIGTERM lands: in the capture or position fsync of this save

    position.before_save = stop
    with pytest.raises(KeyboardInterrupt):
        position.saw(jline(2, 'C'), 101.5)  # C is in flight
    position.unsee()  # what capture_messages does for the line in flight
    position.before_save = None
    position.save()
    # B was handled, so the restart must not read it again
    assert json.loads(path.read_text())['time'] == T + 1


def test_save_without_a_new_line_writes_nothing(tmp_path):
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw('    not a journal line\n', 100.0)
    position.save()
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
    use_journal(monkeypatch)
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


FAKE_JOURNALCTL = r'''#!%s
"""Prints journal.txt like journalctl -o short-iso: from the first line at or after --since=@N (later lines too, whatever
their time, as journalctl seeks and then reads on), or the last --lines=N; then, with --follow, waits. As journalctl
seeks by the time journald STORED a line and shows the time it was SENT, a line of journal.txt may start with '@N ',
the time it was stored: that is not shown, and is what --since compares."""
import calendar, os, sys, time
entries = []
for line in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'journal.txt')).read().splitlines(True):
    stored = None
    if line.startswith('@'):
        number, _, line = line[1:].partition(' ')
        stored = int(number)
    if stored is None:
        try:
            stored = calendar.timegm(time.strptime(line[:19], '%%Y-%%m-%%dT%%H:%%M:%%S'))
        except ValueError:
            pass
    entries.append((stored, line))
args = sys.argv[1:]
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'calls.txt'), 'a') as f:
    f.write(' '.join(args) + '\n')
if '--lines=0' in args:
    sys.exit(0)

for arg in args:
    if arg.startswith('--since=@'):
        since = int(arg[len('--since=@'):])
        first = next((n for n, e in enumerate(entries) if e[0] is not None and e[0] >= since), len(entries))
        entries = entries[first:] or [(None, '-- No entries --\n')]
    if arg.startswith('--lines='):
        entries = entries[-int(arg[len('--lines='):]):]
sys.stdout.write(''.join(line for _, line in entries))
sys.stdout.flush()
if '--follow' in args:
    time.sleep(600)
'''


class Daemon(object):
    """firewatcher as a daemon on a journald host, reading a fake journalctl (FAKE_JOURNALCTL, its journal.txt beside
    it) and saving its position, until done() or 20 seconds, then stopped with SIGTERM."""

    def __init__(self, tmp_path):
        self.bin_dir = tmp_path / 'bin'
        self.bin_dir.mkdir()
        fake = self.bin_dir / 'journalctl'
        fake.write_text(FAKE_JOURNALCTL % sys.executable)
        fake.chmod(0o755)
        self.journal = self.bin_dir / 'journal.txt'
        self.now = int(time.time())
        self.pat = tmp_path / 'p.txt'
        self.pat.write_text('HIT\n')
        self.conf = tmp_path / 'empty.conf'
        self.conf.write_text('')
        self.out = tmp_path / 'out'
        self.position_file = tmp_path / 'journal.position'
        self.env = dict(os.environ, PATH='%s%s%s' % (self.bin_dir, os.pathsep, os.environ.get('PATH', '')))

    def line(self, offset, text):
        return '%s host app[1]: %s\n' % (time.strftime('%Y-%m-%dT%H:%M:%S+0000', time.gmtime(self.now + offset)), text)

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


def test_a_restarted_daemon_matches_only_what_it_has_not_read(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.journal.write_text(line(-40, 'quiet') + line(-30, 'HIT first') + line(-20, 'after the first'))
    first = daemon.run_until(lambda: daemon.captured(1, 'after the first', now - 20))
    assert 'No journal position saved' in first
    assert daemon.saved()['time'] == now - 20
    daemon.journal.write_text(daemon.journal.read_text() + line(-10, 'logged while stopped') + line(-5, 'HIT second'))
    second = daemon.run_until(lambda: daemon.captured(2, 'HIT second', now - 5))
    assert 'Resuming the journal after' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    text = logs[1].read_text()
    assert 'Matched line:    %s' % line(-5, 'HIT second').strip() in text
    # read again as context only, so 'HIT first' did not open a capture of its own
    assert 'logged while stopped' in text and 'after the first' in text and 'HIT first' in text
    assert daemon.saved()['time'] == now - 5
    calls = (daemon.bin_dir / 'calls.txt').read_text().splitlines()
    assert any('--lines=20' in call for call in calls)
    assert any('--since=@%d' % (now - 20 - 60) in call for call in calls)
    # the saved second, read once before resuming, without --follow
    assert any(call.endswith('--since=@%d' % (now - 20)) and '--follow' not in call for call in calls)


def test_a_restart_after_the_journal_lost_the_start_of_the_saved_second_matches_what_followed(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.journal.write_text(line(-40, 'HIT first') + line(-20, 'a') + line(-20, 'b') + line(-20, 'c'))
    daemon.run_until(lambda: daemon.captured(1, 'app[1]: c\n', now - 20))
    assert daemon.saved()['line'] == 3
    # While stopped, the journal file that held the start of that second was rotated away, and a match was logged
    # in that second. 1.68 counted 'c' as the second's first line, never found the saved third one, and replayed
    # the rest of the second as context only.
    daemon.journal.write_text(line(-20, 'c') + line(-20, 'HIT logged while stopped') + line(-5, 'later'))
    daemon.run_until(lambda: daemon.captured(2, 'later', now - 5))
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    assert 'Matched line:    %s' % line(-20, 'HIT logged while stopped').strip() in logs[1].read_text()


def test_a_restart_on_a_journal_without_the_saved_line_and_a_clock_set_back_matches_every_line(tmp_path):
    daemon = Daemon(tmp_path)
    line, now = daemon.line, daemon.now
    daemon.journal.write_text(line(-40, 'HIT first') + line(-20, 'last line read'))
    daemon.run_until(lambda: daemon.captured(1, 'last line read', now - 20))
    # A reboot with a volatile journal (CentOS 7's default) lost the saved line, and the clock came back behind it.
    # 1.68 replayed every line stamped before the saved second as context, until the clock passed it.
    daemon.journal.write_text(line(-50, 'booted with the clock behind') + line(-49, 'HIT after the reboot'))
    second = daemon.run_until(lambda: len(incident_logs(daemon.out)) == 2 and daemon.saved().get('time') == now - 49)
    assert 'no longer holds the last line read' in second
    logs = incident_logs(daemon.out)
    assert len(logs) == 2
    assert 'Matched line:    %s' % line(-49, 'HIT after the reboot').strip() in logs[1].read_text()


def test_a_match_that_opens_a_capture_saves_the_position_at_once(tmp_path, monkeypatch):
    # The periodic save (every POSITION_SAVE_INTERVAL of real time) must not fall inside this run, however slow
    # the disk's fsync is: only the saves that come with the open and the exit are counted.
    monkeypatch.setattr(fw, 'POSITION_SAVE_INTERVAL', 3600)
    saved = []

    class Recording(fw.JournalPosition):
        def save(self, now=None):
            if self.changed:
                saved.append(self.last_line.split(': ', 1)[1].strip())
            super().save(now)

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


def _quiet_after(lines, path, expected):
    """A stdout that serves lines (a str, or a float to wait that many seconds first), then stays quiet, polling
    for up to 5 s until the position file holds `expected` (its line count) before it ends; the polls are returned."""
    class QuietStdout:
        def __init__(self):
            self.lines = list(lines)
            self.seen = []

        def readline(self, size=-1):
            while self.lines:
                item = self.lines.pop(0)
                if isinstance(item, float):
                    time.sleep(item)
                else:
                    return item
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    seen = json.loads(path.read_text())['line']
                except (OSError, ValueError):
                    seen = None
                self.seen.append(seen)
                if seen == expected:
                    break
                time.sleep(0.01)
            return ''
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
    stdout = _quiet_after([jline(0, 'HIT one'), jline(0, 'HIT two')], path, 2)
    _run_quiet(tmp_path, monkeypatch, stdout)
    # 'HIT two' only extended the open capture, so no save came with it: the quiet wait saved it
    assert stdout.seen[-1] == 2


def test_a_line_synced_on_commit_has_its_position_saved_while_the_journal_is_quiet(tmp_path, monkeypatch):
    # The line is read after the capture's sync interval, so the commit syncs it and nothing is left pending:
    # only the position's own deadline wakes the read.
    path = tmp_path / 'journal.position'
    stdout = _quiet_after([jline(0, 'HIT one'), 0.2, jline(0, 'HIT two')], path, 2)
    _run_quiet(tmp_path, monkeypatch, stdout)
    assert stdout.seen[-1] == 2


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
    popen = ScriptedPopen([(jline(0, 'HIT'), 0), (jline(0, 'a'), 0.25), (jline(0, 'b'), 0.25), (jline(1, 'c'), 0.75), (jline(1, 'd'), 0)], clock=clock)
    patch_popen(monkeypatch, popen)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=600, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0,
                        journal_position=Recording(str(tmp_path / 'journal.position'), now=T))
    assert len(unsynced_at_save) >= 2
    assert not any(unsynced_at_save)


def test_a_carriage_return_fragment_that_looks_like_a_stamp_is_harmless(tmp_path, monkeypatch):
    # journalctl --all passes a bare CR through, and reading text splits the line there
    position = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T)
    patch_popen(monkeypatch, ScriptedPopen([jline(0, 'before'), '0000-01-01T00:00:00Z poison\n', '2026-13-01T00:00:00Z poison\n', jline(1, 'after')]))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0, journal_position=position)
    assert json.loads((tmp_path / 'journal.position').read_text())['time'] == T + 1


def _stopped_run(tmp_path, monkeypatch, lines, stop_at=None):
    position = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T)
    real_write = fw.CaptureFile.write

    def write(self, text):
        if stop_at is not None and stop_at in text:
            raise KeyboardInterrupt  # where SIGINT or SIGTERM would land
        return real_write(self, text)

    monkeypatch.setattr(fw.CaptureFile, 'write', write)
    patch_popen(monkeypatch, ScriptedPopen(lines))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0, journal_position=position)
    monkeypatch.setattr(fw.CaptureFile, 'write', real_write)
    return fw.JournalPosition(str(tmp_path / 'journal.position'), now=T + 5)


def test_a_stop_while_a_line_is_handled_reads_it_again(tmp_path, monkeypatch):
    lines = [jline(0, 'HIT'), jline(0, 'post-1'), jline(1, 'post-2'), jline(1, 'post-3')]
    again = _stopped_run(tmp_path, monkeypatch, lines, stop_at='post-2')
    assert replay(again, lines) == ['old', 'old', 'new', 'new']


def test_a_stop_between_lines_keeps_the_last_one_read(tmp_path, monkeypatch):
    lines = [jline(0, 'HIT'), jline(0, 'post-1'), KeyboardInterrupt()]
    again = _stopped_run(tmp_path, monkeypatch, lines)
    assert replay(again, lines[:2] + [jline(1, 'next')]) == ['old', 'old', 'new']


def test_a_stop_after_a_match_is_captured_does_not_capture_it_again(tmp_path, monkeypatch):
    class StopAtOpen(fw.JournalPosition):
        stopped = False

        def save(self, now=None):
            if self.changed and not self.stopped:
                self.stopped = True
                raise KeyboardInterrupt  # lands as the capture that holds the match is saved
            super().save(now)

    patch_popen(monkeypatch, ScriptedPopen([jline(0, 'HIT'), jline(0, 'post-1')]))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0,
                        journal_position=StopAtOpen(str(tmp_path / 'journal.position'), now=T))
    again = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T + 5)
    assert replay(again, [jline(0, 'HIT'), jline(0, 'post-1')]) == ['old', 'new']


def test_a_stop_after_a_line_is_written_does_not_read_it_again(tmp_path, monkeypatch):
    real_end = fw._end_capture
    calls = []

    def stop_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt  # lands as the line cap ends the capture, after post-2 is written
        return real_end(*args, **kwargs)

    monkeypatch.setattr(fw, '_end_capture', stop_once)
    lines = [jline(0, 'HIT'), jline(0, 'post-1'), jline(0, 'post-2'), jline(1, 'post-3')]
    patch_popen(monkeypatch, ScriptedPopen(lines))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(tmp_path / 'out'),
                        compress_after_months=0, delete_after_months=0, capture_line_count_max=1,
                        journal_position=fw.JournalPosition(str(tmp_path / 'journal.position'), now=T))
    again = fw.JournalPosition(str(tmp_path / 'journal.position'), now=T + 5)
    assert replay(again, lines) == ['old', 'old', 'old', 'new']


@pytest.mark.parametrize('content', ['{"time": 1e400, "line": 1, "sha1": "x"}', '{"time": Infinity, "line": 1, "sha1": "x"}'])
def test_an_infinite_time_in_the_position_file_reads_the_last_lines(tmp_path, content):
    path = tmp_path / 'journal.position'
    path.write_text(content)
    position = fw.JournalPosition(str(path), now=T)
    assert position.since is None and 'Cannot read the journal position' in position.note


def test_save_never_follows_a_link_planted_where_the_file_is_written(tmp_path):
    victim = tmp_path / 'victim'
    victim.write_text('keep me')
    path = tmp_path / 'journal.position'
    (tmp_path / ('journal.position.%d.tmp' % os.getpid())).symlink_to(victim)
    position = fw.JournalPosition(str(path), now=T)
    position.saw(jline(0, 'a'), 100.0)
    position.save()
    assert victim.read_text() == 'keep me'
    assert json.loads(path.read_text())['time'] == T
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.endswith('.tmp')) == ['journal.position.%d.tmp' % os.getpid()]


def test_lines_logged_while_stopped_keep_their_own_time_as_context(tmp_path, monkeypatch):
    # 40 minutes of backlog, one line a minute, read in the same instant; then a match in it
    base = int(time.time()) - 2400
    lines = ['%s host app[1]: backlog %02d\n' % (time.strftime('%Y-%m-%dT%H:%M:%S+0000', time.gmtime(base + 60 * i)), i) for i in range(30)]
    lines.append('%s host app[1]: HIT in the backlog\n' % time.strftime('%Y-%m-%dT%H:%M:%S+0000', time.gmtime(base + 60 * 30 - 30)))
    patch_popen(monkeypatch, ScriptedPopen(lines))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    out = tmp_path / 'out'
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=120, output_folder=str(out),
                        compress_after_months=0, delete_after_months=0,
                        journal_position=fw.JournalPosition(str(tmp_path / 'journal.position')))
    text = incident_logs(out)[0].read_text()
    # the two minutes before the match, by the time each line was logged
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
        assert seen['journal_position'] is None and '--output=short-iso' not in seen['command']
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


def test_a_match_in_the_saved_second_keeps_its_own_time(tmp_path, monkeypatch):
    stopped = int(time.time()) - 600
    stamp = time.strftime('%Y-%m-%dT%H:%M:%S+0000', time.gmtime(stopped))
    saved_line = '%s host app[1]: last line read\n' % stamp
    end = fw._iso_stamp(saved_line)[1]
    path = tmp_path / 'journal.position'
    path.write_text(json.dumps({'time': stopped, 'line': 1, 'sha1': fw._line_digest(saved_line, end)}))
    patch_popen(monkeypatch, ScriptedPopen([saved_line, '%s host app[1]: HIT logged as it stopped\n' % stamp]))
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    out = tmp_path / 'out'
    fw.capture_messages(['unused'], fw.load_patterns([str(pat)]), capture_time=60, output_folder=str(out),
                        compress_after_months=0, delete_after_months=0, journal_position=fw.JournalPosition(str(path), context_time=60))
    assert 'Logs since %s' % datetime.datetime.fromtimestamp(stopped - 60).isoformat() in incident_logs(out)[0].read_text()
