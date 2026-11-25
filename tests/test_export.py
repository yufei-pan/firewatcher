import io
import json
import time

import pytest

import firewatcher as fw

# --- journalctl -o export, written as -o short-iso lines ---

T = 1_800_000_000  # 2027-01-15T08:00:00Z
BOOT = 'b' * 32
SEQNUM = 'a' * 32


def cursor(n):
    return 's=%s;i=%x;b=%s;m=%x;t=%x;x=%016x' % (SEQNUM, n, BOOT, n, (T + n) * 1000000, n)


def field(name, value):
    """One field as journalctl -o export writes it: NAME=value, or a binary field for a value with a newline or
    bytes that are not printable."""
    if isinstance(value, str):
        value = value.encode('utf-8')
    if b'\n' in value or any(b < 32 and b != 9 for b in value):
        return name.encode() + b'\n' + len(value).to_bytes(8, 'little') + value + b'\n'
    return name.encode() + b'=' + value + b'\n'


def entry(n, text=None, stored=None, sent=None, host='host', ident='app', pid='1', **extra):
    """The export of entry n: stored at T + n (or stored), shown at sent when given."""
    stored = T + n if stored is None else stored
    out = field('__CURSOR', cursor(n)) + field('__REALTIME_TIMESTAMP', str(stored * 1000000 + 123456))
    out += field('__MONOTONIC_TIMESTAMP', '1') + field('_BOOT_ID', BOOT)
    if sent is not None:
        out += field('_SOURCE_REALTIME_TIMESTAMP', str(sent * 1000000))
    for name, value in (('_HOSTNAME', host), ('SYSLOG_IDENTIFIER', ident), ('_PID', pid)):
        if value is not None:
            out += field(name, value)
    for name, value in extra.items():
        out += field(name, value)
    if text is not None:
        out += field('MESSAGE', text)
    return out + b'\n'


def lines_of(data, skip_cursor=None, limit=-1):
    reader = fw._ExportReader(io.BytesIO(data), skip_cursor=skip_cursor)
    out = []
    while True:
        line = reader.readline(limit)
        if not line:
            return out
        out.append((line, reader.cursor, reader.stored))


def shown(when):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(when)) + _offset(when)


def _offset(when):
    minutes = time.localtime(when).tm_gmtoff // 60
    return '%s%02d:%02d' % ('-' if minutes < 0 else '+', abs(minutes) // 60, abs(minutes) % 60)


def test_an_entry_reads_as_its_short_iso_line_with_its_cursor_and_stored_second():
    assert lines_of(entry(1, 'hello')) == [('%s host app[1]: hello\n' % shown(T + 1), cursor(1), T + 1)]


def test_the_shown_time_is_the_time_sent_and_the_position_the_time_stored():
    [(line, _, stored)] = lines_of(entry(5, 'late', sent=T - 100))
    assert line.startswith(shown(T - 100) + ' ') and stored == T + 5


@pytest.mark.parametrize('kwargs, prefix', [
    ({'ident': None, '_COMM': 'comm'}, 'host comm[1]: '),
    ({'ident': None}, 'host unknown[1]: '),
    ({'pid': None, 'SYSLOG_PID': '7'}, 'host app[7]: '),
    ({'pid': None}, 'host app: '),
    ({'host': None}, 'app[1]: '),
])
def test_the_prefix_falls_back_as_journalctl_does(kwargs, prefix):
    [(line, _, _)] = lines_of(entry(1, 'x', **kwargs))
    assert line == '%s %sx\n' % (shown(T + 1), prefix)


def test_a_multi_line_message_continues_indented_by_the_prefix():
    got = lines_of(entry(1, 'first\nsecond'))
    prefix = '%s host app[1]: ' % shown(T + 1)
    assert [line for line, _, _ in got] == [prefix + 'first\n', ' ' * len(prefix) + 'second\n']
    # every line of an entry names that entry
    assert {(c, s) for _, c, s in got} == {(cursor(1), T + 1)}


def test_text_that_is_not_utf_8_is_replaced_and_non_ascii_text_kept():
    got = lines_of(entry(1, b'bad \xff byte') + entry(2, 'café → ok'))
    assert got[0][0].endswith('bad � byte\n') and got[1][0].endswith('café → ok\n')


def test_an_entry_without_a_message_prints_nothing_and_a_carriage_return_does_not_end_a_line():
    got = lines_of(entry(1) + entry(2, 'a\rb'))
    assert [line for line, _, _ in got] == ['%s host app[1]: a\rb\n' % shown(T + 2)]


def test_unknown_fields_and_lines_that_are_not_fields_are_passed_over():
    data = entry(1, 'one', OTHER_BLOB=b'\x00' * 100000)
    data = data[:-1] + b'not a field line\n' + b'\n' + entry(2, 'two')
    assert [line.split(': ', 1)[1] for line, _, _ in lines_of(data)] == ['one\n', 'two\n']


def test_the_saved_entry_is_dropped_only_when_it_comes_first():
    data = entry(1, 'saved') + entry(2, 'next')
    assert [c for _, c, _ in lines_of(data, skip_cursor=cursor(1))] == [cursor(2)]
    assert [c for _, c, _ in lines_of(data, skip_cursor=cursor(2))] == [cursor(1), cursor(2)]


def test_a_line_longer_than_the_limit_comes_in_pieces():
    got = lines_of(entry(1, 'x' * 50), limit=40)
    assert ''.join(line for line, _, _ in got) == '%s host app[1]: %s\n' % (shown(T + 1), 'x' * 50)
    assert len(got) > 1


def test_an_entry_cut_off_by_the_end_of_the_output_is_not_read():
    assert lines_of(entry(1, 'whole') + entry(2, 'cut')[:-1]) == [lines_of(entry(1, 'whole'))[0]]


# --- the position file and the start ---

def write_position(tmp_path, record):
    path = tmp_path / 'journal.position'
    path.write_text(record if isinstance(record, str) else json.dumps(record))
    return str(path)


def no_journalctl(monkeypatch):
    """The constructor only reads the file: starting journalctl fails the test."""
    def popen(*args, **kwargs):
        raise AssertionError('journalctl started by the constructor')

    monkeypatch.setattr(fw.subprocess, 'Popen', popen)


def test_a_saved_entry_is_where_the_read_starts(tmp_path, monkeypatch):
    no_journalctl(monkeypatch)
    path = write_position(tmp_path, {'cursor': cursor(0), 'time': T})
    position = fw.JournalPosition(path, context_time=60, now=T + 10)
    # whether the journal still holds it is for the read from it to say
    assert position.cursor == cursor(0) and position.since is None and position.note is None
    assert position.context_since == T - 60 and position.saved_time == T


@pytest.mark.parametrize('now, context_time, resume_max, since', [
    (T + 10, 60, 3600, T - 60),  # capture_time before the saved entry
    (T + 3500, 300, 3600, T - 100),  # capture_time would reach past --resume-max: no further back than that
    (T + 5, 300, 10, T - 5),
    (T - 3600, 300, 3600, T - 300),  # a clock set back: the bound is behind the saved entry and changes nothing
])
def test_the_context_is_read_back_no_further_than_resume_max(tmp_path, monkeypatch, now, context_time, resume_max, since):
    no_journalctl(monkeypatch)
    path = write_position(tmp_path, {'cursor': cursor(0), 'time': T})
    position = fw.JournalPosition(path, resume_max=resume_max, context_time=context_time, now=now)
    assert position.context_since == since
    if now > T - 60:
        # the journal lost the entry: the read by time starts there too
        position.lost(now)
        assert position.since == since and position.cursor is None


def test_a_saved_entry_still_there_resumes_whatever_the_clock_says(tmp_path, monkeypatch):
    no_journalctl(monkeypatch)
    position = fw.JournalPosition(write_position(tmp_path, {'cursor': cursor(0), 'time': T}), now=T - 3600)
    assert position.cursor == cursor(0)


@pytest.mark.parametrize('record', [
    {'time': T, 'line': 1, 'sha1': 'x' * 40},  # 1.69's file
    {'cursor': 's=1;--since=@0', 'time': T},
    {'cursor': cursor(0) + '\n', 'time': T},
    {'cursor': 7, 'time': T},
])
def test_a_file_without_a_usable_cursor_goes_by_its_time(tmp_path, monkeypatch, record):
    no_journalctl(monkeypatch)
    position = fw.JournalPosition(write_position(tmp_path, record), context_time=60, now=T + 10)
    assert position.cursor is None and position.since == T - 60
    assert position.note.startswith('Cannot find the last entry read before the stop (')
    assert 'no longer holds' not in position.note


def test_an_entry_the_journal_no_longer_holds_goes_by_its_time(tmp_path, monkeypatch):
    no_journalctl(monkeypatch)
    position = fw.JournalPosition(write_position(tmp_path, {'cursor': cursor(0), 'time': T}), context_time=60, now=T + 10)
    position.lost(T + 10)
    assert position.cursor is None and position.since == T - 60
    assert 'Cannot find the last entry read before the stop' in position.note


def test_the_future_rule_holds_only_where_the_entry_is_gone(tmp_path, monkeypatch):
    no_journalctl(monkeypatch)
    position = fw.JournalPosition(write_position(tmp_path, {'cursor': cursor(0), 'time': T}), now=T - 3600)
    assert position.cursor == cursor(0) and position.note is None
    position.lost(T - 3600)
    assert position.since is None and position.cursor is None and 'is in the future' in position.note


@pytest.mark.parametrize('content', ['', 'not json', '{"cursor": "x"}', '{"time": "soon"}', '{"time": 1e400}', '[]'])
def test_a_damaged_file_reads_the_last_lines(tmp_path, monkeypatch, content):
    no_journalctl(monkeypatch)
    position = fw.JournalPosition(write_position(tmp_path, content), now=T)
    assert position.since is None and position.cursor is None
    assert 'Cannot read the journal position' in position.note


def test_an_old_position_reads_back_only_resume_max_without_the_cursor(tmp_path, monkeypatch):
    no_journalctl(monkeypatch)
    position = fw.JournalPosition(write_position(tmp_path, {'cursor': cursor(0), 'time': T}), resume_max=600, now=T + 3600)
    assert position.cursor is None and position.since == T + 3000 and 'seconds old' in position.note


def test_saw_saves_the_cursor_and_stored_second_and_unsee_takes_it_back(tmp_path):
    path = tmp_path / 'journal.position'
    position = fw.JournalPosition(str(path), now=T)
    position.saw(cursor(1), T + 1, 100.0)
    assert not path.exists()  # saved when the next line comes, so a save covers only handled lines
    position.saw(cursor(1), T + 1, 100.5)  # a later line of the same entry
    assert json.loads(path.read_text()) == {'cursor': cursor(1), 'time': T + 1}
    position.saw(cursor(2), T + 2, 100.6)
    position.unsee()
    position.save()
    assert json.loads(path.read_text()) == {'cursor': cursor(1), 'time': T + 1}
