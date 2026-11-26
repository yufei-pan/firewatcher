import datetime
import os
import stat
import tarfile
import threading
import time

import firewatcher as fw
from conftest import capture

# --- compressor ---

def test_log_compressor_deletes_every_old_month(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    for name in ('2020-01', '2020-02', '2020-03'):
        d = logs / name
        d.mkdir()
        (d / 'x.log').write_text('x')
    fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=1)
    left = {p.name for p in logs.iterdir()}
    assert '2020-01' not in left
    assert '2019-11' not in left
    assert '2019-12' not in left
    assert '2020-02' not in left
    assert '2020-03' not in left


def test_log_compressor_compresses_every_old_month(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    for name in ('2020-01', '2020-02', '2020-03'):
        d = logs / name
        d.mkdir()
        (d / 'x.log').write_text('x')
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    names = sorted(p.name for p in logs.iterdir())
    assert names == ['2020-01.tar.xz', '2020-02.tar.xz', '2020-03.tar.xz']


def test_log_compressor_keeps_current_month(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    current = datetime.datetime.now().strftime('%Y-%m')
    (logs / current).mkdir()
    (logs / current / 'x.log').write_text('x')
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=1)
    assert (logs / current).is_dir()


def test_log_compressor_deletes_old_tarballs_and_ignores_other_names(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    old = logs / '2020-01.tar.xz'
    old.write_bytes(b'not-a-real-tar')
    (logs / 'readme.txt').write_text('keep')
    (logs / 'journal.log').write_text('keep')
    fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=1)
    left = {p.name for p in logs.iterdir()}
    assert '2020-01.tar.xz' not in left
    assert 'readme.txt' in left
    assert 'journal.log' in left


def test_log_compressor_skips_rerun_within_48h(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    d = logs / '2020-01'
    d.mkdir()
    (d / 'x.log').write_text('x')
    c = fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=1)
    assert not (logs / '2020-01').exists()
    later = logs / '2019-06'
    later.mkdir()
    (later / 'x.log').write_text('x')
    c.compressLogs()
    assert later.is_dir()


def test_log_compressor_missing_dir_is_ok(tmp_path):
    fw.Log_Compressor(str(tmp_path / 'missing'), compressAfterMonths=3, deleteLogAfterMonths=1)


def test_log_compressor_deletes_plain_files_and_symlinks(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    (logs / '2020-01').write_text('plain-file')
    (logs / '2019-11').write_text('another-file')
    (logs / '2019-12').write_text('third-file')
    target = tmp_path / 'target-file'
    target.write_text('keep-target')
    (logs / '2020-02').symlink_to(target)
    fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=1)
    left = {p.name for p in logs.iterdir()}
    assert '2020-01' not in left
    assert '2019-11' not in left
    assert '2019-12' not in left
    assert '2020-02' not in left
    assert target.read_text() == 'keep-target'


def test_log_compressor_does_not_tar_nondirectory_month_name(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    (logs / '2020-03').write_text('not-a-dir')
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert (logs / '2020-03').is_file()
    assert not (logs / '2020-03.tar.xz').exists()


def month_dirs(tmp_path, *names):
    logs = tmp_path / 'logs'
    logs.mkdir()
    for name in names:
        (logs / name).mkdir()
        (logs / name / 'x.log').write_text('x')
    return logs


def test_log_compressor_archives_relative_paths(tmp_path):
    logs = month_dirs(tmp_path, '2020-01')
    # the mode tar's own create gave it in 1.72: 0666 less the umask (the exclusive create must not narrow it)
    old_umask = os.umask(0o022)
    try:
        fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    finally:
        os.umask(old_umask)
    with tarfile.open(str(logs / '2020-01.tar.xz')) as archive:
        assert archive.getnames() == ['2020-01', '2020-01/x.log']
    assert stat.S_IMODE((logs / '2020-01.tar.xz').stat().st_mode) == 0o644


def test_log_compressor_keeps_the_month_when_tar_fails(tmp_path, monkeypatch, capsys):
    logs = month_dirs(tmp_path, '2020-01')

    def failing_tar(cmd, **kwargs):
        open(cmd[2], 'wb').close()  # the half-written archive

        class Result:
            returncode = 2
        return Result()

    monkeypatch.setattr(fw.subprocess, 'run', failing_tar)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    # one partial file per process, so two firewatchers on one folder never write the same file
    assert not list(logs.glob('*.partial'))
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01']
    assert (logs / '2020-01' / 'x.log').read_text() == 'x'
    assert 'tar exited 2' in capsys.readouterr().out


def test_log_compressor_removes_the_partial_when_tar_cannot_be_started(tmp_path, monkeypatch, capsys):
    # tar not on PATH, or a fork refused: the empty file the exclusive create made would stay, and keep its month out
    # of a free-space purge for a day
    logs = month_dirs(tmp_path, '2020-01', '2020-02')

    def no_tar(cmd, **kwargs):
        raise FileNotFoundError(fw.errno.ENOENT, 'No such file or directory', 'tar')

    monkeypatch.setattr(fw.subprocess, 'run', no_tar)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01', '2020-02']
    assert (logs / '2020-01' / 'x.log').read_text() == 'x'
    assert 'Compressing logs in %s failed: [Errno 2] No such file or directory' % logs in capsys.readouterr().out


def test_log_compressor_never_overwrites_an_archive(tmp_path):
    logs = month_dirs(tmp_path, '2020-01')
    (logs / '2020-01.tar.xz').write_bytes(b'older archive')
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01.1.tar.xz', '2020-01.tar.xz']
    assert (logs / '2020-01.tar.xz').read_bytes() == b'older archive'


def test_log_compressor_reports_errors_and_waits_for_the_next_interval(tmp_path, monkeypatch, capsys):
    logs = month_dirs(tmp_path, '2020-01')

    def unreadable(path):
        raise OSError(116, 'Stale file handle')

    monkeypatch.setattr(fw.os, 'listdir', unreadable)
    c = fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert 'Stale file handle' in capsys.readouterr().out
    assert c.lastProcessTime > 0


def test_log_compressor_in_background(tmp_path):
    logs = month_dirs(tmp_path, '2020-01')
    c = fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0, background=True)
    first = c.worker
    first.join(60)
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01.tar.xz']
    c.startCompressLogs()
    assert c.worker is first  # within the interval
    running = threading.Event()
    blocker = threading.Thread(target=running.wait)
    blocker.start()
    try:
        c.worker = blocker
        c.lastProcessTime = 0
        c.startCompressLogs()
        assert c.worker is blocker  # one run at a time
    finally:
        running.set()
        blocker.join()


def test_log_compressor_syncs_the_partial_archive_before_removing_the_month(tmp_path, monkeypatch):
    logs = month_dirs(tmp_path, '2020-01')
    synced = []
    real = fw._fsync_path

    def recording(path):
        synced.append((path, (logs / '2020-01').is_dir()))
        real(path)

    monkeypatch.setattr(fw, '_fsync_path', recording)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert synced == [(str(logs / ('2020-01.tar.xz.%d.partial' % fw.os.getpid())), True), (str(logs), True)]
    assert not (logs / '2020-01').exists()


def test_log_compressor_orders_sync_rename_sync_remove(tmp_path, monkeypatch):
    # XFS does not flush a file's data on rename: the archive's data must be synced before it gets its final name.
    logs = month_dirs(tmp_path, '2020-01')
    events = []
    real_fsync, real_replace, real_rmtree = fw.os.fsync, fw.os.replace, fw.shutil.rmtree
    names = {}
    real_open = fw.os.open

    def opening(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        names[fd] = path
        return fd

    def fsync(fd):
        events.append(('fsync', names.get(fd)))
        real_fsync(fd)

    monkeypatch.setattr(fw.os, 'open', opening)
    monkeypatch.setattr(fw.os, 'fsync', fsync)
    monkeypatch.setattr(fw.os, 'replace', lambda a, b: events.append(('replace', a, b)) or real_replace(a, b))
    monkeypatch.setattr(fw.shutil, 'rmtree', lambda path: events.append(('rmtree', path)) or real_rmtree(path))
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    partial = str(logs / ('2020-01.tar.xz.%d.partial' % fw.os.getpid()))
    assert events == [
        ('fsync', partial),
        ('replace', partial, str(logs / '2020-01.tar.xz')),
        ('fsync', str(logs)),
        ('rmtree', str(logs / '2020-01')),
    ]


def test_log_compressor_keeps_the_month_when_a_sync_fails(tmp_path, monkeypatch, capsys):
    # Only the first sync (the data), then only the second (the directory), fail: the month stays both times.
    for failing in (1, 2):
        sub = tmp_path / str(failing)
        sub.mkdir()
        logs = month_dirs(sub, '2020-01')
        calls = []
        real = fw.os.fsync

        def fsync(fd, failing=failing, calls=calls, real=real):
            calls.append(fd)
            if len(calls) == failing:
                raise OSError(fw.errno.EIO, 'Input/output error')
            real(fd)

        monkeypatch.setattr(fw.os, 'fsync', fsync)
        fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
        assert (logs / '2020-01' / 'x.log').read_text() == 'x'
        assert 'failed' in capsys.readouterr().out
        if failing == 1:
            # a later process has another pid and would never reuse the partial's name
            assert not list(logs.glob('*.partial'))
            assert not list(logs.glob('*.tar.xz'))


def test_log_compressor_removes_the_partial_when_the_rename_fails(tmp_path, monkeypatch, capsys):
    logs = month_dirs(tmp_path, '2020-01')

    def failing_replace(src, dst):
        raise OSError(fw.errno.EIO, 'Input/output error')

    monkeypatch.setattr(fw.os, 'replace', failing_replace)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01']
    assert (logs / '2020-01' / 'x.log').read_text() == 'x'


def test_fsync_path_tolerates_filesystems_without_fsync(tmp_path, monkeypatch):
    def unsupported(fd):
        raise OSError(fw.errno.EINVAL, 'Invalid argument')

    monkeypatch.setattr(fw.os, 'fsync', unsupported)
    fw._fsync_path(str(tmp_path))


def test_partial_archive_name_is_per_process(tmp_path, monkeypatch):
    logs = month_dirs(tmp_path, '2020-01')
    commands = []
    real_run = fw.subprocess.run
    monkeypatch.setattr(fw.subprocess, 'run', lambda cmd, **kw: commands.append(cmd) or real_run(cmd, **kw))
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert commands[0][2] == str(logs / ('2020-01.tar.xz.%d.partial' % fw.os.getpid()))


def aged(path, seconds):
    """Make path look last changed that many seconds ago (a symlink itself, not its target)."""
    then = time.time() - seconds
    fw.os.utime(str(path), (then, then), follow_symlinks=False)


DAY = fw.RECENT_MONTH_ACTIVITY


def test_a_compression_run_removes_a_partial_archive_unchanged_for_a_day(tmp_path, capsys):
    # 1.72 kept it, archive-sized, until a purge removed its month: a stop or a crash while tar wrote it
    logs = month_dirs(tmp_path, '2020-01')
    stale = logs / '2020-01.tar.xz.4242.partial'
    other = logs / '2019-12.1.tar.xz.17.partial'
    for path in (stale, other):
        path.write_bytes(b'x' * 4096)
        aged(path, DAY + 60)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01.tar.xz']
    printed = capsys.readouterr().out
    assert 'Removing 2020-01.tar.xz.4242.partial, left by a compression that was stopped' in printed
    assert 'Removing 2019-12.1.tar.xz.17.partial' in printed


def test_a_partial_archive_changed_in_the_last_day_is_kept(tmp_path):
    # another firewatcher sharing the folder (another host, another container: its pid says nothing here) may be
    # writing it, and so may this process
    logs = tmp_path / 'logs'
    logs.mkdir()
    fresh = logs / '2020-01.tar.xz.4242.partial'
    mine = logs / ('2020-02.tar.xz.%d.partial' % fw.os.getpid())
    for path in (fresh, mine):
        path.write_bytes(b'being written')
        aged(path, DAY - 60)
    fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=0)
    assert fresh.read_bytes() == b'being written'
    assert mine.read_bytes() == b'being written'


def test_a_stale_partial_archive_with_this_process_pid_is_removed_too(tmp_path):
    # a container's firewatcher gets the same pid at each start, so an earlier run's file can carry this pid; no
    # compression of this process is running in the folder when its run starts, and the month is compressed after it
    logs = month_dirs(tmp_path, '2020-01')
    mine = logs / ('2020-01.tar.xz.%d.partial' % fw.os.getpid())
    mine.write_bytes(b'left by an earlier run')
    aged(mine, DAY + 60)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert sorted(p.name for p in logs.iterdir()) == ['2020-01.tar.xz']
    with tarfile.open(str(logs / '2020-01.tar.xz')) as archive:
        assert archive.getnames() == ['2020-01', '2020-01/x.log']


def test_a_partial_archive_name_already_taken_is_never_written(tmp_path, monkeypatch):
    # another firewatcher sharing the folder, with this pid (another host or container; a container's firewatcher
    # has the same pid at every start), may be writing it: 1.72's tar wrote the same file, and with single-threaded
    # xz (EL7, EL8) the archive came out corrupt and the month removed. The month is compressed under the next
    # number free, not skipped: a skipped one waited for the leftover to be a day old.
    logs = month_dirs(tmp_path, '2020-01')
    pid = fw.os.getpid()
    taken = [logs / ('2020-01.tar.xz.%d.partial' % number) for number in (pid, pid + 1)]
    for path in taken:
        path.write_bytes(b'another tar is writing this')
    commands = []
    real_run = fw.subprocess.run
    monkeypatch.setattr(fw.subprocess, 'run', lambda cmd, **kw: commands.append(cmd) or real_run(cmd, **kw))
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert [cmd[2] for cmd in commands] == [str(logs / ('2020-01.tar.xz.%d.partial' % (pid + 2)))]
    for path in taken:
        assert path.read_bytes() == b'another tar is writing this'
    assert sorted(p.name for p in logs.iterdir()) == sorted(['2020-01.tar.xz'] + [path.name for path in taken])
    with tarfile.open(str(logs / '2020-01.tar.xz')) as archive:
        assert archive.getnames() == ['2020-01', '2020-01/x.log']


def test_removing_stale_partial_archives_touches_nothing_else(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    (logs / '2019-12').mkdir()
    (logs / '2019-12' / 'x.log').write_text('x')
    for name in ('2019-12.tar.xz', '2019-12.1.tar.xz', '2019-12.tar.xz.partial', '2019-13.tar.xz.5.partial',
                 '2019-12.tar.xz.5.partial.bak', '2019-12.tar.5.partial', 'notes.partial', 'journal.log'):
        (logs / name).write_text('keep')
    # named like one, but not the regular file firewatcher writes
    (logs / '2019-11.tar.xz.6.partial').mkdir()
    (logs / '2019-11.tar.xz.6.partial' / 'y').write_text('keep')
    target = tmp_path / 'target'
    target.write_text('keep')
    (logs / '2019-10.tar.xz.7.partial').symlink_to(target)
    before = sorted(p.name for p in logs.iterdir())
    for path in list(logs.iterdir()) + [target, logs / '2019-12' / 'x.log', logs / '2019-11.tar.xz.6.partial' / 'y']:
        aged(path, DAY + 60)
    fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=0)
    assert sorted(p.name for p in logs.iterdir()) == before
    assert target.read_text() == 'keep'
    assert (logs / '2019-11.tar.xz.6.partial' / 'y').read_text() == 'keep'


def test_a_partial_archive_that_cannot_be_removed_does_not_stop_the_run(tmp_path, monkeypatch, capsys):
    logs = month_dirs(tmp_path, '2020-01')
    stale = logs / '2019-12.tar.xz.4242.partial'
    stale.write_bytes(b'x')
    aged(stale, DAY + 60)
    real = fw.os.remove

    def remove(path):
        if str(path).endswith('.partial'):
            raise OSError(fw.errno.EACCES, 'Permission denied')
        real(path)

    monkeypatch.setattr(fw.os, 'remove', remove)
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    assert 'Removing 2019-12.tar.xz.4242.partial failed: [Errno %d] Permission denied' % fw.errno.EACCES in capsys.readouterr().out
    assert sorted(p.name for p in logs.iterdir()) == ['2019-12.tar.xz.4242.partial', '2020-01.tar.xz']


def test_a_stale_partial_archive_of_a_month_a_purge_holds_is_left_to_it(tmp_path):
    logs = tmp_path / 'logs'
    logs.mkdir()
    compressor = fw.Log_Compressor(str(logs), compressAfterMonths=0, deleteLogAfterMonths=0)
    stale = logs / '2019-12.tar.xz.4242.partial'
    stale.write_bytes(b'x')
    aged(stale, DAY + 60)
    assert compressor._claim('2019-12')  # a purge is deleting that month
    compressor.lastProcessTime = 0
    compressor.compressLogs()
    assert stale.exists()
    compressor._release('2019-12')
    compressor.lastProcessTime = 0
    compressor.compressLogs()
    assert not stale.exists()


def test_stale_partial_archives_go_before_the_compression_asks_for_room(tmp_path):
    logs = month_dirs(tmp_path, '2020-01')
    stale = logs / '2019-12.tar.xz.4242.partial'
    stale.write_bytes(b'x')
    aged(stale, DAY + 60)
    seen = []

    class Recording(fw.DiskGuard):
        def can_spend(self, folder, nbytes):
            seen.append(stale.exists())
            return False

    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0, guard=Recording(10))
    assert seen == [False]


def test_run_that_reads_to_the_end_finishes_compressing(tmp_path, monkeypatch):
    out = tmp_path / 'out'
    out.mkdir()
    (out / '2020-01').mkdir()
    (out / '2020-01' / 'x.log').write_text('x')
    real = fw.Log_Compressor.compressLogs

    def slow(self):
        time.sleep(0.3)
        real(self)

    monkeypatch.setattr(fw.Log_Compressor, 'compressLogs', slow)
    capture(tmp_path, 'noise\n', compress_after_months=1)
    assert (out / '2020-01.tar.xz').is_file()
    assert not (out / '2020-01').exists()
