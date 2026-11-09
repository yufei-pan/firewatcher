import datetime
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
    fw.Log_Compressor(str(logs), compressAfterMonths=1, deleteLogAfterMonths=0)
    with tarfile.open(str(logs / '2020-01.tar.xz')) as archive:
        assert archive.getnames() == ['2020-01', '2020-01/x.log']


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
