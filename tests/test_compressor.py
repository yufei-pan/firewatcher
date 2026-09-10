import datetime

import firewatcher as fw

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
