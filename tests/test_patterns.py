import os

import firewatcher as fw

# --- pattern files / directories ---

def test_expand_pattern_sources_directory(tmp_path):
    d = tmp_path / 'patterns.d'
    d.mkdir()
    (d / 'b.regex').write_text('foo\n')
    (d / 'a.txt').write_text('panic\n')
    (d / '.hidden').write_text('secret\n')
    (d / 'README.md').write_text('ignore\n')
    (d / 'keep.fnmatch').write_text('bar\n')
    files = fw.expand_pattern_sources([str(d)])
    assert [os.path.basename(p) for p in files] == ['a.txt', 'b.regex', 'keep.fnmatch']


def test_expand_pattern_sources_keeps_plain_files(tmp_path):
    f = tmp_path / 'patterns.txt'
    f.write_text('panic\n')
    assert fw.expand_pattern_sources([str(f)]) == [str(f)]


def test_expand_skips_backup_readme_and_hidden(tmp_path):
    d = tmp_path / 'patterns.d'
    d.mkdir()
    (d / 'keep.txt').write_text('panic\n')
    (d / 'keep.txt~').write_text('old\n')
    (d / 'keep.txt.bak').write_text('old\n')
    (d / 'README').write_text('no\n')
    (d / 'readme.txt').write_text('no\n')
    (d / '.secret.regex').write_text('x\n')
    (d / 'subdir').mkdir()
    files = fw.expand_pattern_sources([str(d)])
    assert [os.path.basename(p) for p in files] == ['keep.txt']


def test_expand_mixes_files_and_directories(tmp_path):
    d = tmp_path / 'patterns.d'
    d.mkdir()
    (d / 'dir.txt').write_text('a\n')
    f = tmp_path / 'extra.txt'
    f.write_text('b\n')
    files = fw.expand_pattern_sources([str(f), str(d)])
    assert files[0] == str(f)
    assert files[1].endswith('dir.txt')


def test_expand_empty_directory(tmp_path):
    d = tmp_path / 'empty.d'
    d.mkdir()
    assert fw.expand_pattern_sources([str(d)]) == []


def test_is_pattern_filename_edges():
    assert fw._is_pattern_filename('ok.txt')
    assert fw._is_pattern_filename('nvme.regex')
    assert not fw._is_pattern_filename('')
    assert not fw._is_pattern_filename('.hidden')
    assert not fw._is_pattern_filename('foo~')
    assert not fw._is_pattern_filename('foo.bak')
    assert not fw._is_pattern_filename('README')
    assert not fw._is_pattern_filename('README.md')
    assert not fw._is_pattern_filename('readme.TXT')


def test_load_patterns_from_directory(tmp_path):
    d = tmp_path / 'patterns.d'
    d.mkdir()
    (d / 'sys.txt').write_text('panic\nI/O error\n')
    (d / 'nvme.regex').write_text(r'(?i)\<nvme\>.*fail\n')
    patterns = fw.load_patterns([str(d)])
    assert any(fnmatch_pat == '*panic*' for fnmatch_pat in patterns.get('fnmatch', ()))
    assert patterns.get('regex')


def test_load_patterns_wraps_fnmatch_and_skips_blank_lines(tmp_path):
    f = tmp_path / 'p.txt'
    f.write_text('\n\npanic\n  \nI/O error\n')
    patterns = fw.load_patterns([str(f)])
    assert patterns['fnmatch'] == {'*panic*', '*I/O error*'}


def test_load_patterns_regex_vs_fnmatch_by_extension(tmp_path):
    rx = tmp_path / 'p.regex'
    rx.write_text('kernel: nvme\n')
    plain = tmp_path / 'p.fnmatch'
    plain.write_text('panic\n')
    patterns = fw.load_patterns([str(rx), str(plain)])
    assert any(r.search('kernel: nvme timeout') for r in patterns['regex'])
    assert '*panic*' in patterns['fnmatch']
    assert fw.match_patterns('xx panic yy', patterns)
    assert not fw.match_patterns('kernel: nvme timeout', {'fnmatch': patterns['fnmatch']})


def test_load_patterns_skips_missing_file(tmp_path, capsys):
    missing = tmp_path / 'nope.txt'
    assert fw.load_patterns([str(missing)]) == {}
    assert 'Pattern file not found' in capsys.readouterr().out


def test_load_patterns_skips_invalid_regex(tmp_path, capsys):
    f = tmp_path / 'p.regex'
    f.write_text('(\nvalid_pattern\n')
    patterns = fw.load_patterns([str(f)])
    compiled = patterns.get('regex', set())
    assert any(r.pattern == 'valid_pattern' for r in compiled)
    assert not any(r.pattern == '(' for r in compiled)
    assert 'Invalid regex pattern' in capsys.readouterr().out


def test_load_patterns_unreadable_file(tmp_path, capsys):
    f = tmp_path / 'p.txt'
    f.write_text('panic\n')
    f.chmod(0)
    try:
        patterns = fw.load_patterns([str(f)])
    finally:
        f.chmod(0o644)
    if os.geteuid() == 0:
        # root can still read mode 000
        assert '*panic*' in patterns.get('fnmatch', set()) or patterns == {}
    else:
        assert patterns == {}
        assert 'Error reading pattern file' in capsys.readouterr().out


def test_expand_pattern_sources_empty_list():
    assert fw.expand_pattern_sources([]) == []


def test_load_patterns_empty_file(tmp_path):
    f = tmp_path / 'empty.txt'
    f.write_text('')
    assert fw.load_patterns([str(f)]) == {'fnmatch': set()}


def test_load_patterns_open_error(tmp_path, capsys, monkeypatch):
    import builtins
    f = tmp_path / 'p.txt'
    f.write_text('panic\n')
    real_open = builtins.open

    def fake_open(path, *a, **k):
        if os.path.abspath(str(path)) == os.path.abspath(str(f)):
            raise PermissionError('denied')
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, 'open', fake_open)
    assert fw.load_patterns([str(f)]) == {}
    assert 'Error reading pattern file' in capsys.readouterr().out


def test_seed_skips_existing_dest_even_if_not_a_pattern_file(tmp_path):
    d = tmp_path / 'patterns.d'
    d.mkdir()
    (d / 'sys_msg.txt').mkdir()
    fw._seed_example_patterns([str(d)])
    assert (d / 'sys_msg.txt').is_dir()
    assert (d / 'nvme_failure.regex').is_file()
