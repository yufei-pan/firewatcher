#!/usr/bin/env python3
"""Tests for firewatcher: patterns, capture loop, compressor, systemd helpers, CLI."""
import datetime
import os
import re

import pytest

import firewatcher as fw


def _args(argv):
	return fw.build_parser().parse_args(argv)


def _ok_systemctl(*cmd):
	class R:
		returncode = 0
	return R()


def _systemctl_recorder(calls, returncode=0):
	def fake(*cmd):
		calls.append(cmd)
		class R:
			pass
		R.returncode = returncode if not callable(returncode) else returncode(cmd)
		return R()
	return fake


def _write_log(tmp_path, text, name='src.log'):
	src = tmp_path / name
	if isinstance(text, bytes):
		src.write_bytes(text)
	else:
		src.write_text(text)
	return src


def _capture(tmp_path, lines, pattern='HIT', regex=False, **kw):
	pat = tmp_path / ('p.regex' if regex else 'p.txt')
	pat.write_text(pattern if pattern.endswith('\n') else pattern + '\n')
	src = _write_log(tmp_path, lines)
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


def _incident_logs(out):
	return sorted(p for p in out.rglob('*.log') if p.name != 'journal.log')


def _fake_exists(syslog=False, messages=False):
	real = os.path.exists
	def exists(path):
		if path == '/var/log/syslog':
			return syslog
		if path == '/var/log/messages':
			return messages
		return real(path)
	return exists


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


# --- matching ---

def test_match_fnmatch_and_regex():
	patterns = {
		'fnmatch': {'*I/O error*'},
		'regex': {re.compile(r'nvme\d+n\d+')},
	}
	assert fw.match_patterns('sd 0:0: I/O error', patterns)
	assert fw.match_patterns('nvme0n1: reset', patterns)
	assert not fw.match_patterns('nothing to see', patterns)


def test_get_matched_pattern_returns_regex_span_or_fnmatch():
	patterns = {
		'regex': {re.compile(r'nvme\d+n\d+')},
		'fnmatch': {'*panic*'},
	}
	assert fw.get_matched_pattern('host nvme0n1 timeout', patterns) == 'nvme0n1'
	assert fw.get_matched_pattern('kernel panic', {'fnmatch': {'*panic*'}}) == '*panic*'
	assert fw.get_matched_pattern('nope', patterns) is None


def test_own_log_line_skips_syslog_identifier_not_random_substring():
	patterns = {'fnmatch': {'*error*'}}
	assert fw.match_patterns('host firewatcher[12]: Capturing logs to /tmp/error', patterns) is False
	assert fw.match_patterns('kernel: hardware error on disk', patterns) is True


def test_own_log_line_skips_module_path():
	base = os.path.basename(fw.__file__)
	assert fw._is_own_log_line('Traceback in /usr/lib/' + base)
	assert not fw._is_own_log_line('kernel: watchdog sensor online')
	assert fw._is_own_log_line('box firewatcher[12]: x')
	assert not fw._is_own_log_line('box firewatcher: missing pid')


def test_example_nvme_regex_matches_kernel_lines():
	pat = re.compile(fw.EXAMPLE_PATTERNS['nvme_failure.regex'].strip())
	assert pat.search('kernel: nvme timeout')
	assert pat.search('kernel: nvme0n1: I/O timeout')
	assert pat.search('nvme reset controller')
	assert pat.search('NVMe fail')
	assert pat.search('nvme1n1 abort')
	assert pat.search('kernel: nvme unable to')
	assert not pat.search('firewire timeout')
	assert not pat.search('<nvme> timeout')
	assert not pat.search('kernel: nvme')
	assert not pat.search('renamed vme timeout')


def test_example_sys_msg_fnmatch_hits():
	patterns = {'fnmatch': {f'*{line}*' for line in fw.EXAMPLE_PATTERNS['sys_msg.txt'].splitlines() if line}}
	assert fw.match_patterns('kernel panic - not syncing', patterns)
	assert fw.match_patterns('sd 1:0:0:0: I/O error', patterns)
	assert fw.match_patterns('Out of Memory: Kill process', patterns)
	assert fw.match_patterns('Call Trace:', patterns)
	assert not fw.match_patterns('unrelated info line', patterns)


def test_example_pattern_files_match_embedded_constants():
	root = os.path.dirname(os.path.abspath(fw.__file__))
	for name, content in fw.EXAMPLE_PATTERNS.items():
		path = os.path.join(root, 'examples', name)
		assert os.path.isfile(path)
		assert open(path, encoding='utf-8').read() == content
	assert 'nebula' not in fw.EXAMPLE_PATTERNS['sys_msg.txt'].lower()
	assert 'nebula' not in fw.EXAMPLE_PATTERNS['nvme_failure.regex'].lower()


# --- slugify ---

def test_slugify_truncates_long_matches():
	slug = fw.slugify('nvme ' + ('timeout-' * 40))
	assert len(slug) <= fw.SLUG_MAX_LEN
	assert slug


def test_slugify_normalizes_and_strips():
	assert fw.slugify('  Panic: I/O error!!  ') == 'panic-io-error'
	assert fw.slugify('café') == 'cafe'
	uni = fw.slugify('café', allow_unicode=True)
	assert uni in ('café', 'cafe')
	assert fw.slugify('---') == ''
	assert len(fw.slugify('a' * (fw.SLUG_MAX_LEN + 20))) == fw.SLUG_MAX_LEN


# --- capture loop ---

def test_capture_messages_returns_on_eof(tmp_path):
	out = _capture(tmp_path, 'noise\nPANICMARK here\nmore noise\n', pattern='PANICMARK')
	logs = list(out.rglob('*.log'))
	assert logs
	text = ''.join(p.read_text() for p in logs)
	assert 'PANICMARK' in text


def test_capture_messages_default_output_folder_matches_cli():
	import inspect
	defaults = inspect.signature(fw.capture_messages).parameters
	assert defaults['output_folder'].default == fw.DEFAULT_OUTPUT_FOLDER
	assert fw.DEFAULT_OUTPUT_FOLDER == '/var/log/captured_messages/'


def test_matching_lines_count_toward_capture_cap(tmp_path):
	out = _capture(tmp_path, 'HIT 1\nHIT 2\nHIT 3\nHIT 4\nHIT 5\n', capture_line_count_max=2)
	caps = _incident_logs(out)
	assert caps
	text = caps[0].read_text()
	assert 'Truncated' in text or 'exceeded' in text


def test_capture_writes_journal_and_pre_match_context(tmp_path):
	out = _capture(tmp_path, 'before-a\nbefore-b\nHIT now\nafter-1\n')
	journal = (out / 'journal.log').read_text()
	assert 'HIT' in journal or 'Matched' in journal or 'Captured logs' in journal
	caps = _incident_logs(out)
	assert len(caps) == 1
	text = caps[0].read_text()
	assert 'before-a' in text
	assert 'before-b' in text
	assert 'HIT now' in text
	assert 'after-1' in text
	assert 'End of capture' in text
	assert datetime.datetime.now().strftime('%Y-%m') in str(caps[0])


def test_capture_skips_blank_lines_and_has_no_file_without_match(tmp_path):
	out = _capture(tmp_path, '\n\n   \nno match here\n', pattern='HIT')
	assert _incident_logs(out) == []
	assert not (out / 'journal.log').exists()


def test_capture_regex_pattern(tmp_path):
	out = _capture(tmp_path, 'kernel: nvme0n1 timeout\n', pattern=r'nvme\d+n\d+', regex=True)
	text = _incident_logs(out)[0].read_text()
	assert 'nvme0n1' in text


def test_capture_closes_window_when_time_expires(tmp_path):
	out = _capture(tmp_path, 'HIT\nlater line\n', capture_time=-1)
	text = _incident_logs(out)[0].read_text()
	assert 'HIT' in text
	assert 'End of capture' in text


def test_capture_utf8_replace_does_not_hang(tmp_path):
	out = _capture(tmp_path, b'noise \xff\nHIT here\n', pattern='HIT')
	assert _incident_logs(out)
	assert 'HIT here' in _incident_logs(out)[0].read_text()


def test_capture_skips_own_syslog_lines(tmp_path):
	out = _capture(
		tmp_path,
		'host firewatcher[12]: Capturing logs to /tmp/error\nkernel: real error\n',
		pattern='error',
	)
	text = _incident_logs(out)[0].read_text()
	assert 'real error' in text
	matched_line = text.split('Matched line:')[1].splitlines()[0]
	assert 'real error' in matched_line
	assert 'firewatcher[12]' not in matched_line


def test_end_capture_none_is_noop(tmp_path):
	fw._end_capture(None, 0, 10)
	fw._end_capture('', 0, 10)


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


# --- log source ---

def test_log_source_command_filter_only_journalctl(monkeypatch):
	monkeypatch.setattr(fw.shutil, 'which', lambda name: '/usr/bin/journalctl' if name == 'journalctl' else None)
	args = _args(['--filter_only', 'p.txt'])
	cmd = fw.log_source_command(args)
	assert cmd[0] == 'journalctl'
	assert '--follow' not in cmd
	assert '--no-pager' in cmd
	cmd2 = fw.log_source_command(_args(['p.txt']))
	assert '--follow' in cmd2
	assert '--no-pager' in cmd2
	assert '--lines=20' in cmd2


def test_log_source_command_log_file_cat_vs_tail(monkeypatch):
	monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
	args = _args(['--filter_only', '--log-file', '/tmp/x.log', 'p.txt'])
	assert fw.log_source_command(args) == ['cat', '/tmp/x.log']
	args = _args(['--log-file', '/tmp/x.log', '--tail_lines', '+5', 'p.txt'])
	assert fw.log_source_command(args) == ['tail', '-n', '+5', '-F', '/tmp/x.log']


def test_log_source_command_falls_back_to_syslog(monkeypatch):
	monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
	monkeypatch.setattr(fw.os.path, 'exists', _fake_exists(syslog=True))
	cmd = fw.log_source_command(_args(['p.txt']))
	assert cmd == ['tail', '-n', '20', '-F', '/var/log/syslog']
	cmd = fw.log_source_command(_args(['--filter_only', 'p.txt']))
	assert cmd == ['cat', '/var/log/syslog']


def test_log_source_command_falls_back_to_messages_or_none(monkeypatch):
	monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
	monkeypatch.setattr(fw.os.path, 'exists', _fake_exists(messages=True))
	assert fw.log_source_command(_args(['p.txt']))[-1] == '/var/log/messages'
	monkeypatch.setattr(fw.os.path, 'exists', _fake_exists())
	assert fw.log_source_command(_args(['p.txt'])) is None


# --- systemd unit rendering ---

def test_render_unit_file_uses_pattern_dir_and_output():
	args = _args([
		'--print-unit',
		'-o', '/mnt/logs/captured_messages',
		'--requires-mounts-for', '/mnt/logs/captured_messages',
		'/etc/firewatcher/patterns.d',
	])
	unit = fw.render_unit_file(args, executable='/usr/local/bin/firewatcher')
	assert 'Description=firewatcher:' in unit
	assert 'nebula' not in unit.lower()
	assert 'After=systemd-journald.socket' in unit
	assert 'RequiresMountsFor=/mnt/logs/captured_messages' in unit
	assert 'remote-fs.target' in unit
	assert 'KillSignal=SIGINT' in unit
	assert 'Restart=always' in unit
	assert '/etc/firewatcher/patterns.d' in unit
	assert '-o /mnt/logs/captured_messages' in unit or '-o "/mnt/logs/captured_messages"' in unit
	assert unit.strip().endswith('WantedBy=multi-user.target')


def test_render_unit_skips_journald_after_when_log_file_set():
	args = _args(['--print-unit', '--log-file', '/var/log/messages', 'p.txt'])
	unit = fw.render_unit_file(args, executable='/usr/bin/firewatcher')
	assert 'systemd-journald.socket' not in unit
	assert '--log-file /var/log/messages' in unit


def test_render_unit_quotes_spaces_and_omits_default_flags():
	args = _args(['--print-unit', '-o', '/mnt/My Logs/out', 'p.txt'])
	unit = fw.render_unit_file(args, executable='/usr/local/bin/firewatcher')
	assert '"/mnt/My Logs/out"' in unit
	assert '--compress-after-months' not in unit
	assert '--filter_only' not in unit
	args = _args([
		'--print-unit', '--filter_only', '-t', '15',
		'--compress-after-months', '9', '--delete-after-months', '12',
		'--capture_line_count_max', '50', '--tail_lines', '8',
		'p.txt',
	])
	unit = fw.render_unit_file(args, executable='/bin/fw')
	assert '--filter_only' in unit
	assert '-t 15' in unit
	assert '--compress-after-months 9' in unit
	assert '--delete-after-months 12' in unit
	assert '--capture_line_count_max 50' in unit
	assert '--tail_lines 8' in unit


def test_render_unit_repeatable_requires_mounts():
	args = _args([
		'--print-unit',
		'--requires-mounts-for', '/mnt/a',
		'--requires-mounts-for', '/mnt/b',
		'p.txt',
	])
	unit = fw.render_unit_file(args, executable='/bin/fw')
	assert 'RequiresMountsFor=/mnt/a' in unit
	assert 'RequiresMountsFor=/mnt/b' in unit
	assert unit.count('remote-fs.target') == 1


def test_quote_unit_arg():
	assert fw._quote_unit_arg('/usr/bin/firewatcher') == '/usr/bin/firewatcher'
	assert fw._quote_unit_arg('/mnt/My Logs/out') == '"/mnt/My Logs/out"'
	assert fw._quote_unit_arg('a"b') == '"a\\"b"'
	assert fw._quote_unit_arg('a\\b') == '"a\\\\b"'
	assert fw._quote_unit_arg('') == '""'


def test_unit_name_sanitized():
	args = _args(['--print-unit', '--unit-name', 'firewatcher.service', 'p.txt'])
	assert fw.unit_filename(args.unit_name) == 'firewatcher.service'
	assert fw.unit_filename('custom') == 'custom.service'
	assert fw.unit_filename('') == 'firewatcher.service'
	with pytest.raises(ValueError):
		fw.unit_filename('../evil.service')
	with pytest.raises(ValueError):
		fw.unit_filename('/etc/systemd/system/x.service')


def test_systemd_is_available(tmp_path):
	assert fw.systemd_is_available(str(tmp_path)) is True
	assert fw.systemd_is_available(str(tmp_path / 'missing')) is False


def test_resolve_executable(monkeypatch):
	monkeypatch.setattr(fw.shutil, 'which', lambda name: '/usr/bin/firewatcher' if name == 'firewatcher' else None)
	assert fw.resolve_executable() == '/usr/bin/firewatcher'
	monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
	assert os.path.isabs(fw.resolve_executable())


# --- install / uninstall ---

def test_install_service_without_systemd_warns(tmp_path, capsys):
	args = _args(['--install-service', str(tmp_path / 'p.txt')])
	rc = fw.install_service(args, systemd_available=False)
	assert rc == 1
	err = capsys.readouterr().err
	assert 'systemd is not available' in err
	assert 'Warning' in err


def test_uninstall_service_without_systemd_warns(capsys):
	args = _args(['--uninstall-service'])
	rc = fw.uninstall_service(args, systemd_available=False)
	assert rc == 1
	assert 'systemd is not available' in capsys.readouterr().err


def test_install_service_writes_unit_and_seeds_examples(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	patterns = tmp_path / 'patterns.d'
	out = tmp_path / 'captures'
	calls = []
	args = _args(['--install-service', '-o', str(out), str(patterns)])
	rc = fw.install_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder(calls),
		executable='/usr/local/bin/firewatcher',
	)
	assert rc == 0
	unit_path = unit_dir / 'firewatcher.service'
	assert unit_path.is_file()
	text = unit_path.read_text()
	assert 'ExecStart=/usr/local/bin/firewatcher' in text
	assert str(patterns) in text
	assert out.is_dir()
	assert (patterns / 'sys_msg.txt').is_file()
	assert (patterns / 'nvme_failure.regex').is_file()
	assert (patterns / 'nvme_failure.regex').read_text() == fw.EXAMPLE_PATTERNS['nvme_failure.regex']
	assert any('daemon-reload' in cmd for cmd in calls)
	assert any('enable' in cmd for cmd in calls)
	assert 'nebula' not in text.lower()


def test_install_service_does_not_clobber_existing_patterns(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	patterns = tmp_path / 'patterns.d'
	patterns.mkdir()
	existing = patterns / 'custom.txt'
	existing.write_text('only-mine\n')
	args = _args(['--install-service', '--no-enable', str(patterns)])
	rc = fw.install_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_ok_systemctl,
		executable='/usr/local/bin/firewatcher',
	)
	assert rc == 0
	assert existing.read_text() == 'only-mine\n'
	assert not (patterns / 'sys_msg.txt').exists()


def test_install_service_no_enable_skips_enable(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	calls = []
	args = _args(['--install-service', '--no-enable', '--unit-name', 'fw-custom', str(tmp_path / 'p.d')])
	rc = fw.install_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder(calls),
		executable='/usr/local/bin/firewatcher',
	)
	assert rc == 0
	assert (unit_dir / 'fw-custom.service').is_file()
	assert any('daemon-reload' in cmd for cmd in calls)
	assert not any('enable' in cmd for cmd in calls)


def test_install_service_reload_failure(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	args = _args(['--install-service', str(tmp_path / 'p.d')])
	rc = fw.install_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder([], returncode=3),
		executable='/bin/fw',
	)
	assert rc == 3
	assert (unit_dir / 'firewatcher.service').is_file()


def test_install_service_enable_failure(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	def rc_for(cmd):
		return 7 if 'enable' in cmd else 0
	args = _args(['--install-service', str(tmp_path / 'p.d')])
	rc = fw.install_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder([], returncode=rc_for),
		executable='/bin/fw',
	)
	assert rc == 7


def test_seed_skips_missing_pattern_file(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	missing = tmp_path / 'patterns.txt'
	args = _args(['--install-service', '--no-enable', str(missing)])
	rc = fw.install_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_ok_systemctl,
		executable='/usr/local/bin/firewatcher',
	)
	assert rc == 0
	assert not missing.exists() or missing.is_file()
	assert not missing.is_dir()


def test_looks_like_pattern_dir(tmp_path):
	f = tmp_path / 'p.txt'
	f.write_text('x\n')
	assert fw._looks_like_pattern_dir(str(f)) is False
	d = tmp_path / 'patterns.d'
	d.mkdir()
	assert fw._looks_like_pattern_dir(str(d)) is True
	assert fw._looks_like_pattern_dir(str(tmp_path / 'future.d')) is True
	assert fw._looks_like_pattern_dir(str(tmp_path / 'future') + '/') is True


def test_uninstall_service_removes_unit_leaves_patterns(tmp_path, capsys):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	unit = unit_dir / 'firewatcher.service'
	unit.write_text('[Service]\n')
	patterns = tmp_path / 'patterns.d'
	patterns.mkdir()
	(patterns / 'custom.txt').write_text('keep\n')
	calls = []
	args = _args(['--uninstall-service'])
	rc = fw.uninstall_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder(calls),
	)
	assert rc == 0
	assert not unit.exists()
	assert (patterns / 'custom.txt').read_text() == 'keep\n'
	assert any('disable' in cmd for cmd in calls)
	assert any('daemon-reload' in cmd for cmd in calls)
	assert 'left in place' in capsys.readouterr().out


def test_uninstall_service_missing_unit_still_reloads(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	calls = []
	args = _args(['--uninstall-service', '--unit-name', 'gone'])
	rc = fw.uninstall_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder(calls),
	)
	assert rc == 0
	assert any('daemon-reload' in cmd for cmd in calls)


def test_uninstall_service_reload_failure(tmp_path):
	unit_dir = tmp_path / 'system'
	unit_dir.mkdir()
	(unit_dir / 'firewatcher.service').write_text('x')
	args = _args(['--uninstall-service'])
	rc = fw.uninstall_service(
		args,
		systemd_available=True,
		unit_dir=str(unit_dir),
		systemctl=_systemctl_recorder([], returncode=4),
	)
	assert rc == 4


# --- CLI / main ---

def test_print_unit_via_main(capsys):
	rc = fw.main(['--print-unit', '/etc/firewatcher/patterns.d'])
	assert rc == 0
	out = capsys.readouterr().out
	assert '[Service]' in out
	assert 'nebula' not in out.lower()


def test_print_unit_defaults_pattern_dir(capsys):
	rc = fw.main(['--print-unit'])
	assert rc == 0
	assert fw.DEFAULT_PATTERNS_DIR in capsys.readouterr().out


def test_main_requires_pattern_file():
	with pytest.raises(SystemExit) as exc:
		fw.main([])
	assert exc.value.code != 0


def test_main_dispatches_install_and_uninstall(monkeypatch):
	seen = {}
	def fake_install(args):
		seen['install'] = args
		return 0
	def fake_uninstall(args):
		seen['uninstall'] = args
		return 9
	monkeypatch.setattr(fw, 'install_service', fake_install)
	monkeypatch.setattr(fw, 'uninstall_service', fake_uninstall)
	assert fw.main(['--install-service', 'p.txt']) == 0
	assert 'install' in seen
	assert fw.main(['--uninstall-service']) == 9
	assert 'uninstall' in seen


def test_main_filter_only_captures(tmp_path, capsys):
	pat = tmp_path / 'p.txt'
	pat.write_text('HIT\n')
	src = tmp_path / 'src.log'
	src.write_text('noise\nHIT the fan\n')
	out = tmp_path / 'out'
	rc = fw.main([
		'--filter_only', '--log-file', str(src),
		'-o', str(out), '-t', '5',
		str(pat),
	])
	assert rc == 0
	printed = capsys.readouterr().out
	assert f'Starting firewatcher v{fw.version}' in printed
	assert 'months.' in printed
	assert 'years' not in printed
	assert _incident_logs(out)


def test_main_no_log_source(tmp_path, monkeypatch, capsys):
	pat = tmp_path / 'p.txt'
	pat.write_text('x\n')
	monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
	monkeypatch.setattr(fw.os.path, 'exists', _fake_exists())
	rc = fw.main(['--filter_only', str(pat)])
	assert rc == 1
	assert 'No log file specified' in capsys.readouterr().out


def test_main_empty_pattern_dir(tmp_path, capsys):
	d = tmp_path / 'empty.d'
	d.mkdir()
	src = tmp_path / 'log'
	src.write_text('x\n')
	rc = fw.main(['--filter_only', '--log-file', str(src), str(d)])
	assert rc == 1
	assert 'No pattern files found' in capsys.readouterr().err


def test_main_version():
	with pytest.raises(SystemExit) as exc:
		fw.main(['-V'])
	assert exc.value.code == 0


def test_parser_rejects_conflicting_service_flags():
	with pytest.raises(SystemExit):
		_args(['--install-service', '--print-unit', 'p.txt'])


def test_module_has_no_nebula_product_name():
	src = open(fw.__file__, encoding='utf-8').read().lower()
	assert 'nebula' not in src
	assert fw.version == '1.57'
	assert fw.__version__ == fw.version


def test_print_flushes_by_default(capsys):
	fw.print('hello-flush')
	assert 'hello-flush' in capsys.readouterr().out
