import os

import pytest

import firewatcher as fw
from conftest import parse_cli, ok_systemctl, systemctl_recorder

# --- systemd unit rendering ---

def test_render_unit_file_uses_pattern_dir_and_output():
    parsed = parse_cli([
        '--print-unit',
        '-o', '/mnt/logs/captured_messages',
        '--requires-mounts-for', '/mnt/logs/captured_messages',
        '/etc/firewatcher/patterns.d',
    ])
    unit = fw.render_unit_file(parsed, executable='/usr/local/bin/firewatcher')
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
    parsed = parse_cli(['--print-unit', '--log-file', '/var/log/messages', 'p.txt'])
    unit = fw.render_unit_file(parsed, executable='/usr/bin/firewatcher')
    assert 'systemd-journald.socket' not in unit
    assert '--log-file /var/log/messages' in unit


def test_render_unit_quotes_spaces_and_omits_default_flags():
    parsed = parse_cli(['--print-unit', '-o', '/mnt/My Logs/out', 'p.txt'])
    unit = fw.render_unit_file(parsed, executable='/usr/local/bin/firewatcher')
    assert '"/mnt/My Logs/out"' in unit
    assert '--compress-after-months' not in unit
    assert '--filter_only' not in unit
    parsed = parse_cli([
        '--print-unit', '--filter_only', '-t', '15',
        '--compress-after-months', '9', '--delete-after-months', '12',
        '--capture_line_count_max', '50', '--tail_lines', '8',
        'p.txt',
    ])
    unit = fw.render_unit_file(parsed, executable='/bin/fw')
    assert '--filter_only' in unit
    assert '-t 15' in unit
    assert '--compress-after-months 9' in unit
    assert '--delete-after-months 12' in unit
    assert '--capture_line_count_max 50' in unit
    assert '--tail_lines 8' in unit


def test_render_unit_repeatable_requires_mounts():
    parsed = parse_cli([
        '--print-unit',
        '--requires-mounts-for', '/mnt/a',
        '--requires-mounts-for', '/mnt/b',
        'p.txt',
    ])
    unit = fw.render_unit_file(parsed, executable='/bin/fw')
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
    parsed = parse_cli(['--print-unit', '--unit-name', 'firewatcher.service', 'p.txt'])
    assert fw.unit_filename(parsed.unit_name) == 'firewatcher.service'
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
    parsed = parse_cli(['--install-service', str(tmp_path / 'p.txt')])
    rc = fw.install_service(parsed, systemd_available=False)
    assert rc == 1
    err = capsys.readouterr().err
    assert 'systemd is not available' in err
    assert 'Warning' in err


def test_uninstall_service_without_systemd_warns(capsys):
    parsed = parse_cli(['--uninstall-service'])
    rc = fw.uninstall_service(parsed, systemd_available=False)
    assert rc == 1
    assert 'systemd is not available' in capsys.readouterr().err


def test_install_service_writes_unit_and_seeds_examples(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    patterns = tmp_path / 'patterns.d'
    out = tmp_path / 'captures'
    calls = []
    parsed = parse_cli(['--install-service', '-o', str(out), str(patterns)])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder(calls),
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
    parsed = parse_cli(['--install-service', '--no-enable', str(patterns)])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=ok_systemctl,
        executable='/usr/local/bin/firewatcher',
    )
    assert rc == 0
    assert existing.read_text() == 'only-mine\n'
    assert not (patterns / 'sys_msg.txt').exists()


def test_install_service_no_enable_skips_enable(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    calls = []
    parsed = parse_cli(['--install-service', '--no-enable', '--unit-name', 'fw-custom', str(tmp_path / 'p.d')])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder(calls),
        executable='/usr/local/bin/firewatcher',
    )
    assert rc == 0
    assert (unit_dir / 'fw-custom.service').is_file()
    assert any('daemon-reload' in cmd for cmd in calls)
    assert not any('enable' in cmd for cmd in calls)


def test_install_service_reload_failure(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    parsed = parse_cli(['--install-service', str(tmp_path / 'p.d')])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder([], returncode=3),
        executable='/bin/fw',
    )
    assert rc == 3
    assert (unit_dir / 'firewatcher.service').is_file()


def test_install_service_enable_failure(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    def rc_for(cmd):
        return 7 if 'enable' in cmd else 0
    parsed = parse_cli(['--install-service', str(tmp_path / 'p.d')])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder([], returncode=rc_for),
        executable='/bin/fw',
    )
    assert rc == 7


def test_seed_skips_missing_pattern_file(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    missing = tmp_path / 'patterns.txt'
    parsed = parse_cli(['--install-service', '--no-enable', str(missing)])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=ok_systemctl,
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
    parsed = parse_cli(['--uninstall-service'])
    rc = fw.uninstall_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder(calls),
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
    parsed = parse_cli(['--uninstall-service', '--unit-name', 'gone'])
    rc = fw.uninstall_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder(calls),
    )
    assert rc == 0
    assert any('daemon-reload' in cmd for cmd in calls)


def test_uninstall_service_reload_failure(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    (unit_dir / 'firewatcher.service').write_text('x')
    parsed = parse_cli(['--uninstall-service'])
    rc = fw.uninstall_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder([], returncode=4),
    )
    assert rc == 4


def test_systemd_is_available_uses_module_default(monkeypatch, tmp_path):
    monkeypatch.setattr(fw, 'SYSTEMD_RUNTIME_DIR', str(tmp_path))
    assert fw.systemd_is_available() is True
    monkeypatch.setattr(fw, 'SYSTEMD_RUNTIME_DIR', str(tmp_path / 'missing'))
    assert fw.systemd_is_available() is False


def test_run_systemctl_defaults_to_subprocess(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(fw.subprocess, 'run', fake_run)
    result = fw._run_systemctl(None, 'daemon-reload')
    assert seen == [['systemctl', 'daemon-reload']]
    assert result.returncode == 0


def test_install_service_probes_systemd_when_unspecified(monkeypatch):
    monkeypatch.setattr(fw, 'systemd_is_available', lambda: False)
    parsed = parse_cli(['--install-service', 'p.txt'])
    assert fw.install_service(parsed) == 1


def test_uninstall_service_probes_systemd_when_unspecified(monkeypatch):
    monkeypatch.setattr(fw, 'systemd_is_available', lambda: False)
    parsed = parse_cli(['--uninstall-service'])
    assert fw.uninstall_service(parsed) == 1


def test_install_service_default_unit_dir(tmp_path, monkeypatch):
    unit_dir = tmp_path / 'system'
    monkeypatch.setattr(fw, 'SYSTEMD_UNIT_DIR', str(unit_dir))
    parsed = parse_cli(['--install-service', '--no-enable', str(tmp_path / 'p.d')])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        systemctl=ok_systemctl,
        executable='/bin/fw',
    )
    assert rc == 0
    assert (unit_dir / 'firewatcher.service').is_file()


def test_uninstall_service_default_unit_dir(tmp_path, monkeypatch):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    (unit_dir / 'firewatcher.service').write_text('[Service]\n')
    monkeypatch.setattr(fw, 'SYSTEMD_UNIT_DIR', str(unit_dir))
    parsed = parse_cli(['--uninstall-service'])
    rc = fw.uninstall_service(parsed, systemd_available=True, systemctl=ok_systemctl)
    assert rc == 0
    assert not (unit_dir / 'firewatcher.service').exists()


def test_uninstall_disable_failure_still_removes_unit(tmp_path, capsys):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    unit = unit_dir / 'firewatcher.service'
    unit.write_text('[Service]\n')

    def rc_for(cmd):
        return 5 if 'disable' in cmd else 0

    parsed = parse_cli(['--uninstall-service'])
    rc = fw.uninstall_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=systemctl_recorder([], returncode=rc_for),
    )
    assert rc == 0
    assert not unit.exists()
    assert 'exited 5' in capsys.readouterr().err


def test_unit_filename_none_and_whitespace():
    assert fw.unit_filename(None) == 'firewatcher.service'
    # whitespace-only is truthy, so it does not fall back to the default name
    assert fw.unit_filename('   ') == '.service'


def test_render_unit_resolves_executable_when_omitted(monkeypatch):
    monkeypatch.setattr(fw, 'resolve_executable', lambda: '/opt/bin/firewatcher')
    unit = fw.render_unit_file(parse_cli(['--print-unit', 'p.txt']))
    assert 'ExecStart=/opt/bin/firewatcher' in unit
