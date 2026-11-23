import errno
import os
import shlex

import pytest

import firewatcher as fw
from conftest import file_size_limit, parse_cli, ok_systemctl, systemctl_recorder

# --- systemd unit rendering ---

def test_unit_resolves_relative_config_path_before_systemd_changes_directory(tmp_path, monkeypatch):
    conf = tmp_path / 'firewatcher.conf'
    conf.write_text('[watch]\npatterns = /etc/firewatcher/patterns.d\n')
    monkeypatch.chdir(tmp_path)
    unit = fw.render_unit_file(parse_cli(['--print-unit', '--config', 'firewatcher.conf']), executable='/bin/fw')
    command = next(line.partition('=')[2] for line in unit.splitlines() if line.startswith('ExecStart='))
    monkeypatch.chdir('/')
    resolved = fw.resolve_settings(parse_cli(shlex.split(command)[1:]), environ={})
    assert resolved.config_path == str(conf)
    assert resolved.pattern_file == ['/etc/firewatcher/patterns.d']


def test_install_existing_config_without_patterns_keeps_default_pattern_directory(tmp_path, monkeypatch):
    patterns = tmp_path / 'patterns.d'
    monkeypatch.setattr(fw, 'DEFAULT_PATTERNS_DIR', str(patterns))
    conf = tmp_path / 'firewatcher.conf'
    original = '[llm]\nenabled = false\n'
    conf.write_text(original)
    args = parse_cli(['--install-service', '--no-enable', '--config', str(conf), '-o', str(tmp_path / 'out')])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    unit = (tmp_path / 'units' / 'firewatcher.service').read_text()
    command = next(line.partition('=')[2] for line in unit.splitlines() if line.startswith('ExecStart='))
    resolved = fw.resolve_settings(parse_cli(shlex.split(command)[1:]), environ={})
    assert resolved.pattern_file == [str(patterns)]
    assert conf.read_text() == original


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
    assert 'ExecReload=/bin/kill -HUP $MAINPID' in unit
    assert 'Restart=always' in unit
    assert 'TimeoutStopSec=85' in unit
    assert '--config' in unit
    exec_line = next(line for line in unit.splitlines() if line.startswith('ExecStart='))
    assert '-o ' not in exec_line
    assert '/etc/firewatcher/patterns.d' not in exec_line
    override = fw.render_unit_file(parsed, executable='/usr/local/bin/firewatcher', config_exists=True)
    assert '-o /mnt/logs/captured_messages' in override or '-o "/mnt/logs/captured_messages"' in override
    assert '/etc/firewatcher/patterns.d' in override
    assert unit.strip().endswith('WantedBy=multi-user.target')


def test_render_unit_skips_journald_after_when_log_file_set():
    parsed = parse_cli(['--print-unit', '--log-file', '/var/log/messages', 'p.txt'])
    fresh = fw.render_unit_file(parsed, executable='/usr/bin/firewatcher', config_exists=False)
    assert 'systemd-journald.socket' not in fresh
    assert '--log-file' not in fresh
    unit = fw.render_unit_file(parsed, executable='/usr/bin/firewatcher', config_exists=True)
    assert 'systemd-journald.socket' not in unit
    assert '--log-file /var/log/messages' in unit


def test_render_unit_quotes_spaces_and_omits_default_flags():
    parsed = parse_cli(['--print-unit', '-o', '/mnt/My Logs/out', 'p.txt'])
    unit = fw.render_unit_file(parsed, executable='/usr/local/bin/firewatcher', config_exists=True)
    assert '"/mnt/My Logs/out"' in unit
    assert '--compress-after-months' not in unit
    assert '--filter_only' not in unit
    parsed = parse_cli([
        '--print-unit', '--filter_only', '-t', '15',
        '--compress-after-months', '9', '--delete-after-months', '12',
        '--capture_line_count_max', '50', '--tail_lines', '8',
        'p.txt',
    ])
    unit = fw.render_unit_file(parsed, executable='/bin/fw', config_exists=True)
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


def test_unit_name_sanitized():
    parsed = parse_cli(['--print-unit', '--unit-name', 'firewatcher.service', 'p.txt'])
    assert fw.unit_filename(parsed.unit_name) == 'firewatcher.service'
    assert fw.unit_filename('custom') == 'custom.service'
    assert fw.unit_filename('') == 'firewatcher.service'
    with pytest.raises(ValueError):
        fw.unit_filename('../evil.service')
    with pytest.raises(ValueError):
        fw.unit_filename('/etc/systemd/system/x.service')


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
    assert '--config' in text
    cfg_path = fw.DEFAULT_CONFIG_PATH
    cfg = open(cfg_path, encoding='utf-8').read()
    assert str(patterns) in cfg
    assert str(out) in cfg
    assert (os.stat(cfg_path).st_mode & 0o777) == 0o600
    assert str(patterns) not in text
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


class Systemctl(object):
    """A systemctl that records each call with whether the unit file and the config exist at that moment (and, in
    texts, the unit file's text then, None when it is not there), and fails the calls fails(cmd) names: with an exit
    status, or with the OSError a systemctl that cannot be run raises."""

    def __init__(self, unit_path, fails=lambda cmd: 0):
        self.unit_path, self.fails, self.calls, self.texts = unit_path, fails, [], []

    def __call__(self, *cmd):
        self.calls.append((cmd, os.path.exists(self.unit_path), os.path.exists(fw.DEFAULT_CONFIG_PATH)))
        try:
            with open(self.unit_path) as unit:
                self.texts.append(unit.read())
        except OSError:
            self.texts.append(None)
        outcome = self.fails(cmd)
        if isinstance(outcome, BaseException):
            raise outcome

        class Result:
            returncode = outcome
        return Result()

    def verbs(self):
        return [cmd[0] for cmd, _, _ in self.calls]


def enabling(cmd):
    return 'enable' in cmd


@pytest.mark.parametrize('failing', ['daemon-reload', 'enable'])
def test_a_failed_systemctl_step_removes_the_config_and_unit_the_install_created(tmp_path, capsys, failing):
    # 1.68 left them, so the same command run again found the config and put the flags, the ntfy URL among them,
    # on the unit's ExecStart, which any user can read. (The output folder and example patterns stay.)
    unit_dir = tmp_path / 'system'
    argv = ['--install-service', '--ntfy-url', 'https://ntfy.sh/private-topic', '-t', '120', str(tmp_path / 'p.d')]
    systemctl = Systemctl(str(unit_dir / 'firewatcher.service'), lambda cmd: 7 if failing in cmd else 0)
    rc = fw.install_service(parse_cli(argv), systemd_available=True, unit_dir=str(unit_dir), systemctl=systemctl,
                            executable='/bin/fw')
    assert rc == 7
    assert not os.path.exists(fw.DEFAULT_CONFIG_PATH) and os.listdir(str(unit_dir)) == []
    err = capsys.readouterr().err
    assert 'failed (exit 7)' in err and 'Removed %s' % fw.DEFAULT_CONFIG_PATH in err
    if failing == 'daemon-reload':
        assert systemctl.verbs() == ['daemon-reload']
    else:
        # enable --now may have enabled the unit before its start failed. disable comes while the unit file is
        # still there (systemd 219 refuses once it is gone); the last reload drops the unit from systemd's memory.
        assert systemctl.calls[-2:] == [(('disable', '--', 'firewatcher.service'), True, True),
                                        (('daemon-reload',), False, False)]
        assert systemctl.verbs() == ['daemon-reload', 'enable', 'disable', 'daemon-reload']
    # run again, it is a fresh install: the flags go into the new config, not on ExecStart
    assert fw.install_service(parse_cli(argv), systemd_available=True, unit_dir=str(unit_dir),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    unit = (unit_dir / 'firewatcher.service').read_text()
    assert exec_start_line(unit) == 'ExecStart=/bin/fw --config %s' % fw.DEFAULT_CONFIG_PATH
    with open(fw.DEFAULT_CONFIG_PATH) as config:
        assert 'private-topic' in config.read()


OLD_UNIT = '[Service]\nExecStart=/bin/fw -t 60 --ntfy-url https://ntfy.sh/old /etc/old.d\n'


@pytest.mark.parametrize('enabled_before', [False, True])
def test_a_failed_enable_puts_back_the_unit_it_replaced_and_disables_only_what_it_enabled(tmp_path, capsys, enabled_before):
    # A unit from before there was a config (1.55 to 1.57 wrote ExecStart with the flags). 1.69 as built removed
    # the config it wrote and left the rewritten unit, which names it: `config file not found` at every start, and
    # 1.68 had left the pair, which runs.
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    unit_path = unit_dir / 'firewatcher.service'
    unit_path.write_text(OLD_UNIT)
    systemctl = Systemctl(str(unit_path), lambda cmd: 3 if enabling(cmd) else (0 if enabled_before else 1) if 'is-enabled' in cmd else 0)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), executable='/bin/fw', systemctl=systemctl)
    assert rc == 3
    assert unit_path.read_text() == OLD_UNIT and not os.path.exists(fw.DEFAULT_CONFIG_PATH)
    err = capsys.readouterr().err
    assert 'Removed %s' % fw.DEFAULT_CONFIG_PATH in err and 'Put back %s' % unit_path in err
    # a unit that was enabled before stays enabled; one this run enabled is disabled again
    expected = ['daemon-reload', 'is-enabled', 'enable'] + ([] if enabled_before else ['disable']) + ['daemon-reload']
    assert systemctl.verbs() == expected
    assert systemctl.calls[1][0] == ('is-enabled', '--quiet', '--', 'firewatcher.service')
    # systemd loaded the new text first; the last reload comes after the old one is back, and loads it again
    assert systemctl.texts[0] != OLD_UNIT and systemctl.texts[-1] == OLD_UNIT


def test_a_failed_daemon_reload_puts_back_the_unit_it_replaced(tmp_path, capsys):
    # the reload failed, so systemd never loaded the new text: the old one goes back on disk, and nothing is reloaded
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    unit_path = unit_dir / 'firewatcher.service'
    unit_path.write_text(OLD_UNIT)
    systemctl = Systemctl(str(unit_path), lambda cmd: 3 if 'daemon-reload' in cmd else 0)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), executable='/bin/fw', systemctl=systemctl)
    assert rc == 3
    assert unit_path.read_text() == OLD_UNIT and not os.path.exists(fw.DEFAULT_CONFIG_PATH)
    assert systemctl.verbs() == ['daemon-reload']
    err = capsys.readouterr().err
    assert 'failed (exit 3)' in err and 'Removed %s' % fw.DEFAULT_CONFIG_PATH in err and 'Put back %s' % unit_path in err


def test_a_failed_systemctl_step_keeps_a_config_and_unit_that_were_there(tmp_path, capsys):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    (unit_dir / 'firewatcher.service').write_text('[Service]\n')
    with open(fw.DEFAULT_CONFIG_PATH, 'w') as config:
        config.write('[watch]\n')
    systemctl = Systemctl(str(unit_dir / 'firewatcher.service'), lambda cmd: 3 if enabling(cmd) else 0)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), executable='/bin/fw', systemctl=systemctl)
    assert rc == 3
    assert 'disable' not in systemctl.verbs()
    with open(fw.DEFAULT_CONFIG_PATH) as config:
        assert config.read() == '[watch]\n'
    assert (unit_dir / 'firewatcher.service').read_text() == '[Service]\n'
    assert 'Removed' not in capsys.readouterr().err


def test_a_failed_disable_is_said_and_the_clean_up_goes_on(tmp_path, capsys):
    unit_dir = tmp_path / 'system'
    systemctl = Systemctl(str(unit_dir / 'firewatcher.service'), lambda cmd: 3 if enabling(cmd) else 5 if 'disable' in cmd else 0)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), executable='/bin/fw', systemctl=systemctl)
    assert rc == 3
    assert not os.path.exists(fw.DEFAULT_CONFIG_PATH) and os.listdir(str(unit_dir)) == []
    assert 'systemctl disable failed (exit 5)' in capsys.readouterr().err


def test_a_file_that_cannot_be_removed_does_not_stop_the_clean_up(tmp_path, capsys, monkeypatch):
    unit_dir = tmp_path / 'system'
    real_remove = os.remove

    def remove(path, *args, **kwargs):
        if path == fw.DEFAULT_CONFIG_PATH:
            raise PermissionError(errno.EPERM, 'Operation not permitted', path)
        return real_remove(path, *args, **kwargs)

    monkeypatch.setattr(fw.os, 'remove', remove)
    systemctl = Systemctl(str(unit_dir / 'firewatcher.service'), lambda cmd: 3 if enabling(cmd) else 0)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), executable='/bin/fw', systemctl=systemctl)
    assert rc == 3 and os.listdir(str(unit_dir)) == []
    err = capsys.readouterr().err
    assert 'cannot remove %s' % fw.DEFAULT_CONFIG_PATH in err and 'Traceback' not in err
    assert systemctl.verbs()[-1] == 'daemon-reload'


@pytest.mark.parametrize('cannot_run', ['daemon-reload', 'enable'])
def test_a_systemctl_that_cannot_be_run_ends_the_install_like_one_that_fails(tmp_path, capsys, cannot_run):
    # 1.69 as built: a traceback, with the config and unit left
    unit_dir = tmp_path / 'system'
    gone = FileNotFoundError(errno.ENOENT, 'No such file or directory', 'systemctl')
    systemctl = Systemctl(str(unit_dir / 'firewatcher.service'), lambda cmd: gone if cannot_run in cmd or 'disable' in cmd else 0)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), executable='/bin/fw', systemctl=systemctl)
    assert rc == 1
    assert not os.path.exists(fw.DEFAULT_CONFIG_PATH) and os.listdir(str(unit_dir)) == []
    err = capsys.readouterr().err
    assert 'cannot run systemctl' in err and 'Removed %s' % fw.DEFAULT_CONFIG_PATH in err and 'Traceback' not in err


def test_a_systemctl_that_is_not_installed_is_an_exit_status_not_a_traceback(monkeypatch, capsys):
    def missing(cmd, **kwargs):
        raise FileNotFoundError(errno.ENOENT, 'No such file or directory', 'systemctl')

    monkeypatch.setattr(fw.subprocess, 'run', missing)
    assert fw._run_systemctl(None, 'daemon-reload').returncode == 1
    assert 'cannot run systemctl' in capsys.readouterr().err


@pytest.mark.parametrize('existing', [False, True])
def test_a_unit_that_fills_the_disk_leaves_no_half_written_unit(tmp_path, capsys, existing):
    # a real partial write: the first bytes land, then EFBIG
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    unit_path = unit_dir / 'firewatcher.service'
    if existing:
        unit_path.write_text(OLD_UNIT)
    with open(fw.DEFAULT_CONFIG_PATH, 'w') as config:
        config.write('[watch]\n')
    patterns = tmp_path / 'p.txt'
    patterns.write_text('HIT\n')
    with file_size_limit(len(OLD_UNIT) + 10):
        rc = fw.install_service(parse_cli(['--install-service', '--no-enable', str(patterns)]), systemd_available=True,
                                unit_dir=str(unit_dir), executable='/bin/fw', systemctl=ok_systemctl)
    assert rc == 1
    assert (unit_path.read_text() == OLD_UNIT) if existing else os.listdir(str(unit_dir)) == []
    assert 'cannot write unit' in capsys.readouterr().err


def test_a_unit_that_cannot_be_put_back_is_said(tmp_path, capsys):
    # the disk fills again while the old text is written back: the message says what is left
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    unit_path = unit_dir / 'firewatcher.service'
    unit_path.write_text(OLD_UNIT)
    with open(fw.DEFAULT_CONFIG_PATH, 'w') as config:
        config.write('[watch]\n')
    patterns = tmp_path / 'p.txt'
    patterns.write_text('HIT\n')
    with file_size_limit(10):
        rc = fw.install_service(parse_cli(['--install-service', '--no-enable', str(patterns)]), systemd_available=True,
                                unit_dir=str(unit_dir), executable='/bin/fw', systemctl=ok_systemctl)
    assert rc == 1
    err = capsys.readouterr().err
    assert 'cannot write unit' in err and 'cannot put back %s' % unit_path in err and 'Traceback' not in err


def test_a_config_that_fills_the_disk_leaves_no_partial_config(tmp_path, capsys):
    # 1.69 as built: one os.write, whose short count went unnoticed, and a partial file kept when it failed
    path = tmp_path / 'etc' / 'firewatcher.conf'
    with file_size_limit(100):
        with pytest.raises(OSError) as raised:
            fw.write_config_file(str(path), '[watch]\n' + 'x = %s\n' % ('y' * 500))
    assert raised.value.errno == errno.EFBIG
    assert not path.exists()
    patterns = tmp_path / 'p.txt'
    patterns.write_text('HIT\n')
    with file_size_limit(100):
        rc = fw.install_service(parse_cli(['--install-service', str(patterns)]), systemd_available=True,
                                unit_dir=str(tmp_path / 'system'), executable='/bin/fw', systemctl=ok_systemctl)
    assert rc == 1 and not os.path.exists(fw.DEFAULT_CONFIG_PATH)
    assert 'cannot write config' in capsys.readouterr().err


def test_a_unit_that_cannot_be_written_removes_the_new_config(tmp_path, capsys, monkeypatch):
    blocker = tmp_path / 'system'
    blocker.write_text('')  # a file where the unit folder should be
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(blocker), systemctl=ok_systemctl, executable='/bin/fw')
    assert rc == 1 and not os.path.exists(fw.DEFAULT_CONFIG_PATH)
    err = capsys.readouterr().err
    assert 'cannot write unit' in err and 'Traceback' not in err
    # a unit folder that refuses the file: there is no unit to remove, only the config
    unit_dir = tmp_path / 'units'
    unit_dir.mkdir()

    def refusing_open(path, *args, **kwargs):
        if str(path).startswith(str(unit_dir)):
            raise PermissionError(13, 'Permission denied', str(path))
        return open(path, *args, **kwargs)

    monkeypatch.setattr(fw, 'open', refusing_open, raising=False)
    rc = fw.install_service(parse_cli(['--install-service', str(tmp_path / 'p.d')]), systemd_available=True,
                            unit_dir=str(unit_dir), systemctl=ok_systemctl, executable='/bin/fw')
    assert rc == 1 and not os.path.exists(fw.DEFAULT_CONFIG_PATH) and os.listdir(str(unit_dir)) == []
    err = capsys.readouterr().err
    assert 'Removed %s' % fw.DEFAULT_CONFIG_PATH in err and 'Traceback' not in err


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


def test_systemd_is_available(monkeypatch, tmp_path):
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
    # a blank name means the default, as an empty one does
    assert fw.unit_filename('   ') == 'firewatcher.service'
    assert fw.unit_filename('fw@a:b_c-1.d') == 'fw@a:b_c-1.d.service'


def test_the_unit_name_check_accepts_and_refuses_what_systemd_257_does():
    for good in ('firewatcher.service', 'fw@a:b_c-1.d.service', 'fw-2.service', 'fw@a@b.service', '-fw.service',
                 'x' * 247 + '.service'):
        fw._check_new_unit_name(good)
    for bad in ('fw\u00e9.service', 'my fw.service', '@fw.service', 'fw@.service', 'x' * 248 + '.service'):
        with pytest.raises(ValueError):
            fw._check_new_unit_name(bad)


def test_a_refused_unit_name_leaves_nothing_behind(tmp_path, monkeypatch, capsys):
    # The default config path does not exist yet, so the install would write one: a refusal must come first.
    root = tmp_path / 'root'
    root.mkdir()
    monkeypatch.setattr(fw, 'DEFAULT_PATTERNS_DIR', str(root / 'patterns.d'))
    monkeypatch.setattr(fw, 'DEFAULT_CONFIG_PATH', str(root / 'etc' / 'firewatcher.conf'))
    for name in ('sub/fw', 'fw\u00e9', 'my fw', '@fw', 'fw@', 'x' * 248):
        args = parse_cli(['--install-service', '-o', str(root / 'out'), '--unit-name=' + name])
        assert fw.install_service(args, systemd_available=True, unit_dir=str(root / 'units'),
                                  systemctl=ok_systemctl, executable='/bin/fw') == 2, name
        assert os.listdir(str(root)) == [], name
        assert 'unit name must be' in capsys.readouterr().err
    monkeypatch.setattr(fw, 'systemd_is_available', lambda: True)
    assert fw.main(['--install-service', '-o', str(root / 'out'), '--unit-name', 'a/b']) == 2
    assert 'Traceback' not in capsys.readouterr().err and os.listdir(str(root)) == []


def test_unit_names_reach_systemctl_after_a_double_dash(tmp_path):
    # A name starting with '-' (which systemd loads) is a name to systemctl, not an option.
    calls = []
    args = parse_cli(['--install-service', '-o', str(tmp_path / 'out'), '--unit-name=-fw', str(tmp_path / 'p.d')])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=systemctl_recorder(calls), executable='/bin/fw') == 0
    assert ('enable', '--now', '--', '-fw.service') in calls
    del calls[:]
    args = parse_cli(['--uninstall-service', '--unit-name=-fw'])
    assert fw.uninstall_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                                systemctl=systemctl_recorder(calls)) == 0
    assert ('disable', '--now', '--', '-fw.service') in calls


def test_uninstall_still_removes_a_unit_an_older_firewatcher_named_freely(tmp_path):
    unit_dir = tmp_path / 'system'
    unit_dir.mkdir()
    unit = unit_dir / 'my fw.service'
    unit.write_text('[Service]\n')
    parsed = parse_cli(['--uninstall-service', '--unit-name', 'my fw'])
    assert fw.uninstall_service(parsed, systemd_available=True, unit_dir=str(unit_dir), systemctl=systemctl_recorder([])) == 0
    assert not unit.exists()
    # a path is refused there too, without a traceback
    parsed = parse_cli(['--uninstall-service', '--unit-name', '../fw'])
    assert fw.uninstall_service(parsed, systemd_available=True, unit_dir=str(unit_dir), systemctl=systemctl_recorder([])) == 2


def test_render_unit_resolves_executable_when_omitted(monkeypatch):
    monkeypatch.setattr(fw, 'resolve_executable', lambda: '/opt/bin/firewatcher')
    unit = fw.render_unit_file(parse_cli(['--print-unit', 'p.txt']))
    assert 'ExecStart=/opt/bin/firewatcher' in unit


def test_unit_passes_new_flags_when_config_exists():
    raw = parse_cli(['--capture-time-max', '600', '--fallback-folder', '', '--always-notify', '/a', '--always-notify', '/b', 'p.txt'])
    parts = fw._explicit_cli_args(raw)
    assert parts[:2] == ['--capture-time-max', '600']
    assert ['--fallback-folder', ''] == parts[2:4]
    assert parts[4:8] == ['--always-notify', '/a', '--always-notify', '/b']


def test_install_warns_when_the_topic_goes_on_execstart(tmp_path, capsys, monkeypatch):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\npatterns = %s\n' % (tmp_path / 'patterns.d'))
    args = parse_cli(['--config', str(conf), '--ntfy-url', 'https://ntfy.example/secret-topic', '-o', str(tmp_path / 'out')])
    rc = fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'), systemctl=ok_systemctl, executable='/bin/fw')
    assert rc == 0
    assert 'any user can read it' in capsys.readouterr().err


# --- operator notes in the unit ---

def exec_start_line(unit):
    return next(line for line in unit.splitlines() if line.startswith('ExecStart='))


def systemd_words(exec_start):
    """The words systemd would hand to the program: double quotes with \\ escapes, then %% and $$ undone."""
    return [word.replace('%%', '%').replace('$$', '$') for word in shlex.split(exec_start[len('ExecStart='):])]


def test_quote_unit_arg_escapes_for_systemd():
    assert fw._quote_unit_arg('/usr/bin/firewatcher') == '/usr/bin/firewatcher'
    assert fw._quote_unit_arg('/mnt/My Logs/out') == '"/mnt/My Logs/out"'
    assert fw._quote_unit_arg('a"b') == '"a\\"b"'
    assert fw._quote_unit_arg('a\\b') == '"a\\\\b"'
    assert fw._quote_unit_arg('') == '""'
    assert fw._quote_unit_arg('100%') == '100%%'
    assert fw._quote_unit_arg('$HOME') == '$$HOME'
    assert fw._quote_unit_arg("don't") == '"don\'t"'
    assert fw._quote_unit_arg('a b%$') == '"a b%%$$"'
    # The program path is not $-expanded by systemd, only %-expanded.
    assert fw._quote_unit_arg('/opt/f$w/fw 1%', program=True) == '"/opt/f$w/fw 1%%"'
    assert fw._quote_unit_arg('/opt/f$w/fw', program=True) == '/opt/f$w/fw'


def test_notes_reach_the_unit_as_one_escaped_word(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[llm]\nnotes = from file\n')
    note = '  a  "b"\n c \\ don\'t; 100% $HOME '
    parsed = parse_cli(['--config', str(conf), '--llm-notes', note, 'p.txt'])
    unit = fw.render_unit_file(parsed, executable='/opt/f$w/fw', config_exists=True)
    line = exec_start_line(unit)
    assert line.startswith('ExecStart=/opt/f$w/fw ')
    assert '"--llm-notes=a \\"b\\" c \\\\ don\'t; 100%% $$HOME"' in line
    words = systemd_words(line)
    assert 'a "b" c \\ don\'t; 100% $HOME' == next(w for w in words if w.startswith('--llm-notes='))[len('--llm-notes='):]
    assert fw.resolve_settings(parse_cli(words[1:]), environ={}).llm_notes == 'a "b" c \\ don\'t; 100% $HOME'
    plain = fw.render_unit_file(parse_cli(['--config', str(conf), 'p.txt']), executable='/bin/fw', config_exists=True)
    assert '--llm-notes' not in plain


def test_a_cleared_note_reaches_the_unit_as_an_empty_override(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[llm]\nnotes = from file\n')
    unit = fw.render_unit_file(parse_cli(['--config', str(conf), '--llm-notes', '', 'p.txt']), executable='/bin/fw', config_exists=True)
    words = systemd_words(exec_start_line(unit))
    assert '--llm-notes=' in words
    assert fw.resolve_settings(parse_cli(words[1:]), environ={}).llm_notes == ''


def test_notes_starting_with_a_dash_stay_one_unit_argument(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[llm]\nnotes = from file\n')
    parsed = parse_cli(['--config', str(conf), '--llm-notes=-noisy', 'p.txt'])
    line = exec_start_line(fw.render_unit_file(parsed, executable='/bin/fw', config_exists=True))
    assert ' --llm-notes=-noisy ' in line
    # What systemd hands back to firewatcher parses to the same note.
    assert fw.resolve_settings(parse_cli(systemd_words(line)[1:]), environ={}).llm_notes == '-noisy'


def test_install_with_notes_and_no_config_writes_them_to_the_new_config(tmp_path):
    conf = tmp_path / 'firewatcher.conf'  # the default config path conftest points into tmp_path
    assert not conf.exists()
    args = parse_cli(['--install-service', '--no-enable', '-o', str(tmp_path / 'out'), '--llm-notes', "don't; 100% $HOME", 'p.txt'])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    assert "\nnotes = don't; 100% $HOME\n" in conf.read_text()
    assert 'llm-notes' not in (tmp_path / 'units' / 'firewatcher.service').read_text()


def test_a_rendered_unit_with_a_note_passes_systemd_analyze_verify(tmp_path):
    import shutil
    import subprocess
    analyze = shutil.which('systemd-analyze')
    if not analyze:
        pytest.skip('systemd-analyze is not installed')
    conf = tmp_path / 'fw.conf'
    conf.write_text('[llm]\nenabled = false\n')
    parsed = parse_cli(['--config', str(conf), '--llm-notes', "don't; 100% $HOME", 'p.txt'])
    unit = tmp_path / 'fwtest.service'
    unit.write_text(fw.render_unit_file(parsed, executable='/bin/true', config_exists=True))
    done = subprocess.run([analyze, 'verify', str(unit)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
    assert done.returncode == 0, done.stdout


def test_quote_unit_arg_keeps_a_bare_semicolon_and_newlines_inside_one_argument():
    # A bare ';' ends an ExecStart command, and a raw newline would end the line (or add a directive).
    assert fw._quote_unit_arg(';') == '";"'
    assert fw._quote_unit_arg('m\nExecStartPre=/bin/false\r') == '"m\\nExecStartPre=/bin/false\\r"'


# --- RequiresMountsFor= paths ---
# Checked against systemd 257: a bind mount at each path, then which mount unit the unit's After= named.

def _mounts_line(*paths):
    argv = ['--print-unit']
    for path in paths:
        argv += ['--requires-mounts-for', path]
    unit = fw.render_unit_file(parse_cli(argv + ['/etc/firewatcher/patterns.d']), executable='/bin/fw')
    return [line for line in unit.splitlines() if line.startswith('RequiresMountsFor=')]


def _systemd_reads(value):
    """How systemd reads one RequiresMountsFor= value: words split on whitespace, quotes group, a backslash
    inside double quotes takes the next character, %% is one %."""
    words, word, quoted, started, chars = [], '', False, False, iter(value)
    for ch in chars:
        if quoted and ch == '\\':
            word += next(chars)
        elif ch == '"':
            quoted, started = not quoted, True
        elif ch.isspace() and not quoted:
            if started or word:
                words.append(word)
            word, started = '', False
        else:
            word += ch
    if started or word:
        words.append(word)
    return [w.replace('%%', '%') for w in words]


@pytest.mark.parametrize('path, line', [
    ('/mnt/logs/captured_messages', 'RequiresMountsFor=/mnt/logs/captured_messages'),
    ('/mnt/a$b', 'RequiresMountsFor=/mnt/a$b'),
    ('/mnt/a;b', 'RequiresMountsFor=/mnt/a;b'),
    ('/mnt/a#b', 'RequiresMountsFor=/mnt/a#b'),
    ('/mnt/my logs', 'RequiresMountsFor="/mnt/my logs"'),
    ('/mnt/a\tb', 'RequiresMountsFor="/mnt/a\tb"'),
    ('/mnt/100%', 'RequiresMountsFor=/mnt/100%%'),
    ('/mnt/%h y', 'RequiresMountsFor="/mnt/%%h y"'),
    ('/mnt/a"b', 'RequiresMountsFor="/mnt/a\\"b"'),
    ('/mnt/a\\b', 'RequiresMountsFor="/mnt/a\\\\b"'),
    ("/mnt/a'b", 'RequiresMountsFor="/mnt/a\'b"'),
    ('/mnt/a b\\', 'RequiresMountsFor="/mnt/a b\\\\"'),
    ('/mnt/a"b c\\d', 'RequiresMountsFor="/mnt/a\\"b c\\\\d"'),
])
def test_requires_mounts_for_line_is_quoted_so_systemd_reads_the_path_back(path, line):
    assert _mounts_line(path) == [line]
    assert _systemd_reads(line.partition('=')[2]) == [path]


def test_requires_mounts_for_paths_are_normalized_as_text(tmp_path):
    # systemd ignores '..', '//' and '.' ("not normalized"); normalize as text, follow no symlinks.
    assert _mounts_line('/mnt/logs/') == ['RequiresMountsFor=/mnt/logs']
    assert _mounts_line('//mnt/./logs') == ['RequiresMountsFor=/mnt/logs']
    assert _mounts_line('/mnt/nfs/../logs') == ['RequiresMountsFor=/mnt/logs']
    assert _mounts_line('/mnt/a..b') == ['RequiresMountsFor=/mnt/a..b']
    (tmp_path / 'nfs').mkdir()
    (tmp_path / 'data').symlink_to(tmp_path / 'nfs')
    assert _mounts_line(str(tmp_path / 'data' / 'logs')) == ['RequiresMountsFor=%s' % (tmp_path / 'data' / 'logs')]


def test_requires_mounts_for_touches_no_file(monkeypatch):
    # A hung hard NFS mount or an automount point must not stall or trigger anything.
    def no_fs(*args, **kwargs):
        raise AssertionError('the file system was touched')

    for name in ('lstat', 'stat', 'readlink'):
        monkeypatch.setattr(fw.os, name, no_fs)
    assert fw._mount_paths(['/mnt/nfs/../logs', '/mnt/x']) == ['/mnt/logs', '/mnt/x']


def test_requires_mounts_for_refuses_a_newline_the_current_directory_brings_in(tmp_path, monkeypatch):
    odd = tmp_path / 'a\nb'
    odd.mkdir()
    monkeypatch.chdir(str(odd))
    with pytest.raises(fw.ConfigError) as err:
        fw.resolve_settings(parse_cli(['--print-unit', '--requires-mounts-for', 'logs', 'p.d']), environ={})
    assert 'newline' in str(err.value)


def test_requires_mounts_for_keeps_a_utf8_path_whatever_python_decoded(tmp_path):
    # Python 3.6 under a C locale hands over 'caf\u00e9' as surrogate-escaped bytes; the unit gets the text.
    path = b'/mnt/caf\xc3\xa9'.decode('ascii', 'surrogateescape')
    assert _mounts_line(path) == ['RequiresMountsFor=/mnt/caf\u00e9']


def test_requires_mounts_for_refuses_a_path_that_is_not_utf8():
    path = b'/mnt/caf\xe9'.decode('utf-8', 'surrogateescape')
    with pytest.raises(fw.ConfigError) as err:
        fw.resolve_settings(parse_cli(['--print-unit', '--requires-mounts-for', path, 'p.d']), environ={})
    assert 'not UTF-8' in str(err.value)


def test_requires_mounts_for_relative_path_with_the_current_directory_gone(monkeypatch):
    def gone():
        raise FileNotFoundError(2, 'No such file or directory')

    monkeypatch.setattr(fw.os, 'getcwd', gone)
    monkeypatch.setattr(fw.os, 'getcwdb', gone)
    with pytest.raises(fw.ConfigError) as err:
        fw.resolve_settings(parse_cli(['--print-unit', '--requires-mounts-for', 'logs', 'p.d']), environ={})
    assert 'cannot make' in str(err.value)


def test_requires_mounts_for_relative_path_in_a_non_utf8_directory_is_refused(tmp_path, monkeypatch):
    # The current directory's bytes count too: the resolved path must be UTF-8 as a whole.
    odd = os.path.join(os.fsencode(str(tmp_path)), b'caf\xe9')
    try:
        os.mkdir(odd)
    except OSError as exc:
        if exc.errno != errno.EILSEQ:
            raise
        pytest.skip('this filesystem refuses a name that is not UTF-8 (APFS on macOS)')
    monkeypatch.chdir(odd)
    with pytest.raises(fw.ConfigError) as err:
        fw.resolve_settings(parse_cli(['--print-unit', '--requires-mounts-for', 'logs', 'p.d']), environ={})
    assert 'not UTF-8' in str(err.value)


def test_requires_mounts_for_keeps_each_path_a_separate_line_and_adds_remote_fs():
    lines = _mounts_line('/mnt/my logs', '/mnt/b')
    assert lines == ['RequiresMountsFor="/mnt/my logs"', 'RequiresMountsFor=/mnt/b']
    unit = fw.render_unit_file(parse_cli(['--print-unit', '--requires-mounts-for', '/mnt/my logs', 'p.d']),
                               executable='/bin/fw')
    assert 'remote-fs.target' in unit


def test_requires_mounts_for_makes_a_relative_path_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert _mounts_line('nfs/logs') == ['RequiresMountsFor=' + str(tmp_path / 'nfs' / 'logs')]
    assert _mounts_line('./a b') == ['RequiresMountsFor="%s"' % (tmp_path / 'a b')]
    assert fw.resolve_settings(parse_cli(['--requires-mounts-for', 'x', 'p.d']),
                               environ={}).requires_mounts_for == [str(tmp_path / 'x')]


def test_requires_mounts_for_empty_path_is_dropped():
    assert _mounts_line('') == []


@pytest.mark.parametrize('path', ['/mnt/a\nb', '/mnt/a\rb', 'rel\nx'])
def test_requires_mounts_for_refuses_a_newline_or_carriage_return(path, capsys):
    with pytest.raises(fw.ConfigError) as exc:
        fw.resolve_settings(parse_cli(['--requires-mounts-for', path, 'p.d']), environ={})
    assert '--requires-mounts-for' in str(exc.value)
    assert 'newline' in str(exc.value)
    with pytest.raises(SystemExit) as exit_info:
        fw.main(['--print-unit', '--requires-mounts-for', path])
    assert exit_info.value.code == 2
    assert '--requires-mounts-for' in capsys.readouterr().err


def test_install_refuses_a_bad_mount_path_before_writing_anything(tmp_path, capsys):
    unit_dir = tmp_path / 'system'
    patterns = tmp_path / 'patterns.d'
    out = tmp_path / 'captures'
    calls = []
    parsed = parse_cli(['--install-service', '-o', str(out), '--requires-mounts-for', '/mnt/a\nb', str(patterns)])
    rc = fw.install_service(parsed, systemd_available=True, unit_dir=str(unit_dir),
                            systemctl=systemctl_recorder(calls), executable='/bin/fw')
    assert rc == 2
    err = capsys.readouterr().err
    assert '--requires-mounts-for' in err and 'newline' in err
    assert not unit_dir.exists() and not patterns.exists() and not out.exists()
    assert not os.path.exists(fw.DEFAULT_CONFIG_PATH)
    assert calls == []


def test_main_install_refuses_a_bad_mount_path_with_exit_2_and_no_traceback(tmp_path, capsys):
    out = tmp_path / 'captures'
    with pytest.raises(SystemExit) as exit_info:
        fw.main(['--install-service', '-o', str(out), '--requires-mounts-for', '/mnt/a\rb', str(tmp_path / 'p.d')])
    assert exit_info.value.code == 2
    assert 'Traceback' not in capsys.readouterr().err
    assert not out.exists() and not os.path.exists(fw.DEFAULT_CONFIG_PATH)


def test_install_writes_a_quoted_mount_path_to_the_unit(tmp_path):
    unit_dir = tmp_path / 'system'
    parsed = parse_cli(['--install-service', '--no-enable', '-o', str(tmp_path / 'out'),
                        '--requires-mounts-for', '/mnt/my logs', str(tmp_path / 'p.d')])
    assert fw.install_service(parsed, systemd_available=True, unit_dir=str(unit_dir),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    assert 'RequiresMountsFor="/mnt/my logs"\n' in (unit_dir / 'firewatcher.service').read_text()


# --- values that are not UTF-8 ---
# Python decodes argv, paths and the environment with surrogateescape: bytes the locale cannot decode (every
# non-ASCII byte on Python 3.6 under a C locale) arrive as lone surrogates. An install writes them as the UTF-8
# text they spell, and refuses bytes that are not UTF-8, which no config or unit file can hold.

def not_utf8(path):
    return (str(path).encode() + b'/caf\xe9').decode('utf-8', 'surrogateescape')


def c_locale_utf8(path):
    # valid UTF-8 that Python 3.6 under a C locale reads as escaped bytes
    return (str(path).encode() + b'/caf\xc3\xa9').decode('ascii', 'surrogateescape')


def install_refused_and_nothing_written(root, flags, capsys):
    args = parse_cli(['--install-service', '--ntfy-url', 'https://ntfy.sh/private-topic'] + flags)
    assert fw.install_service(args, systemd_available=True, unit_dir=str(root / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 2, flags
    assert os.listdir(str(root)) == [], flags
    err = capsys.readouterr().err
    # the message never shows a secret: one value may be the private ntfy topic
    assert 'UTF-8' in err and 'private-topic' not in err and 'Traceback' not in err, flags
    return err


def test_a_value_that_is_not_utf8_is_refused_before_anything_is_written(tmp_path, monkeypatch, capsys):
    root = tmp_path / 'root'
    root.mkdir()
    monkeypatch.setattr(fw, 'DEFAULT_PATTERNS_DIR', str(root / 'patterns.d'))
    monkeypatch.setattr(fw, 'DEFAULT_CONFIG_PATH', str(root / 'etc' / 'firewatcher.conf'))
    for flags in (['-o', not_utf8(root)], ['--llm-notes', not_utf8('note')], [not_utf8(root)],
                  ['-o', str(root / 'out'), '--requires-mounts-for', not_utf8(root)]):
        install_refused_and_nothing_written(root, flags, capsys)


def test_a_value_that_is_not_utf8_is_refused_with_a_config_that_exists(tmp_path, capsys):
    # The folder goes on ExecStart then, and only the unit text holds it: that text is checked too.
    root = tmp_path / 'root'
    root.mkdir()
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\npatterns = %s\n' % (tmp_path / 'p.txt'))
    args = parse_cli(['--install-service', '--no-enable', '--config', str(conf), '-o', not_utf8(root)])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(root / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 2
    assert os.listdir(str(root)) == [] and not os.path.exists(not_utf8(root))
    assert 'UTF-8' in capsys.readouterr().err
    # escaped UTF-8 goes on ExecStart as the text it spells
    args = parse_cli(['--install-service', '--no-enable', '--config', str(conf), '-o', c_locale_utf8(root)])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(root / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    unit = (root / 'units' / 'firewatcher.service').read_bytes().decode('utf-8')
    assert ' -o %s/caf\u00e9' % root in unit


def test_a_non_ascii_path_and_note_are_written_as_utf8(tmp_path):
    # Under a UTF-8 locale (Python 3.7 and later under a C locale too) 'café' arrives as text and is installed.
    folder = str(tmp_path / 'café')
    args = parse_cli(['--install-service', '--no-enable', '-o', folder, '--llm-notes', 'café build box',
                      str(tmp_path / 'p.d')])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    again = fw.resolve_settings(parse_cli(['--config', fw.DEFAULT_CONFIG_PATH]), environ={})
    assert again.output_folder == folder and again.llm_notes == 'café build box'
    # with the config there, the folder goes on ExecStart instead
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    unit = (tmp_path / 'units' / 'firewatcher.service').read_bytes().decode('utf-8')
    assert ' -o %s ' % folder in unit


def test_a_secret_that_is_not_written_is_no_reason_to_refuse(tmp_path, monkeypatch):
    # With a config already there, the API key from the environment goes into neither file.
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\npatterns = %s\n' % (tmp_path / 'p.txt'))
    monkeypatch.setenv('FIREWATCHER_LLM_API_KEY', b'k\xe9'.decode('utf-8', 'surrogateescape'))
    args = parse_cli(['--install-service', '--no-enable', '--config', str(conf), '-o', str(tmp_path / 'out')])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=ok_systemctl, executable='/bin/fw') == 0
    assert (tmp_path / 'units' / 'firewatcher.service').exists()
    assert fw.main(['--print-unit', '--config', str(conf), 'p.txt']) == 0
