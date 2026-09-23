import os
import re

import pytest

import firewatcher as fw
from conftest import parse_cli, ok_systemctl


def test_missing_default_config_uses_builtins():
    args = parse_cli(['p.txt'])
    settings = fw.resolve_settings(args, environ={})
    assert settings.capture_time == 300
    assert settings.output_folder == fw.DEFAULT_OUTPUT_FOLDER
    assert settings.tail_lines == '20'
    assert settings.filter_only is False
    assert settings.llm_enabled is False
    assert settings.notify_enabled is False
    assert settings.config_existed is False


def test_explicit_missing_config_is_an_error(tmp_path):
    missing = tmp_path / 'missing.conf'
    with pytest.raises(fw.ConfigError, match='not found'):
        fw.resolve_settings(parse_cli(['--config', str(missing), 'p.txt']), environ={})


def test_main_explicit_missing_config(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        fw.main(['--config', str(tmp_path / 'missing.conf')])
    assert exc.value.code != 0
    assert 'not found' in capsys.readouterr().err


def test_cli_overrides_config_and_patterns_replace(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text(
        '[watch]\n'
        'capture_time = 10\n'
        'filter_only = true\n'
        'patterns = /from/config\n'
        '[llm]\n'
        'enabled = true\n'
        'base_url = http://config/v1\n'
        'model = config-model\n'
    )
    settings = fw.resolve_settings(parse_cli([
        '--config', str(conf),
        '-t', '15',
        '--no-filter_only',
        '--llm-model', 'cli-model',
        '/from/cli',
    ]), environ={})
    assert settings.capture_time == 15
    assert settings.filter_only is False
    assert settings.pattern_file == ['/from/cli']
    assert settings.llm_enabled is True
    assert settings.llm_base_url == 'http://config/v1'
    assert settings.llm_model == 'cli-model'


def test_no_llm_overrides_enabled_config_without_model(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[llm]\nenabled = true\n')
    settings = fw.resolve_settings(parse_cli(['--config', str(conf), '--no-llm', 'p.txt']), environ={})
    assert settings.llm_enabled is False


def test_env_overrides_secrets_and_percent_roundtrips(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[llm]\napi_key = fromfile\n[notify]\ntoken = filetoken\n')
    settings = fw.resolve_settings(parse_cli(['--config', str(conf), 'p.txt']), environ={
        fw.LLM_API_KEY_ENV: 'abc%def',
        fw.NTFY_TOKEN_ENV: 'tok%en',
    })
    assert settings.llm_api_key == 'abc%def'
    assert settings.ntfy_token == 'tok%en'
    dest = tmp_path / 'written.conf'
    fw.write_config_file(str(dest), settings)
    assert (os.stat(dest).st_mode & 0o777) == 0o600
    again = fw.resolve_settings(parse_cli(['--config', str(dest)]), environ={})
    assert again.llm_api_key == 'abc%def'
    assert again.ntfy_token == 'tok%en'


@pytest.mark.parametrize('hostname, topic_host', [
    ('ksxx', 'ksxx'),
    ('node.example/\u03c0', 'node-example'),
    ('n' * 80, 'n' * 39),
    ('...///', 'localhost'),
])
def test_generated_config_prefills_compact_valid_ntfy_topic(tmp_path, monkeypatch, hostname, topic_host):
    monkeypatch.setattr(fw.socket, 'gethostname', lambda: hostname)
    conf = tmp_path / 'generated.conf'
    settings = fw.resolve_settings(parse_cli(['p.txt']), environ={})
    fw.write_config_file(str(conf), settings)

    loaded = fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})
    prefix = 'https://ntfy.sh/firewatcher-' + topic_host + '-'
    assert loaded.ntfy_url.startswith(prefix)
    suffix = loaded.ntfy_url[len(prefix):]
    assert re.fullmatch(r'[A-Za-z0-9_-]{12}', suffix)
    topic = loaded.ntfy_url.rsplit('/', 1)[1]
    assert len(topic) <= 64
    assert loaded.notify_enabled is False
    assert loaded.llm_enabled is False
    assert loaded.pattern_file == ['p.txt']


def test_new_configs_get_distinct_topics_without_overwriting_existing_config(tmp_path):
    settings = fw.resolve_settings(parse_cli(['p.txt']), environ={})
    first = tmp_path / 'first.conf'
    second = tmp_path / 'second.conf'
    fw.write_config_file(str(first), settings)
    fw.write_config_file(str(second), settings)
    first_settings = fw.resolve_settings(parse_cli(['--config', str(first)]), environ={})
    second_settings = fw.resolve_settings(parse_cli(['--config', str(second)]), environ={})
    assert first_settings.ntfy_url != second_settings.ntfy_url

    original = first.read_bytes()
    with pytest.raises(FileExistsError):
        fw.write_config_file(str(first), settings)
    assert first.read_bytes() == original


def test_generated_config_preserves_explicit_url_and_special_values(tmp_path):
    settings = fw.resolve_settings(parse_cli([
        '--ntfy-url', 'https://ntfy.example/my-topic', '--notify',
        '/patterns with spaces', '/patterns#hash',
    ]), environ={
        fw.LLM_API_KEY_ENV: 'key%with#hash ; literal',
        fw.NTFY_TOKEN_ENV: 'token%with;semicolon # literal',
    })
    conf = tmp_path / 'generated.conf'
    fw.write_config_file(str(conf), settings)
    loaded = fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})
    assert loaded.ntfy_url == 'https://ntfy.example/my-topic'
    assert loaded.notify_enabled is True
    assert loaded.pattern_file == ['/patterns with spaces', '/patterns#hash']
    assert loaded.llm_api_key == 'key%with#hash ; literal'
    assert loaded.ntfy_token == 'token%with;semicolon # literal'


def test_config_patterns_split_on_commas_and_lines(tmp_path):
    assert fw._ini_patterns([]) == ''
    assert fw._ini_patterns(['/a', '/b']) == '/a\n\t/b'
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\npatterns = /one, /two\n\t/three\n')
    settings = fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})
    assert settings.pattern_file == ['/one', '/two', '/three']


def test_invalid_config_values(tmp_path):
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\nfilter_only = maybe\n')
    with pytest.raises(fw.ConfigError, match='boolean'):
        fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})
    conf.write_text('[watch]\ncapture_time = no\n')
    with pytest.raises(fw.ConfigError, match='integer'):
        fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})


def test_llm_and_notify_require_their_endpoints():
    with pytest.raises(SystemExit):
        fw.main(['--llm', 'p.txt'])
    with pytest.raises(SystemExit):
        fw.main(['--notify', 'p.txt'])
    with pytest.raises(fw.ConfigError):
        fw.resolve_settings(parse_cli(['--llm', '--llm-base-url', 'http://127.0.0.1:9/v1', 'p.txt']), environ={})


def test_tri_state_flags_reject_both_directions():
    with pytest.raises(SystemExit):
        parse_cli(['--llm', '--no-llm', 'p.txt'])
    with pytest.raises(SystemExit):
        parse_cli(['--notify', '--no-notify', 'p.txt'])
    with pytest.raises(SystemExit):
        parse_cli(['--filter_only', '--no-filter_only', 'p.txt'])


def test_install_keeps_existing_config_and_appends_explicit_flags(tmp_path):
    old_out = tmp_path / 'old-out'
    conf = tmp_path / 'keep.conf'
    conf.write_text('[watch]\ncapture_time = 10\noutput_folder = %s\n' % old_out)
    original = conf.read_text()
    unit_dir = tmp_path / 'system'
    patterns = tmp_path / 'patterns.d'
    parsed = parse_cli([
        '--install-service', '--no-enable', '--config', str(conf), '-t', '15', str(patterns),
    ])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=ok_systemctl,
        executable='/bin/fw',
    )
    assert rc == 0
    assert conf.read_text() == original
    text = (unit_dir / 'firewatcher.service').read_text()
    assert '--config ' in text or '--config\n' in text or str(conf) in text
    assert '-t 15' in text
    assert str(patterns) in text
    assert 'capture_time = 10' in conf.read_text()


def test_install_rejects_enabled_llm_without_model(tmp_path):
    parsed = parse_cli(['--install-service', '--llm', str(tmp_path / 'p.d')])
    rc = fw.install_service(parsed, systemd_available=True, unit_dir=str(tmp_path / 'system'), systemctl=ok_systemctl, executable='/bin/fw')
    assert rc == 2
    assert not (tmp_path / 'system' / 'firewatcher.service').exists()


def test_explicit_feature_flags_resolve_and_append_when_config_exists():
    parsed = parse_cli([
        '--print-unit',
        '--llm-base-url', ' http://llm.example/v1 ',
        '--llm-model', ' m ',
        '--llm-timeout', '9',
        '--llm-max-bytes', '1000',
        '--llm',
        '--notify',
        '--ntfy-url', ' https://ntfy.example/t ',
        '--ntfy-priority', '5',
        '--ntfy-timeout', '3',
        '--no-filter_only',
        'p.txt',
    ])
    settings = fw.resolve_settings(parsed, environ={})
    assert settings.llm_base_url == 'http://llm.example/v1'
    assert settings.llm_model == 'm'
    assert settings.llm_timeout == 9
    assert settings.llm_max_bytes == 1000
    assert settings.ntfy_url == 'https://ntfy.example/t'
    assert settings.ntfy_priority == 5
    assert settings.ntfy_timeout == 3
    assert settings.filter_only is False
    unit = fw.render_unit_file(parsed, executable='/bin/fw', config_exists=True)
    for flag in ('--llm-base-url', '--llm-model', '--llm-timeout 9', '--llm-max-bytes 1000',
                 '--llm', '--notify', '--ntfy-url', '--ntfy-priority 5', '--ntfy-timeout 3',
                 '--no-filter_only', 'p.txt'):
        assert flag in unit
    negated = parse_cli(['--print-unit', '--no-llm', '--no-notify', 'p.txt'])
    unit = fw.render_unit_file(negated, executable='/bin/fw', config_exists=True)
    assert '--no-llm' in unit
    assert '--no-notify' in unit
    resolved = fw.resolve_settings(parsed, environ={})
    again = fw.render_unit_file(resolved, executable='/bin/fw', config_exists=False)
    assert '--config' in again


def test_print_unit_without_patterns_uses_default_dir():
    unit = fw.render_unit_file(parse_cli(['--print-unit']), executable='/bin/fw', config_exists=False)
    assert '--config' in unit


def test_unreadable_and_duplicate_config(tmp_path):
    with pytest.raises(fw.ConfigError, match='cannot read'):
        fw._read_config_file(str(tmp_path / 'missing.conf'))
    conf = tmp_path / 'dup.conf'
    conf.write_text('[watch]\na = 1\n[watch]\nb = 2\n')
    with pytest.raises(fw.ConfigError, match='cannot read'):
        fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})


def test_install_fills_empty_patterns_and_reports_config_write_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fw, 'DEFAULT_PATTERNS_DIR', str(tmp_path / 'patterns.d'))
    resolved = fw.resolve_settings(parse_cli(['--install-service']), environ={})
    resolved.pattern_file = []
    resolved.output_folder = str(tmp_path / 'out')
    unit_dir = tmp_path / 'units'
    rc = fw.install_service(
        resolved,
        systemd_available=True,
        unit_dir=str(unit_dir),
        systemctl=ok_systemctl,
        executable='/bin/fw',
    )
    assert rc == 0
    assert fw.DEFAULT_PATTERNS_DIR in open(fw.DEFAULT_CONFIG_PATH, encoding='utf-8').read()
    blocker = tmp_path / 'not-a-directory'
    blocker.write_text('x')
    monkeypatch.setattr(fw, 'DEFAULT_CONFIG_PATH', str(blocker / 'firewatcher.conf'))
    parsed = parse_cli(['--install-service', '--no-enable', str(tmp_path / 'p.d')])
    rc = fw.install_service(
        parsed,
        systemd_available=True,
        unit_dir=str(tmp_path / 'units2'),
        systemctl=ok_systemctl,
        executable='/bin/fw',
    )
    assert rc == 1
    assert 'cannot write config' in capsys.readouterr().err


def test_main_announces_enabled_llm_and_notify(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fw.syslog, 'openlog', lambda *args, **kwargs: None)
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args, **kwargs: None)
    src = tmp_path / 'src.log'
    src.write_text('quiet\n')
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    rc = fw.main([
        '--filter_only', '--log-file', str(src), '-o', str(tmp_path / 'out'),
        '--llm', '--llm-base-url', 'http://127.0.0.1:9/v1', '--llm-model', 'm',
        '--notify', '--ntfy-url', 'https://ntfy.example/t',
        str(pat),
    ])
    assert rc == 0
    printed = capsys.readouterr().out
    assert 'LLM analysis enabled' in printed
    assert 'Notifications enabled' in printed


def test_log_source_honors_config_filter_only(tmp_path, monkeypatch):
    monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\nfilter_only = true\nlog_file = /tmp/x.log\n')
    settings = fw.resolve_settings(parse_cli(['--config', str(conf)]), environ={})
    assert fw.log_source_command(settings) == ['cat', '/tmp/x.log']
