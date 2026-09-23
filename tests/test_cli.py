import os
import subprocess
import sys
from pathlib import Path

import pytest

import firewatcher as fw
from conftest import ROOT, parse_cli, fake_exists, incident_logs

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
    out = capsys.readouterr().out
    assert '--config' in out
    assert fw.DEFAULT_CONFIG_PATH in out


def test_main_requires_pattern_file():
    with pytest.raises(SystemExit) as exc:
        fw.main([])
    assert exc.value.code != 0


def test_main_dispatches_install_and_uninstall(monkeypatch):
    seen = {}

    def fake_install(args, raw=None):
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
    assert incident_logs(out)


def test_main_no_log_source(tmp_path, monkeypatch, capsys):
    pat = tmp_path / 'p.txt'
    pat.write_text('x\n')
    monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists())
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
        parse_cli(['--install-service', '--print-unit', 'p.txt'])


def test_module_has_no_nebula_product_name():
    src = open(fw.__file__, encoding='utf-8').read().lower()
    assert 'nebula' not in src
    assert fw.version == '1.58'
    assert fw.__version__ == fw.version


def test_print_flushes_by_default(capsys):
    fw.print('hello-flush')
    assert 'hello-flush' in capsys.readouterr().out


def test_module_entrypoint_version():
    result = subprocess.run(
        [sys.executable, str(ROOT / 'firewatcher.py'), '-V'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert fw.version in (result.stdout + result.stderr)


def test_parser_workers_flag():
    parsed = parse_cli(['--workers', '0', 'p.txt'])
    assert parsed.workers == 0


def test_main_install_defaults_pattern_dir(monkeypatch):
    seen = {}

    def fake_install(parsed, raw=None):
        seen['patterns'] = list(parsed.pattern_file)
        return 0

    monkeypatch.setattr(fw, 'install_service', fake_install)
    assert fw.main(['--install-service']) == 0
    assert seen['patterns'] == [fw.DEFAULT_PATTERNS_DIR]


def test_print_honors_explicit_flush_false(capsys):
    fw.print('no-force', flush=False)
    assert 'no-force' in capsys.readouterr().out
