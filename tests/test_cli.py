import os
import signal
import subprocess
import sys
import time
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
    assert fw.version == '1.61'
    assert fw.__version__ == fw.version


def test_print_flushes_by_default(capsys):
    fw.print('hello-flush')
    assert 'hello-flush' in capsys.readouterr().out


def test_module_entrypoint_version():
    result = subprocess.run(
        [sys.executable, str(ROOT / 'firewatcher.py'), '-V'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
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


def test_import_leaves_http_and_secret_modules_unloaded():
    heavy = ('urllib.request', 'http.client', 'ssl', 'json', 'secrets')
    code = (
        'import sys; sys.path.insert(0, %r); import firewatcher; '
        'print(" ".join(m for m in %r if m in sys.modules))'
    ) % (os.path.dirname(os.path.abspath(fw.__file__)), heavy)
    loaded = subprocess.run([sys.executable, '-I', '-S', '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True).stdout.split()
    assert loaded == []


@pytest.mark.parametrize('name, content', [
    ('pattern.d', None),
    ('comments.txt', '# watch for nothing yet\n\n'),
    ('broken.regex', '(\n'),
])
def test_main_exits_when_no_pattern_loads(tmp_path, capsys, name, content):
    # a mistyped path, a file of comments, or only invalid regexes must not leave a daemon watching for nothing
    pat = tmp_path / name
    if content is not None:
        pat.write_text(content)
    src = tmp_path / 'log'
    src.write_text('x\n')
    rc = fw.main(['--filter_only', '--log-file', str(src), str(pat)])
    assert rc == 1
    assert 'No usable patterns' in capsys.readouterr().err


def test_main_keeps_capturing_when_always_notify_loads_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args: None)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    src = tmp_path / 'log'
    src.write_text('HIT now\n')
    out = tmp_path / 'out'
    rc = fw.main(['--filter_only', '--log-file', str(src), '-o', str(out),
                  '--always-notify', str(tmp_path / 'missing.d'), str(pat)])
    assert rc == 0
    assert 'no usable always_notify patterns' in capsys.readouterr().out
    assert incident_logs(out)


def test_main_passes_always_notify_and_restores_sigterm(tmp_path, monkeypatch, capsys):
    seen = {}

    def fake_capture(command, patterns, **kwargs):
        seen.update(kwargs)
        seen['sigterm'] = signal.getsignal(signal.SIGTERM)

    monkeypatch.setattr(fw, 'capture_messages', fake_capture)
    before = signal.getsignal(signal.SIGTERM)
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    always = tmp_path / 'always.txt'
    always.write_text('# pushed whatever the model says\nI/O error\n')
    src = tmp_path / 'log'
    src.write_text('x\n')
    rc = fw.main(['--filter_only', '--log-file', str(src), '--always-notify', str(always),
                  '--capture-time-max', '90', '--fallback-folder', '', str(pat)])
    assert rc == 0
    assert seen['always_notify_patterns'] == {'fnmatch': {'*I/O error*'}}
    assert seen['capture_time_max'] == 90
    assert seen['fallback_folder'] is None
    assert seen['sigterm'] is fw._stop_on_sigterm
    assert signal.getsignal(signal.SIGTERM) == before
    assert 'Always notify for patterns' in capsys.readouterr().out


def test_stop_on_sigterm_interrupts_once_then_takes_the_default():
    previous = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGTERM, fw._stop_on_sigterm)
        with pytest.raises(KeyboardInterrupt):
            fw._stop_on_sigterm(signal.SIGTERM, None)
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
    finally:
        signal.signal(signal.SIGTERM, previous)


def test_sigterm_finishes_the_open_capture(tmp_path):
    live = tmp_path / 'live.log'
    live.write_text('HIT now\n')
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    conf = tmp_path / 'empty.conf'
    conf.write_text('')
    out = tmp_path / 'out'
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / 'firewatcher.py'), '--config', str(conf), '--log-file', str(live),
         '-o', str(out), '--fallback-folder', '', str(pat)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
    )
    try:
        deadline = time.time() + 20
        while not list(out.rglob('hit_*.log')) and time.time() < deadline:
            time.sleep(0.05)
        assert list(out.rglob('hit_*.log'))
        proc.send_signal(signal.SIGTERM)
        output, _ = proc.communicate(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == 0, output
    assert 'Exiting.' in output
    assert 'End of capture' in next(out.rglob('hit_*.log')).read_text()


def test_parser_hides_unimplemented_workers_flag():
    assert '--workers' not in fw.build_parser().format_help()


def test_parser_accepts_hyphenated_spellings():
    parsed = parse_cli(['--tail-lines', '5', '--filter-only', '--capture-line-count-max', '7', 'p.txt'])
    assert parsed.tail_lines == '5'
    assert parsed.filter_only is True
    assert parsed.capture_line_count_max == 7
    assert parse_cli(['--no-filter-only', 'p.txt']).filter_only is False
