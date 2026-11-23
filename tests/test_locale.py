import codecs
import io
import json
import os
import subprocess
import sys

import pytest

import firewatcher as fw
from conftest import ROOT, incident_logs

# --- Python 3.6 under a C locale, where file names, stdout and open() are ASCII ---
# Python 3.7 and later behave the same with PYTHONCOERCECLOCALE=0 and PYTHONUTF8=0, so these run on every Python.


def escaped(path):
    """path as Python 3.6 under a C locale hands it over: its UTF-8 bytes escaped."""
    return os.fsencode(str(path)).decode('ascii', 'surrogateescape')


def run_in_ascii_locale(*args):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('LC_') and key not in ('LANG', 'LANGUAGE', 'PYTHONIOENCODING')}
    env.update(LC_ALL='C', PYTHONCOERCECLOCALE='0', PYTHONUTF8='0')
    probe = subprocess.run([sys.executable, '-c', 'import sys; print(sys.getfilesystemencoding())'],
                           env=env, stdout=subprocess.PIPE, universal_newlines=True)
    if codecs.lookup(probe.stdout.strip()).name != 'ascii':
        pytest.skip('file names are UTF-8 in every locale here (macOS)')
    proc = subprocess.run([sys.executable, str(ROOT / 'firewatcher.py')] + [str(arg) for arg in args], env=env,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    return proc.returncode, proc.stdout.decode('utf-8', 'replace')


@pytest.mark.parametrize('given', ['config', 'command line'])
def test_non_ascii_paths_patterns_and_lines_work_in_an_ascii_locale(tmp_path, given):
    # 1.68 stopped with UnicodeEncodeError: at start for a path from the config (a service installed under a UTF-8
    # locale and started under a C one), at the first capture for one from the command line or a non-ASCII matched
    # line; and it could not read a non-ASCII pattern file.
    out = tmp_path / 'café'
    patterns = tmp_path / 'pé.txt'
    patterns.write_text('HIT\nnaïve\n', encoding='utf-8')
    log = tmp_path / 'logé.txt'
    log.write_text('a line\nHIT café\nafter\n', encoding='utf-8')
    conf = tmp_path / 'fw.conf'
    if given == 'config':
        conf.write_text('[watch]\npatterns = %s\nlog_file = %s\noutput_folder = %s\nfallback_folder =\n' % (
            patterns, log, out), encoding='utf-8')
        argv = ['--config', conf, '--filter-only', '-t', '1']
    else:
        conf.write_text('')
        argv = ['--config', conf, '--filter-only', '-t', '1', '--log-file', log, '-o', out, '--fallback-folder', '',
                patterns]
    rc, output = run_in_ascii_locale(*argv)
    assert rc == 0 and 'Traceback' not in output, output
    logs = incident_logs(out)
    assert len(logs) == 1
    assert 'HIT café' in logs[0].read_text(encoding='utf-8')
    assert str(logs[0]) in (out / 'journal.log').read_text(encoding='utf-8')
    # the pattern file's non-ASCII pattern loaded too
    assert '*naïve*' in output or 'na\\xefve' in output


def test_a_capture_moved_from_a_non_ascii_folder_names_it_in_an_ascii_locale(tmp_path):
    blocked = tmp_path / 'bloqué'
    blocked.write_text('')  # a file where the output folder should be
    fallback = tmp_path / 'fallback'
    patterns = tmp_path / 'p.txt'
    patterns.write_text('HIT\n')
    log = tmp_path / 'log.txt'
    log.write_text('a line\nHIT here\nafter\n')
    conf = tmp_path / 'fw.conf'
    conf.write_text('[watch]\noutput_folder = %s\nfallback_folder = %s\n' % (blocked, fallback), encoding='utf-8')
    rc, output = run_in_ascii_locale('--config', conf, '--filter-only', '-t', '1', '--log-file', log, patterns)
    assert rc == 0 and 'Traceback' not in output, output
    logs = incident_logs(fallback)
    assert len(logs) == 1
    assert 'capture moved here from %s' % blocked in logs[0].read_text(encoding='utf-8')


def test_an_install_writes_escaped_utf8_as_its_text_and_the_service_reads_it_back(tmp_path, monkeypatch):
    # 1.68 refused it (exit 2), because the service, started under the same locale, could not use it
    monkeypatch.setattr(fw, 'DEFAULT_PATTERNS_DIR', str(tmp_path / 'patterns.d'))
    folder = tmp_path / 'café'
    args = fw.build_parser().parse_args(['--install-service', '--no-enable', '-o', escaped(folder),
                                         '--llm-notes', escaped('café build box')])
    assert fw.install_service(args, systemd_available=True, unit_dir=str(tmp_path / 'units'),
                              systemctl=lambda *cmd: None, executable='/bin/fw') == 0
    with open(fw.DEFAULT_CONFIG_PATH, 'rb') as config:
        text = config.read().decode('utf-8')
    assert 'output_folder = %s\n' % folder in text and 'notes = café build box\n' in text
    assert folder.is_dir()
    again = fw.resolve_settings(fw.build_parser().parse_args(['--config', fw.DEFAULT_CONFIG_PATH]), environ={})
    assert os.fsencode(again.output_folder) == os.fsencode(str(folder))


def test_print_escapes_what_the_stream_cannot_encode():
    stream = io.TextIOWrapper(io.BytesIO(), encoding='ascii')
    fw.print('Matched line: HIT café', file=stream)
    stream.seek(0)
    assert stream.read() == 'Matched line: HIT caf\\xe9\n'


def test_text_firewatcher_logs_or_sends_spells_escaped_bytes_as_utf8(tmp_path, monkeypatch):
    path = escaped(tmp_path / 'café.log')
    with open(path, 'w') as capture:
        capture.write('HIT now\n')
    # syslog takes UTF-8 only; 1.68 lost such a line
    records = []
    monkeypatch.setattr(fw.syslog, 'syslog', lambda priority, line: records.append(line.encode('utf-8')))
    fw._journal(fw.syslog.LOG_ERR, 'cannot write capture %s' % path)
    assert records == [('firewatcher-self cannot write capture %s' % (tmp_path / 'café.log')).encode('utf-8')]
    # a push names the capture; 1.68 stopped the push with UnicodeEncodeError
    body = fw._notify_body('HIT café', path)
    assert body.encode('utf-8').endswith(('\n%s' % (tmp_path / 'café.log')).encode('utf-8'))
    # the events service gets the path as text, not as lone surrogates
    posted = []
    monkeypatch.setattr(fw, 'post_event', lambda url, token, payload, timeout: posted.append(json.dumps(payload)))
    settings = fw.resolve_settings(fw.build_parser().parse_args(['p.txt']), environ={})
    settings.events_url = 'http://events.example/api'
    incident = {'path': path, 'pattern': 'HIT', 'matched_line': 'HIT now', 'hostname': 'box'}
    fw.IncidentDispatcher(settings, start_thread=False)._post_event(incident, False, 'box: HIT', 'HIT now', 3)
    assert json.loads(posted[0])['path'] == str(tmp_path / 'café.log')
    # so does the model
    requests = []

    class Reply(object):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({'choices': [{'message': {'content': '{"title": "t", "summary": "s", "notify": false}'}}]}).encode()

    monkeypatch.setattr(fw, '_open_url', lambda request, timeout: requests.append(request.data) or Reply())
    settings.llm_base_url, settings.llm_model = 'http://llm.example/v1', 'm'
    fw.call_llm(settings, incident)
    assert 'Capture path: %s\n' % (tmp_path / 'café.log') in json.loads(requests[0])['messages'][1]['content']
    # a lone surrogate that is no escaped byte, as a JSON reply can spell one
    assert fw._as_utf8('a\ud800b') == 'a\ufffdb'


def test_a_lone_surrogate_that_is_no_escaped_byte_does_not_turn_the_escaped_bytes_next_to_it_into_question_marks():
    # surrogateescape maps only U+DC80 to U+DCFF: other surrogates become U+FFFD first, so the bytes that
    # are escaped UTF-8 still spell their text ('?? caf? ?' before)
    assert fw._as_utf8('\udcc3\udca9 caf\udce9 \ud800') == '\u00e9 caf\ufffd \ufffd'
    assert fw._as_utf8('\udc7f \udd00 \udfff') == '\ufffd \ufffd \ufffd'
    assert fw._as_utf8('caf\u00e9 \U0001f600') == 'caf\u00e9 \U0001f600'


def test_print_with_several_arguments_writes_them_once_when_a_later_one_cannot_be_encoded():
    # the earlier arguments had been written when the later one raised, and were written again by the fallback
    stream = io.TextIOWrapper(io.BytesIO(), encoding='ascii')
    fw.print('Matched line:', 'HIT café', 3, file=stream)
    fw.print('a', 'b', 'café', sep='-', end='!\n', file=stream)
    fw.print('plain', 'text', file=stream)
    stream.seek(0)
    assert stream.read() == 'Matched line: HIT caf\\xe9 3\na-b-caf\\xe9!\nplain text\n'


def test_an_appended_note_holds_what_the_model_wrote_however_it_spelled_it(tmp_path):
    capture = tmp_path / 'cap.log'
    capture.write_text('HIT\n')
    fw._append_note(str(capture), 'LLM analysis\nsummary:\nbad \ud800 reply, caf\udcc3\udca9')
    assert capture.read_text(encoding='utf-8') == 'HIT\n\nfirewatcher-self LLM analysis\nfirewatcher-self summary:\nfirewatcher-self bad \ufffd reply, café\n'


def test_print_unit_writes_utf8_bytes_whatever_the_locale(tmp_path):
    # piped into a unit file it held backslash escapes in place of the path (1.69 as built); 1.68 stopped
    folder = tmp_path / 'café'
    rc, output = run_in_ascii_locale('--print-unit', '--requires-mounts-for', folder, tmp_path / 'p.txt')
    assert rc == 0 and 'Traceback' not in output
    assert 'RequiresMountsFor=%s\n' % folder in output


def test_print_unit_refuses_what_an_install_would_refuse(tmp_path, capsys):
    # a folder that is not UTF-8, in the ExecStart of a unit for an existing config: the install exits 2 with this
    # message; --print-unit printed the unit with escapes before
    conf = tmp_path / 'fw.conf'
    conf.write_text('')
    assert fw.main(['--print-unit', '--config', str(conf), '-o', os.fsdecode(b'/tmp/caf\xe9'), 'p.txt']) == 2
    captured = capsys.readouterr()
    assert captured.out == '' and 'not UTF-8' in captured.err
