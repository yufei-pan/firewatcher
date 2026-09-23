import io
import json
import sys
import urllib.error

import pytest

import firewatcher as fw


class Body:
    def __init__(self, payload):
        self.payload = payload if isinstance(payload, bytes) else payload.encode('utf-8')

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def chat(content):
    return Body(json.dumps({'choices': [{'message': {'content': content}}]}))


def silence_syslog(monkeypatch):
    records = []
    monkeypatch.setattr(fw.syslog, 'openlog', lambda *args, **kwargs: None)
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args: records.append(args))
    return records


def settings_from(tmp_path, text, extra=None, environ=None):
    conf = tmp_path / 'notify.conf'
    conf.write_text(text)
    argv = ['--config', str(conf), 'p.txt']
    if extra:
        argv = extra + argv
    return fw.resolve_settings(fw.build_parser().parse_args(argv), environ=environ or {})


def incident(path, pattern='HIT', line='HIT now'):
    return {'path': str(path), 'pattern': pattern, 'matched_line': line, 'hostname': 'box'}


def test_flatten_and_programmatic_title():
    assert fw._flatten('a\nb\r\nc') == 'a / b / c'
    title = fw._programmatic_title('host', 'p' * 300)
    assert title.startswith('host:')
    assert len(title) <= fw.PROGRAMMATIC_TITLE_MAX
    assert '\n' not in title


def test_parse_llm_object_accepts_fences_and_embedded_json():
    fenced = fw._parse_llm_object('```json\n{"title": "T", "summary": "line\\nmore", "notify": false}\n```')
    assert fenced['notify'] is False
    assert fenced['title'] == 'T'
    assert 'more' in fenced['summary']
    embedded = fw._parse_llm_object('note {"title": "Hi", "summary": "x", "notify": true} trailing')
    assert embedded == {'title': 'Hi', 'summary': 'x', 'notify': True}
    with pytest.raises(ValueError):
        fw._parse_llm_object('{"title": "Hi", "summary": "x", "notify": "yes"}')
    with pytest.raises(ValueError):
        fw._parse_llm_object('no object here')


def test_excerpt_keeps_head_and_tail(tmp_path):
    path = tmp_path / 'big.log'
    path.write_bytes(b'H' * 100 + b'T' * 100)
    text = fw._capture_excerpt(str(path), 40)
    assert text.startswith('H')
    assert 'T' in text
    assert '...' in text
    assert len(text.encode('utf-8')) <= 40
    assert fw._capture_excerpt(str(path), 0) == ''
    assert fw._capture_excerpt(str(path), 10000).startswith('H')


def test_notify_body_stays_within_byte_cap():
    body = fw._notify_body('m' * 10000, '/tmp/capture.log')
    assert len(body.encode('utf-8')) <= fw.NTFY_BODY_MAX
    assert body.endswith('/tmp/capture.log')


def test_capture_notifies_without_llm(tmp_path, monkeypatch):
    calls = []
    records = silence_syslog(monkeypatch)

    def urlopen(req, timeout=None):
        calls.append((req, timeout))
        return Body(b'ok')

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    resolved = settings_from(tmp_path, '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\npriority = 4\ntoken = secret\n')
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    src = tmp_path / 'src.log'
    src.write_text('noise\nHIT the disk\n')
    out = tmp_path / 'out'
    fw.capture_messages(
        ['cat', str(src)], fw.load_patterns([str(pat)]),
        capture_time=5, output_folder=str(out),
        compress_after_months=0, delete_after_months=0,
        notify_settings=resolved,
    )
    assert len(calls) == 1
    req, timeout = calls[0]
    assert req.full_url == 'https://ntfy.example/alerts'
    assert req.get_header('Priority') == '4'
    assert 'Bearer secret' in req.get_header('Authorization')
    assert 'HIT' in req.get_header('Title')
    assert b'HIT the disk' in req.data
    assert any(item[0] == fw.syslog.LOG_WARNING and fw.SELF_MARKER in item[1] and '\n' not in item[1] for item in records)
    assert timeout == resolved.ntfy_timeout


def test_quiet_live_source_notifies_before_eof(tmp_path, monkeypatch):
    silence_syslog(monkeypatch)
    delivered = tmp_path / 'delivered'
    expired = tmp_path / 'source-timed-out'
    calls = []

    def send(url, title, body, priority, token, timeout):
        calls.append((url, body))
        delivered.write_text('notification received')

    monkeypatch.setattr(fw, 'send_ntfy', send)
    settings = settings_from(tmp_path, '[notify]\nenabled = true\nntfy_url = https://ntfy.example/test\n')
    source = (
        'import pathlib, sys, time\n'
        'delivered, expired = map(pathlib.Path, sys.argv[1:])\n'
        'print("HIT quiet source", flush=True)\n'
        'deadline = time.monotonic() + 2\n'
        'while not delivered.exists() and time.monotonic() < deadline:\n'
        '    time.sleep(0.01)\n'
        'if not delivered.exists():\n'
        '    expired.write_text("notification waited for EOF")\n'
    )
    fw.capture_messages(
        [sys.executable, '-c', source, str(delivered), str(expired)],
        {'fnmatch': {'*HIT*'}}, capture_time=0.05,
        output_folder=str(tmp_path / 'out'),
        compress_after_months=0, delete_after_months=0,
        notify_settings=settings,
    )
    assert not expired.exists(), 'Capture must close while the source is still idle and running'
    assert len(calls) == 1
    assert calls[0][0] == 'https://ntfy.example/test'
    assert 'HIT quiet source' in calls[0][1]


def test_llm_notify_true_appends_report_and_pushes(tmp_path, monkeypatch):
    calls = []
    records = silence_syslog(monkeypatch)
    payload = json.dumps({'title': 'NVMe timeout', 'summary': 'disk timed out\nlook soon', 'notify': True})

    def urlopen(req, timeout=None):
        calls.append(req)
        if req.full_url.endswith('/chat/completions'):
            assert req.get_header('Authorization') == 'Bearer key'
            return chat(payload)
        return Body(b'ok')

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    resolved = settings_from(
        tmp_path,
        '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\napi_key = key\n'
        '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\n',
    )
    pat = tmp_path / 'p.txt'
    pat.write_text('HIT\n')
    src = tmp_path / 'src.log'
    src.write_text('HIT now\n')
    out = tmp_path / 'out'
    fw.capture_messages(
        ['cat', str(src)], fw.load_patterns([str(pat)]),
        capture_time=5, output_folder=str(out),
        compress_after_months=0, delete_after_months=0,
        notify_settings=resolved,
    )
    urls = [req.full_url for req in calls]
    assert urls[0] == 'http://llm.example/v1/chat/completions'
    assert urls[1] == 'https://ntfy.example/alerts'
    assert calls[1].get_header('Title') == 'NVMe timeout'
    text = ''.join(p.read_text() for p in out.rglob('*.log') if p.name != 'journal.log')
    assert 'disk timed out' in text
    assert 'look soon' in text
    assert fw.SELF_MARKER in text
    assert any(item[0] == fw.syslog.LOG_INFO and 'model_notify=yes' in item[1] and ' / ' in item[1] for item in records)
    assert any(item[0] == fw.syslog.LOG_WARNING and 'notification sent' in item[1] for item in records)


def test_llm_decline_does_not_push(tmp_path, monkeypatch):
    calls = []
    silence_syslog(monkeypatch)
    payload = json.dumps({'title': 'Benign', 'summary': 'expected noise', 'notify': False})

    def urlopen(req, timeout=None):
        calls.append(req.full_url)
        return chat(payload)

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    resolved = settings_from(
        tmp_path,
        '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\n'
        '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\n',
    )
    path = tmp_path / 'cap.log'
    path.write_text('HIT now\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=True)
    dispatcher.submit(incident(path))
    dispatcher.close()
    assert calls == ['http://llm.example/v1/chat/completions']
    assert 'expected noise' in path.read_text()
    assert 'notify: false' in path.read_text()


def test_llm_bad_json_and_http_error_fail_open(tmp_path, monkeypatch):
    records = silence_syslog(monkeypatch)
    calls = []

    def bad_json(req, timeout=None):
        calls.append(req.full_url)
        if req.full_url.endswith('/chat/completions'):
            return chat('not json')
        return Body(b'ok')

    monkeypatch.setattr(fw.urllib.request, 'urlopen', bad_json)
    resolved = settings_from(
        tmp_path,
        '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\ntimeout = 3\n'
        '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\ntimeout = 2\n',
    )
    path = tmp_path / 'cap.log'
    path.write_text('HIT now\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=True)
    dispatcher.submit(incident(path, pattern='panic'))
    dispatcher.close()
    assert 'https://ntfy.example/alerts' in calls
    assert 'LLM analysis failed' in path.read_text()
    assert any(item[0] == fw.syslog.LOG_ERR and 'LLM analysis failed' in item[1] for item in records)

    calls.clear()

    def http_down(req, timeout=None):
        calls.append(req.full_url)
        if req.full_url.endswith('/chat/completions'):
            raise urllib.error.HTTPError(req.full_url, 503, 'down', {}, io.BytesIO(b'busy'))
        return Body(b'ok')

    monkeypatch.setattr(fw.urllib.request, 'urlopen', http_down)
    path2 = tmp_path / 'cap2.log'
    path2.write_text('HIT again\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=True)
    dispatcher.submit(incident(path2))
    dispatcher.close()
    assert 'https://ntfy.example/alerts' in calls
    assert 'HTTP 503' in path2.read_text()


def test_ntfy_failure_is_journaled(tmp_path, monkeypatch):
    records = silence_syslog(monkeypatch)

    def urlopen(req, timeout=None):
        raise urllib.error.URLError('unreachable')

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    resolved = settings_from(tmp_path, '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=True)
    dispatcher.submit(incident(tmp_path / 'cap.log'))
    dispatcher.close()
    assert any(item[0] == fw.syslog.LOG_ERR and 'ntfy failed' in item[1] for item in records)


def test_queue_full_skips_llm_and_notifies_immediately(tmp_path, monkeypatch):
    records = silence_syslog(monkeypatch)
    calls = []

    def urlopen(req, timeout=None):
        calls.append((req.full_url, timeout))
        return Body(b'ok')

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    resolved = settings_from(
        tmp_path,
        '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\n'
        '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\n',
    )
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=False)
    for index in range(fw.ANALYSIS_QUEUE_MAX):
        dispatcher.submit(incident(tmp_path / 'cap.log', pattern='P%s' % index))
    assert dispatcher.queue.qsize() == fw.ANALYSIS_QUEUE_MAX
    assert dispatcher.queue.queue[0][0] == 1
    dispatcher.submit(incident(tmp_path / 'cap.log', pattern='OVERFLOW'))
    assert calls == [('https://ntfy.example/alerts', fw.OVERFLOW_NOTIFY_TIMEOUT)]
    assert any(item[0] == fw.syslog.LOG_WARNING and 'queue full' in item[1] for item in records)
    dispatcher.close()


def test_notify_only_jobs_use_higher_priority(tmp_path, monkeypatch):
    silence_syslog(monkeypatch)
    monkeypatch.setattr(fw.urllib.request, 'urlopen', lambda *args, **kwargs: Body(b'ok'))
    resolved = settings_from(tmp_path, '[notify]\nenabled = true\nntfy_url = https://ntfy.example/alerts\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=False)
    dispatcher.submit(incident(tmp_path / 'cap.log'))
    assert dispatcher.queue.queue[0][0] == 0
    dispatcher.close()


def test_helper_edges(tmp_path, monkeypatch, capsys):
    assert fw._split_patterns(None) == []
    assert fw._coerce_bool(True, 'k') is True
    assert fw._coerce_bool('yes', 'k') is True
    with pytest.raises(fw.ConfigError):
        fw._coerce_bool('   ', 'k')
    monkeypatch.setattr(fw.socket, 'gethostname', lambda: '')
    assert fw._hostname() == 'localhost'
    monkeypatch.setattr(fw.socket, 'gethostname', lambda: (_ for _ in ()).throw(OSError('down')))
    assert fw._hostname() == 'localhost'
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args: (_ for _ in ()).throw(OSError('no syslog')))
    fw._journal(fw.syslog.LOG_INFO, 'z' * (fw.JOURNAL_LINE_MAX + 50), status='short status')
    assert 'short status' in capsys.readouterr().out
    header = fw._http_header('héllo\n' + ('y' * 400), 12)
    assert '\n' not in header
    assert len(header) <= 12
    huge = fw._notify_body('hi', 'p' * 5000)
    assert len(huge.encode('utf-8')) <= fw.NTFY_BODY_MAX
    path = tmp_path / 'odd.log'
    path.write_bytes(b'\xff' * 30)
    assert fw._capture_excerpt(str(path), 4) != ''
    with pytest.raises(ValueError):
        fw._parse_llm_object('{not-json{')
    with pytest.raises(ValueError):
        fw._parse_llm_object('[true]')
    with pytest.raises(ValueError):
        fw._parse_llm_object('{"title": "  ", "notify": true}')
    long_title = fw._parse_llm_object('{"title": "%s", "summary": "s", "notify": true}' % ('T' * 400))
    assert len(long_title['title']) <= fw.NTFY_TITLE_MAX
    assert fw._parse_llm_object('{"title": "T", "notify": true}')['summary'] == ''

    class Boom:
        def read(self):
            raise OSError('unreadable')

        def close(self):
            return None

    def urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, 'err', {}, Boom())

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    with pytest.raises(RuntimeError, match='HTTP 500'):
        fw._urlopen_bytes('http://llm.example/v1', b'{}', {}, 1)
    monkeypatch.setattr(fw.urllib.request, 'urlopen', lambda req, timeout=None: Body(b'not-json'))
    settings = settings_from(tmp_path, '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\n')
    with pytest.raises(ValueError, match='unreadable'):
        fw.call_llm(settings, incident(path))


def test_overflow_without_notify_and_unwritable_failure_note(tmp_path, monkeypatch):
    records = silence_syslog(monkeypatch)
    monkeypatch.setattr(fw.urllib.request, 'urlopen', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('no http')))
    resolved = settings_from(tmp_path, '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=False)
    for index in range(fw.ANALYSIS_QUEUE_MAX):
        dispatcher.submit(incident(tmp_path / 'cap.log', pattern='P%s' % index))
    dispatcher.submit(incident(tmp_path / 'cap.log', pattern='OVERFLOW'))
    assert any('queue full' in item[1] for item in records)
    dispatcher.close()
    failing = fw.IncidentDispatcher(resolved, start_thread=True)
    failing.submit(incident(tmp_path))
    failing.close()
    assert any('LLM analysis failed' in item[1] for item in records)


def test_llm_without_notify_writes_report_only(tmp_path, monkeypatch):
    calls = []
    silence_syslog(monkeypatch)
    payload = json.dumps({'title': 'Noted', 'summary': 'stored only', 'notify': True})

    def urlopen(req, timeout=None):
        calls.append(req.full_url)
        return chat(payload)

    monkeypatch.setattr(fw.urllib.request, 'urlopen', urlopen)
    resolved = settings_from(
        tmp_path,
        '[llm]\nenabled = true\nbase_url = http://llm.example/v1\nmodel = m\n',
    )
    path = tmp_path / 'cap.log'
    path.write_text('HIT\n')
    dispatcher = fw.IncidentDispatcher(resolved, start_thread=True)
    dispatcher.submit(incident(path))
    dispatcher.close()
    assert calls == ['http://llm.example/v1/chat/completions']
    assert 'stored only' in path.read_text()
