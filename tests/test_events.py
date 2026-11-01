import http.server
import json
import socket
import threading

import pytest

import firewatcher as fw

SECRET = 'SECRETTOKEN-9f3a'


class FakeServer(object):
    """A local HTTP server that records each POST and answers with a fixed status."""

    def __init__(self, status=200, location=None):
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length') or 0)
                outer.requests.append({'path': self.path, 'headers': dict(self.headers), 'body': self.rfile.read(length)})
                self.send_response(status)
                if location:
                    self.send_header('Location', location)
                reply = ('echo %s' % self.headers.get('Authorization', '')).encode('utf-8')
                self.send_header('Content-Length', str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path='/api/events'):
        return 'http://127.0.0.1:%d%s' % (self.port, path)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    made = []

    def make(**kwargs):
        item = FakeServer(**kwargs)
        made.append(item)
        return item

    yield make
    for item in made:
        item.close()


@pytest.fixture(autouse=True)
def no_proxy_no_syslog(monkeypatch):
    for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('no_proxy', '127.0.0.1')
    monkeypatch.delenv(fw.EVENTS_TOKEN_ENV, raising=False)


@pytest.fixture
def records(monkeypatch):
    items = []
    monkeypatch.setattr(fw.syslog, 'openlog', lambda *args, **kwargs: None)
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args: items.append(args))
    return items


def settings_from(tmp_path, text, environ=None):
    conf = tmp_path / 'events.conf'
    conf.write_text(text)
    return fw.resolve_settings(fw.build_parser().parse_args(['--config', str(conf), 'p.txt']), environ=environ or {})


def conf(events_url='', ntfy_url='', timeout=3, notify=True, llm=False):
    lines = ['[notify]', 'enabled = %s' % ('true' if notify else 'false'), 'timeout = %d' % timeout]
    if events_url:
        lines.append('events_url = %s' % events_url)
        lines.append('events_token = %s' % SECRET)
    if ntfy_url:
        lines.append('ntfy_url = %s' % ntfy_url)
    return '\n'.join(lines) + '\n'


def incident(path='/tmp/cap.log', **extra):
    item = {'path': path, 'pattern': 'HIT', 'matched_line': 'HIT now', 'hostname': 'box'}
    item.update(extra)
    return item


def dispatcher(settings):
    return fw.IncidentDispatcher(settings, start_thread=False)


def test_event_posted_and_no_ntfy_when_accepted(tmp_path, server, records):
    events, ntfy = server(), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    dispatcher(settings)._process(incident())
    assert len(events.requests) == 1 and ntfy.requests == []
    request = events.requests[0]
    assert request['path'] == '/api/events'
    assert request['headers']['Content-Type'].startswith('application/json')
    assert request['headers']['Authorization'] == 'Bearer ' + SECRET
    payload = json.loads(request['body'].decode('utf-8'))
    assert payload['source'] == 'firewatcher'
    assert payload['version'] == fw.version
    assert payload['host'] == 'box'
    assert payload['pattern'] == 'HIT'
    assert payload['title'] == 'box: HIT'
    assert payload['body'] == fw._notify_body('HIT now', '/tmp/cap.log')
    assert payload['push'] is True
    assert payload['always_notify'] is False
    assert payload['model_notify'] is None
    assert payload['path'] == '/tmp/cap.log'
    assert 'T' in payload['time'] and payload['time'][:4].isdigit()
    assert any('event sent title=box: HIT' in item[1] for item in records)


def test_fallback_to_ntfy_on_refused_connection_500_and_timeout(tmp_path, server, records):
    # refused: a port nothing listens on
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    # timeout: the connection is accepted by the kernel but nobody ever answers
    silent = socket.socket()
    silent.bind(('127.0.0.1', 0))
    silent.listen(5)
    try:
        cases = [
            'http://127.0.0.1:%d/api/events' % dead_port,
            server(status=500).url(),
            'http://127.0.0.1:%d/api/events' % silent.getsockname()[1],
        ]
        for url in cases:
            ntfy = server()
            settings = settings_from(tmp_path, conf(url, ntfy.url('/topic'), timeout=1))
            del records[:]
            dispatcher(settings)._process(incident())
            assert len(ntfy.requests) == 1, url
            assert any('event post failed: ' in item[1] and '; pushing to ntfy' in item[1] for item in records)
            assert any('notification sent' in item[1] for item in records)
    finally:
        silent.close()


def test_redirect_and_client_errors_are_failures(tmp_path, server, records):
    for status, location in ((302, 'http://127.0.0.1:1/x'), (301, None), (400, None), (401, None), (403, None)):
        events, ntfy = server(status=status, location=location), server()
        settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
        dispatcher(settings)._process(incident())
        assert len(events.requests) == 1
        assert len(ntfy.requests) == 1, status


def test_push_false_is_posted_and_never_pushed(tmp_path, server, monkeypatch, records):
    events, ntfy, llm = server(), server(), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: {'title': 'Benign', 'summary': 'fine', 'notify': False})
    monkeypatch.setattr(fw, '_append_note', lambda path, text: None)
    settings.llm_enabled = True
    dispatcher(settings)._process(incident())
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['push'] is False
    assert payload['model_notify'] is False
    assert payload['title'] == 'Benign'
    assert payload['body'].startswith('fine')
    assert ntfy.requests == []


def test_push_false_and_post_failed_sends_nothing(tmp_path, server, monkeypatch, records):
    events, ntfy = server(status=500), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: {'title': 'Benign', 'summary': 'fine', 'notify': False})
    monkeypatch.setattr(fw, '_append_note', lambda path, text: None)
    settings.llm_enabled = True
    dispatcher(settings)._process(incident())
    assert len(events.requests) == 1
    assert ntfy.requests == []
    assert any('event post failed: ' in item[1] and 'pushing to ntfy' not in item[1] for item in records)


def test_overflow_posts_with_push_true(tmp_path, server, records):
    events, ntfy = server(), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    dispatcher(settings)._overflow(incident(path=None))
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['push'] is True
    assert payload['path'] is None
    assert payload['model_notify'] is None
    assert payload['body'].endswith('capture not saved; see the firewatcher journal')
    assert ntfy.requests == []
    # a failed POST falls back to ntfy here too
    events2, ntfy2 = server(status=503), server()
    settings = settings_from(tmp_path, conf(events2.url(), ntfy2.url('/topic')))
    dispatcher(settings)._overflow(incident())
    assert len(ntfy2.requests) == 1


def test_events_only_without_ntfy(tmp_path, server, records):
    events = server()
    settings = settings_from(tmp_path, conf(events.url(), notify=False))
    dispatcher(settings)._overflow(incident())
    assert len(events.requests) == 1
    failing = server(status=500)
    settings = settings_from(tmp_path, conf(failing.url(), notify=False))
    del records[:]
    dispatcher(settings)._process(incident())
    assert len(failing.requests) == 1
    assert any('event post failed: ' in item[1] and 'pushing to ntfy' not in item[1] for item in records)


def test_always_notify_and_model_fields(tmp_path, server, monkeypatch, records):
    events = server()
    settings = settings_from(tmp_path, conf(events.url(), notify=False))
    settings.llm_enabled = True
    monkeypatch.setattr(fw, '_append_note', lambda path, text: None)
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: {'title': 'Model title', 'summary': 'sum', 'notify': False})
    dispatcher(settings)._process(incident(always_notify=True, always_notify_line='the line'))
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['always_notify'] is True
    assert payload['model_notify'] is False
    assert payload['push'] is True
    assert payload['title'] == 'box: HIT'
    assert payload['body'].startswith('the line')
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: {'title': 'Model title', 'summary': 'sum', 'notify': True})
    dispatcher(settings)._process(incident())
    payload = json.loads(events.requests[1]['body'].decode('utf-8'))
    assert payload['model_notify'] is True and payload['push'] is True
    assert payload['title'] == 'Model title'
    assert payload['always_notify'] is False
    # a failed LLM call: no model verdict
    def boom(s, i):
        raise RuntimeError('down')
    monkeypatch.setattr(fw, 'call_llm', boom)
    dispatcher(settings)._process(incident())
    payload = json.loads(events.requests[2]['body'].decode('utf-8'))
    assert payload['model_notify'] is None and payload['push'] is True


def test_token_never_in_journal_or_errors(tmp_path, server, capsys, records):
    secret_path = '/hook-PATHSECRET'
    events, ntfy = server(status=401), server()
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    urls = [
        events.url(secret_path),
        'http://userpart:PASSSECRET@127.0.0.1:%d%s' % (events.port, secret_path),
        'http://127.0.0.1:%d%s' % (dead_port, secret_path),
    ]
    for url in urls:
        settings = settings_from(tmp_path, conf(url, ntfy.url('/topic')))
        dispatcher(settings)._process(incident())
    shown = capsys.readouterr().out + '\n'.join(str(item) for item in records)
    assert 'event post failed' in shown
    for secret in (SECRET, 'PATHSECRET', 'PASSSECRET'):
        assert secret not in shown
    # a bad URL reports no part of itself
    with pytest.raises(fw.ConfigError) as caught:
        settings_from(tmp_path, '[notify]\nevents_url = ftp://user:PASSSECRET@h/PATHSECRET\nevents_token = %s\n' % SECRET)
    for secret in (SECRET, 'PATHSECRET', 'PASSSECRET'):
        assert secret not in str(caught.value)
    # a token with a line break is flattened for the header, not echoed in an error
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')), environ={fw.EVENTS_TOKEN_ENV: 'line\r\nbreak' + SECRET})
    dispatcher(settings)._process(incident())
    assert SECRET not in capsys.readouterr().out + '\n'.join(str(item) for item in records)
    assert fw._url_origin('https://user:pw@host.example:8443/p?q=1') == 'https://host.example:8443'


def test_token_env_overrides_config(tmp_path, server, records):
    events = server()
    settings = settings_from(tmp_path, conf(events.url(), notify=False), environ={fw.EVENTS_TOKEN_ENV: 'from-env'})
    dispatcher(settings)._process(incident())
    assert events.requests[0]['headers']['Authorization'] == 'Bearer from-env'


def test_events_url_must_be_http(tmp_path):
    for bad in ('ftp://host/x', 'host/x', 'http://ho st/x'):
        with pytest.raises(fw.ConfigError) as caught:
            settings_from(tmp_path, '[notify]\nevents_url = %s\n' % bad)
        assert 'events_url' in str(caught.value)
    settings = settings_from(tmp_path, '[notify]\nevents_url = https://hk.example/api/events\n')
    assert settings.events_url == 'https://hk.example/api/events'
    assert settings_from(tmp_path, '[notify]\nenabled = false\n').events_url == ''


def test_dispatcher_starts_with_events_only(tmp_path):
    settings = settings_from(tmp_path, '[notify]\nevents_url = http://127.0.0.1:9/api/events\n')
    assert not settings.notify_enabled and not settings.llm_enabled
    started = fw._start_dispatcher(settings)
    try:
        assert started is not None
    finally:
        started.close()
    assert fw._start_dispatcher(settings_from(tmp_path, '[notify]\nenabled = false\n')) is None


def test_init_config_lists_events_keys(tmp_path):
    settings = fw.Settings()
    text = fw.render_config_text(settings)
    assert '\nevents_url = \n' in text or '\nevents_url =\n' in text
    assert 'events_token' in text
    # a written config reads back, with the keys carried over
    settings.events_url = 'https://hk.example/api/events'
    settings.events_token = 'tok'
    path = tmp_path / 'written.conf'
    fw.write_config_file(str(path), settings)
    again = settings_from(tmp_path, path.read_text())
    assert again.events_url == 'https://hk.example/api/events'
    assert again.events_token == 'tok'
