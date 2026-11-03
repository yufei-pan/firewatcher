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
    conf.write_text(text, encoding='utf-8')
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
    assert payload['push'] is False
    assert payload['always_notify'] is False
    assert 'model_notify' not in payload
    assert 'excerpt' in payload
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
            dispatcher(settings)._process(incident(always_notify=True, always_notify_line='HIT now'))
            assert len(ntfy.requests) == 1, url
            assert any('event post failed: ' in item[1] and '; pushing to ntfy' in item[1] for item in records)
            assert any('notification sent' in item[1] for item in records)
    finally:
        silent.close()


def test_redirect_and_client_errors_are_failures(tmp_path, server, records):
    for status, location in ((302, 'http://127.0.0.1:1/x'), (301, None), (400, None), (401, None), (403, None)):
        events, ntfy = server(status=status, location=location), server()
        settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
        dispatcher(settings)._process(incident(always_notify=True))
        assert len(events.requests) == 1
        assert len(ntfy.requests) == 1, status


def test_push_false_is_posted_and_never_pushed(tmp_path, server, monkeypatch, records):
    events, ntfy = server(), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    dispatcher(settings)._process(incident())
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['push'] is False
    assert 'model_notify' not in payload
    assert payload['title'] == 'box: HIT'
    assert payload['body'].startswith('HIT now')
    assert ntfy.requests == []


def test_push_false_and_post_failed_sends_nothing(tmp_path, server, monkeypatch, records):
    events, ntfy = server(status=500), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    dispatcher(settings)._process(incident())
    assert len(events.requests) == 1
    assert ntfy.requests == []
    assert any('event post failed: ' in item[1] and 'pushing to ntfy' not in item[1] for item in records)


def test_overflow_posts_push_as_always_notify(tmp_path, server, records):
    events, ntfy = server(), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    dispatcher(settings)._overflow(incident(path=None))
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['push'] is False
    assert payload['path'] is None
    assert 'model_notify' not in payload
    assert payload['excerpt'] == ''
    assert payload['body'].endswith('capture not saved; see the firewatcher journal')
    assert ntfy.requests == []
    # a failed POST falls back to ntfy here too, for an always_notify capture only
    events2, ntfy2 = server(status=503), server()
    settings = settings_from(tmp_path, conf(events2.url(), ntfy2.url('/topic')))
    dispatcher(settings)._overflow(incident())
    assert ntfy2.requests == []
    dispatcher(settings)._overflow(incident(always_notify=True))
    assert len(ntfy2.requests) == 1


def test_overflow_wording_follows_events_url(tmp_path, server, records):
    events = server()
    settings = settings_from(tmp_path, conf(events.url(), notify=False))
    dispatcher(settings)._overflow(incident())
    assert any('queue full: posting the capture without waiting' in item[1] for item in records)
    assert not any('analysis skipped' in item[1] for item in records)
    del records[:]
    ntfy = server()
    settings = settings_from(tmp_path, conf(ntfy_url=ntfy.url('/topic')))
    dispatcher(settings)._overflow(incident())
    assert any('analysis skipped, queue full' in item[1] for item in records)
    assert len(ntfy.requests) == 1


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
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: pytest.fail('the receiver judges'))
    dispatcher(settings)._process(incident(always_notify=True, always_notify_line='the line'))
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['always_notify'] is True
    assert 'model_notify' not in payload
    assert payload['push'] is True
    assert payload['title'] == 'box: HIT'
    assert payload['body'].startswith('the line')
    dispatcher(settings)._process(incident())
    payload = json.loads(events.requests[1]['body'].decode('utf-8'))
    assert 'model_notify' not in payload and payload['push'] is False
    assert payload['title'] == 'box: HIT'
    assert payload['always_notify'] is False


def _capture(tmp_path, text, name='cap.log'):
    path = tmp_path / name
    path.write_bytes(text.encode('utf-8') if isinstance(text, str) else text)
    return str(path)


def test_events_url_turns_the_llm_off(tmp_path, server, monkeypatch, records):
    events, ntfy = server(), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    settings.llm_enabled = True
    calls = []
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: calls.append(i) or {'title': 't', 'summary': 's', 'notify': True})
    disp = dispatcher(settings)
    disp.submit(incident(path=_capture(tmp_path, 'HIT now\n')))
    priority, _seq, item = disp.queue.get_nowait()
    assert priority == 0
    disp._process(item)
    assert calls == []
    assert len(events.requests) == 1 and ntfy.requests == []
    assert not any('analysis' in entry[1] for entry in records)


def test_event_carries_excerpt_under_16k_json(tmp_path, server, records):
    events = server()
    settings = settings_from(tmp_path, conf(events.url(), notify=False))
    small = _capture(tmp_path, 'header\nHIT now\nafter\n', 'small.log')
    dispatcher(settings)._process(incident(path=small))
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['excerpt'] == 'header\nHIT now\nafter\n'
    big_text = ''.join('line %06d \u00e9\u4e2d some text\n' % n for n in range(20000))
    big = _capture(tmp_path, big_text, 'big.log')
    dispatcher(settings)._process(incident(path=big))
    payload = json.loads(events.requests[1]['body'].decode('utf-8'))
    assert payload['excerpt']
    assert len(json.dumps(payload['excerpt'])) <= 16384
    assert len(events.requests[1]['body']) < 64 * 1024
    # P27: the capture is gone; the event is still posted with an empty excerpt
    dispatcher(settings)._process(incident(path=str(tmp_path / 'gone.log')))
    payload = json.loads(events.requests[2]['body'].decode('utf-8'))
    assert payload['excerpt'] == ''
    assert payload['path'] == str(tmp_path / 'gone.log')


def test_excerpt_with_control_chars_stays_under_budget(tmp_path, server, records):
    events = server()
    settings = settings_from(tmp_path, conf(events.url(), notify=False))
    # Every byte a control character: json.dumps writes each as six characters.
    path = _capture(tmp_path, b'\x01\x02\x03\x04' * 20000, 'ctl.log')
    dispatcher(settings)._process(incident(path=path))
    payload = json.loads(events.requests[0]['body'].decode('utf-8'))
    assert payload['excerpt']
    assert len(json.dumps(payload['excerpt'])) <= 16384
    assert len(events.requests[0]['body']) < 64 * 1024


def test_post_failure_pushes_only_always_notify(tmp_path, server, records):
    events, ntfy = server(status=500), server()
    settings = settings_from(tmp_path, conf(events.url(), ntfy.url('/topic')))
    dispatcher(settings)._process(incident())
    assert ntfy.requests == []
    assert any('event post failed: ' in item[1] and '; not pushed (not always_notify)' in item[1] for item in records)
    del records[:]
    dispatcher(settings)._process(incident(always_notify=True, always_notify_line='HIT now'))
    assert len(ntfy.requests) == 1
    assert any('event post failed: ' in item[1] and '; pushing to ntfy' in item[1] for item in records)
    assert len(events.requests) == 2


def test_no_events_url_keeps_llm_judging(tmp_path, server, monkeypatch, records):
    ntfy = server()
    settings = settings_from(tmp_path, conf(ntfy_url=ntfy.url('/topic')))
    settings.llm_enabled = True
    calls = []
    monkeypatch.setattr(fw, 'call_llm', lambda s, i: calls.append(i) or {'title': 'Model title', 'summary': 'sum', 'notify': True})
    monkeypatch.setattr(fw, '_append_note', lambda path, text: None)
    disp = dispatcher(settings)
    disp.submit(incident())
    priority, _seq, item = disp.queue.get_nowait()
    assert priority == 1
    disp._process(item)
    assert len(calls) == 1
    assert len(ntfy.requests) == 1
    assert any('notification sent title=Model title' in entry[1] for entry in records)
    assert any('analysis title=Model title' in entry[1] for entry in records)


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


def test_strip_userinfo():
    assert fw._strip_userinfo('https://user:PASSSECRET@hk.example/api/events?x=1') == 'https://hk.example/api/events?x=1'
    assert fw._strip_userinfo('http://user@127.0.0.1:8080/p') == 'http://127.0.0.1:8080/p'
    assert fw._strip_userinfo('http://[::1]:8080/p@q') == 'http://[::1]:8080/p@q'
    assert fw._strip_userinfo('http://u:p@w@host/x') == 'http://host/x'
    assert fw._strip_userinfo('https://hk.example/api/events') == 'https://hk.example/api/events'


def test_strip_userinfo_never_raises():
    pw = 'ab\uff1aPASSSECRET'  # fullwidth colon
    assert fw._strip_userinfo('http://user:%s@127.0.0.1/x?' % pw) == 'http://127.0.0.1/x?'
    assert fw._strip_userinfo('http://user:ab\uff20PASSSECRET@127.0.0.1:81/x') == 'http://127.0.0.1:81/x'
    # a fullwidth '@' alone is not a separator; the URL is refused at config time and has no origin
    url = 'http://user:PASSSECRET\uff20127.0.0.1/x'
    assert fw._strip_userinfo(url) == url
    assert not fw._is_http_url(url) and fw._url_origin(url) == '(invalid URL)'
    assert fw._strip_userinfo('HTTP://u:p@Host#frag@x') == 'HTTP://Host#frag@x'
    assert fw._strip_userinfo('not a url') == 'not a url'
    assert fw._strip_userinfo('') == ''


def test_userinfo_without_port_leaks_nowhere(tmp_path, server, capsys, records, monkeypatch):
    import http.client
    # No port in the URLs: the default ports are pointed at fake servers, so nothing else is contacted.
    events, ntfy, llm = server(), server(), server()
    monkeypatch.setattr(http.client.HTTPConnection, 'default_port', events.port)
    monkeypatch.setattr(http.client.HTTPSConnection, 'default_port', events.port)
    shown = ''
    for password in ('PASSSECRET', 'ab\uff1aPASSSECRET', 'ab\uff20PASSSECRET'):
        monkeypatch.setattr(http.client.HTTPConnection, 'default_port', events.port)
        settings = settings_from(tmp_path, conf('http://user:%s@127.0.0.1/api/events' % password, 'http://127.0.0.1:%d/topic' % ntfy.port, timeout=1))
        dispatcher(settings)._process(incident())
        # ntfy alone
        monkeypatch.setattr(http.client.HTTPConnection, 'default_port', ntfy.port)
        settings = settings_from(tmp_path, conf(ntfy_url='http://user:%s@127.0.0.1/topic' % password, timeout=1))
        dispatcher(settings)._process(incident())
        # the shared request helper, which the LLM URL goes through
        monkeypatch.setattr(http.client.HTTPConnection, 'default_port', llm.port)
        fw._urlopen_bytes('http://user:%s@127.0.0.1/v1/chat' % password, b'{}', {}, 1)
        shown += capsys.readouterr().out + '\n'.join(str(item) for item in records)
        del records[:]
    # the stripped requests arrived, each on the right fake server
    assert [r['path'] for r in events.requests] == ['/api/events'] * 3
    assert [r['path'] for r in ntfy.requests] == ['/topic'] * 3
    assert [r['path'] for r in llm.requests] == ['/v1/chat'] * 3
    assert 'event sent' in shown and 'notification sent' in shown
    assert 'PASSSECRET' not in shown
    # a refused connection quotes no password either
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    for password in ('PASSSECRET', 'ab\uff1aPASSSECRET', 'ab\uff20PASSSECRET'):
        with pytest.raises(Exception) as caught:
            fw._urlopen_bytes('http://user:%s@127.0.0.1:%d/v1/chat' % (password, dead_port), b'{}', {}, 1)
        assert 'PASSSECRET' not in str(caught.value) + repr(caught.value)


def test_2xx_with_stalled_body_is_accepted(tmp_path, server, records):
    stalled = socket.socket()
    stalled.bind(('127.0.0.1', 0))
    stalled.listen(5)
    held = []

    def serve():
        conn, _ = stalled.accept()
        held.append(conn)
        conn.recv(65536)
        conn.sendall(b'HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\n\r\n')

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        ntfy = server()
        settings = settings_from(tmp_path, conf('http://127.0.0.1:%d/api/events' % stalled.getsockname()[1], ntfy.url('/topic'), timeout=1))
        dispatcher(settings)._process(incident())
        assert ntfy.requests == []
        assert any('event sent' in item[1] for item in records)
        assert not any('event post failed' in item[1] for item in records)
    finally:
        for conn in held:
            conn.close()
        stalled.close()


def test_unparseable_urls_refused_at_config_time(tmp_path, capsys, records):
    for mark in ('/', '?', '#'):
        url = 'http://user:pa%sPASSSECRET@127.0.0.1/e' % mark
        cases = [
            ('[notify]\nevents_url = %s\n' % url, 'events_url', 'events_token'),
            ('[notify]\nenabled = true\nntfy_url = %s\n' % url, 'ntfy_url', 'token'),
            ('[llm]\nenabled = true\nmodel = m\nbase_url = %s\n' % url, 'base_url', 'api_key'),
        ]
        for text, key, hint in cases:
            with pytest.raises(fw.ConfigError) as caught:
                settings_from(tmp_path, text)
            assert key in str(caught.value) and hint in str(caught.value)
            assert 'PASSSECRET' not in str(caught.value) + repr(caught.value)
    # an empty host, a bad port
    for bad in ('http:///x', 'http://host:99999/x', 'http://host:abc/x', 'http://user:pw@/x'):
        with pytest.raises(fw.ConfigError) as caught:
            settings_from(tmp_path, '[notify]\nevents_url = %s\n' % bad)
        assert 'events_url' in str(caught.value)
    # URLs that work still pass
    for good in ('http://user:pw@127.0.0.1:81/e', 'https://[::1]:8443/e', 'http://u:12/e@h/x'):
        assert settings_from(tmp_path, '[notify]\nevents_url = %s\n' % good).events_url == good
    out = capsys.readouterr()
    assert 'PASSSECRET' not in out.out + out.err + '\n'.join(str(item) for item in records)


def test_url_origin_strips_userinfo_first():
    assert fw._url_origin('https://user:ab\uff1aPW@host.example:8443/p?q') == 'https://host.example:8443'
    assert fw._url_origin('https://user:ab\uff20PW@host.example/p') == 'https://host.example'
    assert fw._url_origin('https://user:pw@[::1]:81/p') == 'https://[::1]:81'


def test_userinfo_with_a_later_at_refused(tmp_path, capsys, records):
    # The password held an '@' before a '/', '?' or '#': the text between them would be logged as the host.
    for mark in ('/', '?', '#'):
        for at in ('@', '＠'):
            url = 'http://u:ab@HIDDENPART%sREST%s127.0.0.1/e' % (mark, at)
            cases = [
                ('[notify]\nevents_url = %s\n' % url, 'events_url', 'events_token'),
                ('[notify]\nenabled = true\nntfy_url = %s\n' % url, 'ntfy_url', 'token'),
                ('[llm]\nenabled = true\nmodel = m\nbase_url = %s\n' % url, 'base_url', 'api_key'),
            ]
            for text, key, hint in cases:
                with pytest.raises(fw.ConfigError) as caught:
                    settings_from(tmp_path, text)
                assert key in str(caught.value) and hint in str(caught.value)
                for part in ('HIDDENPART', 'hiddenpart', 'REST', 'ab@'):
                    assert part not in str(caught.value) + repr(caught.value)
    # user:password and no later '@' is stripped and accepted; an '@' in the path without user:password is fine
    for good in ('http://user:pw@127.0.0.1:81/e', 'http://h/p@x', 'http://h/p?q=a@b#c@d', 'https://user:pw@ntfy.example/topic'):
        assert settings_from(tmp_path, '[notify]\nevents_url = %s\n' % good).events_url == good
    assert fw._strip_userinfo('http://user:pw@127.0.0.1:81/e') == 'http://127.0.0.1:81/e'
    out = capsys.readouterr()
    logged = out.out + out.err + '\n'.join(str(item) for item in records)
    for part in ('HIDDENPART', 'hiddenpart', 'REST'):
        assert part not in logged


def test_authority_checked_by_our_own_pattern(tmp_path, capsys, records):
    # A '[' ... ']' inside a password, before its first '/', '?' or '#': Python 3.8 and older took the host from inside
    # the brackets. Our own check refuses the same on every Python.
    for rest in ('[HIDDENPART]/REST', 'x[HIDDENPART]x?REST', '][HIDDENPART#REST', '[v1.HIDDENPART]/REST'):
        url = 'http://usr:%s@127.0.0.1/e' % rest
        cases = [
            ('[notify]\nevents_url = %s\n' % url, 'events_url', 'events_token'),
            ('[notify]\nenabled = true\nntfy_url = %s\n' % url, 'ntfy_url', 'token'),
            ('[llm]\nenabled = true\nmodel = m\nbase_url = %s\n' % url, 'base_url', 'api_key'),
        ]
        for text, key, hint in cases:
            with pytest.raises(fw.ConfigError) as caught:
                settings_from(tmp_path, text)
            assert key in str(caught.value) and hint in str(caught.value)
            for part in ('HIDDENPART', 'hiddenpart', 'REST'):
                assert part not in str(caught.value) + repr(caught.value)
        assert fw._url_origin(url) == '(invalid URL)'
    # Accepted, with the origin built from the checked server part only
    for url, origin in (
        ('http://127.0.0.1:81/e', 'http://127.0.0.1:81'),
        ('https://[::1]:8443/e', 'https://[::1]:8443'),
        ('http://[::1]/e', 'http://[::1]'),
        ('http://[fe80::1%25eth0]:81/e', 'http://[fe80::1%25eth0]:81'),
        ('http://[fe80::1%eth0]:81/e', 'http://[fe80::1%eth0]:81'),
        ('http://[::ffff:127.0.0.1]/e', 'http://[::ffff:127.0.0.1]'),
        ('http://u:p%40ss@h.example/e', 'http://h.example'),
        ('http://u:p%40ss@h.example:81/e', 'http://h.example:81'),
        ('HTTP://H.EXAMPLE/x', 'http://h.example'),
        ('HTTPS://H.EXAMPLE:8443/x', 'https://h.example:8443'),
        ('http://h.example:/x', 'http://h.example'),
        ('http://h.example:080/x', 'http://h.example:80'),
        ('http://h.example', 'http://h.example'),
        ('http://h.example?x=1', 'http://h.example'),
        ('http://bücher.example/', 'http://bücher.example'),
        ('http://user:pw@127.0.0.1:81/e', 'http://127.0.0.1:81'),
        ('https://user:pass@ntfy.example/topic', 'https://ntfy.example'),
        ('https://h.example/@cf/x', 'https://h.example'),
        ('http://h/p?q=a@b#c@d', 'http://h'),
    ):
        assert fw._is_http_url(url), url
        assert fw._url_origin(url) == origin
        assert settings_from(tmp_path, '[notify]\nevents_url = %s\n' % url).events_url == url
    # Refused: a server part that is not a name or a bracketed IPv6 address, then up to 5 ASCII digits of port
    for url in ('http://u%3Aab/REST@127.0.0.1/e', 'http://:8080/x', 'http:///x', 'http://h.example:+80/',
                'http://[127.0.0.1]:80/', 'http://[v1.abc]/', 'http://h.example:٨٠/', 'http://h.example:８０/',
                'http://h.example:99999/', 'http://h.example:123456/', 'http://h.example:1:2/', 'http://h：80/',
                'http://h[x]/', 'http://[::1]x/', 'http://[::1%]/'):
        assert not fw._is_http_url(url), url
        assert fw._url_origin(url) == '(invalid URL)'
        with pytest.raises(fw.ConfigError) as caught:
            settings_from(tmp_path, '[notify]\nevents_url = %s\n' % url)
        assert 'events_url' in str(caught.value) and 'REST' not in str(caught.value)
    out = capsys.readouterr()
    logged = out.out + out.err + '\n'.join(str(item) for item in records)
    for part in ('HIDDENPART', 'hiddenpart', 'REST'):
        assert part not in logged
