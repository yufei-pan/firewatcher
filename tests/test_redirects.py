"""Every outgoing request (LLM, ntfy, events) refuses redirects, and a user:password in a URL is warned about."""
import http.server
import threading

import pytest

import firewatcher as fw

TOKEN = 'tok-redirect-0123456789'


class Server(object):
    """Records every request, whatever its method; answers status, with Location when given."""

    def __init__(self, status=200, location=None, body=b'{"choices": [{"message": {"content": "{\\"title\\": \\"t\\", \\"notify\\": true, \\"summary\\": \\"s\\"}"}}]}'):
        self.requests = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def answer(self):
                length = int(self.headers.get('Content-Length') or 0)
                outer.requests.append({'method': self.command, 'path': self.path, 'headers': dict(self.headers), 'body': self.rfile.read(length)})
                self.send_response(status)
                if location:
                    self.send_header('Location', location)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_HEAD = answer

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, path):
        return 'http://127.0.0.1:%d%s' % (self.port, path)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def pair():
    """A server that redirects to a second one, which records whatever reaches it."""
    made = []

    def make(status):
        second = Server()
        first = Server(status=status, location=second.url('/stolen?where=elsewhere'))
        made.extend([first, second])
        return first, second

    yield make
    for item in made:
        item.close()


@pytest.fixture
def records(monkeypatch):
    for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('no_proxy', '127.0.0.1')
    items = []
    monkeypatch.setattr(fw.syslog, 'openlog', lambda *args, **kwargs: None)
    monkeypatch.setattr(fw.syslog, 'syslog', lambda *args: items.append(args))
    return items


def settings_from(tmp_path, text):
    conf = tmp_path / 'redirect.conf'
    conf.write_text(text, encoding='utf-8')
    return fw.resolve_settings(fw.build_parser().parse_args(['--config', str(conf), 'p.txt']), environ={})


def journal(records):
    return '\n'.join(str(item) for item in records)


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_ntfy_redirect_is_a_failure_and_sends_nothing_on(tmp_path, pair, records, status):
    first, second = pair(status)
    settings = settings_from(tmp_path, '[notify]\nenabled = true\ntimeout = 3\nntfy_url = %s\ntoken = %s\n' % (first.url('/topic-secret'), TOKEN))
    fw.IncidentDispatcher(settings, start_thread=False)._process({'path': None, 'pattern': 'HIT', 'matched_line': 'HIT now', 'hostname': 'box'})
    assert len(first.requests) == 1 and first.requests[0]['method'] == 'POST'
    assert second.requests == []
    text = journal(records)
    assert 'notification sent' not in text
    assert 'ntfy failed: HTTP %d from http://127.0.0.1:%d (redirect, not followed)' % (status, first.port) in text
    assert TOKEN not in text and 'topic-secret' not in text and 'stolen' not in text and str(second.port) not in text


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_llm_redirect_is_a_failure_and_sends_nothing_on(tmp_path, pair, records, status):
    first, second = pair(status)
    capture = tmp_path / 'cap.log'
    capture.write_text('HIT now\n', encoding='utf-8')
    settings = settings_from(tmp_path, '[llm]\nenabled = true\nbase_url = %s\nmodel = m\napi_key = %s\ntimeout = 3\n' % (first.url('/v1'), TOKEN))
    fw.IncidentDispatcher(settings, start_thread=False)._process({'path': str(capture), 'pattern': 'HIT', 'matched_line': 'HIT now', 'hostname': 'box'})
    assert len(first.requests) == 1 and first.requests[0]['path'] == '/v1/chat/completions'
    assert second.requests == []
    text = journal(records)
    assert 'LLM analysis failed: HTTP %d from http://127.0.0.1:%d (redirect, not followed)' % (status, first.port) in text
    assert TOKEN not in text and 'stolen' not in text and str(second.port) not in text
    note = capture.read_text(encoding='utf-8')
    assert 'redirect, not followed' in note and TOKEN not in note and 'stolen' not in note


@pytest.mark.parametrize('status', [301, 302])
def test_events_redirect_is_a_failure_and_sends_nothing_on(tmp_path, pair, records, status):
    first, second = pair(status)
    settings = settings_from(tmp_path, '[notify]\nenabled = false\ntimeout = 3\nevents_url = %s\nevents_token = %s\n' % (first.url('/api/events'), TOKEN))
    fw.IncidentDispatcher(settings, start_thread=False)._process({'path': None, 'pattern': 'HIT', 'matched_line': 'HIT now', 'hostname': 'box'})
    assert len(first.requests) == 1 and second.requests == []
    text = journal(records)
    assert 'event post failed: HTTP %d from http://127.0.0.1:%d (redirect, not followed)' % (status, first.port) in text
    assert TOKEN not in text and 'stolen' not in text


def test_a_4xx_keeps_its_body_detail_and_says_nothing_of_redirects(records):
    server = Server(status=401, body=b'bad key')
    try:
        with pytest.raises(RuntimeError) as caught:
            fw._urlopen_bytes(server.url('/v1/chat/completions'), b'{}', {}, 3)
    finally:
        server.close()
    assert str(caught.value) == 'HTTP 401 from http://127.0.0.1:%d: bad key' % server.port


def test_userinfo_warnings_name_the_setting_never_the_value():
    settings = fw.Settings()
    assert fw.userinfo_warnings(settings) == []
    settings.llm_base_url = 'http://u:PASSSECRET@llm.example/v1'
    settings.ntfy_url = 'https://ntfy.example/topic@x'  # an '@' in the path is no user:password
    settings.events_url = 'https://user@hk.example/api/events'
    rows = fw.userinfo_warnings(settings)
    assert len(rows) == 2
    assert 'llm.base_url' in rows[0] and 'api_key' in rows[0]
    assert 'notify.events_url' in rows[1] and 'events_token' in rows[1]
    shown = '\n'.join(rows)
    assert 'PASSSECRET' not in shown and 'user' not in shown.replace('a user:password', '') and 'hk.example' not in shown
    settings.ntfy_url = 'https://me:pw@ntfy.example/topic'
    assert any('notify.ntfy_url' in row and 'token under [notify]' in row for row in fw.userinfo_warnings(settings))


def test_startup_prints_the_userinfo_warning(tmp_path, capsys):
    conf = tmp_path / 'firewatcher.conf'
    conf.write_text('[notify]\nenabled = true\nntfy_url = https://me:PASSSECRET@ntfy.example/topic\n', encoding='utf-8')
    assert fw.main(['--config', str(conf), '--print-unit', str(tmp_path / 'p.txt')]) == 0
    err = capsys.readouterr().err
    assert 'Warning: notify.ntfy_url holds a user:password' in err
    assert 'PASSSECRET' not in err and 'me:' not in err


def test_startup_is_quiet_without_userinfo(tmp_path, capsys):
    conf = tmp_path / 'firewatcher.conf'
    conf.write_text('[notify]\nenabled = true\nntfy_url = https://ntfy.example/topic\n', encoding='utf-8')
    assert fw.main(['--config', str(conf), '--print-unit', str(tmp_path / 'p.txt')]) == 0
    assert 'user:password' not in capsys.readouterr().err
