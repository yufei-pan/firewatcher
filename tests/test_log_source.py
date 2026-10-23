import firewatcher as fw
from conftest import parse_cli, fake_exists, use_journal

# --- log source ---

def test_log_source_command_filter_only_journalctl(monkeypatch):
    use_journal(monkeypatch)
    parsed = parse_cli(['--filter_only', 'p.txt'])
    cmd = fw.log_source_command(parsed)
    assert cmd[0] == 'journalctl'
    assert '--follow' not in cmd
    assert '--no-pager' in cmd
    cmd2 = fw.log_source_command(parse_cli(['p.txt']))
    assert '--follow' in cmd2
    assert '--no-pager' in cmd2
    assert '--lines=20' in cmd2


def test_log_source_command_log_file_cat_vs_tail(monkeypatch):
    monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
    parsed = parse_cli(['--filter_only', '--log-file', '/tmp/x.log', 'p.txt'])
    assert fw.log_source_command(parsed) == ['cat', '/tmp/x.log']
    parsed = parse_cli(['--log-file', '/tmp/x.log', '--tail_lines', '+5', 'p.txt'])
    assert fw.log_source_command(parsed) == ['tail', '-n', '+5', '-F', '/tmp/x.log']


def test_log_source_command_falls_back_to_syslog(monkeypatch):
    monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists(syslog=True))
    cmd = fw.log_source_command(parse_cli(['p.txt']))
    assert cmd == ['tail', '-n', '20', '-F', '/var/log/syslog']
    cmd = fw.log_source_command(parse_cli(['--filter_only', 'p.txt']))
    assert cmd == ['cat', '/var/log/syslog']


def test_log_source_command_falls_back_to_messages_or_none(monkeypatch):
    monkeypatch.setattr(fw.shutil, 'which', lambda name: None)
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists(messages=True))
    assert fw.log_source_command(parse_cli(['p.txt']))[-1] == '/var/log/messages'
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists())
    assert fw.log_source_command(parse_cli(['p.txt'])) is None


def test_log_source_log_file_wins_over_journalctl(monkeypatch):
    use_journal(monkeypatch)
    cmd = fw.log_source_command(parse_cli(['--log-file', '/tmp/x.log', 'p.txt']))
    assert cmd == ['tail', '-n', '20', '-F', '/tmp/x.log']


def test_log_source_journalctl_custom_tail_lines(monkeypatch):
    use_journal(monkeypatch)
    cmd = fw.log_source_command(parse_cli(['--tail_lines', '7', 'p.txt']))
    assert '--lines=7' in cmd
    assert '--follow' in cmd


def test_journalctl_without_journald_falls_back_to_syslog_files(monkeypatch):
    # journalctl installed, but another init and rsyslog run the host
    monkeypatch.setattr(fw.shutil, 'which', lambda name: '/usr/bin/journalctl' if name == 'journalctl' else None)
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists(syslog=True))
    assert fw.log_source_command(parse_cli(['p.txt'])) == ['tail', '-n', '20', '-F', '/var/log/syslog']
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists(messages=True))
    assert fw.log_source_command(parse_cli(['p.txt'])) == ['tail', '-n', '20', '-F', '/var/log/messages']
    # with no syslog file either, journalctl is still the best guess
    monkeypatch.setattr(fw.os.path, 'exists', fake_exists())
    assert fw.log_source_command(parse_cli(['p.txt']))[0] == 'journalctl'


def test_journald_is_present_with_its_socket_or_journal_files(tmp_path, monkeypatch):
    assert not fw._journald_present()
    journal = tmp_path / 'journal'
    journal.mkdir()
    assert not fw._journald_present()
    (journal / 'machine-id').mkdir()
    assert fw._journald_present()
    monkeypatch.setattr(fw, 'JOURNAL_DIRS', ())
    assert not fw._journald_present()
    (tmp_path / 'journald.socket').write_text('')
    assert fw._journald_present()
