import os
import re

import firewatcher as fw

# --- matching ---

def test_match_fnmatch_and_regex():
    patterns = {
        'fnmatch': {'*I/O error*'},
        'regex': {re.compile(r'nvme\d+n\d+')},
    }
    assert fw.match_patterns('sd 0:0: I/O error', patterns)
    assert fw.match_patterns('nvme0n1: reset', patterns)
    assert not fw.match_patterns('nothing to see', patterns)


def test_get_matched_pattern_returns_regex_span_or_fnmatch():
    patterns = {
        'regex': {re.compile(r'nvme\d+n\d+')},
        'fnmatch': {'*panic*'},
    }
    assert fw.get_matched_pattern('host nvme0n1 timeout', patterns) == 'nvme0n1'
    assert fw.get_matched_pattern('kernel panic', {'fnmatch': {'*panic*'}}) == '*panic*'
    assert fw.get_matched_pattern('nope', patterns) is None


def test_own_log_line_skips_syslog_identifier_not_random_substring():
    patterns = {'fnmatch': {'*error*'}}
    assert fw.match_patterns('host firewatcher[12]: Capturing logs to /tmp/error', patterns) is False
    assert fw.match_patterns('kernel: hardware error on disk', patterns) is True


def test_own_log_line_skips_self_marker_even_when_it_quotes_a_pattern():
    patterns = {'fnmatch': {'*panic*', '*I/O error*'}}
    assert fw.match_patterns('firewatcher-self panic in the summary', patterns) is False
    assert fw._is_own_log_line('continuation firewatcher-self I/O error')
    assert fw.match_patterns('kernel panic', patterns) is True


def test_own_log_line_skips_module_path():
    base = os.path.basename(fw.__file__)
    assert fw._is_own_log_line('Traceback in /usr/lib/' + base)
    assert not fw._is_own_log_line('kernel: watchdog sensor online')
    assert fw._is_own_log_line('box firewatcher[12]: x')
    assert not fw._is_own_log_line('box firewatcher: missing pid')


def test_example_nvme_regex_matches_kernel_lines():
    pat = re.compile(fw.EXAMPLE_PATTERNS['nvme_failure.regex'].strip())
    assert pat.search('kernel: nvme timeout')
    assert pat.search('kernel: nvme0n1: I/O timeout')
    assert pat.search('nvme reset controller')
    assert pat.search('NVMe fail')
    assert pat.search('nvme1n1 abort')
    assert pat.search('kernel: nvme unable to')
    assert not pat.search('firewire timeout')
    assert not pat.search('<nvme> timeout')
    assert not pat.search('kernel: nvme')
    assert not pat.search('renamed vme timeout')


def test_example_sys_msg_fnmatch_hits():
    patterns = {'fnmatch': {f'*{line}*' for line in fw.EXAMPLE_PATTERNS['sys_msg.txt'].splitlines() if line}}
    assert fw.match_patterns('kernel panic - not syncing', patterns)
    assert fw.match_patterns('sd 1:0:0:0: I/O error', patterns)
    assert fw.match_patterns('Out of Memory: Kill process', patterns)
    assert fw.match_patterns('Call Trace:', patterns)
    assert not fw.match_patterns('unrelated info line', patterns)


def test_example_pattern_files_match_embedded_constants():
    root = os.path.dirname(os.path.abspath(fw.__file__))
    for name, content in fw.EXAMPLE_PATTERNS.items():
        path = os.path.join(root, 'examples', name)
        assert os.path.isfile(path)
        assert open(path, encoding='utf-8').read() == content
    assert 'nebula' not in fw.EXAMPLE_PATTERNS['sys_msg.txt'].lower()
    assert 'nebula' not in fw.EXAMPLE_PATTERNS['nvme_failure.regex'].lower()


def test_match_empty_patterns_is_false():
    assert fw.match_patterns('panic', {}) is False
    assert fw.get_matched_pattern('panic', {}) is None
    assert fw.get_matched_pattern('panic', {'regex': set()}) is None


def test_match_regex_miss_falls_through_to_fnmatch():
    patterns = {
        'regex': {re.compile(r'^ONLY$')},
        'fnmatch': {'*HIT*'},
    }
    assert fw.match_patterns('xx HIT yy', patterns)
    assert fw.get_matched_pattern('xx HIT yy', patterns) == '*HIT*'
    assert fw.match_patterns('nope', patterns) is False
    assert fw.get_matched_pattern('nope', patterns) is None
