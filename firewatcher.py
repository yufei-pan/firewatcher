#!/usr/bin/env python3
# requires-python = ">=3.6"
# -*- coding: utf-8 -*-
"""Watch logs for incident patterns and persist surrounding context."""
import argparse
import fnmatch
import subprocess
import re
import shutil
import sys
import builtins
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as ReadTimeout
import time
import datetime
import os
import unicodedata
import configparser
import json
import queue
import secrets
import socket
import syslog
import threading
import urllib.error
import urllib.request

version = '1.58'
__version__ = version

DEFAULT_OUTPUT_FOLDER = '/var/log/captured_messages/'
DEFAULT_PATTERNS_DIR = '/etc/firewatcher/patterns.d'
DEFAULT_UNIT_NAME = 'firewatcher'
SYSTEMD_RUNTIME_DIR = '/run/systemd/system'
SYSTEMD_UNIT_DIR = '/etc/systemd/system'
SLUG_MAX_LEN = 80
_OWN_SYSLOG_IDENT_RE = re.compile(r'(?:^|\s)firewatcher\[\d+\]:')

DEFAULT_CONFIG_PATH = '/etc/firewatcher/firewatcher.conf'
SELF_MARKER = 'firewatcher-self'
ANALYSIS_QUEUE_MAX = 4
OVERFLOW_NOTIFY_TIMEOUT = 5
PROGRAMMATIC_TITLE_MAX = 120
NTFY_TITLE_MAX = 200
NTFY_BODY_MAX = 4096
EXCERPT_HEAD_BYTES = 2048
JOURNAL_LINE_MAX = 8000
LLM_API_KEY_ENV = 'FIREWATCHER_LLM_API_KEY'
NTFY_TOKEN_ENV = 'FIREWATCHER_NTFY_TOKEN'
LLM_SYSTEM_PROMPT = (
	'You analyze one firewatcher incident capture from a Linux host. '
	'You receive a matched pattern and an excerpt of surrounding logs. '
	'Respond with a single JSON object and no other text. '
	'Keys: "title" (short, one line), "summary" (plain text, a few sentences), '
	'"notify" (boolean: true only if a person should look soon; '
	'false for benign, expected, or duplicate-looking noise). '
	'Do not invent hosts, times, or causes that are not in the excerpt.'
)

class Log_Compressor:
	def __init__(self, logsDir, compressAfterMonths, deleteLogAfterMonths):
		self.logsDir = logsDir
		self.compressAfterMonths = compressAfterMonths
		self.deleteLogAfterMonths = deleteLogAfterMonths
		self.lastProcessTime = 0
		self.compressLogs()
		
	def compressLogs(self):
		# if the compressor had been ran in the last 48 hours, don't run it again
		if time.time() - self.lastProcessTime < 172800:
			return
		# Get the list of files and directories in the logsDir
		if not os.path.exists(self.logsDir):
			return
		pathsList = os.listdir(self.logsDir)
		pathToDelete = []
		pathToCompress = []
		for path in pathsList:
			try:
				# Convert the path to a timestamp
				pathTime = datetime.datetime.strptime(path.partition('.')[0],'%Y-%m')
				if self.deleteLogAfterMonths > 0 and (datetime.datetime.now() - pathTime).days > self.deleteLogAfterMonths*30:
					pathToDelete.append(path)
				elif self.compressAfterMonths > 0 and (datetime.datetime.now() - pathTime).days > self.compressAfterMonths*30 and os.path.isdir(os.path.join(self.logsDir,path)):
					pathToCompress.append(path)
			except:
				pass
		# Iterate copies: mutating the lists while looping skipped every other entry.
		for dirName in list(pathToDelete):
			print(f"Deleting {dirName}")
			full = os.path.join(self.logsDir, dirName)
			if os.path.isdir(full) and not os.path.islink(full):
				shutil.rmtree(full)
			elif os.path.lexists(full):
				os.remove(full)
		for dirName in list(pathToCompress):
			print(f"Compressing {dirName}")
			subprocess.run(['tar','-caf',os.path.join(self.logsDir,dirName+".tar.xz"),'--remove-files',os.path.join(self.logsDir,dirName)])

		self.lastProcessTime = time.time()

def print(*args, **kwargs):
	'''Print with flush=True by default.'''
	kwargs.setdefault('flush', True)
	return builtins.print(*args, **kwargs)

class bcolors:
		HEADER = '\033[95m'
		OKBLUE = '\033[94m'
		OKCYAN = '\033[96m'
		OKGREEN = '\033[92m'
		warning = '\033[93m'
		critical = '\033[91m'
		info = '\033[0m'
		debug = '\033[0m'
		ENDC = '\033[0m'
		BOLD = '\033[1m'
		UNDERLINE = '\033[4m'

def slugify(value, allow_unicode=False):
	"""
	Taken from https://github.com/django/django/blob/master/django/utils/text.py
	Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
	dashes to single dashes. Remove characters that aren't alphanumerics,
	underscores, or hyphens. Convert to lowercase. Also strip leading and
	trailing whitespace, dashes, and underscores.
	"""
	value = str(value)
	if allow_unicode:
		value = unicodedata.normalize('NFKC', value)
	else:
		value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
	value = re.sub(r'[^\w\s-]', '', value.lower())
	value = re.sub(r'[-\s]+', '-', value).strip('-_')
	if len(value) > SLUG_MAX_LEN:
		value = value[:SLUG_MAX_LEN].rstrip('-_')
	return value

def load_patterns(pattern_files):
	"""Load patterns from a file and compile them if regex is used."""
	rtn_patterns = {}
	for pattern_file in expand_pattern_sources(pattern_files):
		if not os.path.exists(pattern_file):
			print(f"Pattern file not found: {pattern_file}")
			continue
		try:
			with open(pattern_file, 'r') as f:
				patterns = [line.strip() for line in f if line.strip()]
		except Exception as e:
			print(f"Error reading pattern file: {pattern_file}")
			print(e)
			continue
		# process regex patterns if file ends with .regex
		if pattern_file.endswith('.regex'):
			# ignore invalid regex patterns
			for pattern in patterns:
				try:
					pattern = re.compile(pattern)
					if pattern:
						rtn_patterns.setdefault('regex', set()).add(pattern)
				except Exception:
					print(f"Invalid regex pattern: {pattern}")
		# process fnmatch patterns if file ends with .fnmatch
		else:
			patterns = [f'*{pattern}*' for pattern in patterns]
			rtn_patterns.setdefault('fnmatch', set()).update(patterns)
	return rtn_patterns

def _is_own_log_line(line):
	"""True for this process's own syslog/journal lines, not incidental matching text."""
	if SELF_MARKER in line:
		return True
	if _OWN_SYSLOG_IDENT_RE.search(line):
		return True
	base = os.path.basename(__file__)
	if base and ('/' + base) in line:
		return True
	return False

def match_patterns(line, patterns):
	"""Check if the line matches any of the patterns based on the matching mode."""
	if _is_own_log_line(line):
		return False
	if 'regex' in patterns:
		if any(regex.search(line) for regex in patterns['regex']):
			return True
	if 'fnmatch' in patterns:
		if any(fnmatch.fnmatch(line, pattern) for pattern in patterns['fnmatch']):
			return True
	return False
	
def get_matched_pattern(line, patterns):
	'''Get the first matched pattern for the line'''
	if 'regex' in patterns:
		for regex in patterns['regex']:
			# if regex.search(line):
			# 	return regex.pattern
			matched = regex.search(line)
			if matched:
				return matched[0]
	if 'fnmatch' in patterns:
		for pattern in patterns['fnmatch']:
			if fnmatch.fnmatch(line, pattern):
				return pattern
	return None

class ConfigError(Exception):
	"""Raised when the config file or merged settings are unusable."""


class Settings(object):
	"""Resolved runtime settings. `_resolved` marks CLI defaults as already applied."""

	_resolved = True

	def __init__(self):
		self.raw = None
		self.config_path = DEFAULT_CONFIG_PATH
		self.config_existed = False
		self.config_has_patterns = False
		self.pattern_file = []
		self.log_file = None
		self.capture_time = 300
		self.output_folder = DEFAULT_OUTPUT_FOLDER
		self.tail_lines = '20'
		self.filter_only = False
		self.compress_after_months = 3
		self.delete_after_months = 0
		self.capture_line_count_max = 10000
		self.llm_enabled = False
		self.llm_base_url = ''
		self.llm_model = ''
		self.llm_api_key = ''
		self.llm_timeout = 60
		self.llm_max_bytes = 48000
		self.notify_enabled = False
		self.ntfy_url = ''
		self.ntfy_token = ''
		self.ntfy_priority = 4
		self.ntfy_timeout = 10
		self.unit_name = DEFAULT_UNIT_NAME
		self.no_enable = False
		self.requires_mounts_for = []


def _flatten(text):
	"""One physical line. Newlines become a visible separator."""
	text = str(text).replace('\r\n', '\n').replace('\r', '\n')
	return text.replace('\n', ' / ')


def _hostname():
	try:
		return socket.gethostname() or 'localhost'
	except Exception:
		return 'localhost'


def _split_patterns(value):
	if value is None:
		return []
	text = str(value).replace(',', '\n')
	return [part.strip() for part in text.splitlines() if part.strip()]


def _coerce_bool(value, key):
	if isinstance(value, bool):
		return value
	text = str(value).strip().lower()
	if text in ('1', 'true', 'yes', 'on'):
		return True
	if text in ('0', 'false', 'no', 'off', ''):
		if text == '':
			raise ConfigError('invalid boolean for %s: empty' % key)
		return False
	raise ConfigError('invalid boolean for %s: %s' % (key, value))


def _coerce_int(value, key):
	try:
		return int(str(value).strip())
	except (TypeError, ValueError):
		raise ConfigError('invalid integer for %s: %s' % (key, value))


def _read_config_file(path):
	parser = configparser.ConfigParser(interpolation=None)
	try:
		loaded = parser.read(path, encoding='utf-8')
	except configparser.Error as exc:
		raise ConfigError('cannot read config %s: %s' % (path, exc))
	if not loaded:
		raise ConfigError('cannot read config %s' % path)
	values = {}

	def take(section, key, dest, kind):
		if not parser.has_section(section) or not parser.has_option(section, key):
			return
		raw = parser.get(section, key)
		label = '%s.%s' % (section, key)
		if kind == 'patterns':
			values[dest] = _split_patterns(raw)
		elif kind == 'int':
			values[dest] = _coerce_int(raw, label)
		elif kind == 'bool':
			values[dest] = _coerce_bool(raw, label)
		else:
			values[dest] = str(raw).strip()

	take('watch', 'patterns', 'patterns', 'patterns')
	take('watch', 'log_file', 'log_file', 'str')
	take('watch', 'capture_time', 'capture_time', 'int')
	take('watch', 'output_folder', 'output_folder', 'str')
	take('watch', 'tail_lines', 'tail_lines', 'str')
	take('watch', 'filter_only', 'filter_only', 'bool')
	take('watch', 'compress_after_months', 'compress_after_months', 'int')
	take('watch', 'delete_after_months', 'delete_after_months', 'int')
	take('watch', 'capture_line_count_max', 'capture_line_count_max', 'int')
	take('llm', 'enabled', 'llm_enabled', 'bool')
	take('llm', 'base_url', 'llm_base_url', 'str')
	take('llm', 'model', 'llm_model', 'str')
	take('llm', 'api_key', 'llm_api_key', 'str')
	take('llm', 'timeout', 'llm_timeout', 'int')
	take('llm', 'max_bytes', 'llm_max_bytes', 'int')
	take('notify', 'enabled', 'notify_enabled', 'bool')
	take('notify', 'ntfy_url', 'ntfy_url', 'str')
	take('notify', 'token', 'ntfy_token', 'str')
	take('notify', 'priority', 'ntfy_priority', 'int')
	take('notify', 'timeout', 'ntfy_timeout', 'int')
	return values


def resolve_settings(args, environ=None):
	"""Merge built-in defaults, the config file, explicit CLI flags, then secret env vars."""
	if environ is None:
		environ = os.environ
	if getattr(args, 'config', None):
		config_path = args.config
		required = True
	else:
		config_path = DEFAULT_CONFIG_PATH
		required = False
	config_path = os.path.abspath(config_path)
	existed = os.path.isfile(config_path)
	if not existed:
		if required:
			raise ConfigError('config file not found: %s' % config_path)
		file_values = {}
	else:
		file_values = _read_config_file(config_path)
	settings = Settings()
	settings.raw = args
	settings.config_path = config_path
	settings.config_existed = existed
	settings.config_has_patterns = bool(file_values.get('patterns'))
	if 'patterns' in file_values:
		settings.pattern_file = list(file_values['patterns'])
	if 'log_file' in file_values:
		settings.log_file = file_values['log_file'] or None
	for key in ('capture_time', 'compress_after_months', 'delete_after_months', 'capture_line_count_max',
				'llm_timeout', 'llm_max_bytes', 'ntfy_priority', 'ntfy_timeout',
				'filter_only', 'llm_enabled', 'notify_enabled'):
		if key in file_values:
			setattr(settings, key, file_values[key])
	if file_values.get('output_folder'):
		settings.output_folder = file_values['output_folder']
	if file_values.get('tail_lines'):
		settings.tail_lines = file_values['tail_lines']
	for key in ('llm_base_url', 'llm_model', 'llm_api_key', 'ntfy_url', 'ntfy_token'):
		if key in file_values:
			setattr(settings, key, file_values[key])
	if getattr(args, 'pattern_file', None):
		settings.pattern_file = list(args.pattern_file)
	if getattr(args, 'log_file', None):
		settings.log_file = args.log_file
	if getattr(args, 'output_folder', None):
		settings.output_folder = args.output_folder
	if getattr(args, 'tail_lines', None) is not None:
		settings.tail_lines = str(args.tail_lines)
	if getattr(args, 'capture_time', None) is not None:
		settings.capture_time = args.capture_time
	if getattr(args, 'compress_after_months', None) is not None:
		settings.compress_after_months = args.compress_after_months
	if getattr(args, 'delete_after_months', None) is not None:
		settings.delete_after_months = args.delete_after_months
	if getattr(args, 'capture_line_count_max', None) is not None:
		settings.capture_line_count_max = args.capture_line_count_max
	if getattr(args, 'filter_only', None) is not None:
		settings.filter_only = bool(args.filter_only)
	if getattr(args, 'llm', None) is not None:
		settings.llm_enabled = bool(args.llm)
	if getattr(args, 'llm_base_url', None) is not None:
		settings.llm_base_url = args.llm_base_url.strip()
	if getattr(args, 'llm_model', None) is not None:
		settings.llm_model = args.llm_model.strip()
	if getattr(args, 'llm_timeout', None) is not None:
		settings.llm_timeout = args.llm_timeout
	if getattr(args, 'llm_max_bytes', None) is not None:
		settings.llm_max_bytes = args.llm_max_bytes
	if getattr(args, 'notify', None) is not None:
		settings.notify_enabled = bool(args.notify)
	if getattr(args, 'ntfy_url', None) is not None:
		settings.ntfy_url = args.ntfy_url.strip()
	if getattr(args, 'ntfy_priority', None) is not None:
		settings.ntfy_priority = args.ntfy_priority
	if getattr(args, 'ntfy_timeout', None) is not None:
		settings.ntfy_timeout = args.ntfy_timeout
	if LLM_API_KEY_ENV in environ:
		settings.llm_api_key = environ[LLM_API_KEY_ENV]
	if NTFY_TOKEN_ENV in environ:
		settings.ntfy_token = environ[NTFY_TOKEN_ENV]
	settings.llm_base_url = (settings.llm_base_url or '').strip()
	settings.llm_model = (settings.llm_model or '').strip()
	settings.ntfy_url = (settings.ntfy_url or '').strip()
	settings.unit_name = getattr(args, 'unit_name', None) or DEFAULT_UNIT_NAME
	settings.no_enable = bool(getattr(args, 'no_enable', False))
	settings.requires_mounts_for = list(getattr(args, 'requires_mounts_for', None) or [])
	validate_settings(settings)
	return settings


def validate_settings(settings):
	if settings.llm_enabled and (not settings.llm_base_url or not settings.llm_model):
		raise ConfigError('LLM analysis requires base_url and model (--llm-base-url and --llm-model, or llm.base_url and llm.model in the config)')
	if settings.notify_enabled and not settings.ntfy_url:
		raise ConfigError('notifications require an ntfy topic URL (--ntfy-url, or notify.ntfy_url in the config)')


def _ini_patterns(paths):
	paths = list(paths or [])
	if not paths:
		return ''
	first = paths[0]
	return first + ''.join('\n\t' + item for item in paths[1:])


def _ini_text(value):
	return str('' if value is None else value).replace('\r', '').replace('\n', '').strip()


def _generate_ntfy_url():
	"""A hostname plus 72 random bits in ntfy's allowed URL-safe alphabet."""
	prefix = 'firewatcher-'
	suffix = secrets.token_urlsafe(9)
	hostname = re.sub(r'[^A-Za-z0-9_-]+', '-', _hostname()).strip('-_') or 'localhost'
	hostname = hostname[:64 - len(prefix) - 1 - len(suffix)]
	return 'https://ntfy.sh/%s%s-%s' % (prefix, hostname, suffix)


def render_config_text(settings):
	"""INI text for a new config file. Secrets are included; the file is mode 0600."""
	lines = [
		'# firewatcher configuration. Explicit command-line flags override this file.',
		'# FIREWATCHER_LLM_API_KEY and FIREWATCHER_NTFY_TOKEN override api_key and token.',
		'# Those two secrets are not command-line flags.',
		'',
		'[watch]',
		'# Pattern files or directories, comma-separated or one per indented line.',
		'patterns = %s' % _ini_patterns(settings.pattern_file),
		'# Leave blank to use journald, then /var/log/syslog or /var/log/messages.',
		'log_file = %s' % _ini_text(settings.log_file),
		'# Seconds of context to capture after a match.',
		'capture_time = %s' % int(settings.capture_time),
		'# Directory for incident captures and journal.log.',
		'output_folder = %s' % _ini_text(settings.output_folder),
		'# Initial lines to read; +N starts at line N when reading a file.',
		'tail_lines = %s' % _ini_text(settings.tail_lines),
		'# Process existing logs only instead of following new messages.',
		'filter_only = %s' % ('true' if settings.filter_only else 'false'),
		'# Compress monthly capture directories after this many months; 0 disables.',
		'compress_after_months = %s' % int(settings.compress_after_months),
		'# Delete monthly capture directories after this many months; 0 disables.',
		'delete_after_months = %s' % int(settings.delete_after_months),
		'# Maximum context lines before and after a match.',
		'capture_line_count_max = %s' % int(settings.capture_line_count_max),
		'',
		'[llm]',
		'# Set true after configuring your OpenAI-compatible API and model.',
		'enabled = %s' % ('true' if settings.llm_enabled else 'false'),
		'# API root, e.g. http://127.0.0.1:11434/v1; do not add /chat/completions.',
		'base_url = %s' % _ini_text(settings.llm_base_url),
		'# Model name accepted by the API, e.g. llama3.1.',
		'model = %s' % _ini_text(settings.llm_model),
		'# Optional secret; FIREWATCHER_LLM_API_KEY overrides this value.',
		'api_key = %s' % _ini_text(settings.llm_api_key),
		'# HTTP timeout in seconds.',
		'timeout = %s' % int(settings.llm_timeout),
		'# Maximum capture bytes sent to the model.',
		'max_bytes = %s' % int(settings.llm_max_bytes),
		'',
		'[notify]',
		'# Enable pushes; when LLM analysis is on, the model decides whether to notify.',
		'enabled = %s' % ('true' if settings.notify_enabled else 'false'),
		'# Subscribe to this topic in ntfy; keep unprotected topic URLs private.',
		'# If no URL is supplied, generate firewatcher-<hostname>-<12 random characters>.',
		'ntfy_url = %s' % _ini_text(settings.ntfy_url or _generate_ntfy_url()),
		'# Optional secret; FIREWATCHER_NTFY_TOKEN overrides this value.',
		'token = %s' % _ini_text(settings.ntfy_token),
		'# ntfy priority: 1 (minimum) through 5 (maximum).',
		'priority = %s' % int(settings.ntfy_priority),
		'# HTTP timeout in seconds.',
		'timeout = %s' % int(settings.ntfy_timeout),
		'',
	]
	return '\n'.join(lines)


def write_config_file(path, settings):
	directory = os.path.dirname(path)
	if directory:
		os.makedirs(directory, exist_ok=True)
	payload = render_config_text(settings).encode('utf-8')
	fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
	try:
		os.write(fd, payload)
	finally:
		os.close(fd)
	os.chmod(path, 0o600)


def _explicit_cli_args(raw):
	"""Flags the operator actually passed. Omitted flags are not overrides."""
	parts = []
	if getattr(raw, 'log_file', None):
		parts.extend(['--log-file', raw.log_file])
	if getattr(raw, 'capture_time', None) is not None:
		parts.extend(['-t', str(raw.capture_time)])
	if getattr(raw, 'output_folder', None):
		parts.extend(['-o', raw.output_folder])
	if getattr(raw, 'tail_lines', None) is not None:
		parts.extend(['--tail_lines', str(raw.tail_lines)])
	if getattr(raw, 'filter_only', None) is True:
		parts.append('--filter_only')
	elif getattr(raw, 'filter_only', None) is False:
		parts.append('--no-filter_only')
	if getattr(raw, 'compress_after_months', None) is not None:
		parts.extend(['--compress-after-months', str(raw.compress_after_months)])
	if getattr(raw, 'capture_line_count_max', None) is not None:
		parts.extend(['--capture_line_count_max', str(raw.capture_line_count_max)])
	if getattr(raw, 'delete_after_months', None) is not None:
		parts.extend(['--delete-after-months', str(raw.delete_after_months)])
	if getattr(raw, 'llm', None) is True:
		parts.append('--llm')
	elif getattr(raw, 'llm', None) is False:
		parts.append('--no-llm')
	if getattr(raw, 'llm_base_url', None) is not None:
		parts.extend(['--llm-base-url', raw.llm_base_url])
	if getattr(raw, 'llm_model', None) is not None:
		parts.extend(['--llm-model', raw.llm_model])
	if getattr(raw, 'llm_timeout', None) is not None:
		parts.extend(['--llm-timeout', str(raw.llm_timeout)])
	if getattr(raw, 'llm_max_bytes', None) is not None:
		parts.extend(['--llm-max-bytes', str(raw.llm_max_bytes)])
	if getattr(raw, 'notify', None) is True:
		parts.append('--notify')
	elif getattr(raw, 'notify', None) is False:
		parts.append('--no-notify')
	if getattr(raw, 'ntfy_url', None) is not None:
		parts.extend(['--ntfy-url', raw.ntfy_url])
	if getattr(raw, 'ntfy_priority', None) is not None:
		parts.extend(['--ntfy-priority', str(raw.ntfy_priority)])
	if getattr(raw, 'ntfy_timeout', None) is not None:
		parts.extend(['--ntfy-timeout', str(raw.ntfy_timeout)])
	if getattr(raw, 'pattern_file', None):
		parts.extend(list(raw.pattern_file))
	return parts


def _prepare_unit_settings(args, raw=None):
	if getattr(args, '_resolved', False):
		resolved = args
		if raw is None:
			raw = args.raw
	else:
		raw = args
		resolved = resolve_settings(args)
		if not resolved.pattern_file and (getattr(raw, 'print_unit', False) or getattr(raw, 'install_service', False)):
			resolved.pattern_file = [DEFAULT_PATTERNS_DIR]
	return resolved, raw


def _journal(priority, message, status=None):
	"""Write one syslog line and a shorter stdout line. Both carry the self marker."""
	syslog_line = _flatten('%s %s' % (SELF_MARKER, message))
	if len(syslog_line) > JOURNAL_LINE_MAX:
		syslog_line = syslog_line[:JOURNAL_LINE_MAX]
	try:
		syslog.syslog(priority, syslog_line)
	except Exception:
		pass
	shown = message if status is None else status
	print(_flatten('%s %s' % (SELF_MARKER, shown)))


def _programmatic_title(hostname, pattern):
	title = _flatten('%s: %s' % (hostname, pattern))
	if len(title) > PROGRAMMATIC_TITLE_MAX:
		title = title[:PROGRAMMATIC_TITLE_MAX].rstrip()
	return title


def _http_header(text, limit):
	flat = _flatten(text).strip()
	if len(flat) > limit:
		flat = flat[:limit].rstrip()
	return flat.encode('latin-1', 'replace').decode('latin-1')


def _notify_body(text, path):
	suffix = '\n' + str(path)
	suffix_b = suffix.encode('utf-8')
	if len(suffix_b) >= NTFY_BODY_MAX:
		return suffix_b[:NTFY_BODY_MAX].decode('utf-8', 'ignore')
	budget = NTFY_BODY_MAX - len(suffix_b)
	body = _flatten(text).encode('utf-8')[:budget]
	return body.decode('utf-8', 'ignore') + suffix


def _urlopen_bytes(url, data, headers, timeout):
	request = urllib.request.Request(url, data=data, headers=headers, method='POST')
	try:
		with urllib.request.urlopen(request, timeout=timeout) as response:
			return response.read()
	except urllib.error.HTTPError as exc:
		detail = ''
		try:
			detail = exc.read().decode('utf-8', 'replace')
		except Exception:
			detail = ''
		raise RuntimeError('HTTP %s from %s: %s' % (getattr(exc, 'code', '?'), url, detail[:300]))


def _parse_llm_object(content):
	text = str(content).strip()
	if text.startswith('```'):
		rows = text.splitlines()
		if rows and rows[0].startswith('```'):
			rows = rows[1:]
		if rows and rows[-1].strip().startswith('```'):
			rows = rows[:-1]
		text = '\n'.join(rows).strip()
	try:
		obj = json.loads(text)
	except ValueError:
		start = text.find('{')
		end = text.rfind('}')
		if start < 0 or end <= start:
			raise ValueError('LLM response did not contain a JSON object')
		try:
			obj = json.loads(text[start:end + 1])
		except ValueError:
			raise ValueError('LLM response did not contain a JSON object')
	if not isinstance(obj, dict):
		raise ValueError('LLM JSON was not an object')
	if not isinstance(obj.get('notify'), bool):
		raise ValueError('LLM JSON notify was not a boolean')
	title = _flatten(obj.get('title') or '').strip()
	if not title:
		raise ValueError('LLM JSON missing title')
	if len(title) > NTFY_TITLE_MAX:
		title = title[:NTFY_TITLE_MAX].rstrip()
	summary = obj.get('summary')
	if summary is None:
		summary = ''
	return {'title': title, 'summary': str(summary), 'notify': obj['notify']}


def _capture_excerpt(path, max_bytes):
	max_bytes = int(max_bytes)
	if max_bytes < 1:
		return ''
	with open(path, 'rb') as handle:
		data = handle.read()
	if len(data) <= max_bytes:
		text = data.decode('utf-8', 'replace')
	else:
		head_n = min(EXCERPT_HEAD_BYTES, max(1, max_bytes // 2))
		sep = b'\n...\n'
		tail_n = max_bytes - head_n - len(sep)
		if tail_n < 1:
			sep = b''
			tail_n = max(0, max_bytes - head_n)
		head = data[:head_n]
		tail = data[-tail_n:] if tail_n else b''
		text = (head + sep + tail).decode('utf-8', 'replace')
	raw = text.encode('utf-8')
	if len(raw) > max_bytes:
		text = raw[:max_bytes].decode('utf-8', 'ignore')
	return text


def call_llm(settings, incident):
	excerpt = _capture_excerpt(incident['path'], settings.llm_max_bytes)
	user = (
		'Host: %s\nMatched pattern: %s\nMatched line: %s\nCapture path: %s\n\nExcerpt:\n%s'
		% (incident.get('hostname', ''), incident.get('pattern', ''), incident.get('matched_line', ''), incident.get('path', ''), excerpt)
	)
	url = settings.llm_base_url.rstrip('/') + '/chat/completions'
	payload = {
		'model': settings.llm_model,
		'temperature': 0,
		'messages': [
			{'role': 'system', 'content': LLM_SYSTEM_PROMPT},
			{'role': 'user', 'content': user},
		],
	}
	headers = {'Content-Type': 'application/json'}
	if settings.llm_api_key:
		headers['Authorization'] = 'Bearer ' + settings.llm_api_key
	raw = _urlopen_bytes(url, json.dumps(payload).encode('utf-8'), headers, settings.llm_timeout)
	try:
		parsed = json.loads(raw.decode('utf-8', 'replace'))
		content = parsed['choices'][0]['message']['content']
	except (ValueError, KeyError, IndexError, TypeError) as exc:
		raise ValueError('unreadable LLM response: %s' % exc)
	return _parse_llm_object(content)


def send_ntfy(url, title, body, priority, token, timeout):
	headers = {
		'Title': _http_header(title, NTFY_TITLE_MAX),
		'Priority': str(int(priority)),
		'Content-Type': 'text/plain; charset=utf-8',
	}
	if token:
		headers['Authorization'] = 'Bearer ' + _http_header(token, 2000)
	_urlopen_bytes(url, body.encode('utf-8'), headers, timeout)


def _append_note(path, text):
	rows = str(text).splitlines() or ['']
	with open(path, 'a', encoding='utf-8') as handle:
		handle.write('\n')
		for row in rows:
			handle.write('%s %s\n' % (SELF_MARKER, row))


def _format_analysis(result):
	return 'LLM analysis\ntitle: %s\nnotify: %s\nsummary:\n%s' % (
		result['title'],
		'true' if result['notify'] else 'false',
		result['summary'],
	)


def _format_failure(exc):
	return 'LLM analysis failed: %s' % exc


class IncidentDispatcher(object):
	"""One worker. Notify-only jobs (priority 0) run ahead of LLM jobs (priority 1)."""

	def __init__(self, settings, start_thread=True):
		self.settings = settings
		self.queue = queue.PriorityQueue(maxsize=ANALYSIS_QUEUE_MAX)
		self.seq = 0
		self._seq_lock = threading.Lock()
		self.thread = None
		try:
			syslog.openlog('firewatcher', syslog.LOG_PID | syslog.LOG_NDELAY, syslog.LOG_DAEMON)
		except Exception:
			pass
		if start_thread:
			self.thread = threading.Thread(target=self._run, name='firewatcher-notify', daemon=True)
			self.thread.start()

	def submit(self, incident):
		with self._seq_lock:
			self.seq += 1
			seq = self.seq
		priority = 1 if self.settings.llm_enabled else 0
		try:
			self.queue.put_nowait((priority, seq, incident))
		except queue.Full:
			self._overflow(incident)

	def close(self):
		if self.thread is None:
			return
		with self._seq_lock:
			self.seq += 1
			seq = self.seq
		try:
			self.queue.put((2, seq, None), timeout=1)
		except queue.Full:
			pass
		timeout = float(self.settings.llm_timeout) + float(self.settings.ntfy_timeout)
		self.thread.join(timeout)

	def _run(self):
		while True:
			try:
				item = self.queue.get()
			except Exception:
				return
			try:
				_priority, _seq, incident = item
				if incident is None:
					return
				self._process(incident)
			except Exception as exc:
				_journal(syslog.LOG_ERR, 'analysis worker error: %s' % exc, status='analysis worker error')
			finally:
				self.queue.task_done()

	def _overflow(self, incident):
		_journal(syslog.LOG_WARNING, 'analysis skipped, queue full', status='analysis skipped, queue full')
		if not self.settings.notify_enabled:
			return
		self._push(incident, _programmatic_title(incident.get('hostname', ''), incident.get('pattern', '')), incident.get('matched_line') or '', OVERFLOW_NOTIFY_TIMEOUT)

	def _process(self, incident):
		should_push = True
		title = _programmatic_title(incident.get('hostname', ''), incident.get('pattern', ''))
		body_source = incident.get('matched_line') or ''
		if self.settings.llm_enabled:
			try:
				result = call_llm(self.settings, incident)
				_append_note(incident['path'], _format_analysis(result))
				decision = 'yes' if result['notify'] else 'no'
				_journal(
					syslog.LOG_INFO,
					'analysis title=%s model_notify=%s summary=%s' % (result['title'], decision, _flatten(result['summary'])),
					status='analysis title=%s model_notify=%s' % (result['title'][:80], decision),
				)
				should_push = result['notify']
				title = result['title']
				if result['summary']:
					body_source = result['summary']
			except Exception as exc:
				try:
					_append_note(incident['path'], _format_failure(exc))
				except Exception:
					pass
				_journal(syslog.LOG_ERR, 'LLM analysis failed: %s' % exc, status='LLM analysis failed')
				should_push = True
				title = _programmatic_title(incident.get('hostname', ''), incident.get('pattern', ''))
				body_source = incident.get('matched_line') or ''
		if not self.settings.notify_enabled or not should_push:
			return
		self._push(incident, title, body_source, self.settings.ntfy_timeout)

	def _push(self, incident, title, body_source, timeout):
		body = _notify_body(body_source, incident.get('path', ''))
		try:
			send_ntfy(self.settings.ntfy_url, title, body, self.settings.ntfy_priority, self.settings.ntfy_token, timeout)
		except Exception as exc:
			_journal(syslog.LOG_ERR, 'ntfy failed: %s' % exc, status='ntfy failed')
			return
		_journal(syslog.LOG_WARNING, 'notification sent title=%s' % title, status='notification sent')


def _start_dispatcher(settings):
	if settings is None:
		return None
	if not settings.llm_enabled and not settings.notify_enabled:
		return None
	return IncidentDispatcher(settings)

def _end_capture(log_file_name, captured_line_counter, capture_line_count_max, incident=None, dispatcher=None):
	if not log_file_name:
		return
	with open(log_file_name, "a") as log_file:
		if captured_line_counter > capture_line_count_max:
			log_file.write(f"{bcolors.warning}Captured line count exceeded capture_line_count_max {capture_line_count_max}. Truncated to {capture_line_count_max} lines.{bcolors.ENDC}\n")
		log_file.write(bcolors.warning + '-'*80 +bcolors.ENDC + '\n')
		log_file.write(f"{bcolors.warning}End of capture at {datetime.datetime.now().isoformat()}{bcolors.ENDC}\n")
		log_file.write(f"{bcolors.warning}Captured {captured_line_counter} lines after first match.{bcolors.ENDC}\n")
		log_file.write(bcolors.warning+'-'*80 + bcolors.ENDC +'\n')
		print(f"  End of capture at {datetime.datetime.now().isoformat()}")
		log_file.write('-'*80 +'\n')
	if dispatcher is not None and incident is not None:
		job = dict(incident)
		job['path'] = log_file_name
		dispatcher.submit(job)


def capture_messages(command_to_run, patterns, capture_time=300, output_folder=DEFAULT_OUTPUT_FOLDER, compress_after_months=3, delete_after_months=0,capture_line_count_max=10000, notify_settings=None):
	"""Tail the log file and process lines with buffer management."""
	log_buffer = deque()  # Stores tuples of (read_time, line)
	log_compressor = Log_Compressor(output_folder, compress_after_months, delete_after_months)
	capture_until = None
	log_file_name = None
	captured_line_counter = 0
	processed_line_counter = 0
	incident = None
	dispatcher = _start_dispatcher(notify_settings)
	try:
		with subprocess.Popen(
			command_to_run,
			stdout=subprocess.PIPE,
			universal_newlines=True,
			encoding='utf-8',
			errors='replace',
		) as proc, ThreadPoolExecutor(max_workers=1) as reader:
			pending_read = None
			while True:
				try:
					if pending_read is None:
						pending_read = reader.submit(proc.stdout.readline)
					remaining = None if capture_until is None else max(0, capture_until - time.time())
					line = pending_read.result(timeout=remaining)
					pending_read = None
				except ReadTimeout:
					# Keep the same pending read while the source is quiet.
					_end_capture(log_file_name, captured_line_counter, capture_line_count_max, incident=incident, dispatcher=dispatcher)
					capture_until = None
					captured_line_counter = 0
					log_file_name = None
					continue
				except KeyboardInterrupt:
					print("Exiting.")
					try:
						proc.terminate()
					except Exception:
						pass
					break
				except Exception as e:
					pending_read = None
					print(f"Error reading line: {e}")
					continue
				if line == '':
					break
				if not line.strip():
					continue
				read_time = time.time()
				processed_line_counter += 1

				# Maintain a 10-minute buffer
				while log_buffer and read_time - log_buffer[0][0] > capture_time:
					log_buffer.popleft()
				log_buffer.append((read_time, line))

				# if the current line matches the pattern, capture the logs for the next capture_time seconds
				if match_patterns(line, patterns):
					if not capture_until:
						matched_pattern = get_matched_pattern(line, patterns)
						# Dump the buffer to file at output_folder/{Year-Month}/{Day-Hour-Minute-Second}.log
						log_folder = f"{output_folder}/{datetime.datetime.fromtimestamp(read_time).strftime('%Y-%m')}"
						os.makedirs(log_folder, exist_ok=True)
						log_file_name = os.path.abspath(f"{log_folder}/{slugify(matched_pattern)}_{datetime.datetime.fromtimestamp(read_time).strftime('%Y-%m-%dT%H_%M_%S%z')}.log")
						# also record a journal of all logs captured in {output_folder}/journal.log
						journal_file_name = os.path.abspath(f"{output_folder}/journal.log")
						with open(journal_file_name, "a") as journal_file:
							journal_file.write(f"{datetime.datetime.fromtimestamp(read_time).isoformat()} Captured logs for {matched_pattern} to {log_file_name}\n")
						print(f"Capturing logs to {log_file_name}")
						incident = {
							'pattern': matched_pattern if matched_pattern is not None else '',
							'matched_line': line.strip(),
							'hostname': _hostname(),
						}
						with open(log_file_name, "a") as log_file:
							log_file.write(bcolors.warning + '-'*80 +bcolors.ENDC + '\n')
							# Write the matched pattern and the line that matched
							log_file.write(f"{bcolors.warning}Matched pattern: {bcolors.critical}{matched_pattern}{bcolors.ENDC}\n")
							print(f"  Matched pattern: {matched_pattern}")
							log_file.write(f"{bcolors.warning}Matched line:    {line}{bcolors.ENDC}")
							print(f"  Matched line:    {line.strip()}")
							log_file.write(f"{bcolors.warning}Captured at:     {datetime.datetime.now().isoformat()}{bcolors.ENDC}\n")
							print(f"  Captured at:     {datetime.datetime.now().isoformat()}")
							log_file.write(bcolors.warning + '-'*80 +bcolors.ENDC + '\n')
							log_file.write(f"{bcolors.warning}Logs since {datetime.datetime.fromtimestamp(read_time - capture_time).isoformat()}:{bcolors.ENDC}\n")
							skip_lines = 0
							if len(log_buffer) > capture_line_count_max:
								skip_lines = len(log_buffer) - capture_line_count_max
								log_file.write(f"{bcolors.warning}Captured line count exceeded capture_line_count_max {capture_line_count_max}. Skipping cached {skip_lines} in-memory lines ...{bcolors.ENDC}\n")
							for i in range(skip_lines, len(log_buffer)):
								buffered_line = log_buffer[i][1]
								if match_patterns(buffered_line, patterns):
									log_file.write(f'{bcolors.critical}-> {buffered_line.strip()}{bcolors.ENDC}\n')
								else:
									log_file.write(buffered_line)
					else:
						# Append the line to the current log file
						with open(log_file_name, "a") as log_file:
							log_file.write(f'{bcolors.critical}-> {line.strip()}{bcolors.ENDC}\n')
						captured_line_counter += 1
					# If a match is found, set to capture the next capture_time seconds
					capture_until = read_time + capture_time
					if log_file_name and captured_line_counter > capture_line_count_max:
						_end_capture(log_file_name, captured_line_counter, capture_line_count_max, incident=incident, dispatcher=dispatcher)
						capture_until = None
						captured_line_counter = 0
						log_file_name = None
				# if the current line doesn't match the pattern, and capture_until is set and expired, reset capture_until and close the current log file
				elif log_file_name and ((capture_until and read_time > capture_until) or captured_line_counter > capture_line_count_max):
					_end_capture(log_file_name, captured_line_counter, capture_line_count_max, incident=incident, dispatcher=dispatcher)
					capture_until = None
					captured_line_counter = 0
					log_file_name = None
				# if the current line doesn't match the pattern, continue to write the logs to the current log file if capture_until is set and not expired
				elif capture_until and read_time <= capture_until:
					with open(log_file_name, "a") as log_file:
						log_file.write(line)
					captured_line_counter += 1
					if captured_line_counter > capture_line_count_max:
						_end_capture(log_file_name, captured_line_counter, capture_line_count_max, incident=incident, dispatcher=dispatcher)
						capture_until = None
						captured_line_counter = 0
						log_file_name = None
				# if the current line doesn't match the pattern, and capture_until is not set, check for log compression
				else:
					log_compressor.compressLogs()
				if processed_line_counter % 10000 == 0:
					print(f"Processed {processed_line_counter} lines.",flush=True)
	finally:
		try:
			if log_file_name:
				_end_capture(log_file_name, captured_line_counter, capture_line_count_max, incident=incident, dispatcher=dispatcher)
		finally:
			if dispatcher is not None:
				dispatcher.close()
	print("Process ended. Exiting.")
	print(f"Processed {processed_line_counter} lines.")

EXAMPLE_PATTERNS = {
	'sys_msg.txt': (
		'hard resetting link\n'
		'Initializing cgroup subsys cpuset\n'
		'Linux version\n'
		'Out of Memory\n'
		'Call Trace\n'
		'I/O error\n'
		'bad sector\n'
		'panic\n'
		'Critical\n'
		'controller is down\n'
		'timeout, aborting\n'
		'timeout, reset controller\n'
		'timeout, disable controller\n'
		'iotest: 1% high is too high compared to 1% low!\n'
		'Hardware error\n'
	),
	'nvme_failure.regex': (
		'(?i)(?:^|[\\s:])nvme(?:\\d+n\\d+)?\\W.*(timeout|abort|restart|reset|unable|cannot|invalid|'
		'froze|fail|down|above|cancel|dead|large|bogus|could not|deprecate)\n'
	),
}


def systemd_is_available(runtime_dir=None):
	"""True when this host is booted with systemd (PID 1)."""
	if runtime_dir is None:
		runtime_dir = SYSTEMD_RUNTIME_DIR
	return os.path.isdir(runtime_dir)


def _is_pattern_filename(name):
	if not name or name.startswith('.'):
		return False
	if name.endswith('~') or name.endswith('.bak'):
		return False
	lower = name.lower()
	if lower == 'readme' or lower.startswith('readme.'):
		return False
	return True


def expand_pattern_sources(paths):
	"""Expand directories to pattern files; keep plain files as-is."""
	files = []
	for path in paths:
		if os.path.isdir(path):
			for name in sorted(os.listdir(path)):
				if not _is_pattern_filename(name):
					continue
				full = os.path.join(path, name)
				if os.path.isfile(full):
					files.append(full)
		else:
			files.append(path)
	return files


def unit_filename(unit_name):
	name = (unit_name or DEFAULT_UNIT_NAME).strip()
	if not name.endswith('.service'):
		name = name + '.service'
	base = os.path.basename(name)
	if base != name or not base or base in ('.', '..'):
		raise ValueError('unit name must be a simple filename, not a path')
	return base


def resolve_executable():
	found = shutil.which('firewatcher')
	if found:
		return os.path.abspath(found)
	return os.path.abspath(sys.argv[0])


def _quote_unit_arg(value):
	value = str(value)
	if value and not any(ch.isspace() or ch in '"\\' for ch in value):
		return value
	return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'



def render_unit_file(args, executable=None, config_exists=None, raw=None):
	"""Render a systemd unit. Does not require systemd to be present."""
	resolved, raw = _prepare_unit_settings(args, raw=raw)
	if config_exists is None:
		config_exists = os.path.isfile(resolved.config_path)
	executable = executable or resolve_executable()
	parts = ['--config', resolved.config_path]
	if config_exists:
		parts.extend(_explicit_cli_args(raw))
		if not resolved.config_has_patterns and not getattr(raw, 'pattern_file', None):
			parts.extend(resolved.pattern_file or [DEFAULT_PATTERNS_DIR])
	exec_start = ' '.join([_quote_unit_arg(executable)] + [_quote_unit_arg(p) for p in parts])
	after = ['network-online.target']
	wants = ['network-online.target']
	if not resolved.log_file:
		after.insert(0, 'systemd-journald.socket')
	requires = []
	for mount in (getattr(resolved, 'requires_mounts_for', None) or []):
		requires.append(mount)
		if 'remote-fs.target' not in after:
			after.append('remote-fs.target')
	lines = [
		'[Unit]',
		'Description=firewatcher: persist log context around incident patterns',
		'After=' + ' '.join(after),
		'Wants=' + ' '.join(wants),
	]
	for mount in requires:
		lines.append('RequiresMountsFor=' + mount)
	stop_sec = max(30, int(resolved.llm_timeout) + int(resolved.ntfy_timeout) + 15)
	lines.extend([
		'',
		'[Service]',
		'Type=simple',
		'User=root',
		'ExecStart=' + exec_start,
		'Restart=always',
		'RestartSec=5',
		'TimeoutStopSec=%d' % stop_sec,
		'KillSignal=SIGINT',
		'StandardOutput=journal',
		'StandardError=journal',
		'',
		'[Install]',
		'WantedBy=multi-user.target',
		'',
	])
	return '\n'.join(lines)


def _warn_no_systemd(action):
	print(
		'Warning: systemd is not available on this host. '
		+ action
		+ ' only supports systemd. '
		'firewatcher itself still runs without systemd: it follows journalctl when present, '
		'else /var/log/syslog or /var/log/messages, or --log-file.',
		file=sys.stderr,
	)


def _run_systemctl(systemctl, *cmd):
	if systemctl is None:
		return subprocess.run(['systemctl', *cmd])
	return systemctl(*cmd)


def _looks_like_pattern_dir(path):
	if os.path.isfile(path):
		return False
	if os.path.isdir(path):
		return True
	base = os.path.basename(path.rstrip(os.sep))
	return path.endswith(('/', os.sep)) or base.endswith('.d')


def _seed_example_patterns(pattern_paths):
	"""Write example patterns into empty directories. Never overwrite existing files."""
	for path in pattern_paths:
		if not _looks_like_pattern_dir(path):
			continue
		os.makedirs(path, exist_ok=True)
		existing = [
			name for name in os.listdir(path)
			if _is_pattern_filename(name) and os.path.isfile(os.path.join(path, name))
		]
		if existing:
			continue
		for name, content in EXAMPLE_PATTERNS.items():
			dest = os.path.join(path, name)
			if not os.path.exists(dest):
				with open(dest, 'w', encoding='utf-8') as fh:
					fh.write(content)
				print(f"Wrote example pattern {dest}")



def install_service(args, systemd_available=None, unit_dir=None, systemctl=None, executable=None, raw=None):
	if systemd_available is None:
		systemd_available = systemd_is_available()
	if not systemd_available:
		_warn_no_systemd('--install-service')
		return 1
	try:
		resolved, raw = _prepare_unit_settings(args, raw=raw)
	except ConfigError as exc:
		print(str(exc), file=sys.stderr)
		return 2
	if not resolved.pattern_file:
		resolved.pattern_file = [DEFAULT_PATTERNS_DIR]
	if unit_dir is None:
		unit_dir = SYSTEMD_UNIT_DIR
	os.makedirs(resolved.output_folder, exist_ok=True)
	_seed_example_patterns(resolved.pattern_file)
	config_existed = os.path.isfile(resolved.config_path)
	if not config_existed:
		try:
			write_config_file(resolved.config_path, resolved)
		except OSError as exc:
			print('cannot write config %s: %s' % (resolved.config_path, exc), file=sys.stderr)
			return 1
	os.makedirs(unit_dir, exist_ok=True)
	unit_path = os.path.join(unit_dir, unit_filename(resolved.unit_name))
	text = render_unit_file(resolved, executable=executable, config_exists=config_existed, raw=raw)
	with open(unit_path, 'w', encoding='utf-8') as fh:
		fh.write(text)
	print(f"Wrote {unit_path}")
	reload = _run_systemctl(systemctl, 'daemon-reload')
	if getattr(reload, 'returncode', 0):
		print(f"systemctl daemon-reload failed (exit {reload.returncode})", file=sys.stderr)
		return reload.returncode
	if getattr(resolved, 'no_enable', False):
		return 0
	enable = _run_systemctl(systemctl, 'enable', '--now', unit_filename(resolved.unit_name))
	if getattr(enable, 'returncode', 0):
		print(f"systemctl enable --now failed (exit {enable.returncode})", file=sys.stderr)
		return enable.returncode
	print(f"Enabled and started {unit_filename(resolved.unit_name)}")
	return 0


def uninstall_service(args, systemd_available=None, unit_dir=None, systemctl=None):
	if systemd_available is None:
		systemd_available = systemd_is_available()
	if not systemd_available:
		_warn_no_systemd('--uninstall-service')
		return 1
	if unit_dir is None:
		unit_dir = SYSTEMD_UNIT_DIR
	name = unit_filename(args.unit_name)
	unit_path = os.path.join(unit_dir, name)
	disable = _run_systemctl(systemctl, 'disable', '--now', name)
	if getattr(disable, 'returncode', 0) not in (0, None) and os.path.exists(unit_path):
		print(f"systemctl disable --now {name} exited {disable.returncode}", file=sys.stderr)
	if os.path.exists(unit_path):
		os.remove(unit_path)
		print(f"Removed {unit_path}")
	reload = _run_systemctl(systemctl, 'daemon-reload')
	if getattr(reload, 'returncode', 0):
		print(f"systemctl daemon-reload failed (exit {reload.returncode})", file=sys.stderr)
		return reload.returncode
	print(f"Uninstalled {name} (pattern files and capture logs were left in place)")
	return 0


def build_parser():
	parser = argparse.ArgumentParser(description='Monitor system logs for specific patterns and persist surrounding context.')
	parser.add_argument('pattern_file', type=str, nargs='*', help='Pattern files or directories. Files ending with .regex load regex patterns. '
					 'Other files load fnmatch (bash like) patterns with * wildcards added at both ends. '
					 'A directory (such as /etc/firewatcher/patterns.d) loads every non-hidden pattern file inside it. '
					 'Optional for --install-service / --print-unit (defaults to /etc/firewatcher/patterns.d) and --uninstall-service.')
	parser.add_argument('--log-file', type=str, help='Path to the log file to monitor. Default: journalctl -> /var/log/syslog -> /var/log/messages.')
	parser.add_argument('--workers', type=int, default=1, help='(Not Implemented) Number of processes for processing logs. '
					 ' Will divide patterns equally across workers. Use 0 to spawn a process for every pattern in the source file. '
					 ' Warning: may produce duplicated log files if a line matches multiple patterns. Default: 1 worker.')
	parser.add_argument('-t','--capture-time', type=int, default=None, help='Time in seconds to capture logs after a match. Default: 300 seconds.')
	parser.add_argument('-o','--output-folder', type=str, default=None, help='Output folder for matched logs. Default: /var/log/captured_messages/')
	parser.add_argument('--tail_lines', type=str, default=None, help='Number of lines to tail from the log file. Default: 20 lines. ( Note: Use +N to tail from the Nth line.) ( Note: +N does not work with journalctl.)')

	filt = parser.add_mutually_exclusive_group()
	filt.add_argument('--filter_only', dest='filter_only', action='store_true', help='Only filter logs and do not wait for new lines. Uses cat instead of tail -F, or journalctl without --follow.')
	filt.add_argument('--no-filter_only', dest='filter_only', action='store_false', help='Follow new log lines. Overrides filter_only from the config file.')
	parser.add_argument('--compress-after-months', type=int, default=None, help='Compress logs after this many months. Default: 3 months.')
	parser.add_argument('--capture_line_count_max', type=int, default=None, help='Maximum number of lines to capture before and after in a single log file. Default: 10000 lines. Note: The final file maybe 2 * this number.')
	parser.add_argument('--delete-after-months', type=int, default=None, help='Delete logs after this many months. (will only delete files in YYYY-MM format) Default: 0 (never).')
	svc = parser.add_mutually_exclusive_group()
	svc.add_argument('--install-service', action='store_true', help='Install and enable a systemd unit for this command line. Warns and exits if systemd is not available.')
	svc.add_argument('--print-unit', action='store_true', help='Print the systemd unit that --install-service would write, then exit. Works without systemd.')
	svc.add_argument('--uninstall-service', action='store_true', help='Disable and remove the systemd unit. Warns and exits if systemd is not available.')
	parser.add_argument('--unit-name', type=str, default=DEFAULT_UNIT_NAME, help='systemd unit name (default: firewatcher).')
	parser.add_argument('--requires-mounts-for', action='append', default=[], metavar='PATH', help='Add RequiresMountsFor= to the unit (repeatable). Use when -o is on NFS or another remote filesystem.')
	parser.add_argument('--no-enable', action='store_true', help='With --install-service, write the unit and daemon-reload but do not enable or start it.')

	parser.add_argument('--config', default=None, help='INI config file. Default: /etc/firewatcher/firewatcher.conf when that file exists. An explicit path must exist. CLI flags override the file.')
	llm = parser.add_mutually_exclusive_group()
	llm.add_argument('--llm', dest='llm', action='store_true', help='Analyze each finished capture with an OpenAI-compatible LLM.')
	llm.add_argument('--no-llm', dest='llm', action='store_false', help='Disable LLM analysis, overriding the config file.')
	parser.add_argument('--llm-base-url', default=None, help='OpenAI-compatible API root, for example https://api.openai.com/v1 or http://127.0.0.1:11434/v1.')
	parser.add_argument('--llm-model', default=None, help='Model name sent to the LLM API.')
	parser.add_argument('--llm-timeout', type=int, default=None, help='LLM HTTP timeout in seconds. Default: 60.')
	parser.add_argument('--llm-max-bytes', type=int, default=None, help='Maximum capture bytes sent to the LLM. Default: 48000.')
	notify = parser.add_mutually_exclusive_group()
	notify.add_argument('--notify', dest='notify', action='store_true', help='Push a notification for finished captures. With --llm, only when the model asks for one.')
	notify.add_argument('--no-notify', dest='notify', action='store_false', help='Disable notifications, overriding the config file.')
	parser.add_argument('--ntfy-url', default=None, help='ntfy topic URL, for example https://ntfy.sh/mytopic.')
	parser.add_argument('--ntfy-priority', type=int, default=None, help='ntfy priority 1-5. Default: 4.')
	parser.add_argument('--ntfy-timeout', type=int, default=None, help='ntfy HTTP timeout in seconds for the worker. Default: 10. Queue overflow uses 5 seconds.')
	parser.add_argument('-V','--version', action='version', version=f'%(prog)s {version}')
	parser.set_defaults(filter_only=None, llm=None, notify=None)
	return parser


def log_source_command(args):
	"""Return the argv used to read logs, or None if nothing is available."""
	if not getattr(args, '_resolved', False):
		args = resolve_settings(args)
	if args.filter_only:
		file_pre = ['cat']
	else:
		file_pre = ['tail', '-n', str(args.tail_lines), '-F']
	if args.log_file:
		return file_pre + [args.log_file]
	if shutil.which('journalctl'):
		cmd = ['journalctl', '--all', '--no-pager', '--lines=%s' % args.tail_lines]
		if not args.filter_only:
			cmd.append('--follow')
		return cmd
	if os.path.exists('/var/log/syslog'):
		return file_pre + ['/var/log/syslog']
	if os.path.exists('/var/log/messages'):
		return file_pre + ['/var/log/messages']
	return None

def main(argv=None):
	parser = build_parser()
	args = parser.parse_args(argv)
	if args.uninstall_service:
		return uninstall_service(args)
	try:
		resolved = resolve_settings(args)
	except ConfigError as exc:
		parser.error(str(exc))
	if not resolved.pattern_file:
		if args.install_service or args.print_unit:
			resolved.pattern_file = [DEFAULT_PATTERNS_DIR]
		else:
			parser.error('pattern file or directory required (for example /etc/firewatcher/patterns.d)')
	if args.print_unit:
		print(render_unit_file(resolved, raw=args), end='')
		return 0
	if args.install_service:
		return install_service(resolved, raw=args)
	print(f"Starting firewatcher v{version}")
	command_to_run = log_source_command(resolved)
	if not command_to_run:
		print("No log file specified and no journalctl / syslog / messages found. Use --log-file. Exiting.")
		return 1
	pattern_files = expand_pattern_sources(resolved.pattern_file)
	if not pattern_files:
		print(f"No pattern files found in {resolved.pattern_file}. Exiting.", file=sys.stderr)
		return 1
	patterns = load_patterns(pattern_files)
	print(f"Monitoring {command_to_run} for patterns: {patterns}")
	print(f"Capturing logs for {resolved.capture_time} seconds.")
	print(f"Output folder: {resolved.output_folder}")
	print(f"Compress logs after {resolved.compress_after_months} months.")
	print(f"Delete logs after {resolved.delete_after_months} months.")
	if resolved.llm_enabled:
		print(f"LLM analysis enabled ({resolved.llm_base_url}, model {resolved.llm_model}).")
	if resolved.notify_enabled:
		print(f"Notifications enabled ({resolved.ntfy_url}).")
	capture_messages(
		command_to_run, patterns,
		capture_time=resolved.capture_time,
		output_folder=resolved.output_folder,
		compress_after_months=resolved.compress_after_months,
		delete_after_months=resolved.delete_after_months,
		capture_line_count_max=resolved.capture_line_count_max,
		notify_settings=resolved,
	)
	return 0


if __name__ == '__main__':
	sys.exit(main() or 0)
