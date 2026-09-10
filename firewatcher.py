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
import time
import datetime
import os
import unicodedata

version = '1.57'
__version__ = version

DEFAULT_OUTPUT_FOLDER = '/var/log/captured_messages/'
DEFAULT_PATTERNS_DIR = '/etc/firewatcher/patterns.d'
DEFAULT_UNIT_NAME = 'firewatcher'
SYSTEMD_RUNTIME_DIR = '/run/systemd/system'
SYSTEMD_UNIT_DIR = '/etc/systemd/system'
SLUG_MAX_LEN = 80
_OWN_SYSLOG_IDENT_RE = re.compile(r'(?:^|\s)firewatcher\[\d+\]:')

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

def _end_capture(log_file_name, captured_line_counter, capture_line_count_max):
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

def capture_messages(command_to_run, patterns, capture_time=300, output_folder=DEFAULT_OUTPUT_FOLDER, compress_after_months=3, delete_after_months=0,capture_line_count_max=10000):
	"""Tail the log file and process lines with buffer management."""
	log_buffer = deque()  # Stores tuples of (read_time, line)
	log_compressor = Log_Compressor(output_folder, compress_after_months, delete_after_months)
	capture_until = None
	log_file_name = None
	captured_line_counter = 0
	processed_line_counter = 0
	with subprocess.Popen(
		command_to_run,
		stdout=subprocess.PIPE,
		universal_newlines=True,
		encoding='utf-8',
		errors='replace',
	) as proc:
		while True:
			try:
				line = proc.stdout.readline()
			except KeyboardInterrupt:
				print("Exiting.")
				try:
					proc.terminate()
				except Exception:
					pass
				break
			except Exception as e:
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
					_end_capture(log_file_name, captured_line_counter, capture_line_count_max)
					capture_until = None
					captured_line_counter = 0
					log_file_name = None
			# if the current line doesn't match the pattern, and capture_until is set and expired, reset capture_until and close the current log file
			elif log_file_name and ((capture_until and read_time > capture_until) or captured_line_counter > capture_line_count_max):
				_end_capture(log_file_name, captured_line_counter, capture_line_count_max)
				capture_until = None
				captured_line_counter = 0
				log_file_name = None
			# if the current line doesn't match the pattern, continue to write the logs to the current log file if capture_until is set and not expired
			elif capture_until and read_time <= capture_until:
				with open(log_file_name, "a") as log_file:
					log_file.write(line)
				captured_line_counter += 1
				if captured_line_counter > capture_line_count_max:
					_end_capture(log_file_name, captured_line_counter, capture_line_count_max)
					capture_until = None
					captured_line_counter = 0
					log_file_name = None
			# if the current line doesn't match the pattern, and capture_until is not set, check for log compression
			else:
				log_compressor.compressLogs()
			if processed_line_counter % 10000 == 0:
				print(f"Processed {processed_line_counter} lines.",flush=True)
	if log_file_name:
		_end_capture(log_file_name, captured_line_counter, capture_line_count_max)
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


def _exec_start_args(args):
	parts = []
	if args.log_file:
		parts.extend(['--log-file', args.log_file])
	if args.capture_time != 300:
		parts.extend(['-t', str(args.capture_time)])
	if args.output_folder != DEFAULT_OUTPUT_FOLDER:
		parts.extend(['-o', args.output_folder])
	if args.tail_lines != '20':
		parts.extend(['--tail_lines', args.tail_lines])
	if args.filter_only:
		parts.append('--filter_only')
	if args.compress_after_months != 3:
		parts.extend(['--compress-after-months', str(args.compress_after_months)])
	if args.capture_line_count_max != 10000:
		parts.extend(['--capture_line_count_max', str(args.capture_line_count_max)])
	if args.delete_after_months != 0:
		parts.extend(['--delete-after-months', str(args.delete_after_months)])
	parts.extend(list(args.pattern_file))
	return parts


def render_unit_file(args, executable=None):
	"""Render a systemd unit. Does not require systemd to be present."""
	executable = executable or resolve_executable()
	exec_start = ' '.join([_quote_unit_arg(executable)] + [_quote_unit_arg(p) for p in _exec_start_args(args)])
	after = ['network-online.target']
	wants = ['network-online.target']
	if not args.log_file:
		after.insert(0, 'systemd-journald.socket')
	requires = []
	for mount in (getattr(args, 'requires_mounts_for', None) or []):
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
	lines.extend([
		'',
		'[Service]',
		'Type=simple',
		'User=root',
		'ExecStart=' + exec_start,
		'Restart=always',
		'RestartSec=5',
		'TimeoutStopSec=30',
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


def install_service(args, systemd_available=None, unit_dir=None, systemctl=None, executable=None):
	if systemd_available is None:
		systemd_available = systemd_is_available()
	if not systemd_available:
		_warn_no_systemd('--install-service')
		return 1
	if unit_dir is None:
		unit_dir = SYSTEMD_UNIT_DIR
	os.makedirs(args.output_folder, exist_ok=True)
	_seed_example_patterns(args.pattern_file)
	os.makedirs(unit_dir, exist_ok=True)
	unit_path = os.path.join(unit_dir, unit_filename(args.unit_name))
	text = render_unit_file(args, executable=executable)
	with open(unit_path, 'w', encoding='utf-8') as fh:
		fh.write(text)
	print(f"Wrote {unit_path}")
	reload = _run_systemctl(systemctl, 'daemon-reload')
	if getattr(reload, 'returncode', 0):
		print(f"systemctl daemon-reload failed (exit {reload.returncode})", file=sys.stderr)
		return reload.returncode
	if getattr(args, 'no_enable', False):
		return 0
	enable = _run_systemctl(systemctl, 'enable', '--now', unit_filename(args.unit_name))
	if getattr(enable, 'returncode', 0):
		print(f"systemctl enable --now failed (exit {enable.returncode})", file=sys.stderr)
		return enable.returncode
	print(f"Enabled and started {unit_filename(args.unit_name)}")
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
	parser.add_argument('-t','--capture-time', type=int, default=300, help='Time in seconds to capture logs after a match. Default: 300 seconds.')
	parser.add_argument('-o','--output-folder', type=str, default=DEFAULT_OUTPUT_FOLDER, help='Output folder for matched logs. Default: /var/log/captured_messages/')
	parser.add_argument('--tail_lines', type=str, default='20', help='Number of lines to tail from the log file. Default: 20 lines. ( Note: Use +N to tail from the Nth line.) ( Note: +N does not work with journalctl.)')
	parser.add_argument('--filter_only', action='store_true', help='Only filter logs and do not wait for new lines. Uses cat instead of tail -F, or journalctl without --follow. Default: False.')
	parser.add_argument('--compress-after-months', type=int, default=3, help='Compress logs after this many months. Default: 3 months.')
	parser.add_argument('--capture_line_count_max', type=int, default=10000, help='Maximum number of lines to capture before and after in a single log file. Default: 10000 lines. Note: The final file maybe 2 * this number.')
	parser.add_argument('--delete-after-months', type=int, default=0, help='Delete logs after this many months. (will only delete files in YYYY-MM format) Default: 0 (never).')
	svc = parser.add_mutually_exclusive_group()
	svc.add_argument('--install-service', action='store_true', help='Install and enable a systemd unit for this command line. Warns and exits if systemd is not available.')
	svc.add_argument('--print-unit', action='store_true', help='Print the systemd unit that --install-service would write, then exit. Works without systemd.')
	svc.add_argument('--uninstall-service', action='store_true', help='Disable and remove the systemd unit. Warns and exits if systemd is not available.')
	parser.add_argument('--unit-name', type=str, default=DEFAULT_UNIT_NAME, help='systemd unit name (default: firewatcher).')
	parser.add_argument('--requires-mounts-for', action='append', default=[], metavar='PATH', help='Add RequiresMountsFor= to the unit (repeatable). Use when -o is on NFS or another remote filesystem.')
	parser.add_argument('--no-enable', action='store_true', help='With --install-service, write the unit and daemon-reload but do not enable or start it.')
	parser.add_argument('-V','--version', action='version', version=f'%(prog)s {version}')
	return parser

def log_source_command(args):
	"""Return the argv used to read logs, or None if nothing is available."""
	if args.filter_only:
		file_pre = ['cat']
	else:
		file_pre = ['tail', '-n', args.tail_lines, '-F']
	if args.log_file:
		return file_pre + [args.log_file]
	if shutil.which('journalctl'):
		cmd = ['journalctl', '--all', '--no-pager', f'--lines={args.tail_lines}']
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
	if not args.pattern_file:
		if args.install_service or args.print_unit:
			args.pattern_file = [DEFAULT_PATTERNS_DIR]
		else:
			parser.error('pattern file or directory required (for example /etc/firewatcher/patterns.d)')
	if args.print_unit:
		print(render_unit_file(args), end='')
		return 0
	if args.install_service:
		return install_service(args)
	print(f"Starting firewatcher v{version}")
	command_to_run = log_source_command(args)
	if not command_to_run:
		print("No log file specified and no journalctl / syslog / messages found. Use --log-file. Exiting.")
		return 1
	pattern_files = expand_pattern_sources(args.pattern_file)
	if not pattern_files:
		print(f"No pattern files found in {args.pattern_file}. Exiting.", file=sys.stderr)
		return 1
	patterns = load_patterns(pattern_files)
	print(f"Monitoring {command_to_run} for patterns: {patterns}")
	print(f"Capturing logs for {args.capture_time} seconds.")
	print(f"Output folder: {args.output_folder}")
	print(f"Compress logs after {args.compress_after_months} months.")
	print(f"Delete logs after {args.delete_after_months} months.")
	capture_messages(command_to_run, patterns,capture_time=args.capture_time,output_folder=args.output_folder,compress_after_months=args.compress_after_months,delete_after_months=args.delete_after_months,capture_line_count_max=args.capture_line_count_max)
	return 0

if __name__ == '__main__':
	sys.exit(main() or 0)
