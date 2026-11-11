"""Finite independently supervised Bash/PTY sessions; no host fallback from isolation."""
import hashlib
from itertools import chain
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import time
import uuid

from commander_policy import allowed, atomic_json
from execution import MAX_FILE_BYTES, sandbox
from security import Denied, nonroot, private_directory, redact

ACTIVE = ('queued', 'running')
LOG_LIMIT = 128 * 1024


def identity(pid):
    try:
        p = Path('/proc') / str(pid)
        fields = (p / 'stat').read_text().rsplit(')', 1)[1].split()
        return fields[19] if p.stat().st_uid == os.getuid() and fields[0] != 'Z' else None
    except (OSError, IndexError):
        return None


def clean_environment(home):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(home),
            'TERM': 'dumb', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_TERMINAL_PROMPT': '0', 'BASH_ENV': '/dev/null', 'ENV': '/dev/null'}


def process_tree(pid, limit=128):
    """Only descendants of this tracked supervisor; no command lines/environments."""
    pending, entries, seen = [pid], [], set()
    while pending and len(seen) < limit:
        parent = pending.pop()
        if parent in seen or identity(parent) is None:
            continue
        seen.add(parent)
        try:
            children = Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
            for text in children[:limit-len(seen)]:
                child = int(text)
                start = identity(child)
                if start:
                    entries.append({'pid': child, 'parent_pid': parent, 'start': start})
                    pending.append(child)
        except (OSError, ValueError):
            pass
    return entries


class Processes:
    def __init__(self, policy):
        self.policy = policy
        self.directory = private_directory(policy.state / 'sessions')
        self.children = []

    def location(self, session_id):
        if not isinstance(session_id, str) or not re.fullmatch('[a-f0-9]{32}', session_id):
            raise Denied('Invalid session ID; arbitrary PIDs are not accepted.')
        p = self.directory / session_id
        if p.is_symlink() or not p.is_dir():
            raise Denied('Unknown tracked session.')
        return p

    def status(self, session_id):
        nonroot()
        path = self.location(session_id)
        with self.policy.paths.lock:
            state = json.loads((path / 'status.json').read_text())
            if state['state'] in ACTIVE:
                worker = state.get('worker_pid')
                lost = bool(worker and identity(worker) != state.get('worker_start'))
                lost |= not worker and time.time()-state['created_at'] > 10
                if lost:
                    state.update(state='orphaned', error='Supervisor lost; outcome unknown. No command replay and no arbitrary PID killing.')
                    atomic_json(path / 'status.json', state)
            worker = state.get('worker_pid')
            return {**state, 'process_tree': process_tree(worker) if worker and identity(worker) == state.get('worker_start') else []}

    def list(self):
        self.children = [p for p in self.children if p.poll() is None]
        return {'sessions': [self.status(p.name) for p in sorted(self.directory.iterdir())
                             if p.is_dir() and re.fullmatch('[a-f0-9]{32}', p.name)]}

    def snapshot(self, cwd, target):
        adapter, rel = self.policy.adapter(cwd, directory=True, isolated=True)
        root = adapter.roots['path']
        target.mkdir(mode=0o700)
        pending = [()]
        count = total = 0
        deadline = time.monotonic() + 10
        from security import relative
        while pending:
            parts = pending.pop()
            fd = adapter.directory_fd('path', parts)
            try:
                with os.scandir(fd) as entries:
                    for e in entries:
                        count += 1
                        if count > 10000 or time.monotonic() > deadline:
                            raise Denied('Snapshot entry/time limit; use a smaller cwd/project.')
                        if not allowed(e.name) or e.is_symlink():
                            continue
                        current = (*parts, e.name)
                        if len(current) > 12:
                            continue
                        destination = target.joinpath(*current)
                        if e.is_dir(follow_symlinks=False):
                            destination.mkdir(mode=0o700)
                            pending.append(current)
                        elif e.is_file(follow_symlinks=False):
                            s = e.stat(follow_symlinks=False)
                            if s.st_nlink != 1 or s.st_size > 1024*1024:
                                continue
                            try:
                                text, _, before = adapter.read('path', '/'.join(current))
                            except Denied:
                                continue
                            # Source snapshots cannot import credential-like contents.
                            if redact(text) != text:
                                continue
                            data = text.encode()
                            total += len(data)
                            if total > 32*1024*1024:
                                raise Denied('Snapshot byte limit (32 MiB).')
                            destination.write_bytes(data)
                            destination.chmod(0o700 if before.st_mode & 0o111 else 0o600)
            finally:
                os.close(fd)
        working = target if rel == '.' else target / rel
        if not working.is_dir():
            raise Denied('Working directory excluded from safe snapshot.')
        return '/work' if rel == '.' else '/work/' + rel

    def start(self, command, cwd, pty=False, timeout_seconds=None, mode='auto', approval_hint=''):
        nonroot()
        if not isinstance(command, str) or not 1 <= len(command.encode()) <= 16384 or '\x00' in command:
            raise Denied('Bash command must be 1..16384 UTF-8 bytes without NUL.')
        if redact(command) != command:
            raise Denied('Do not place credentials in commands.')
        config = self.policy.config()
        if mode == 'auto':
            mode = 'trusted' if self.policy.host_authorized(config) else 'isolated'
        if mode in ('desktop_compatible', 'trusted_local_dev'):
            mode = 'trusted'
        timeout = config['default_timeout'] if timeout_seconds is None else timeout_seconds
        if type(timeout) is not int or not 1 <= timeout <= 3600 or type(pty) is not bool:
            raise Denied('Timeout must be 1..3600 seconds; pty must be boolean.')
        if mode not in ('isolated', 'trusted'):
            raise Denied('Use isolated snapshot or locally approved trusted terminal.')
        if mode == 'trusted':
            self.policy.trusted(cwd)
        else:
            self.policy.resolve(cwd, directory=True, isolated=True)
        # Obvious sensitive requests are also confirmed in isolated mode. Isolation,
        # rather than this incomplete detector, enforces host file/network boundaries.
        if mode == 'isolated' and re.search(r'(?i)(\b(?:sudo|pkexec|su|rm|rmdir|kill|killall|pkill|curl|wget|ssh|scp|sftp|apt|apt-get|pip|npm\s+publish)\b|\bgit\s+(?:reset|clean|stash|rebase|merge|push)\b|\b(?:assemble|install|publish)[a-z]*\b)', command):
            self.policy.approval.require('sensitive_isolated_command', {
                'command': command, 'boundary': 'offline disposable snapshot, never live source'})
        self.policy.audit('terminal_authorized', mode=mode,
                          command_sha256=hashlib.sha256(command.encode()).hexdigest())
        with self.policy.paths.lock:
            states = self.list()['sessions']
            if sum(s['state'] in ACTIVE for s in states) >= config['session_limit']:
                raise Denied('Concurrent session limit reached.')
            ended = sorted((s for s in states if s['state'] not in ACTIVE), key=lambda s: s['created_at'])
            while ended and (len(states) >= 30 or time.time()-ended[0]['created_at'] > 86400):
                old = ended.pop(0)
                shutil.rmtree(self.location(old['session_id']))
                states.remove(old)
            ident = uuid.uuid4().hex
            path = private_directory(self.directory / ident)
            try:
                if mode == 'isolated':
                    work = path / 'snapshot'
                    working = self.snapshot(cwd, work)
                    argv = sandbox([(work, '/work', True)], working,
                                   ['/usr/bin/bash', '--noprofile', '--norc', '-c', command], timeout=timeout)
                    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
                else:
                    home = private_directory(path / 'home')
                    environment = clean_environment(home)
                    # Never try to raise an inherited hard CPU limit. Container and
                    # nested shells can set a lower cap, and prlimit would refuse
                    # the entire command instead of enforcing a stricter one.
                    inherited_hard = resource.getrlimit(resource.RLIMIT_CPU)[1]
                    cpu_limit = timeout if inherited_hard == resource.RLIM_INFINITY else min(timeout, inherited_hard)
                    argv = ['/usr/bin/setpriv', '--no-new-privs', '/usr/bin/prlimit', '--core=0', '--nofile=128', f'--fsize={MAX_FILE_BYTES}',
                            '--as=6442450944', '--cpu='+str(cpu_limit), '--',
                            '/usr/bin/bash', '--noprofile', '--norc', '-c', command]
                state = {'session_id': ident, 'state': 'queued', 'created_at': time.time(),
                         'cwd': cwd, 'mode': mode, 'pty': pty, 'timeout_seconds': timeout,
                         'pid': None, 'exit_code': None, 'output_base': 0, 'output_end': 0,
                         'truncated': False, 'streams': 'pty' if pty else 'stdout_stderr'}
                atomic_json(path / 'status.json', state)
                atomic_json(path / 'plan.json', {'argv': argv, 'cwd': cwd, 'environment': environment,
                    'timeout': timeout, 'idle_timeout': config['idle_timeout'], 'pty': pty})
                os.mkfifo(path / 'input', 0o600)
                (path / 'output.json').write_text('{"base":0,"end":0,"records":[]}', encoding='utf-8')
                (path / 'output.json').chmod(0o600)
                child = subprocess.Popen([sys.executable, str(Path(__file__).with_name('commander_worker.py')), str(path)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True, start_new_session=True)
                self.children.append(child)
            except BaseException:
                shutil.rmtree(path)
                raise
        return state

    def output(self, session_id, offset=0, limit=8192):
        if type(offset) is not int or offset < 0 or not 1 <= limit <= 16384:
            raise Denied('Output offset >=0; limit 1..16384 bytes.')
        path = self.location(session_id)
        data = json.loads((path / 'output.json').read_text())
        cursor = min(max(offset, data['base']), data['end'])
        records = []
        budget = limit
        for record in data['records']:
            end = record['offset'] + len(record['text'].encode())
            if end <= cursor:
                continue
            begin = max(0, cursor-record['offset'])
            raw = record['text'].encode()[begin:begin+budget]
            # Byte offsets are authoritative; UTF-8 chunks may split a codepoint.
            if raw:
                records.append({'offset': cursor, 'stream': record['stream'], 'text': raw.decode('utf-8', 'replace')})
                cursor += len(raw)
                budget -= len(raw)
            if budget == 0:
                break
        return {'session_id': session_id, 'records': records, 'next_offset': cursor,
                'retained_from': data['base'], 'output_end': data['end'],
                'truncated': offset < data['base'] or cursor < data['end'],
                'dropped_prefix': offset < data['base'], 'has_more': cursor < data['end'],
                'offset_unit': 'UTF-8 bytes'}

    def interact(self, session_id, input='', read_budget=8192):
        if not isinstance(input, str) or len(input.encode()) > 4096 or '\x00' in input or redact(input) != input:
            raise Denied('Input must be nonsensitive UTF-8, at most 4096 bytes.')
        if not 1 <= read_budget <= 16384:
            raise Denied('Read budget must be 1..16384.')
        state = self.status(session_id)
        if state['state'] != 'running':
            raise Denied('Session is not running; poll status before input.')
        path = self.location(session_id)
        if input:
            try:
                fd = os.open(path / 'input', os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
                try:
                    data = input.encode()
                    written = os.write(fd, data)
                    if written != len(data):
                        raise Denied('Input was partially accepted; do not retry blindly.')
                finally:
                    os.close(fd)
            except BlockingIOError:
                raise Denied('Input buffer full; input not accepted.') from None
            except OSError:
                raise Denied('Input unavailable; session may have ended.') from None
        return {'accepted_bytes': len(input.encode()), **self.output(session_id, max(0, state['output_end']-read_budget), read_budget)}

    def terminate(self, session_id):
        state = self.status(session_id)
        if state['state'] in ACTIVE:
            path = self.location(session_id) / 'cancel'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            self.policy.audit('terminate_owned_session', session_id=session_id)
        return {'session_id': session_id, 'cancellation_requested': state['state'] in ACTIVE, 'state': state['state']}

    def execute(self, command, cwd, timeout_seconds=None, max_output_bytes=16384, mode='auto', approval_hint=''):
        if timeout_seconds is None:
            timeout_seconds = min(30, self.policy.config()['default_timeout'])
        if not 1 <= timeout_seconds <= 30 or not 1 <= max_output_bytes <= 16384:
            raise Denied('Foreground timeout 1..30 seconds, output 1..16384 bytes; use start_process for longer jobs.')
        result = self.start(command, cwd, False, timeout_seconds, mode, approval_hint)
        ident = result['session_id']
        deadline = time.monotonic() + min(timeout_seconds+1, 31)
        while time.monotonic() < deadline:
            result = self.status(ident)
            if result['state'] not in ACTIVE:
                break
            time.sleep(.04)
        return {**result, 'output': self.output(ident, 0, max_output_bytes),
                'detached': result['state'] in ACTIVE}

    def processes(self, filter='', limit=100):
        if not isinstance(filter, str) or len(filter) > 80 or not 1 <= limit <= 200:
            raise Denied('Process filter <=80 characters and limit 1..200.')
        owned = {s.get('pid'): s['session_id'] for s in self.list()['sessions']
                 if s['state'] in ACTIVE and type(s.get('pid')) is int}
        entries = []
        # The process limit applies to the entire user, whose /proc ordering is
        # arbitrary. Put tracked sessions first so unrelated processes cannot
        # hide the very processes this API is responsible for reporting.
        proc = Path('/proc')
        tracked = [proc / str(pid) for pid in owned]
        others = (p for p in proc.iterdir() if p.name.isdigit() and int(p.name) not in owned)
        for p in chain(tracked, others):
            try:
                if p.stat().st_uid != os.getuid():
                    continue
                name = (p / 'comm').read_text().strip()
                if filter.casefold() not in name.casefold():
                    continue
                fields = (p / 'stat').read_text().rsplit(')', 1)[1].split()
                entries.append({'pid': int(p.name), 'name': redact(name), 'state': fields[0],
                                'parent_pid': int(fields[1]), 'session_id': owned.get(int(p.name))})
                if len(entries) >= limit:
                    break
            except (OSError, ValueError, IndexError):
                continue
        return {'processes': entries, 'truncated': len(entries) == limit,
                'policy': 'Only session IDs can be terminated. Untracked/user/system PIDs are never accepted.'}
