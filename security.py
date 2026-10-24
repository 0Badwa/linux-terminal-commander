"""Local policy, path confinement, output filtering, and human approvals."""
import hashlib
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import threading


class Denied(ValueError):
    pass


MAX_FILE = 1024 * 1024
MAX_OUTPUT = 65536
FORBIDDEN = {'.git', '.ssh', '.aws', '.azure', '.gnupg', '.codex', '.agents',
             '.env', '.npmrc', '.pypirc', '.netrc', 'local.properties',
             'gradle.properties', 'credentials', 'secrets', 'saves', 'savegames'}
SHELL = re.compile(r'[\x00-\x1f\x7f;&|`<>$\\]')
TOKEN = re.compile(r'(?i)\b(?:sk-[a-z0-9_-]{12,}|(?:gh[pousr]_|github_pat_)[a-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b')
ASSIGNMENT = re.compile(r'(?i)(?:api[_-]?key|password|passwd|secret|access[_-]?token|refresh[_-]?token|authorization|private[_-]?key)\s*["\']?\s*[:=]\s*\S+')
URL_AUTH = re.compile(r'https?://[^\s/@]+:[^\s/@]+@', re.I)
TOKEN_FILE = re.compile(r'(?:^|[._-])(?:(?:access|refresh|auth)[._-]?)?tokens?(?:$|[._-])', re.I)


def nonroot():
    if os.geteuid() == 0:
        raise Denied('Root execution is forbidden.')


def argument(value, maximum=160):
    if not isinstance(value, str) or not value or len(value) > maximum or SHELL.search(value):
        raise Denied('Invalid structured argument; shell syntax is forbidden.')
    return value


def redact(text):
    """Never emit private-key bodies, recognizable tokens, or secret assignments."""
    result, private = [], False
    for line in text.splitlines(keepends=True):
        if '-----BEGIN ' in line and 'PRIVATE KEY-----' in line:
            private = True
        if private or TOKEN.search(line) or ASSIGNMENT.search(line) or URL_AUTH.search(line) or re.search(r'(?i)\bBearer\s+\S+', line):
            result.append('[REDACTED]\n')
        else:
            # Terminal control codes must not affect a downstream UI.
            result.append(''.join(c for c in line if c in '\t\n' or ord(c) >= 32 and ord(c) != 127))
        if '-----END ' in line and 'PRIVATE KEY-----' in line:
            private = False
    return ''.join(result)


def component_allowed(part):
    low = part.lower()
    return not (low in FORBIDDEN or low.startswith('.env.') or TOKEN_FILE.search(low) or
                low.endswith(('.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.kdbx', '.sav', '.save')) or
                any(word in low for word in ('credential', 'api_key', 'apikey', 'private_key', 'secret', 'password')) or
                low in ('id_rsa', 'id_ed25519', 'authorized_keys', 'known_hosts'))


def relative(value, allow_dot=False):
    if value == '.' and allow_dot:
        return ()
    argument(value, 512)
    p = PurePosixPath(value)
    parts = value.split('/')
    if p.is_absolute() or any(x in ('', '.', '..') or not component_allowed(x) for x in parts):
        raise Denied('Path is outside policy or contains a protected component.')
    return tuple(parts)


def private_directory(path):
    path = Path(path)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    s = path.lstat()
    if path.absolute()!=path.resolve() or not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise Denied('Private workspace must be an owned real directory with mode 0700.')
    return path


class Paths:
    def __init__(self, project, workspace, root_config=None, development_locations=None, codex_worktrees=None):
        nonroot()
        project=Path(project)
        if project.is_symlink() or project.absolute()!=project.resolve(strict=True):
            raise Denied('Approved project root must be a canonical real directory.')
        self.project = project.resolve(strict=True)
        self.workspace = private_directory(workspace)
        self.files = private_directory(self.workspace / 'files')
        self.worktrees = private_directory(self.workspace / 'worktrees')
        self.jobs = private_directory(self.workspace / 'jobs')
        self.cache = private_directory(self.workspace / 'gradle-cache')
        self.roots = {'project': self.project, 'scratch': self.files}
        self.enrolled = {}
        if root_config is not None:
            from roots import load
            self.enrolled = load(root_config, self.project, self.workspace.parent,
                                 development_locations, codex_worktrees)
            self.roots.update({name: entry['path'] for name, entry in self.enrolled.items()})
        self.identities={name:(p.stat().st_dev,p.stat().st_ino) for name,p in self.roots.items()}
        self.lock = ProcessLock(self.workspace/'operations.lock')

    def root(self, name):
        nonroot()
        if name not in self.roots:
            raise Denied('Unknown approved root.')
        p = self.roots[name]
        try:
            if p.is_symlink() or p.resolve(strict=True) != p:
                raise Denied('Approved root identity changed.')
            identity=(p.stat().st_dev,p.stat().st_ino)
        except OSError:
            raise Denied('Approved root is missing or unavailable.') from None
        if name in self.identities and self.identities[name]!=identity:
            raise Denied('Approved root was replaced.')
        self.identities[name]=identity
        if name in self.enrolled:
            from roots import git_layout
            git_layout(p, self.enrolled[name]['common'])
        return p

    def git_layout(self, name):
        from roots import git_layout
        path = self.root(name)
        if name == 'scratch':
            raise Denied('Scratch is not a Git repository.')
        common = self.enrolled[name]['common'] if name in self.enrolled else self.project / '.git'
        return git_layout(path, common)

    def git_writable(self, name):
        self.root(name)
        if name in self.enrolled or name == 'scratch':
            raise Denied('Enrolled existing checkouts are read-only; use managed codex worktrees for Git writes.')

    def directory_fd(self, root, parts=()):
        fd = os.open(self.root(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise Denied('Directory traversal or symlink access refused.') from None

    def parent(self, root, path):
        parts = relative(path)
        return self.directory_fd(root, parts[:-1]), parts[-1]

    def read(self, root, path):
        parent, name = self.parent(root, path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
                    raise Denied('Only bounded, non-hardlinked regular text files are accessible.')
                data = bytearray()
                while len(data) <= MAX_FILE:
                    chunk = os.read(fd, min(65536, MAX_FILE + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                after = os.fstat(fd)
                if len(data) > MAX_FILE or (before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (after.st_mtime_ns, after.st_ctime_ns, after.st_size):
                    raise Denied('File changed while reading; retry.')
                try:
                    text = bytes(data).decode('utf-8')
                except UnicodeDecodeError:
                    raise Denied('Only UTF-8 text files are accessible.') from None
                if '\x00' in text:
                    raise Denied('Binary content is forbidden.')
                version = hashlib.sha256(bytes(data) + str((after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)).encode()).hexdigest()
                return text, version, after
            finally:
                os.close(fd)
        except OSError:
            raise Denied('File access refused or file unavailable.') from None
        finally:
            os.close(parent)


class Approval:
    """Only a local human dialog can grant an action; there is no MCP approval token."""
    def __init__(self):
        self.lock = threading.Lock()

    def require(self, action, details):
        nonroot()
        summary = json.dumps({'operation': action, **details}, ensure_ascii=False, sort_keys=True)
        summary = redact(summary)[:5000]
        digest = hashlib.sha256(summary.encode()).hexdigest()[:16]
        from desktop_session import environment
        desktop = environment()
        if not (desktop.get('DISPLAY') or desktop.get('WAYLAND_DISPLAY')):
            raise Denied('Local approval unavailable; read tools remain available.')
        if not self.lock.acquire(blocking=False):
            raise Denied('Another local approval is pending; retry later.')
        try:
            try:
                result = subprocess.run(['/usr/bin/zenity', '--question', '--no-markup',
                    '--title=Romans! MCP — local approval', '--ok-label=Approve once',
                    '--cancel-label=Deny', '--timeout=55',
                    '--text=' + summary + '\n\nAction fingerprint: ' + digest],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=60, env=desktop)
            except (OSError, subprocess.TimeoutExpired):
                raise Denied('Local approval unavailable or timed out.') from None
            if result.returncode != 0:
                raise Denied('Operation was not approved by the local user.')
        finally:
            self.lock.release()


class ProcessLock:
    """Coordinate multiple server processes and independent Git job workers."""
    def __init__(self,path):
        self.path=path
        self.thread=threading.RLock()
        self.depth=0
        self.fd=None

    def __enter__(self):
        self.thread.acquire()
        if self.depth==0:
            self.fd=os.open(self.path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            try:
                fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(self.fd)
                self.fd=None
                self.thread.release()
                raise Denied('Another repository operation is active; retry later.') from None
        self.depth+=1
        return self

    def __exit__(self,*args):
        self.depth-=1
        if self.depth==0:
            fcntl.flock(self.fd,fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd=None
        self.thread.release()
