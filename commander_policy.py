"""Phase 5 policy. Shell isolation, not command text, is the restricted boundary."""
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

from security import Denied, Paths, component_allowed, private_directory, redact, nonroot

HOST_MODES = ("desktop_compatible", "trusted_local_dev", "trusted")
HOST_CONSENT_VERSION = 1

EXCLUDES = {'node_modules', '.venv', 'venv', '__pycache__', '.gradle', 'build',
            'dist', '.cache', '.config', '.local', '.git', '.hg', '.svn'}


def allowed(part):
    return component_allowed(part) and part not in EXCLUDES


def atomic_json(path, value):
    temporary = path.with_name('.new-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


class Policy:
    def __init__(self, paths, approval, locations=None):
        self.paths, self.approval = paths, approval
        self.state = private_directory(paths.workspace / 'commander')
        self.config_path = self.state / 'config.json'
        self.locations = tuple(Path(x) for x in (locations or (
            str(Path.home() / 'Projects'), str(Path.home() / 'projects'), str(Path.home() / '.codex/worktrees'))))

    def config(self):
        nonroot()
        with self.paths.lock:
            if not self.config_path.exists():
                return {'default_cwd': str(self.paths.files), 'session_limit': 2,
                        'default_timeout': 300, 'idle_timeout': 900,
                        'approval_mode': 'isolated', 'approved_project_scopes': []}
            fd = os.open(self.config_path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'r') as stream:
                s = os.fstat(stream.fileno())
                if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_size > 32768:
                    raise Denied('Unsafe Commander configuration metadata.')
                return json.load(stream)

    def audit(self, operation, **metadata):
        # Never store commands, input, contents, environment, or exception strings.
        path = self.state / 'audit.jsonl'
        with self.paths.lock:
            if path.exists() and path.stat().st_size > 1024 * 1024:
                os.replace(path, self.state / 'audit.previous.jsonl')
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(json.dumps({'time': time.time(), 'operation': operation, **metadata}) + '\n')
                stream.flush()
                os.fsync(stream.fileno())

    def set(self, key, value):
        before = self.config()
        if key in ('default_timeout', 'idle_timeout', 'session_limit'):
            low, high = {'default_timeout': (1, 3600), 'idle_timeout': (10, 3600), 'session_limit': (1, 4)}[key]
            if type(value) is not int or not low <= value <= high:
                raise Denied('Configuration value outside documented limits.')
        elif key == 'default_cwd':
            self.resolve(value, directory=True)
        elif key == 'approval_mode':
            if value not in ('isolated', *HOST_MODES):
                raise Denied('Use isolated or desktop_compatible (trusted_local_dev/trusted aliases).')
        elif key == 'approved_project_scopes':
            if not isinstance(value, list) or len(value) > 32:
                raise Denied('At most 32 explicit project scopes.')
            for entry in value:
                if not isinstance(entry, dict) or set(entry) != {'path', 'write', 'trusted_terminal'} or type(entry['write']) is not bool or type(entry['trusted_terminal']) is not bool:
                    raise Denied('Each scope needs path, write and trusted_terminal booleans.')
                root = self.canonical(entry['path'], directory=True)
                if not any(root.is_relative_to(location) and root != location for location in self.locations):
                    raise Denied('Scopes must be individual development projects, never home/system directories.')
                if any(not allowed(p) for p in root.relative_to(next(x for x in self.locations if root.is_relative_to(x))).parts):
                    raise Denied('Protected project scope.')
                if not (root / '.git').exists():
                    raise Denied('Explicit project scopes must be existing Git checkouts/worktrees.')
                if root == self.paths.project:
                    raise Denied('Configured primary project remains read-only.')
        elif key == 'advisory_guards':
            if not isinstance(value, list) or len(value) > 32 or any(
                not isinstance(e, dict) or len(e) != 1 or
                next(iter(e)) not in ('path_prefix', 'command_pattern') or
                not isinstance(next(iter(e.values())), str) or
                len(next(iter(e.values()))) > 512 for e in value):
                raise Denied('Use up to 32 path_prefix/command_pattern string objects; informational only.')
        else:
            raise Denied('Unsupported setting. Security blocks cannot be disabled.')
        activating = key == 'approval_mode' and value in HOST_MODES
        if before.get(key) == value and (not activating or self.host_authorized(before)):
            return before
        # All configuration changes receive local approval, including tightening.
        self.approval.require('commander_configuration', {
            'key': key, 'value': value,
            'warning': ('ONE-TIME REAL HOST ACTIVATION: connected trusted callers may read/modify anything accessible to the local Linux user, run Bash and network commands in any real cwd WITHOUT further command/project dialogs. File APIs retain protected-name/version checks. Directory lists and command patterns are advisory, NOT a shell sandbox. No root elevation. Approve only for trusted callers.' if activating else 'Durable preference change; host mode is user-level shell access.')})
        with self.paths.lock:
            if self.config() != before:
                raise Denied('Configuration changed during approval; retry.')
            self.audit('configuration_approved', key=key, value_sha256=hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest())
            updated = {**before, key: value}
            if activating:
                updated['host_consent_version'] = HOST_CONSENT_VERSION
            atomic_json(self.config_path, updated)
        return self.config()

    @staticmethod
    def canonical(value, directory=False):
        if not isinstance(value, str) or not value.startswith('/') or len(value) > 2048 or '\x00' in value:
            raise Denied('Use an absolute canonical path.')
        p = Path(value)
        if '..' in value.split('/') or str(p) != value.rstrip('/'):
            raise Denied('Traversal/noncanonical path refused.')
        try:
            existing = p if p.exists() else p.parent
            if existing.resolve(strict=True) != existing or p.is_symlink():
                raise Denied('Symlink paths refused.')
            if directory and not p.is_dir():
                raise Denied('Working directory does not exist.')
        except OSError:
            raise Denied('Path is unavailable.') from None
        return p

    def host_authorized(self, config=None):
        config = self.config() if config is None else config
        return (config.get('approval_mode') in HOST_MODES and
                config.get('host_consent_version') == HOST_CONSENT_VERSION)

    def path_allowed(self, part):
        return (component_allowed(part) and part != '.config') if self.host_authorized() else allowed(part)

    def describe(self):
        config = self.config()
        active = self.host_authorized(config)
        return {**config, 'active_mode': 'real_host' if active else 'isolated',
                'locally_authorized': active, 'exact_command_approval': False if active else 'host_activation_required',
                'default_shell': '/usr/bin/bash',
                'filesystem_policy': ('real paths with Linux permissions, protected names, no symlinks/hardlinks, bounded UTF-8/versioned atomic writes; root-ID APIs unchanged' if active else 'existing development roots; writes require project consent'),
                'terminal_policy': 'Real host after one local activation; no per-command dialog. Explicit isolated uses offline /work. Shell has all user-level file/network access; advisory guards are NOT security boundaries.',
                'blocked_actions': ['root elevation (no-new-privs)', 'untracked PID termination API', 'protected credential file APIs'],
                'intent_requirements': 'Destructive actions, recursive deletion, Git reset/clean/stash/force-push, installs/deploy/publication and private-save changes require explicit user instruction. Shell text cannot enforce intent.'}

    def resolve(self, value, write=False, directory=False, isolated=False):
        p = self.canonical(value, directory)
        if not isolated and self.host_authorized():
            # Keep old root-ID APIs untouched. Pin traversal from a real root and
            # reject symlinks rather than following them across protected names.
            root = Path('/')
            worktrees = Path.home() / '.codex/worktrees'
            if p.is_relative_to(worktrees) and len(p.relative_to(worktrees).parts) >= 2:
                root = worktrees / p.relative_to(worktrees).parts[0]
            if any(not self.path_allowed(part) for part in p.relative_to(root).parts):
                raise Denied('Protected path.')
            return root, p.relative_to(root).as_posix()
        candidates = [root for name, root in self.paths.roots.items()
                      if p.is_relative_to(root) and self.paths.root(name) == root]
        scopes = self.config()['approved_project_scopes']
        candidates += [Path(e['path']) for e in scopes if p.is_relative_to(e['path'])]
        # Discover individual Git projects without exposing development parent trees.
        for location in self.locations:
            if p.is_relative_to(location) and p != location:
                q = p if p.is_dir() else p.parent
                while q != location:
                    if (q / '.git').exists() and not (q / '.git').is_symlink():
                        candidates.append(q)
                        break
                    q = q.parent
        if not candidates:
            raise Denied('Path needs an existing development Git project or approved root.')
        root = max(candidates, key=lambda x: len(x.parts))
        for location in self.locations:
            if root.is_relative_to(location) and any(not allowed(part) for part in root.relative_to(location).parts):
                raise Denied('Protected project directory.')
        parts = p.relative_to(root).parts
        if any(not allowed(part) for part in parts):
            raise Denied('Protected path or generated/cache directory.')
        if write:
            if p.is_relative_to(self.paths.project):
                raise Denied('Configured primary project remains read-only.')
            writable = p.is_relative_to(self.paths.files)
            writable |= any(p.is_relative_to(e['path']) and e['write'] for e in scopes)
            # Existing enrolled read-only roots never become implicitly writable.
            if not writable:
                raise Denied('Write scope requires one-time local project authorization in set_config_value.')
        return root, p.relative_to(root).as_posix()

    def adapter(self, value, write=False, directory=False, isolated=False):
        root, relative = self.resolve(value, write, directory, isolated)
        # Reuse the existing pinned-descriptor read and traversal implementation.
        adapter = object.__new__(Paths)
        adapter.roots = {'path': root}
        adapter.enrolled = {}
        adapter.identities = {'path': (root.stat().st_dev, root.stat().st_ino)}
        adapter.lock = self.paths.lock
        return adapter, relative

    def trusted(self, cwd):
        if not self.host_authorized():
            raise Denied('Real host requires ONE local activation: set_config_value approval_mode=desktop_compatible, then approve the local dialog.')
        self.canonical(cwd, directory=True)
