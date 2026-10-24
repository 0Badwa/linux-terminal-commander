"""Explicit local root enrollment. No runtime directory discovery or wildcard roots."""
import json
import os
from pathlib import Path
import re
import stat

from security import Denied, component_allowed


DEVELOPMENT_LOCATIONS = (Path.home() / 'Projects', Path.home() / 'projects')
CODEX_WORKTREES = Path.home() / '.codex/worktrees'
ROOT_ID = re.compile(r'[a-z][a-z0-9-]{0,79}\Z')


def real_directory(path):
    path = Path(path)
    try:
        s = path.lstat()
        if not path.is_absolute() or path.resolve(strict=True) != path or not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid():
            raise Denied('Approved root must be an existing canonical directory owned by the current user.')
    except OSError:
        raise Denied('Approved root is missing or unavailable.') from None
    return path


def metadata_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_size > 4096:
            raise Denied('Invalid Git metadata file.')
        return os.read(fd, 4097).decode('utf-8').strip()
    except (OSError, UnicodeError):
        raise Denied('Git metadata is unavailable or invalid.') from None
    finally:
        os.close(fd)


def git_layout(path, expected_common):
    """Validate both worktree pointers; never trust an arbitrary .git indirection."""
    path = real_directory(path)
    common = real_directory(expected_common)
    dot = path / '.git'
    try:
        if dot.is_symlink():
            raise Denied('Symlinked Git metadata is forbidden.')
        if dot.is_dir():
            if dot != common:
                raise Denied('Repository common directory does not match enrollment.')
        elif dot.is_file():
            text = metadata_text(dot)
            if not text.startswith('gitdir: '):
                raise Denied('Invalid worktree pointer.')
            admin = Path(text[8:])
            if not admin.is_absolute():
                admin = path / admin
            # Real Git worktree admins have one component under common/worktrees.
            admin = real_directory(admin)
            if admin.parent != common / 'worktrees':
                raise Denied('Worktree points outside its enrolled repository.')
            relative_common = Path(metadata_text(admin / 'commondir'))
            resolved_common = (admin / relative_common).resolve(strict=True)
            if resolved_common != common:
                raise Denied('Worktree common-directory pointer changed.')
            backlink = Path(metadata_text(admin / 'gitdir'))
            if not backlink.is_absolute() or backlink != dot:
                raise Denied('Worktree backlink does not match its enrolled checkout.')
        else:
            raise Denied('Approved root has no valid Git metadata.')
        if not (common / 'objects').is_dir() or not (common / 'refs').is_dir():
            raise Denied('Approved root is not a usable Git repository.')
        metadata_text(common / 'HEAD')
        if common.is_symlink() or (common / 'objects').is_symlink() or (common / 'refs').is_symlink():
            raise Denied('Symlinked Git common metadata is forbidden.')
    except OSError:
        raise Denied('Git metadata is missing or unavailable.') from None
    return path, common


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Denied('Duplicate configuration keys are forbidden.')
        result[key] = value
    return result


def load(config, project, service, development_locations=None, codex_worktrees=None):
    config, project, service = Path(config), Path(project), Path(service)
    if config.is_symlink() or config.resolve(strict=True) != config:
        raise Denied('Root configuration must be a canonical regular file.')
    fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid() or s.st_mode & 0o022 or s.st_size > 65536:
            raise Denied('Root configuration is too large, unowned, or writable by other users.')
        data = json.loads(os.read(fd, 65537), object_pairs_hook=no_duplicate_keys)
    except (ValueError, UnicodeError):
        raise Denied('Root configuration must be valid JSON without duplicate keys.') from None
    finally:
        os.close(fd)
    if set(data) != {'version', 'roots'} or data['version'] != 1 or not isinstance(data['roots'], list) or len(data['roots']) > 128:
        raise Denied('Unsupported root configuration schema or root count.')
    locations = tuple(Path(x) for x in (development_locations or DEVELOPMENT_LOCATIONS))
    codex = Path(codex_worktrees or CODEX_WORKTREES)
    entries, targets = {}, {project, service / 'workspace' / 'files'}
    for item in data['roots']:
        if not isinstance(item, dict) or set(item) != {'id', 'path', 'common_dir', 'kind'}:
            raise Denied('Each root requires exactly id, path, common_dir and kind.')
        name = item['id']
        if not isinstance(name, str) or not ROOT_ID.fullmatch(name) or name in ('project', 'scratch') or name in entries:
            raise Denied('Duplicate, reserved or invalid root ID.')
        path, common = Path(item['path']), Path(item['common_dir'])
        kind = item['kind']
        if path in targets:
            raise Denied('Duplicate root paths are forbidden.')
        if path == service or path.is_relative_to(service) or service.is_relative_to(path):
            raise Denied('The MCP service and parent directories cannot be enrolled.')
        direct = path.parent in locations
        primary_worktree = path.parent.parent == codex and kind == 'primary_worktree' and common == project / '.git'
        if not direct and not primary_worktree:
            raise Denied('Root is outside the fixed development locations.')
        components = (path.name,) if direct else (path.parent.name, path.name)
        if any(not component_allowed(part) for part in components):
            raise Denied('Sensitive development paths cannot be enrolled.')
        if kind == 'repository':
            if common != path / '.git':
                raise Denied('A repository root must have its own Git common directory.')
        elif kind == 'primary_worktree':
            if common != project / '.git' or path == project:
                raise Denied('Primary worktree must belong to the original repository.')
        elif kind == 'development_worktree':
            if common.parent.parent not in locations or common.name != '.git':
                raise Denied('Development worktree common directory is outside the fixed locations.')
        else:
            raise Denied('Unknown root enrollment kind.')
        git_layout(path, common)
        entries[name] = {'path': path, 'common': common, 'kind': kind}
        targets.add(path)
    # A secondary project's worktrees require its main repository to be enrolled.
    enrolled_repositories = {e['common'] for e in entries.values() if e['kind'] == 'repository'}
    for entry in entries.values():
        if entry['kind'] == 'development_worktree' and entry['common'] not in enrolled_repositories:
            raise Denied('Enroll the development repository before any of its worktrees.')
    return entries
