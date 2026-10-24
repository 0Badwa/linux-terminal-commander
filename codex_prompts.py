"""Create-only Markdown delivery in one private, shared /tmp directory."""
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import uuid

from security import Denied, nonroot


PROMPT_DIRECTORY = Path('/tmp/romans-codex-prompts')
MAX_PROMPT_BYTES = 256 * 1024
FILENAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,119}\.md\Z', re.ASCII)


def _identity(info):
    return info.st_dev, info.st_ino


def _rename_new(parent, source, destination):
    # Linux renameat2 publishes the complete inode atomically, without replacing
    # even a dangling symlink created at the destination during this request.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(source), parent, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise Denied('Prompt already exists; choose a new filename. No file was replaced.')
        raise OSError(code, 'Atomic prompt publication failed.')


def _check_directory(parent, directory):
    visible = os.stat(PROMPT_DIRECTORY.name, dir_fd=parent, follow_symlinks=False)
    pinned = os.fstat(directory)
    if (_identity(visible) != _identity(pinned) or not stat.S_ISDIR(visible.st_mode)
            or visible.st_uid != os.getuid() or stat.S_IMODE(visible.st_mode) != 0o700):
        raise Denied('Prompt directory changed or is unsafe; restore an owned real directory with mode 0700.')


def save_prompt(filename, content):
    nonroot()
    if os.getuid() != pwd.getpwnam('exampleuser').pw_uid:
        raise Denied('Codex prompt delivery must run as exampleuser.')
    if not isinstance(filename, str) or not FILENAME.fullmatch(filename):
        raise Denied('Use a basename ending in .md: 1..120 ASCII letters, digits, underscores or hyphens; start with a letter or digit.')
    if not isinstance(content, str) or not content or '\x00' in content or len(content) > MAX_PROMPT_BYTES:
        raise Denied('Content must be nonempty UTF-8 Markdown, without NUL, at most 256 KiB.')
    try:
        data = content.encode('utf-8')
    except UnicodeError:
        raise Denied('Content must be valid UTF-8 Markdown.') from None
    if len(data) > MAX_PROMPT_BYTES:
        raise Denied('UTF-8 content exceeds 256 KiB; shorten the prompt.')
    parent = directory = handle = None
    temporary = '.prompt-' + uuid.uuid4().hex
    created = None
    try:
        parent = os.open(PROMPT_DIRECTORY.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(PROMPT_DIRECTORY.name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        directory = os.open(PROMPT_DIRECTORY.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        _check_directory(parent, directory)
        handle = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        created = _identity(os.fstat(handle))
        os.fchmod(handle, 0o600)
        with os.fdopen(os.dup(handle), 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _check_directory(parent, directory)
        before = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        if _identity(before) != created or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Denied('Temporary prompt changed; no prompt was published. Retry with a new filename.')
        _rename_new(directory, temporary, filename)
        os.fsync(directory)
        _check_directory(parent, directory)
        with os.fdopen(os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (_identity(info) != created or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                    or stream.read(MAX_PROMPT_BYTES + 1) != data):
                raise Denied('Published prompt changed; verify the directory before retrying.')
        _check_directory(parent, directory)
        if _identity(os.stat(filename, dir_fd=directory, follow_symlinks=False)) != created:
            raise Denied('Published prompt changed; verify the directory before retrying.')
        return {'path': str(PROMPT_DIRECTORY / filename), 'bytes_written': len(data),
                'sha256': hashlib.sha256(data).hexdigest()}
    except Denied:
        raise
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            raise Denied('Prompt directory is not writable; check exampleuser ownership, mode 0700 and service filesystem restrictions.') from None
        if exc.errno == errno.ENOSPC:
            raise Denied('No space available in /tmp; free space and retry with a new filename.') from None
        raise Denied('Prompt delivery failed safely; check for symlinks, changed directory entries or unavailable /tmp storage.') from None
    finally:
        if handle is not None:
            os.close(handle)
        if directory is not None:
            try:
                if created is not None and _identity(os.stat(temporary, dir_fd=directory, follow_symlinks=False)) == created:
                    os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory)
        if parent is not None:
            os.close(parent)
