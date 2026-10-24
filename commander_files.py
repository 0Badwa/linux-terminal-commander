"""Path workflows preserve descriptor traversal, versions and atomic updates."""
import fnmatch
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import threading
import time
import uuid

from commander_policy import allowed
from files import Files
from security import Denied, MAX_FILE, redact


class NoDialog:
    def require(self, *args):
        pass


class PathFiles:
    def __init__(self, policy):
        self.policy = policy
        self.search_lock = threading.Lock()
        self.searches = {}

    def files(self, path, write=False):
        adapter, rel = self.policy.adapter(path, write)
        files = Files(adapter, NoDialog())
        # Authorization is checked again by each write under the shared lock.
        files._writable = lambda root: self.policy.resolve(path, write=True)
        return files, rel

    def read(self, path, start_line=1, end_line=120):
        f, rel = self.files(path)
        return {'path': path, **f.read('path', rel, start_line, end_line)}

    def multiple(self, paths):
        if not isinstance(paths, list) or not 1 <= len(paths) <= 16:
            raise Denied('Read 1..16 files per request.')
        result = [self.read(p, 1, 80) for p in paths]
        if sum(len(r['text'].encode()) for r in result) > 65536:
            raise Denied('Combined response too large; use smaller ranges.')
        return {'files': result}

    def info(self, path):
        f, rel = self.files(path)
        return {'path': path, **f.metadata('path', rel)}

    def write(self, path, content, mode='create', expected_version=''):
        f, rel = self.files(path, True)
        data = f._text(content)
        with self.policy.paths.lock:
            if mode == 'create':
                parent, name = f.paths.parent('path', rel)
                temporary = '.commander-' + uuid.uuid4().hex
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    self.policy.resolve(path, write=True)
                    self._rename(parent, temporary, parent, name)
                    os.fsync(parent)
                except FileExistsError:
                    raise Denied('File already exists; create never overwrites.') from None
                finally:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                    os.close(parent)
                result = f.metadata('path', rel)
            elif mode in ('replace', 'append'):
                old, version, before = f.paths.read('path', rel)
                if version != expected_version or redact(old) != old:
                    raise Denied('Exact nonsensitive file version required.')
                updated = old + content if mode == 'append' else content
                data = f._text(updated)
                self._replace(f, rel, updated, version, before)
                result = f.metadata('path', rel)
            else:
                raise Denied('Use create, replace or append.')
        self.policy.audit('write_file_path', mode=mode, bytes=len(data))
        return {'path': path, **result}

    def _replace(self, f, rel, content, version, before):
        parent, name = f.paths.parent('path', rel)
        temporary = '.commander-' + uuid.uuid4().hex
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content.encode())
                os.fchmod(stream.fileno(), stat.S_IMODE(before.st_mode) & 0o777)
                stream.flush()
                os.fsync(stream.fileno())
            if f.paths.read('path', rel)[1] != version:
                raise Denied('Concurrent modification; nothing replaced.')
            f._writable('path')
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def edit(self, path, old_text, new_text, expected_version):
        f, rel = self.files(path, True)
        with self.policy.paths.lock:
            result = f.edit('path', rel, expected_version, old_text, new_text)
        self.policy.audit('edit_block_path')
        return {'path': path, **result}

    def mkdir(self, path):
        adapter, rel = self.policy.adapter(path, True)
        with self.policy.paths.lock:
            self.policy.resolve(path, write=True)
            parent, name = adapter.parent('path', rel)
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
        self.policy.audit('create_directory')
        return {'path': path, 'created': True}

    def move(self, src, dst, expected_version):
        source, source_rel = self.policy.adapter(src, True)
        target, target_rel = self.policy.adapter(dst, True)
        # Regular files only: moving a directory could move protected contents.
        with self.policy.paths.lock:
            self.policy.resolve(src, True)
            self.policy.resolve(dst, True)
            if source.read('path', source_rel)[1] != expected_version:
                raise Denied('Source version changed.')
            a, x = source.parent('path', source_rel)
            b, y = target.parent('path', target_rel)
            try:
                self._rename(a, x, b, y)
                os.fsync(a)
                os.fsync(b)
            finally:
                os.close(a)
                os.close(b)
        self.policy.audit('move_path')
        return self.info(dst)

    @staticmethod
    def _rename(source_fd, source, destination_fd, destination):
        import ctypes
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1):
            code = ctypes.get_errno()
            raise OSError(code, 'Atomic move/publication refused.')

    def listing(self, path, offset=0, limit=100):
        if type(offset) is not int or not 0 <= offset <= 20000 or not 1 <= limit <= 200:
            raise Denied('Invalid directory page (offset <=20000, limit 1..200).')
        adapter, rel = self.policy.adapter(path, directory=True)
        from security import relative
        fd = adapter.directory_fd('path', relative(rel, allow_dot=True))
        items, scanned = [], 0
        try:
            with os.scandir(fd) as entries:
                for e in entries:
                    scanned += 1
                    if scanned > 20000:
                        break
                    if not self.policy.path_allowed(e.name) or e.is_symlink():
                        continue
                    s = e.stat(follow_symlinks=False)
                    if stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) and s.st_nlink == 1:
                        items.append({'name': redact(e.name), 'directory': stat.S_ISDIR(s.st_mode), 'size': s.st_size})
            items.sort(key=lambda e: e['name'])
            page = items[offset:offset+limit]
            return {'entries': page, 'next_offset': offset+len(page) if offset+len(page) < len(items) else None,
                    'scan_truncated': scanned > 20000, 'pagination': 'rescan; directory changes can shift pages'}
        finally:
            os.close(fd)

    def search(self, paths, pattern, kind='text', regex=False, file_glob='*', offset=0, limit=50, max_depth=8, search_id=''):
        if not isinstance(paths, list) or not 1 <= len(paths) <= 8 or not isinstance(pattern, str) or not 1 <= len(pattern) <= 200 or '\x00' in pattern:
            raise Denied('Use 1..8 directories and a 1..200-character pattern.')
        if kind not in ('text', 'filename') or not 1 <= limit <= 100 or not 0 <= offset <= 10000 or not 0 <= max_depth <= 12:
            raise Denied('Invalid search kind/page/depth.')
        if not isinstance(file_glob, str) or not 1 <= len(file_glob) <= 80 or '/' in file_glob or '\\' in file_glob:
            raise Denied('Use a bounded basename glob.')
        if regex and (kind != 'text' or not Path('/usr/bin/rg').is_file()):
            raise Denied('Regex text search requires installed ripgrep (linear-time engine).')
        if search_id and (len(search_id) != 32 or any(c not in '0123456789abcdef' for c in search_id)):
            raise Denied('Invalid search ID.')
        ident = search_id or uuid.uuid4().hex
        cancel = threading.Event()
        with self.search_lock:
            if ident in self.searches or len(self.searches) >= 4:
                raise Denied('Search ID already active or four concurrent searches reached.')
            self.searches[ident] = cancel
        deadline = time.monotonic() + 3
        scanned = matched = 0
        hits = []
        truncated = cancelled = False
        from security import relative
        try:
            for path in paths:
                adapter, rel = self.policy.adapter(path, directory=True)
                pending = [relative(rel, allow_dot=True)]
                start_depth = len(pending[0])
                while pending:
                    if cancel.is_set():
                        cancelled = True
                        break
                    if scanned >= 10000 or time.monotonic() >= deadline:
                        truncated = True
                        break
                    parts = pending.pop()
                    fd = adapter.directory_fd('path', parts)
                    try:
                        # Bound entries before sorting; never materialize a huge directory.
                        entries = []
                        with os.scandir(fd) as iterator:
                            for entry in iterator:
                                scanned += 1
                                if scanned > 10000 or time.monotonic() >= deadline:
                                    truncated = True
                                    break
                                entries.append(entry)
                        entries.sort(key=lambda e: e.name)
                        for e in entries:
                            if cancel.is_set():
                                cancelled = True
                                break
                            if time.monotonic() >= deadline:
                                truncated = True
                                break
                            if not self.policy.path_allowed(e.name) or e.is_symlink():
                                continue
                            current = (*parts, e.name)
                            if e.is_dir(follow_symlinks=False):
                                if len(current)-start_depth <= max_depth:
                                    pending.append(current)
                                continue
                            if not e.is_file(follow_symlinks=False) or not fnmatch.fnmatchcase(e.name, file_glob):
                                continue
                            full = str(adapter.roots['path'].joinpath(*current))
                            found = []
                            if kind == 'filename':
                                if fnmatch.fnmatchcase(e.name, pattern):
                                    found = [{'path': full}]
                            else:
                                try:
                                    text, _, _ = adapter.read('path', '/'.join(current))
                                except Denied:
                                    continue
                                lines = redact(text).splitlines()
                                if regex:
                                    try:
                                        result = subprocess.run(['/usr/bin/rg', '--no-config', '--line-number', '--max-count', str(offset+limit+1), '--max-columns', '1000', '--regexp', pattern],
                                            input='\n'.join(lines), capture_output=True, text=True,
                                            timeout=max(.01, min(.2, deadline-time.monotonic())),
                                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
                                    except subprocess.TimeoutExpired:
                                        truncated = True
                                        break
                                    if result.returncode > 1:
                                        raise Denied('Invalid/unsupported regex; PCRE/backreferences are not enabled.')
                                    found = [{'path': full, 'line': int(line.split(':', 1)[0]), 'text': line.split(':', 1)[1][:500]}
                                             for line in result.stdout.splitlines() if ':' in line and line.split(':', 1)[0].isdigit()]
                                else:
                                    found = [{'path': full, 'line': n, 'text': line[:500]}
                                             for n, line in enumerate(lines, 1) if pattern in line][:offset+limit+1]
                            for hit in found:
                                if matched >= offset:
                                    hits.append(hit)
                                matched += 1
                                if len(hits) > limit:
                                    truncated = True
                                    break
                            if len(hits) > limit or time.monotonic() >= deadline:
                                break
                    finally:
                        os.close(fd)
                    if len(hits) > limit or truncated or cancelled:
                        break
                if cancelled or truncated:
                    break
            return {'search_id': ident, 'matches': hits[:limit], 'scanned': scanned, 'cancelled': cancelled,
                    'truncated': truncated, 'next_offset': offset+limit if len(hits) > limit else None,
                    'continuation': 'rescan; narrow paths/glob if scan budget exhausted without a next_offset'}
        finally:
            with self.search_lock:
                self.searches.pop(ident, None)

    def cancel_search(self, search_id):
        if len(search_id) != 32 or any(c not in '0123456789abcdef' for c in search_id):
            raise Denied('Invalid search ID.')
        with self.search_lock:
            cancel = self.searches.get(search_id)
            if cancel is not None:
                cancel.set()
        return {'search_id': search_id, 'cancellation_requested': cancel is not None}
