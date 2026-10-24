"""Bounded text operations using pinned directory descriptors."""
import fnmatch
import hashlib
import os
from pathlib import Path
import stat
import uuid

from security import Denied, MAX_FILE, MAX_OUTPUT, component_allowed, redact, relative


class Files:
    def __init__(self, paths, approval, branch_check=None):
        self.paths, self.approval = paths, approval
        self.branch_check=branch_check

    def _writable(self,root):
        self.paths.root(root)
        if root=='project':
            raise Denied('The original checkout is read-only; use scratch or a managed codex worktree.')
        if root!='scratch' and (not root.startswith('worktree:') or
                               self.branch_check and not self.branch_check(root)):
            raise Denied('File writes require a managed codex branch.')

    def roots(self):
        return {'roots': [{'id': name, 'path': str(self.paths.root(name))} for name in sorted(self.paths.roots)]}

    def listing(self, root='project', path='.', limit=100):
        if not 1 <= limit <= 200:
            raise Denied('Directory limit must be 1..200.')
        fd = self.paths.directory_fd(root, relative(path, allow_dot=True))
        try:
            items = []
            scanned = 0
            with os.scandir(fd) as entries:
                for e in entries:
                    scanned += 1
                    if scanned > 2000:
                        break
                    if not component_allowed(e.name) or e.is_symlink():
                        continue
                    s = e.stat(follow_symlinks=False)
                    if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) and s.st_nlink == 1):
                        continue
                    items.append({'name': redact(e.name), 'directory': stat.S_ISDIR(s.st_mode), 'size': s.st_size})
                    if len(items) == limit:
                        break
            return {'entries': items, 'truncated': len(items) == limit or scanned > 2000}
        finally:
            os.close(fd)

    def read(self, root, path, start_line=1, end_line=120):
        if not 1 <= start_line <= end_line or end_line - start_line >= 200:
            raise Denied('Read at most 200 lines, starting at line 1 or later.')
        text, version, _ = self.paths.read(root, path)
        lines = redact(text).splitlines()
        selected = '\n'.join(lines[start_line-1:end_line])
        return {'text': selected[:MAX_OUTPUT], 'version': version,
                'total_lines': len(lines), 'truncated': len(selected) > MAX_OUTPUT}

    def metadata(self, root, path):
        text, version, s = self.paths.read(root, path)
        return {'size': s.st_size, 'mtime_ns': s.st_mtime_ns,
                'mode': oct(stat.S_IMODE(s.st_mode)), 'version': version,
                'redacted': redact(text) != text}

    def search(self, root, pattern, file_pattern='*', path='.', limit=50):
        # Literal content matching and basename-only globbing avoid regex denial of service.
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 200 or '\x00' in pattern:
            raise Denied('Use a nonempty literal pattern of at most 200 characters.')
        if not isinstance(file_pattern, str) or not 1 <= len(file_pattern) <= 80 or '/' in file_pattern or '\\' in file_pattern:
            raise Denied('File pattern must be a bounded basename glob.')
        if not 1 <= limit <= 100:
            raise Denied('Search result limit must be 1..100.')
        start = relative(path, allow_dot=True)
        pending, scanned, hits = [start], 0, []
        while pending and scanned < 1000 and len(hits) < limit:
            parts = pending.pop()
            fd = self.paths.directory_fd(root, parts)
            try:
                with os.scandir(fd) as entries:
                    for e in entries:
                        scanned += 1
                        if scanned > 1000 or len(hits) >= limit:
                            break
                        if not component_allowed(e.name) or e.is_symlink():
                            continue
                        current = (*parts, e.name)
                        if e.is_dir(follow_symlinks=False):
                            if len(current) <= 8 and e.name not in ('build','.gradle','node_modules'):
                                pending.append(current)
                        elif fnmatch.fnmatchcase(e.name, file_pattern):
                            try:
                                text, _, _ = self.paths.read(root, '/'.join(current))
                            except Denied:
                                continue
                            for n, line in enumerate(redact(text).splitlines(), 1):
                                if pattern in line:
                                    hits.append({'path': '/'.join(current), 'line': n, 'text': line[:1000]})
                                    if len(hits) == limit:
                                        break
            finally:
                os.close(fd)
        return {'matches': hits, 'scanned': min(scanned,1000),
                'truncated': bool(pending) or scanned >= 1000 or len(hits) == limit}

    def _text(self, text):
        if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_FILE or '\x00' in text:
            raise Denied('Text exceeds the size limit or contains binary data.')
        if redact(text) != text:
            raise Denied('Credential-like content cannot be written through MCP.')
        return text.encode('utf-8')

    def create(self, root, path, content):
        self._writable(root)
        data = self._text(content)
        relative(path)
        self.paths.root(root)
        self.approval.require('create_text_file', {'root':root,'path':path,'bytes':len(data),
                              'sha256':hashlib.sha256(data).hexdigest(), 'preview':content[:1500]})
        with self.paths.lock:
            self._writable(root)
            parent, name = self.paths.parent(root,path)
            try:
                fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                with os.fdopen(fd,'wb') as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.fsync(parent)
            except FileExistsError:
                raise Denied('File already exists; create never overwrites.') from None
            finally:
                os.close(parent)
        return self.metadata(root,path)

    def edit(self, root, path, expected_version, old_text, new_text):
        self._writable(root)
        if not old_text or len(expected_version) != 64:
            raise Denied('An exact version and nonempty unique old text are required.')
        self._text(old_text)
        self._text(new_text)
        original, version, before = self.paths.read(root,path)
        if version != expected_version:
            raise Denied('Concurrent modification: expected version does not match.')
        if redact(original) != original or original.count(old_text) != 1:
            raise Denied('Edit requires nonsensitive text and exactly one old-text match.')
        updated = original.replace(old_text,new_text,1)
        data = self._text(updated)
        self.approval.require('edit_text_file', {'root':root,'path':path,'expected_version':version,
            'old_text':old_text[:1500], 'new_text':new_text[:1500], 'new_sha256':hashlib.sha256(data).hexdigest()})
        with self.paths.lock:
            self._writable(root)
            current, current_version, _ = self.paths.read(root,path)
            if current_version != version:
                raise Denied('Concurrent modification after approval; no file was replaced.')
            parent, name = self.paths.parent(root,path)
            temporary = '.mcp-edit-' + uuid.uuid4().hex
            try:
                fd = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                with os.fdopen(fd,'wb') as f:
                    f.write(data)
                    f.flush()
                    os.fchmod(f.fileno(),stat.S_IMODE(before.st_mode) & 0o777)
                    os.fsync(f.fileno())
                _, final_version, _ = self.paths.read(root,path)
                if final_version != version:
                    raise Denied('Concurrent modification before replacement; no file was replaced.')
                # Atomic replacement under the service lock; external editors must also
                # avoid writing in the final check/rename interval (documented limitation).
                os.replace(temporary,name,src_dir_fd=parent,dst_dir_fd=parent)
                os.fsync(parent)
            finally:
                try:
                    os.unlink(temporary,dir_fd=parent)
                except FileNotFoundError:
                    pass
                os.close(parent)
        return self.metadata(root,path)
