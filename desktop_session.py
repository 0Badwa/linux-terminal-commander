"""Find only this user's active local GUI coordinates after a pre-login boot."""
import os
from pathlib import Path
import re
import stat
import subprocess


def _x11_display(directory):
    """Fallback for local X11 sessions whose logind Display field is empty."""
    if directory.is_symlink() or not directory.is_dir():
        return ''
    matches = []
    with os.scandir(directory) as entries:
        for count, entry in enumerate(entries):
            if count >= 64:
                return ''
            if re.fullmatch(r'X[0-9]{1,3}', entry.name):
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid():
                    matches.append(':' + entry.name[1:])
    return matches[0] if len(matches) == 1 else ''


def environment(source=None, runtime=None):
    source = os.environ if source is None else source
    allowed = ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR',
               'DBUS_SESSION_BUS_ADDRESS', 'LANG', 'PATH')
    result = {name: source[name] for name in allowed if source.get(name)}
    if result.get('DISPLAY') or result.get('WAYLAND_DISPLAY'):
        return result
    uid = os.getuid()
    directory = Path(runtime or f'/run/user/{uid}')
    try:
        s = directory.lstat()
        if directory.resolve() != directory or not stat.S_ISDIR(s.st_mode) or s.st_uid != uid:
            return result
        result['XDG_RUNTIME_DIR'] = str(directory)
        result['PATH'] = '/usr/bin:/bin'
        result['LANG'] = 'C.UTF-8'
        bus = directory / 'bus'
        if bus.exists() and stat.S_ISSOCK(bus.lstat().st_mode) and bus.lstat().st_uid == uid:
            result['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=' + str(bus)
        # Owned local sockets only; no environment dumps, credentials, or user files.
        for name in ('wayland-0', 'wayland-1', 'wayland-2', 'wayland-3'):
            socket = directory / name
            if socket.exists():
                s = socket.lstat()
                if stat.S_ISSOCK(s.st_mode) and s.st_uid == uid:
                    result['WAYLAND_DISPLAY'] = name
                    return result
        query = ['/usr/bin/loginctl', '--no-ask-password']
        clean = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
        sessions = subprocess.run([*query, 'show-user', str(uid), '-p', 'Sessions', '--value'],
                                 capture_output=True, text=True, timeout=2, env=clean)
        for ident in sessions.stdout.split()[:8]:
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', ident):
                continue
            data = subprocess.run([*query, 'show-session', ident, '-p', 'User', '-p', 'Active',
                '-p', 'Type', '-p', 'Display', '-p', 'Remote'], capture_output=True, text=True,
                timeout=2, env=clean)
            fields = dict(line.split('=', 1) for line in data.stdout.splitlines() if '=' in line)
            display = fields.get('Display', '')
            if fields.get('User') != str(uid) or fields.get('Active') != 'yes' or fields.get('Remote') != 'no' or fields.get('Type') != 'x11':
                continue
            if not display:
                display = _x11_display(Path('/tmp/.X11-unix'))
            if not re.fullmatch(r':[0-9]{1,3}(?:\.[0-9])?', display):
                continue
            authority = directory / 'gdm' / 'Xauthority'
            if authority.is_file() and not authority.is_symlink() and authority.stat().st_uid == uid:
                result['DISPLAY'] = display
                result['XAUTHORITY'] = str(authority)
                return result
    except (OSError, subprocess.SubprocessError):
        pass
    return result
