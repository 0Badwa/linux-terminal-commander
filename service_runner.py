"""Noninteractive user-service entry point. Secret contents are never read here."""
import fcntl
import json
import os
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parent
from settings import project_root, tunnel_client, PROFILE_NAME, home_dir
CLIENT = str(Path.home() / '.local/bin/tunnel-client')


def build_environment(environment):
    result = {'PATH': '/usr/bin:/bin', 'HOME': str(home_dir()), 'LANG': 'C.UTF-8'}
    # Only desktop/session coordinates needed for existing local approval dialogs.
    for name in ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS'):
        if environment.get(name):
            result[name] = environment[name]
    return result


def command(credential_directory):
    return [str(CLIENT), 'run', '--profile', PROFILE_NAME, '--profile-dir', str(ROOT / 'profiles'),
            '--control-plane.api-key', 'file:' + str(credential_directory / 'runtime-api-key'),
            '--log.level', 'warn', '--health.listen-addr', '127.0.0.1:0',
            '--health.url-file', str(ROOT / 'runtime' / 'custom-health.url'),
            '--pid.file', str(ROOT / 'runtime' / 'custom.pid')]


def validate_roots():
    """Fail startup unless the configured project and optional root enrollment are usable."""
    from security import Paths
    from gitops import Git
    selected = project_root()
    config = ROOT / 'approved_roots.json'
    paths = Paths(selected, ROOT / 'workspace', root_config=config if config.is_file() else None)
    class ReadOnly:
        def require(self, *args):
            raise ValueError('Startup validation does not approve writes.')
    state = Git(paths, ReadOnly()).state('project')
    if not state.get('head'):
        raise ValueError('Project repository has no Git HEAD.')


def main():
    if os.geteuid() == 0:
        raise ValueError('The service must run as the existing unprivileged user.')
    credential_directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
    credential = credential_directory / 'runtime-api-key'
    s = credential.lstat()
    if credential.is_symlink() or not credential.is_file() or s.st_uid != os.getuid() or s.st_mode & 0o077 or not 16 <= s.st_size <= 1024:
        raise ValueError('The runtime credential is missing or has unsafe metadata.')
    runtime = ROOT / 'runtime'
    if runtime.resolve() != runtime or runtime.is_symlink():
        raise ValueError('Invalid runtime directory.')
    lock = os.open(runtime / 'client.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.set_inheritable(lock, True)
    pid_file = runtime / 'custom.pid'
    if pid_file.exists():
        if pid_file.is_symlink() or pid_file.stat().st_size > 32:
            raise ValueError('Invalid runtime PID file.')
        pid = int(pid_file.read_text().strip())
        proc = Path('/proc') / str(pid)
        if proc.exists() and pid != os.getpid():
            raise ValueError('A prior runtime is still present; stop the verified manual client first.')
    for name in ('custom-health.url', 'custom.pid'):
        path = runtime / name
        if path.exists():
            path.unlink()
    os.umask(0o077)
    validate_roots()
    global CLIENT
    CLIENT = tunnel_client()
    os.execve(CLIENT, command(credential_directory), build_environment(os.environ))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No exception strings, argv, environment, or credential content in the journal.
        print('Linux Terminal Commander startup refused: check credential metadata, configuration, and prior runtime.', file=sys.stderr)
        raise SystemExit(78)
