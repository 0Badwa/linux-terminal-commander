"""Local, nonsecret configuration for Linux Terminal Commander."""
import os
from pathlib import Path
import stat
import pwd

ROOT = Path(__file__).resolve().parent
PROJECT_POINTER = ROOT / 'runtime' / 'project-root.txt'
PROFILE_NAME = 'linux-terminal-commander'

def home_dir():
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def canonical_project(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError('Project must be an existing canonical absolute directory (no symlinks).')
    if not (path / '.git').exists():
        raise ValueError('The project directory must contain a Git checkout.')
    return path


def project_root():
    explicit = os.environ.get('LTC_PROJECT_ROOT')
    if explicit:
        return canonical_project(explicit)
    if PROJECT_POINTER.exists() or PROJECT_POINTER.is_symlink():
        info = PROJECT_POINTER.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 4096:
            raise ValueError('Unsafe project settings. Remove/recreate them locally.')
        return canonical_project(PROJECT_POINTER.read_text().strip())
    return canonical_project(ROOT)


def tunnel_client():
    import shutil
    selected = os.environ.get('LTC_TUNNEL_CLIENT') or shutil.which('tunnel-client') or str(home_dir() / '.local/bin/tunnel-client')
    path = Path(selected).expanduser()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError('Install the official tunnel-client and set LTC_TUNNEL_CLIENT if needed.')
    return str(path)
