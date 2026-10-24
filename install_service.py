"""Generate a private systemd user unit; never enable or start it automatically."""
import os
from pathlib import Path
import pwd
import re
import stat

from settings import ROOT, PROFILE_NAME, project_root


def checked_path(path):
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)):
        raise ValueError('Paths with spaces or systemd-special characters are unsupported.')
    return str(path)


def prepare(destination=None):
    if os.geteuid() == 0:
        raise ValueError('Do not install as root.')
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    profile = ROOT / 'profiles' / (PROFILE_NAME + '.yaml')
    if not profile.is_file() or profile.is_symlink():
        raise FileNotFoundError('Run configure.py first to create your private tunnel profile.')
    key_file = home / '.config/linux-terminal-commander/runtime-api-key'
    if not key_file.is_file() or key_file.is_symlink():
        raise FileNotFoundError('Store your local runtime key using setup_runtime_secret.py first.')
    info = key_file.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or not 16 <= info.st_size <= 1024:
        raise ValueError('Unsafe runtime-key permissions.')
    root = checked_path(ROOT)
    python = checked_path(ROOT / '.venv/bin/python')
    if not Path(python).is_file():
        raise FileNotFoundError('Run install.sh first.')
    project = checked_path(project_root())
    text = (ROOT / 'linux-terminal-commander.service.in').read_text()
    text = text.replace('@ROOT@', root).replace('@PYTHON@', python)
    text = text.replace('@CONFIG@', checked_path(key_file.parent))
    text = text.replace('@PROJECT@', project)
    if '@' in text:
        raise ValueError('Unresolved service template placeholder.')
    if destination is None:
        destination = home / '.config/systemd/user/linux-terminal-commander.service'
    destination = Path(destination)
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor = os.open(destination, os.O_WRONLY | os.O_EXCL | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(text)
    return destination


if __name__ == '__main__':
    result = prepare()
    print(f'Unit created: {result}')
    print('To enable explicitly: systemctl --user daemon-reload && systemctl --user enable --now linux-terminal-commander.service')
