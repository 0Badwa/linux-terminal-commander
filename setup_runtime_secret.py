"""Owner-only local input for the same runtime key; never reads process memory."""
import os
import getpass
import argparse
from pathlib import Path
from settings import home_dir
import stat
import subprocess


DESTINATION = home_dir() / '.config' / 'linux-terminal-commander' / 'runtime-api-key'


def store_secret(destination, key):
    if os.geteuid() == 0:
        raise ValueError('Root is forbidden.')
    destination = Path(destination)
    parent = destination.parent
    parent.mkdir(mode=0o700, exist_ok=True)
    s = parent.lstat()
    if parent.resolve() != parent or not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise ValueError('Secret directory must be owned, canonical, and mode 0700.')
    if not isinstance(key, str) or not 16 <= len(key) <= 1024 or any(c.isspace() for c in key) or key.startswith('sk-admin'):
        raise ValueError('A restricted non-admin runtime key is required.')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(key.encode('utf-8'))
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description='Store your own restricted tunnel runtime key locally.')
    parser.add_argument('--terminal-input', action='store_true', help='Use a private terminal prompt instead of Zenity.')
    args = parser.parse_args()
    if DESTINATION.exists() or DESTINATION.is_symlink():
        raise ValueError('An existing runtime key is never overwritten.')
    if args.terminal_input:
        print(f'Local key destination: {DESTINATION} (directory 0700, file 0600).')
        approval = input('Type YES to store your key locally for the optional service: ')
        if approval != 'YES':
            print('Cancelled; no changes.')
            return
        key = getpass.getpass('Restricted runtime key (input hidden): ')
    else:
        consent = subprocess.run(['/usr/bin/zenity', '--question', '--no-markup',
            '--title=Linux Terminal Commander - local setup', '--ok-label=Approve storage',
            '--cancel-label=Cancel', '--text=Store your own restricted runtime key locally? Destination: ' + str(DESTINATION)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if consent.returncode:
            print('Cancelled; no changes.')
            return
        entry = subprocess.run(['/usr/bin/zenity', '--password',
            '--title=Linux Terminal Commander - runtime key',
            '--text=Enter your restricted tunnel runtime key (Tunnels Read + Use).'],
            stdin=subprocess.DEVNULL, capture_output=True, text=True)
        if entry.returncode:
            print('Cancelled; no changes.')
            return
        key = entry.stdout.rstrip('\n')
    store_secret(DESTINATION, key)
    print('Restricted runtime key stored locally; key contents were not logged.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Secret setup refused safely; check the chosen destination and local input. No secret was printed.')
        raise SystemExit(1)
