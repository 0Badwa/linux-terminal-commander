"""Owner-only local input for the same runtime key; never reads process memory."""
import os
from pathlib import Path
import stat
import subprocess


DESTINATION = Path('/home/exampleuser/.config/ubuntu-commander/runtime-api-key')


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
    if DESTINATION.exists() or DESTINATION.is_symlink():
        raise ValueError('An existing secret is never overwritten or copied.')
    consent = subprocess.run(['/usr/bin/zenity', '--question', '--no-markup',
        '--title=Ubuntu Commander — boot credential', '--ok-label=Approve local storage',
        '--cancel-label=Cancel', '--text=Za start pri boot-u potrebno je lokalno sačuvati isti Restricted runtime ključ.\n\nDestinacija: ' + str(DESTINATION) +
        '\nDirektorijum: 0700; fajl: 0600. Ključ neće biti prikazan niti preuzet iz memorije starog procesa.\n\nOdobravaš ovu destinaciju?'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if consent.returncode:
        print('Local credential storage was not approved; nothing changed.')
        return
    entry = subprocess.run(['/usr/bin/zenity', '--password', '--title=Ubuntu Commander — existing runtime key',
        '--text=Unesi isti Restricted runtime API key (Tunnels Read + Use). Ne pravi novi ključ.'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if entry.returncode:
        print('Local key entry cancelled; nothing changed.')
        return
    store_secret(DESTINATION, entry.stdout.rstrip('\n'))
    print('Existing runtime key stored locally at the approved destination; contents were not logged.')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Secret setup refused safely; check the chosen destination and local input. No secret was printed.')
        raise SystemExit(1)
