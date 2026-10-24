"""Prepare a per-user tunnel profile, without recording keys or starting services."""
import argparse
import os
from pathlib import Path
import re
import stat
import shlex
import subprocess
import sys

from settings import ROOT, PROFILE_NAME, PROJECT_POINTER, canonical_project, tunnel_client


def configure(project, tunnel_id, client=None):
    if os.geteuid() == 0:
        raise ValueError('Do not configure this server as root.')
    if not re.fullmatch(r'tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}', tunnel_id):
        raise ValueError('Invalid tunnel ID syntax.')
    project = canonical_project(project)
    python = ROOT / '.venv/bin/python'
    if not python.is_file():
        raise ValueError('Run ./install.sh first to create the project virtual environment.')
    binary = client or tunnel_client()
    if PROJECT_POINTER.exists() or PROJECT_POINTER.is_symlink():
        raise FileExistsError('Project configuration already exists; do not replace a running setup.')
    profiles = ROOT / 'profiles'
    profiles.mkdir(mode=0o700, exist_ok=True)
    mode = profiles.lstat()
    if profiles.is_symlink() or mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) != 0o700:
        raise ValueError('Profiles directory must be owned, private (0700), and not a symlink.')
    profile = profiles / (PROFILE_NAME + '.yaml')
    if profile.exists() or profile.is_symlink():
        raise FileExistsError('Tunnel profile already exists; this utility does not replace live configuration.')
    argv = [binary, 'init', '--sample', 'sample_mcp_stdio_local', '--profile', PROFILE_NAME,
            '--profile-dir', str(profiles), '--tunnel-id', tunnel_id,
            '--health-listen-addr', '127.0.0.1:0',
            '--mcp-command', shlex.join([str(python), str(ROOT / 'server.py')])]
    subprocess.run(argv, check=True, timeout=60)
    if not profile.is_file():
        raise ValueError('Tunnel client did not create its expected profile.')
    os.chmod(profile, 0o600)
    runtime = ROOT / 'runtime'
    runtime.mkdir(mode=0o700, exist_ok=True)
    mode = runtime.lstat()
    if runtime.is_symlink() or mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) != 0o700:
        raise ValueError('Runtime directory must be owned, private (0700), and not a symlink.')
    fd = os.open(PROJECT_POINTER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(str(project) + '\n')
    print('Profile created. Start with: ./.venv/bin/python run_client.py --terminal-input')
    print('No runtime API key was stored by this configurator.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tunnel-id', required=True, help='Your own tunnel ID')
    parser.add_argument('--project', default=str(ROOT), help='An existing local Git checkout')
    args = parser.parse_args()
    configure(args.project, args.tunnel_id)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, FileExistsError, FileNotFoundError, subprocess.CalledProcessError) as error:
        print(f'Configuration failed: {error}', file=sys.stderr)
        raise SystemExit(1)
