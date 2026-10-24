#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $EUID == 0 ]]; then printf 'Run as your normal Linux user, not root.\n' >&2; false; fi
command -v python3 >/dev/null || { printf 'Install python3 and python3-venv first.\n' >&2; false; }
command -v git >/dev/null || { printf 'Install git first.\n' >&2; false; }
command -v bwrap >/dev/null || { printf 'Install bubblewrap for isolated execution first.\n' >&2; false; }
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
printf '\nLinux Terminal Commander dependencies installed locally.\n'
printf 'Next: read README.md and run .venv/bin/python configure.py --tunnel-id YOUR_OWN_TUNNEL_ID\n'
