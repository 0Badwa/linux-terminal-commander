"""Manual foreground runtime; reads a key locally and never persists it."""
import argparse
import getpass
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent
from settings import tunnel_client, PROFILE_NAME
CLIENT = tunnel_client()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--terminal-input', action='store_true', help='Use hidden terminal input instead of the local GUI dialog')
parser.add_argument('--replace-running', action='store_true', help='After local key entry and doctor, stop only the verified existing foreground runtime')
args = parser.parse_args()
if os.geteuid() == 0:
    raise SystemExit('Do not run as root.')
if args.terminal_input:
    key = getpass.getpass('Restricted runtime API key (Tunnels Read + Use): ')
else:
    entry = subprocess.run(['/usr/bin/zenity', '--password', '--title=Linux Terminal Commander runtime key', '--text=Enter a restricted tunnel runtime key (Tunnels Read + Use). Kept only in memory.'], capture_output=True, text=True)
    if entry.returncode:
        raise SystemExit('Local key entry cancelled; no tunnel started.')
    key = entry.stdout.rstrip('\n')
if not key or '\n' in key or key.startswith('sk-admin'):
    raise SystemExit('A non-admin runtime key is required.')
env = {k:v for k,v in os.environ.items() if not k.startswith(('CONTROL_PLANE_', 'OPENAI_', 'MCP_', 'HARPOON_', 'CLOUDFLARED_', 'TUNNEL_CLIENT_', 'HEALTH_', 'LOG_', 'TRACING_'))}
env['CONTROL_PLANE_API_KEY'] = key
profile = ['--profile', PROFILE_NAME, '--profile-dir', str(ROOT/'profiles')]
check = subprocess.run([CLIENT, 'doctor', *profile, '--explain'], env=env, capture_output=True, text=True, timeout=60)
print(check.stdout.replace(key, '[REDACTED]'), flush=True)
print(check.stderr.replace(key, '[REDACTED]'), flush=True)
if check.returncode:
    raise SystemExit('Doctor failed; tunnel not started.')
runtime = ROOT/'runtime'
runtime.mkdir(mode=0o700, exist_ok=True)
pid_file = runtime/'custom.pid'
if pid_file.exists():
    try:
        previous_pid = int(pid_file.read_text().strip())
        proc = Path('/proc')/str(previous_pid)
        command = (proc/'cmdline').read_bytes().split(b'\0')
    except (FileNotFoundError, ValueError):
        command = []
    if command:
        if command[:2] != [CLIENT.encode(), b'run']:
            raise SystemExit('PID file identifies another process; refusing to stop it.')
        if not args.replace_running:
            raise SystemExit('An existing runtime is active. Use --replace-running for a controlled restart.')
        status = (proc/'status').read_text().splitlines()
        parent_pid = int(next(line.split()[1] for line in status if line.startswith('PPid:')))
        parent_command = (Path('/proc')/str(parent_pid)/'cmdline').read_bytes().split(b'\0')
        if len(parent_command)<2 or parent_command[1] != str(ROOT/'run_client.py').encode():
            raise SystemExit('Existing supervisor identity differs; stop it manually before restarting.')
        descriptor = os.pidfd_open(parent_pid)
        try:
            # A pidfd prevents signaling an unrelated reused PID.
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        finally:
            os.close(descriptor)
        for _ in range(100):
            if not proc.exists():
                break
            time.sleep(.1)
        else:
            raise SystemExit('Previous client did not stop; no second runtime was started.')

url_file = runtime/'custom-health.url'
if url_file.exists():
    url_file.unlink()
child = subprocess.Popen([CLIENT, 'run', *profile, '--log.level', 'warn', '--health.url-file', str(url_file), '--pid.file', str(runtime/'custom.pid')], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
def safe_output():
    for line in child.stdout:
        print(line.replace(key, '[REDACTED]'), end='', flush=True)
threading.Thread(target=safe_output, daemon=True).start()
def stop(signum, frame):
    child.terminate()
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
print('Custom MCP tunnel running in this foreground session; Ctrl+C stops it.', flush=True)
try:
    child.wait()
finally:
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=10)
