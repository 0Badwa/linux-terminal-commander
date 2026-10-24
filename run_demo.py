"""Foreground official demo. Runtime key lives only in process memory."""
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

ROOT = Path('/home/exampleuser/projects/linux-terminal-commander')
CLIENT = '/home/exampleuser/.local/bin/tunnel-client'
TUNNEL = 'tunnel_EXAMPLE_ID'
RUNTIME = ROOT / 'runtime'
RUNTIME.mkdir(mode=0o700, exist_ok=True)
secret = subprocess.run(['/usr/bin/zenity', '--password', '--title=Romans! MCP runtime key', '--text=Unesi Restricted runtime API key (samo Tunnels Read + Use). Ključ se ne čuva.'], capture_output=True, text=True)
if secret.returncode:
    raise SystemExit('Local key entry cancelled; no tunnel started.')
key = secret.stdout.rstrip('\n')
if not key or '\n' in key or key.startswith('sk-admin'):
    raise SystemExit('A non-admin runtime key is required.')
env = {k:v for k,v in os.environ.items() if not k.startswith(('CONTROL_PLANE_', 'OPENAI_', 'MCP_', 'HARPOON_', 'CLOUDFLARED_', 'TUNNEL_CLIENT_', 'HEALTH_', 'LOG_', 'TRACING_'))}
env['CONTROL_PLANE_API_KEY'] = key
base = ['--control-plane.tunnel-id', TUNNEL, '--control-plane.api-key', 'env:CONTROL_PLANE_API_KEY', '--profile-dir', str(ROOT/'profiles')]
url_file = RUNTIME/'demo-health.url'
if url_file.exists():
    url_file.unlink()
child = subprocess.Popen([CLIENT, 'run', '--embedded-mcp-stub', '--embedded-mcp-listen-addr', '127.0.0.1:18765', '--health.listen-addr', '127.0.0.1:0', '--health.url-file', str(url_file), *base], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
def safe_output():
    for line in child.stdout:
        print(line.replace(key, '[REDACTED]'), end='', flush=True)
threading.Thread(target=safe_output, daemon=True).start()
def stop(signum, frame):
    child.terminate()
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    for _ in range(100):
        if child.poll() is not None or url_file.exists():
            break
        time.sleep(.1)
    if child.poll() is None and url_file.exists():
        check = subprocess.run([CLIENT, 'doctor', '--mcp.server-url', 'http://127.0.0.1:18765/mcp', '--explain', *base], env=env, capture_output=True, text=True, timeout=60)
        print(check.stdout.replace(key, '[REDACTED]'), flush=True)
        print(check.stderr.replace(key, '[REDACTED]'), flush=True)
        print('Doctor return code:', check.returncode, flush=True)
    child.wait()
finally:
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=10)
