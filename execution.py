"""Fixed executable sandbox and bounded foreground command capture."""
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from security import Denied, MAX_OUTPUT, nonroot, redact


def sandbox(mounts, cwd, argv, network=False, cache=None, timeout=30):
    """No host home, /tmp, process namespace, hooks, or inherited secrets."""
    nonroot()
    if not Path('/usr/bin/bwrap').is_file():
        raise Denied('bubblewrap is required; execution is disabled.')
    cmd = ['/usr/bin/prlimit', '--core=0', '--nofile=128',
           '--fsize=67108864', '--as=6442450944', '--cpu=' + str(timeout), '--',
           '/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
           '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr',
           '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
           '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
           '--size', '134217728', '--tmpfs', '/tmp', '--dir', '/home',
           '--dir', '/home/mcp', '--clearenv', '--setenv', 'HOME', '/home/mcp',
           '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
           '--setenv', 'GIT_CONFIG_NOSYSTEM', '1', '--setenv', 'GIT_CONFIG_GLOBAL', '/dev/null',
           '--setenv', 'GIT_OPTIONAL_LOCKS', '0', '--setenv', 'GIT_TERMINAL_PROMPT', '0',
           '--setenv', 'GIT_ALLOW_PROTOCOL', 'https', '--setenv', 'GIT_ATTR_NOSYSTEM', '1']
    if network:
        cmd += ['--share-net']
        for p in ('/etc/resolv.conf','/etc/hosts','/etc/nsswitch.conf','/etc/ssl/certs'):
            if Path(p).exists():
                cmd += ['--ro-bind',p,p]
    else:
        # Local system Java configuration has no user secrets.
        for p in ('/etc/java-21-openjdk','/etc/java-17-openjdk','/etc/alternatives'):
            if Path(p).exists():
                cmd += ['--ro-bind',p,p]
    for source, destination, write in mounts:
        cmd += ['--bind' if write else '--ro-bind',str(source),str(destination)]
    if cache:
        cmd += ['--ro-bind',str(cache),'/cache-seed','--size','268435456','--tmpfs','/gradle-cache',
                '--size','268435456','--tmpfs','/work',
                '--setenv','GRADLE_USER_HOME','/gradle-cache',
                '--ro-bind',str(Path(__file__).with_name('gradle_runner.py')),'/gradle_runner.py']
    # Apply the process cap after entering the private user namespace, so the
    # desktop user's pre-existing threads do not exhaust the sandbox allowance.
    cmd += ['--chdir',str(cwd),'--','/usr/bin/prlimit','--nproc=128','--',*argv]
    return cmd


def capture(command, timeout=15, maximum=MAX_OUTPUT):
    nonroot()
    p = subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                         start_new_session=True)
    data = bytearray()
    deadline = time.monotonic() + timeout
    truncated = False
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout,selectors.EVENT_READ)
            while sel.get_map():
                if time.monotonic() > deadline:
                    raise Denied('Operation timed out; process group terminated.')
                for key,_ in sel.select(.1):
                    chunk = os.read(key.fileobj.fileno(),8192)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    else:
                        remaining=maximum-len(data)
                        data.extend(chunk[:remaining])
                        if len(chunk)>remaining:
                            truncated=True
                            os.killpg(p.pid,signal.SIGKILL)
                            break
                if truncated:
                    break
        code=p.wait(timeout=max(.1,deadline-time.monotonic()))
        # Drop a truncated final line, so a partial token cannot escape filtering.
        if truncated:
            data=data[:data.rfind(b'\n')+1]
        return {'returncode':code,'output':redact(data.decode('utf-8','replace')),
                'truncated':truncated}
    finally:
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGKILL)
            p.wait()
        p.stdout.close()
