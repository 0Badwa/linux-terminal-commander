"""One temporary independent supervisor per bounded job; never installed as a service."""
import json
import fcntl
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from jobs import LOG_LIMIT
from security import nonroot, redact


def atomic(path,text):
    temporary=path.with_suffix('.new')
    temporary.write_text(text)
    temporary.chmod(0o600)
    os.replace(temporary,path)


def run(directory):
    nonroot()
    directory=Path(directory)
    plan=json.loads((directory/'plan.json').read_text())
    state=json.loads((directory/'status.json').read_text())
    p=None
    retained=bytearray()
    pending=bytearray()
    dropped=0
    private=False
    overflow=False
    produced=0
    lockfd=None
    def save():
        state['log_truncated']=dropped>0
        state['log_generation']=dropped
        atomic(directory/'output.txt',retained.decode('utf-8','replace'))
        atomic(directory/'status.json',json.dumps(state))
    def line(raw):
        nonlocal private,dropped
        text=raw.decode('utf-8','replace')
        if '-----BEGIN ' in text and 'PRIVATE KEY-----' in text:
            private=True
        clean='[REDACTED]\n' if private else redact(text+'\n')
        if '-----END ' in text and 'PRIVATE KEY-----' in text:
            private=False
        retained.extend(clean.encode())
        if len(retained)>LOG_LIMIT:
            excess=len(retained)-LOG_LIMIT
            cut=retained.find(b'\n',excess)
            cut=cut+1 if cut>=0 else excess
            del retained[:cut]
            dropped+=cut
    try:
        # /proc start time identifies this exact worker across PID reuse.
        ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
        state.update(state='running',started_at=time.time(),worker_pid=os.getpid(),worker_start=ticks)
        save()
        if plan.get('lock_file'):
            lockfd=os.open(plan['lock_file'],os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            try:
                fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('Another repository operation is active.') from None
        p=subprocess.Popen(plan['command'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
             stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
             start_new_session=True,close_fds=True)
        deadline=time.monotonic()+plan['timeout']
        outcome='completed'
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout,selectors.EVENT_READ)
            while sel.get_map() or p.poll() is None:
                if (directory/'cancel').exists():
                    outcome='cancelled'
                    break
                if time.monotonic()>deadline:
                    outcome='timed_out'
                    break
                for key,_ in sel.select(.1):
                    chunk=os.read(key.fileobj.fileno(),8192)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        continue
                    produced+=len(chunk)
                    for piece in chunk.splitlines(keepends=True):
                        if not overflow:
                            pending.extend(piece)
                            if len(pending)>4096:
                                pending.clear()
                                overflow=True
                        if piece.endswith(b'\n'):
                            line(b'[Oversized log line omitted]' if overflow else pending.rstrip(b'\r\n'))
                            pending.clear()
                            overflow=False
                    if produced>8*1024*1024:
                        outcome='output_limit'
                        break
                save()
                if outcome=='output_limit':
                    break
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGKILL)
        code=p.wait()
        if pending and not overflow:
            line(pending)
        state.update(state=outcome if outcome!='completed' or code==0 else 'failed',returncode=code)
    except BaseException:
        state.update(state='failed',error='Job supervisor or isolated command failed; no unsafe fallback used.')
    finally:
        if p is not None:
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGKILL)
                p.wait()
            p.stdout.close()
        state['finished_at']=time.time()
        if lockfd is not None:
            os.close(lockfd)
        save()
        # Bound scratch retention; logs/state survive, copied build trees do not.
        import shutil
        shutil.rmtree(directory/'source',ignore_errors=True)


if __name__=='__main__':
    run(sys.argv[1])
