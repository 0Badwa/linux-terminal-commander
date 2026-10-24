"""Temporary per-session supervisor, bounded logs/TTL; never a second daemon."""
import errno
import json
import os
from pathlib import Path
import pty
import selectors
import signal
import subprocess
import sys
import time

from commander_policy import atomic_json
from commander_processes import LOG_LIMIT, identity, process_tree
from security import nonroot, redact


def run(path):
    nonroot()
    path = Path(path)
    os.umask(0o077)
    # Adopt daemonizing descendants so cancellation can still clean our own tree.
    import ctypes
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
        raise RuntimeError('Subreaper unavailable; refuse untracked child lifetimes.')
    plan = json.loads((path / 'plan.json').read_text())
    (path / 'plan.json').unlink()  # Commands/environment never become retained logs.
    state = json.loads((path / 'status.json').read_text())
    state.update(state='running', worker_pid=os.getpid(), worker_start=identity(os.getpid()), started_at=time.time())
    output = {'base': 0, 'end': 0, 'records': []}
    buffers = {'stdout': bytearray(), 'stderr': bytearray(), 'pty': bytearray()}
    private = {key: False for key in buffers}
    overflow = {key: False for key in buffers}
    p = None
    master = slave = fifo = None
    produced = 0
    outcome = 'completed'
    last_activity = time.monotonic()
    dirty = False

    def emit(stream, raw):
        nonlocal dirty
        text = raw.decode('utf-8', 'replace')
        if '-----BEGIN ' in text and 'PRIVATE KEY-----' in text:
            private[stream] = True
        clean = '[REDACTED]\n' if private[stream] else redact(text)
        if '-----END ' in text and 'PRIVATE KEY-----' in text:
            private[stream] = False
        if not clean:
            return
        output['records'].append({'offset': output['end'], 'stream': stream, 'text': clean})
        output['end'] += len(clean.encode())
        while (output['end']-output['base'] > LOG_LIMIT or len(output['records']) > 2048) and output['records']:
            removed = output['records'].pop(0)
            output['base'] = removed['offset'] + len(removed['text'].encode())
        dirty = True

    def consume(stream, chunk):
        for part in chunk.splitlines(keepends=True):
            if not overflow[stream]:
                buffers[stream].extend(part)
                if len(buffers[stream]) > 4096:
                    buffers[stream].clear()
                    overflow[stream] = True
            if part.endswith(b'\n'):
                emit(stream, b'[Oversized output line omitted]\n' if overflow[stream] else bytes(buffers[stream]))
                buffers[stream].clear()
                overflow[stream] = False

    def save():
        nonlocal dirty
        state.update(output_base=output['base'], output_end=output['end'], truncated=output['base'] > 0)
        atomic_json(path / 'output.json', output)
        atomic_json(path / 'status.json', state)
        dirty = False

    try:
        fifo = os.open(path / 'input', os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW)
        kwargs = dict(cwd=plan['cwd'], env=plan['environment'], close_fds=True, start_new_session=True)
        if plan['pty']:
            master, slave = pty.openpty()
            if '--new-session' in plan['argv']:
                plan['argv'].remove('--new-session')
            def controlling_terminal():
                import fcntl
                import termios
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            kwargs.update(start_new_session=False, preexec_fn=controlling_terminal)
            p = subprocess.Popen(plan['argv'], stdin=slave, stdout=slave, stderr=slave, **kwargs)
            os.close(slave)
            slave = None
            os.set_blocking(master, False)
            input_fd = master
            streams = [(master, 'pty')]
        else:
            p = subprocess.Popen(plan['argv'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
            input_fd = p.stdin.fileno()
            os.set_blocking(input_fd, False)
            streams = [(p.stdout.fileno(), 'stdout'), (p.stderr.fileno(), 'stderr')]
        state.update(pid=p.pid, process_start=identity(p.pid), process_group=p.pid)
        save()
        deadline = time.monotonic() + plan['timeout']
        last_save = time.monotonic()
        with selectors.DefaultSelector() as sel:
            sel.register(fifo, selectors.EVENT_READ, 'input')
            for fd, stream in streams:
                sel.register(fd, selectors.EVENT_READ, stream)
            while p.poll() is None or any(k.data != 'input' for k in sel.get_map().values()):
                now = time.monotonic()
                if (path / 'cancel').exists():
                    outcome = 'cancelled'
                    break
                if now >= deadline:
                    outcome = 'timed_out'
                    break
                if now-last_activity >= plan['idle_timeout']:
                    outcome = 'idle_timeout'
                    break
                for key, _ in sel.select(.05):
                    try:
                        chunk = os.read(key.fd, 4096)
                    except OSError as exc:
                        if exc.errno == errno.EIO:
                            chunk = b''
                        elif exc.errno == errno.EAGAIN:
                            continue
                        else:
                            raise
                    if key.data == 'input':
                        if chunk:
                            try:
                                if os.write(input_fd, chunk) != len(chunk):
                                    state['input_error'] = 'Partial process input; do not retry blindly.'
                            except (BrokenPipeError, BlockingIOError):
                                state['input_error'] = 'Process input unavailable; do not retry blindly.'
                            last_activity = now
                        continue
                    if not chunk:
                        sel.unregister(key.fd)
                    else:
                        produced += len(chunk)
                        last_activity = now
                        consume(key.data, chunk)
                # PTY prompts commonly lack newlines. Sanitize partial prompt text;
                # redaction is heuristic, never a claim to secure host command output.
                if plan['pty'] and now-last_activity > .15 and buffers['pty']:
                    emit('pty', bytes(buffers['pty']))
                    buffers['pty'].clear()
                if dirty and now-last_save > .1:
                    save()
                    last_save = now
                if produced > 8*1024*1024:
                    outcome = 'output_limit'
                    break
        if p.poll() is None or outcome != 'completed':
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                p.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=2)
        # Descendants inheriting this process group are not left running after Bash.
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for stream, data in buffers.items():
            if data or overflow[stream]:
                emit(stream, b'[Oversized output line omitted]\n' if overflow[stream] else bytes(data))
        state.update(state=outcome, exit_code=p.returncode, ended_at=time.time(), emitted_bytes=produced)
    except BaseException:
        if p is not None and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                pass
        state.update(state='failed', error='Session supervisor failed safely; no command retry.', ended_at=time.time())
    finally:
        # A trusted command can call setsid. Subreaper ancestry plus start-time
        # checks keep cleanup limited to descendants of this exact supervisor.
        for _ in range(3):
            descendants = process_tree(os.getpid())
            if not descendants:
                break
            for child in reversed(descendants):
                if identity(child['pid']) == child['start']:
                    try:
                        os.kill(child['pid'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            time.sleep(.02)
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
        save()
        for fd in (master, slave, fifo):
            if fd is not None:
                os.close(fd)
        if p is not None:
            for stream in (p.stdin, p.stdout, p.stderr):
                if stream is not None:
                    stream.close()
        # No automatic deletion of host files. Only the generated snapshot is cleaned.
        import shutil
        if (path / 'snapshot').exists():
            shutil.rmtree(path / 'snapshot')


if __name__ == '__main__':
    run(sys.argv[1])
