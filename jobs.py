"""Bounded independent job workers; only internally constructed plans are accepted."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

from execution import capture, sandbox
from security import Denied, MAX_FILE, ProcessLock, component_allowed, private_directory, relative


TASKS = {'core_test', 'desktop_classes', 'diff_check', 'git_fetch', 'git_push'}
FILTER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z')
LOG_LIMIT = 131072
JOB_LIMIT = 30


def gradle_args(task, tests):
    if task=='core_test':
        if not 1<=len(tests)<=10 or any(not FILTER.fullmatch(f) or f in ('*','**') for f in tests):
            raise Denied('Targeted core tests need 1..10 package-qualified class/method filters.')
        result=[':core:test']
        for f in tests:
            result+=['--tests',f]
    elif task=='desktop_classes' and not tests:
        result=[':lwjgl3:classes']
    else:
        raise Denied('Only targeted :core:test and :lwjgl3:classes are permitted.')
    return ['/bin/sh','/work/gradlew',*result,'--offline','--no-daemon','--max-workers=1',
            '--console=plain','-Dorg.gradle.jvmargs=-Xmx512m -XX:MaxMetaspaceSize=256m',
            '-Dorg.gradle.vfs.watch=false']


class Jobs:
    def __init__(self,paths,approval,git):
        self.paths,self.approval,self.git=paths,approval,git
        self.lock=ProcessLock(paths.workspace/'job-start.lock')

    def _directory(self,job_id):
        if not re.fullmatch(r'[0-9a-f]{32}',job_id):
            raise Denied('Invalid job id.')
        path=self.paths.jobs/job_id
        if path.is_symlink() or not path.is_dir():
            raise Denied('Unknown job id.')
        return path

    def _status(self,directory):
        state=directory/'status.json'
        if state.is_symlink() or state.stat().st_size>16384:
            raise Denied('Invalid job state.')
        result=json.loads(state.read_text())
        if result.get('state')=='running' and result.get('worker_pid'):
            try:
                ticks=Path('/proc',str(int(result['worker_pid'])),'stat').read_text().rsplit(')',1)[1].split()[19]
            except (FileNotFoundError,ProcessLookupError):
                ticks=None
            if ticks!=result.get('worker_start'):
                result={**result,'state':'interrupted','error':'Job worker no longer exists; operation was not retried.'}
        elif result.get('state')=='queued' and time.time()-result.get('created_at',time.time())>15:
            result={**result,'state':'interrupted','error':'Job worker did not publish a running state.'}
        return result

    def _capacity(self):
        directories=[]
        active=0
        for p in self.paths.jobs.iterdir():
            if p.is_dir() and not p.is_symlink() and re.fullmatch(r'[0-9a-f]{32}',p.name):
                state=self._status(p)
                if state['state'] in ('queued','running'):
                    active+=1
                else:
                    directories.append((p.stat().st_mtime,p))
        if active>=2:
            raise Denied('At most two jobs may run concurrently.')
        while len(directories)+active>=JOB_LIMIT or directories and time.time()-min(directories)[0]>86400:
            _,p=min(directories)
            directories.remove(min(directories))
            shutil.rmtree(p)

    def _snapshot(self,root,destination):
        """Copy through no-follow descriptors, never bind the live source writable."""
        destination.mkdir(mode=0o700)
        pending=[()]
        count=total=scanned=0
        manifest=[]
        while pending:
            parts=pending.pop()
            fd=self.paths.directory_fd(root,parts)
            try:
                with os.scandir(fd) as entries:
                    for e in entries:
                        scanned+=1
                        if scanned>5000:
                            raise Denied('Snapshot entry limit exceeded.')
                        if not component_allowed(e.name) or e.name in ('build','.gradle','node_modules') or e.is_symlink():
                            continue
                        rel=(*parts,e.name)
                        if len(rel)>12:
                            raise Denied('Snapshot depth limit exceeded.')
                        target=destination.joinpath(*rel)
                        if e.is_dir(follow_symlinks=False):
                            target.mkdir(mode=0o700)
                            pending.append(rel)
                        elif e.is_file(follow_symlinks=False):
                            s=e.stat(follow_symlinks=False)
                            if s.st_nlink!=1 or s.st_size>16*MAX_FILE:
                                continue
                            source=os.open(e.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                            try:
                                before=os.fstat(source)
                                if before.st_ino!=s.st_ino or before.st_nlink!=1:
                                    raise Denied('Snapshot source changed.')
                                with os.fdopen(os.dup(source),'rb') as f:
                                    data=f.read(16*MAX_FILE+1)
                                after=os.fstat(source)
                                if len(data)>16*MAX_FILE or (before.st_mtime_ns,before.st_ctime_ns,before.st_size)!=(after.st_mtime_ns,after.st_ctime_ns,after.st_size):
                                    raise Denied('Snapshot source changed while copying.')
                                count+=1
                                total+=len(data)
                                if count>3000 or total>128*MAX_FILE:
                                    raise Denied('Snapshot size limit exceeded.')
                                target.write_bytes(data)
                                target.chmod(0o700 if s.st_mode&0o111 else 0o600)
                                import hashlib
                                manifest.append(('/'.join(rel),hashlib.sha256(data).hexdigest()))
                            finally:
                                os.close(source)
            finally:
                os.close(fd)
        import hashlib
        digest=hashlib.sha256(json.dumps(sorted(manifest)).encode()).hexdigest()
        return {'files':count,'bytes':total,'source_manifest_sha256':digest}

    def start(self,task,root='project',tests=None,paths=None,expected_head='',timeout=300):
        if task not in TASKS or not 1<=timeout<=600:
            raise Denied('Unknown job task or timeout outside 1..600 seconds.')
        tests,paths=tests or [],paths or []
        self.paths.root(root)
        # Validate before approvals or writes.
        if task in ('core_test','desktop_classes'):
            _, common = self.git._layout(root)
            if common != self.paths.project / '.git':
                raise Denied('Gradle presets are restricted to the configured primary project checkout.')
            if paths or expected_head:
                raise Denied('Gradle jobs accept only root, task, test filters and timeout.')
            argv=gradle_args(task,tests)
        elif tests:
            raise Denied('Test filters only belong to core_test.')
        if task=='diff_check':
            self.git._paths(paths)
            for path in paths:
                p=self.paths.root(root)/path
                if p.exists() or p.is_symlink():
                    self.paths.read(root,path)
        if task in ('git_fetch','git_push') and paths:
            raise Denied('Network Git jobs do not accept paths.')
        with self.lock:
            self._capacity()
            job_id=uuid.uuid4().hex
            directory=private_directory(self.paths.jobs/job_id)
            try:
                snapshot=None
                if task in ('core_test','desktop_classes'):
                    snapshot=self._snapshot(root,directory/'source')
                    self.approval.require('start_gradle_job',{'root':root,'task':task,'tests':tests,
                         'timeout_seconds':timeout,**snapshot,'network':'disabled','live_project':'read only'})
                    command=sandbox([(directory/'source','/source',False)],'/work',
                                    ['/usr/bin/python3','/gradle_runner.py',*argv],
                                    cache=self.paths.cache,timeout=timeout)
                elif task=='diff_check':
                    command=self.git.command(root,['diff','--check','--no-ext-diff','--no-textconv',
                                                   '--ignore-submodules=all','--',*paths])
                elif task=='git_fetch':
                    command=self.git.fetch_plan(root,expected_head)
                else:
                    command=self.git.push_plan(root,expected_head)
                plan={'command':command,'timeout':timeout,'task':task,'root':root,'snapshot':snapshot,
                      'lock_file':str(self.paths.lock.path) if task in ('git_fetch','git_push') else None}
                (directory/'plan.json').write_text(json.dumps(plan))
                (directory/'plan.json').chmod(0o600)
                state={'id':job_id,'task':task,'root':root,'state':'queued','created_at':time.time(),
                       'timeout_seconds':timeout,'log_limit_bytes':LOG_LIMIT}
                (directory/'status.json').write_text(json.dumps(state))
                (directory/'status.json').chmod(0o600)
                worker=subprocess.Popen([sys.executable,str(Path(__file__).with_name('worker.py')),str(directory)],
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},start_new_session=True,close_fds=True)
                threading.Thread(target=worker.wait,daemon=True).start()
                return state
            except BaseException:
                shutil.rmtree(directory)
                raise

    def status(self,job_id):
        return self._status(self._directory(job_id))

    def output(self,job_id,offset=0,limit=8192):
        if offset<0 or not 1<=limit<=16384:
            raise Denied('Output offset must be nonnegative; limit must be 1..16384 bytes.')
        directory=self._directory(job_id)
        state=self._status(directory)
        p=directory/'output.txt'
        data=p.read_bytes() if p.exists() and not p.is_symlink() else b''
        data=data[-LOG_LIMIT:]
        # Offset is relative to the retained window, and polling is explicitly bounded.
        result=data[offset:offset+limit].decode('utf-8','replace')
        return {'text':result,'next_offset':offset+len(data[offset:offset+limit]),
                'retained_bytes':len(data),'window_generation':state.get('log_generation',0),
                'truncated':state.get('log_truncated',False),'state':state['state']}

    def cancel(self,job_id):
        directory=self._directory(job_id)
        state=self._status(directory)
        if state['state'] not in ('queued','running'):
            return state
        # Marker, never a caller-controlled PID or a shell kill command.
        try:
            fd=os.open(directory/'cancel',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            os.close(fd)
        except FileExistsError:
            pass
        return {'id':job_id,'cancel_requested':True}
