"""Focused security/regression tests. Fixtures never touch the configured project checkout."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from mcp import Client
from mcp.server import MCPServer
from api import register
from execution import capture,sandbox
from files import Files
from gitops import Git
from jobs import Jobs,gradle_args,LOG_LIMIT
from security import Approval,Denied,Paths,redact,relative


class Allow:
    def require(self,*args):
        pass


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ltc-fixture-test-')
        self.base=Path(self.tmp.name)
        self.repo=self.base/'repo'
        self.repo.mkdir()
        subprocess.run(['/usr/bin/git','init','-q','-b','main',str(self.repo)],check=True)
        self.rawgit('config','user.name','MCP Test')
        self.rawgit('config','user.email','mcp-test@example.invalid')
        (self.repo/'hello.txt').write_text('one\ntwo\nthree\n')
        self.rawgit('add','hello.txt')
        self.rawgit('commit','-q','-m','Fixture')
        self.paths=Paths(self.repo,self.base/'workspace')
        self.approval=Allow()
        self.files=Files(self.paths,self.approval)
        self.git=Git(self.paths,self.approval)
        self.jobs=Jobs(self.paths,self.approval,self.git)

    def tearDown(self):
        for p in self.paths.jobs.iterdir():
            if p.is_dir() and (p/'status.json').exists():
                state=json.loads((p/'status.json').read_text())
                if state['state'] in ('queued','running'):
                    self.jobs.cancel(p.name)
                    self.wait(p.name)
        self.tmp.cleanup()

    def rawgit(self,*args):
        return subprocess.run(['/usr/bin/git','-C',str(self.repo),*args],capture_output=True,text=True,check=True).stdout.strip()

    def wait(self,ident,maximum=10):
        until=time.monotonic()+maximum
        while time.monotonic()<until:
            state=self.jobs.status(ident)
            if state['state'] not in ('queued','running'):
                return state
            time.sleep(.05)
        self.fail('Job did not terminate in time')

    def internal_job(self,code,timeout=3):
        """Test-only worker fixture; no public API accepts code or command vectors."""
        import uuid
        ident=uuid.uuid4().hex
        directory=self.paths.jobs/ident
        directory.mkdir(mode=0o700)
        command=sandbox([], '/tmp',['/usr/bin/python3','-c',code],timeout=max(timeout,1))
        plan={'command':command,'timeout':timeout,'task':'fixture','lock_file':None}
        (directory/'plan.json').write_text(json.dumps(plan))
        (directory/'status.json').write_text(json.dumps({'id':ident,'state':'queued'}))
        worker=subprocess.Popen([sys.executable,str(Path(__file__).with_name('worker.py')),str(directory)],
                         stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                         env={'PATH':'/usr/bin:/bin'},start_new_session=True)
        import threading
        threading.Thread(target=worker.wait,daemon=True).start()
        return ident


class AccessTests(Fixture):
    def test_roots_listing_ranges_metadata(self):
        self.assertEqual({r['id'] for r in self.files.roots()['roots']},{'project','scratch'})
        self.assertIn('hello.txt',[e['name'] for e in self.files.listing()['entries']])
        result=self.files.read('project','hello.txt',2,2)
        self.assertEqual(result['text'],'two')
        self.assertEqual(self.files.metadata('project','hello.txt')['version'],result['version'])

    def test_outside_and_protected_paths(self):
        for path in ('../other','/etc/passwd','a/../../x','.git/config','.env','.ssh/id_rsa',
                     'local.properties','private_key.txt','saves/game.json','a//x','a/./b'):
            with self.subTest(path=path),self.assertRaises(Denied):
                self.files.read('project',path)
        with self.assertRaises(Denied):
            self.files.read('unapproved','hello.txt')

    def test_symlink_and_hardlink(self):
        outside=self.base/'outside'
        outside.write_text('private')
        (self.repo/'escape').symlink_to(outside)
        (self.repo/'escape-dir').symlink_to(self.base,target_is_directory=True)
        os.link(outside,self.repo/'hardlink.txt')
        for path in ('escape','escape-dir/outside','hardlink.txt'):
            with self.subTest(path=path),self.assertRaises(Denied):
                self.files.read('project',path)
        self.assertNotIn('escape',[e['name'] for e in self.files.listing()['entries']])

    def test_injection_rejection(self):
        for path in ('a;touch pwn','$(id)','a`id`','a|id','a\nfile','a\\b','a>file'):
            with self.subTest(path=path),self.assertRaises(Denied):
                relative(path)
        for revision in ('HEAD;id','--exec=id','HEAD:../.env','$(id)'):
            with self.assertRaises(Denied):
                self.git.read('project','show',revision=revision)

    def test_search_bounded_literal(self):
        result=self.files.search('project','two',file_pattern='*.txt',limit=1)
        self.assertEqual(result['matches'][0]['line'],2)
        self.assertTrue(result['truncated'])
        self.assertEqual(self.files.search('project','.*')['matches'],[])
        with self.assertRaises(Denied):
            self.files.search('project','',limit=10000)

    def test_safe_create_edit_and_versions(self):
        meta=self.files.create('scratch','probe.txt','before\n')
        self.files.edit('scratch','probe.txt',meta['version'],'before','after')
        self.assertEqual((self.paths.files/'probe.txt').read_text(),'after\n')
        with self.assertRaises(Denied):
            self.files.edit('scratch','probe.txt',meta['version'],'after','lost')
        with self.assertRaises(Denied):
            self.files.create('scratch','probe.txt','overwrite')

    def test_modification_during_approval(self):
        path=self.paths.files/'hello.txt'
        path.write_text('one\ntwo\nthree\n')
        version=self.files.metadata('scratch','hello.txt')['version']
        class Concurrent:
            def require(self,*args):
                path.write_text('external change\n')
        self.files.approval=Concurrent()
        with self.assertRaises(Denied):
            self.files.edit('scratch','hello.txt',version,'two','new')
        self.assertEqual(path.read_text(),'external change\n')

    def test_original_checkout_always_read_only(self):
        with self.assertRaises(Denied):
            self.files.create('project','new.txt','not permitted')
        version=self.files.metadata('project','hello.txt')['version']
        with self.assertRaises(Denied):
            self.files.edit('project','hello.txt',version,'two','modified')
        self.assertEqual((self.repo/'hello.txt').read_text(),'one\ntwo\nthree\n')

    def test_approval_failure_keeps_reads(self):
        self.files.approval=Approval()
        with patch.dict(os.environ,{},clear=True),patch('desktop_session.environment',return_value={}),self.assertRaises(Denied):
            self.files.create('scratch','no.txt','content')
        self.assertFalse((self.paths.files/'no.txt').exists())
        self.assertEqual(self.files.read('project','hello.txt')['total_lines'],3)

    def test_secrets_redacted_or_denied(self):
        secret='sk-'+('not-a-real-key-'*3)
        text='normal\nAPI_KEY='+secret+'\n-----BEGIN PRIVATE KEY-----\nhidden-body\n-----END PRIVATE KEY-----\n'
        (self.repo/'notes.txt').write_text(text)
        result=self.files.read('project','notes.txt')['text']
        self.assertNotIn(secret,result)
        self.assertNotIn('hidden-body',result)
        self.assertEqual(self.files.search('project',secret)['matches'],[])
        with self.assertRaises(Denied):
            self.files.create('scratch','notes.txt',text)

    def test_root_refusal(self):
        with patch.object(os,'geteuid',return_value=0),self.assertRaises(Denied):
            self.paths.root('project')


class GitTests(Fixture):
    def test_read_allowlist(self):
        for operation in ('status','log','branch','rev_parse','show'):
            self.assertIsInstance(self.git.read('project',operation),dict)
        self.assertIn('two',self.git.read('project','show',paths=['hello.txt'])['output'])
        (self.repo/'hello.txt').write_text('changed\n')
        self.assertIn('changed',self.git.read('project','diff',paths=['hello.txt'])['output'])
        self.assertEqual(self.git.read('project','diff_check',paths=['hello.txt'])['returncode'],0)
        for op in ('reset','clean','stash','merge','checkout','push'):
            with self.assertRaises(Denied):
                self.git.read('project',op)

    def test_no_secret_diff_or_show(self):
        for op in ('diff','show'):
            with self.assertRaises(Denied):
                self.git.read('project',op,paths=['.env'])
        with self.assertRaises(Denied):
            self.git.read('project','diff',paths=[])

    def test_config_commands_never_execute(self):
        marker=self.base/'hook-ran'
        hook=self.repo/'.git/hooks/pre-commit'
        hook.write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
        hook.chmod(0o700)
        self.rawgit('config','diff.external','touch '+str(marker))
        self.rawgit('config','core.fsmonitor','touch '+str(marker))
        self.rawgit('config','include.path',str(self.base/'nonexistent'))
        self.git.read('project','status')
        self.git.read('project','diff',paths=['hello.txt'])
        self.assertFalse(marker.exists())

    def test_branch_worktree_and_safe_commit(self):
        head=self.git.state('project')['head']
        self.git.create_branch('codex/branch-test',head)
        self.assertEqual(self.git.state('project')['branch'],'main')
        created=self.git.create_worktree('codex/worktree-test',head)
        root=created['root']
        self.assertEqual(self.git.state(root)['branch'],'codex/worktree-test')
        meta=self.files.create(root,'new.txt','task file\n')
        result=self.git.commit(root,head,'Add task file',{'new.txt':meta['version']})
        self.assertNotEqual(result['head'],head)
        self.assertEqual(self.git.state('project')['head'],head)
        self.assertEqual(self.rawgit('status','--porcelain'),'')
        self.assertEqual(Git(self.paths,self.approval).state(root)['head'],result['head'])

    def test_expected_head_and_main_commit_denied(self):
        head=self.git.state('project')['head']
        with self.assertRaises(Denied):
            self.git.create_branch('codex/stale','0'*40)
        with self.assertRaises(Denied):
            self.git.create_branch('main',head)
        with self.assertRaises(Denied):
            self.git.commit('project',head,'Disallowed',{})

    def test_branch_change_during_approval_denied(self):
        head=self.git.state('project')['head']
        created=self.git.create_worktree('codex/change-test',head)
        root=created['root']
        meta=self.files.create(root,'new.txt','task content\n')
        self.rawgit('branch','other-branch',head)
        repo=self.paths.root(root)
        class Change:
            def require(self,*args):
                subprocess.run(['/usr/bin/git','-C',str(repo),'switch','-q','other-branch'],check=True)
        self.git.approval=Change()
        with self.assertRaises(Denied):
            self.git.commit(root,head,'Must fail',{'new.txt':meta['version']})
        self.assertEqual(self.git.state(root)['head'],head)

    def test_explicit_identity_without_global_config(self):
        head=self.git.state('project')['head']
        created=self.git.create_worktree('codex/identity-test',head)
        root=created['root']
        meta=self.files.create(root,'identity.txt','task file\n')
        result=self.git.commit(root,head,'Explicit identity',{'identity.txt':meta['version']},
                               'Approved Author','approved@example.invalid')
        self.assertNotEqual(result['head'],head)
        info=self.git.read(root,'show')['output']
        self.assertIn('Approved Author',info)

    def test_network_plans_need_approval_and_no_credentials(self):
        head=self.git.state('project')['head']
        self.rawgit('config','remote.origin.url','https://github.com/example/fixture.git')
        plan=self.git.fetch_plan('project',head)
        self.assertIn('--share-net',plan)
        self.assertNotIn('credential.helper=secret',plan)
        self.rawgit('config','remote.origin.url','https://user:password@github.com/example/fixture.git')
        with self.assertRaises(Denied):
            self.git.fetch_plan('project',head)


class JobTests(Fixture):
    def test_gradle_validation(self):
        args=gradle_args('core_test',['com.example.RouteTest','com.example.RouteTest.findRoute'])
        self.assertIn('--tests',args)
        self.assertIn('--offline',args)
        self.assertIn(':lwjgl3:classes',gradle_args('desktop_classes',[]))
        for task,filters in [('core_test',[]),('core_test',['*']),('core_test',['com.example.*']),('core_test',['a;id']),
                             ('core_test',['$(id)']),('desktop_classes',['com.Test']),
                             ('test',[]),(':android:assembleDebug',[]),(':lwjgl3:run',[])]:
            with self.subTest(task=task,filters=filters),self.assertRaises(Denied):
                gradle_args(task,filters)

    def test_job_start_poll_output(self):
        job=self.jobs.start('diff_check',paths=['hello.txt'],timeout=5)
        result=self.wait(job['id'])
        self.assertEqual(result['state'],'completed')
        self.assertLessEqual(self.jobs.output(job['id'])['retained_bytes'],LOG_LIMIT)
        with self.assertRaises(Denied):
            self.jobs.start('shell',timeout=1)
        with self.assertRaises(Denied):
            self.jobs.output(job['id'],limit=1000000)

    def test_job_cancel(self):
        ident=self.internal_job('import time; print("started",flush=True); time.sleep(30)',timeout=10)
        time.sleep(.25)
        self.jobs.cancel(ident)
        self.assertEqual(self.wait(ident)['state'],'cancelled')

    def test_job_timeout(self):
        ident=self.internal_job('import time; time.sleep(30)',timeout=1)
        self.assertEqual(self.wait(ident)['state'],'timed_out')

    def test_job_log_bound_and_redaction(self):
        secret='sk-'+('fake-key-material-'*3)
        code='print('+repr(secret)+'); print("-----BEGIN PRIVATE KEY-----"); print("private-body"); print("-----END PRIVATE KEY-----"); print(("harmless log line"*10+"\\n")*2000)'
        ident=self.internal_job(code,timeout=5)
        self.wait(ident)
        output=self.jobs.output(ident,limit=16384)
        self.assertLessEqual(output['retained_bytes'],LOG_LIMIT)
        self.assertNotIn(secret,output['text'])
        self.assertNotIn('private-body',output['text'])
        self.assertTrue(output['truncated'])

    def test_sandbox_hides_host_and_environment(self):
        sentinel=self.base/'unrelated-secret'
        sentinel.write_text('unrelated')
        code='import os; from pathlib import Path; print(Path('+repr(str(sentinel))+').exists()); print(os.environ.get("OPENAI_API_KEY","absent")); print(os.getuid())'
        with patch.dict(os.environ,{'OPENAI_API_KEY':'DO-NOT-LEAK'}):
            result=capture(sandbox([],'/tmp',['/usr/bin/python3','-c',code]))
        self.assertEqual(result['returncode'],0,result['output'])
        self.assertIn('False\nabsent',result['output'])
        self.assertNotIn('DO-NOT-LEAK',result['output'])

    def test_resource_limits_and_network_isolation(self):
        code=('import resource,socket; '
              'print(resource.getrlimit(resource.RLIMIT_NPROC)[0]); '
              'print(resource.getrlimit(resource.RLIMIT_NOFILE)[0]); '
              'print(resource.getrlimit(resource.RLIMIT_CORE)[0]); '
              's=socket.socket(); s.settimeout(0.1); '
              'print(s.connect_ex(("192.0.2.1",443)) != 0)')
        result=capture(sandbox([],'/tmp',['/usr/bin/python3','-c',code]))
        self.assertEqual(result['returncode'],0,result['output'])
        self.assertEqual(result['output'].splitlines(),['128','128','0','True'])

    def test_snapshot_gradle_no_live_write(self):
        # Fixed fake wrapper tests transport/isolation only, never the game build.
        (self.repo/'gradlew').write_text('#!/bin/sh\necho fixture-gradle\necho temp > generated.txt\n')
        (self.repo/'gradlew').chmod(0o700)
        job=self.jobs.start('desktop_classes',timeout=10)
        result=self.wait(job['id'])
        self.assertEqual(result['state'],'completed',self.jobs.output(job['id']))
        self.assertIn('fixture-gradle',self.jobs.output(job['id'])['text'])
        self.assertFalse((self.repo/'generated.txt').exists())

    def test_worker_survives_request_object(self):
        job=self.jobs.start('diff_check',paths=['hello.txt'],timeout=5)
        other=Jobs(self.paths,self.approval,self.git)
        self.wait(job['id'])
        self.assertEqual(other.status(job['id'])['state'],'completed')

    def test_worker_survives_starter_process(self):
        (self.repo/'gradlew').write_text('#!/bin/sh\nsleep 1\necho independent-worker\n')
        (self.repo/'gradlew').chmod(0o700)
        code=('from pathlib import Path; from security import Paths; from gitops import Git; '
              'from jobs import Jobs; import json; '
              'p=Paths(Path('+repr(str(self.repo))+'),Path('+repr(str(self.paths.workspace))+')); '
              'a=type("Allow",(),{"require":lambda *a:None})(); '
              'print(json.dumps(Jobs(p,a,Git(p,a)).start("desktop_classes",timeout=10)))')
        started=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,check=True,
                               cwd=str(Path(__file__).parent))
        job=json.loads(started.stdout)
        self.assertEqual(self.wait(job['id'])['state'],'completed')
        self.assertIn('independent-worker',self.jobs.output(job['id'])['text'])

    def test_capacity_and_identifier_guards(self):
        first=self.internal_job('import time; time.sleep(10)',timeout=5)
        second=self.internal_job('import time; time.sleep(10)',timeout=5)
        with self.assertRaises(Denied):
            self.jobs.start('diff_check',paths=['hello.txt'])
        for ident in ('../escape','/tmp','not-a-job'):
            with self.assertRaises(Denied):
                self.jobs.status(ident)
        self.jobs.cancel(first)
        self.jobs.cancel(second)

    def test_lost_worker_reported_without_replay(self):
        import uuid
        ident=uuid.uuid4().hex
        directory=self.paths.jobs/ident
        directory.mkdir(mode=0o700)
        (directory/'status.json').write_text(json.dumps({'id':ident,'state':'running',
             'worker_pid':os.getpid(),'worker_start':'impossible-start-time'}))
        self.assertEqual(self.jobs.status(ident)['state'],'interrupted')


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_tools_discoverable(self):
        with tempfile.TemporaryDirectory(prefix='ltc-fixture-discovery-') as tmp:
            repo=Path(tmp)/'repo'
            repo.mkdir()
            subprocess.run(['/usr/bin/git','init','-q',str(repo)],check=True)
            mcp=MCPServer('Phase 2 fixture')
            register(mcp,repo,Path(tmp)/'workspace')
            async with Client(mcp) as client:
                tools=(await client.list_tools()).tools
                names={t.name for t in tools}
                self.assertEqual(len(names),36)
                self.assertIn('start_job',names)
                for t in tools:
                    if t.name in ('create_text_file','edit_text_file','git_create_branch','git_create_worktree','git_commit','start_job','cancel_job'):
                        self.assertFalse(t.annotations.read_only_hint)
                result=await client.call_tool('list_directory',{'root':'project'})
                self.assertFalse(result.is_error)


if __name__=='__main__':
    unittest.main()
