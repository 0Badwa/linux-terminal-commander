"""Focused root enrollment/startup tests; all mutations use disposable fixtures."""
import json
import os
from pathlib import Path
import stat
import subprocess
import unittest
from unittest.mock import patch

from files import Files
from gitops import Git
from jobs import Jobs
from roots import git_layout, load
from security import Denied, Paths
from service_runner import build_environment, command
from setup_runtime_secret import store_secret
from desktop_session import environment
from test_phase2 import Allow, Fixture


class RootTests(Fixture):
    def setUp(self):
        super().setUp()
        self.service=self.base/'service'
        self.service.mkdir(mode=0o700)
        self.config=self.service/'approved_roots.json'
        self.other=self.base/'other'
        self.other.mkdir()
        subprocess.run(['/usr/bin/git','init','-q','-b','main',str(self.other)],check=True)
        (self.other/'readme.txt').write_text('other project\n')
        self.entry={'id':'dev-other','path':str(self.other),'common_dir':str(self.other/'.git'),'kind':'repository'}

    def config_write(self,entries):
        self.config.write_text(json.dumps({'version':1,'roots':entries}))
        self.config.chmod(0o600)

    def read_config(self):
        return load(self.config,self.repo,self.service,development_locations=(self.base,),codex_worktrees=self.base/'codex-worktrees')

    def configured_paths(self,entries=None):
        self.config_write(entries or [self.entry])
        return Paths(self.repo,self.service/'workspace',root_config=self.config,
                     development_locations=(self.base,),codex_worktrees=self.base/'codex-worktrees')

    def test_exact_named_roots_preserve_ids(self):
        paths=self.configured_paths()
        self.assertEqual(set(paths.roots),{'project','scratch','dev-other'})
        self.assertEqual(paths.root('project'),self.repo)
        self.assertEqual(paths.root('dev-other'),self.other)
        self.assertEqual(Files(paths,Allow()).read('dev-other','readme.txt')['text'],'other project')

    def test_missing_root_rejected(self):
        self.config_write([{**self.entry,'path':str(self.base/'absent')}])
        with self.assertRaises(Denied):self.read_config()

    def test_duplicate_ids_paths_keys_and_reserved(self):
        for entries in ([self.entry,self.entry],
                        [self.entry,{**self.entry,'id':'another-id'}],
                        [{**self.entry,'id':'project'}],[{**self.entry,'id':'scratch'}],
                        [{**self.entry,'id':'worktree:pretend'}]):
            self.config_write(entries)
            with self.subTest(entries=entries),self.assertRaises(Denied):self.read_config()
        self.config.write_text('{"version":1,"version":1,"roots":[]}')
        with self.assertRaises(Denied):self.read_config()

    def test_broad_and_service_roots_rejected(self):
        for path in (self.base,self.service,self.service/'workspace',Path('/tmp'),Path('/home'),Path('/home')):
            self.config_write([{**self.entry,'path':str(path)}])
            with self.subTest(path=path),self.assertRaises(Denied):self.read_config()

    def test_outside_locations_and_sensitive_names(self):
        for path in (self.base/'nested'/'repo',self.base/'private-secrets',self.base/'.ssh'):
            path.mkdir(parents=True)
            self.config_write([{**self.entry,'path':str(path)}])
            with self.subTest(path=path),self.assertRaises(Denied):self.read_config()

    def test_symlink_root_and_config(self):
        link=self.base/'link'
        link.symlink_to(self.other,target_is_directory=True)
        self.config_write([{**self.entry,'path':str(link)}])
        with self.assertRaises(Denied):self.read_config()
        self.config_write([self.entry])
        moved=self.config.with_suffix('.real')
        self.config.rename(moved)
        self.config.symlink_to(moved)
        with self.assertRaises(Denied):self.read_config()

    def test_config_permissions_and_unknown_fields(self):
        self.config_write([self.entry])
        self.config.chmod(0o666)
        with self.assertRaises(Denied):self.read_config()
        self.config_write([{**self.entry,'writable':True}])
        with self.assertRaises(Denied):self.read_config()

    def test_symlink_escape_protected_files_and_traversal(self):
        paths=self.configured_paths()
        files=Files(paths,Allow())
        outside=self.base/'outside.txt'
        outside.write_text('not accessible')
        (self.other/'escape.txt').symlink_to(outside)
        for path in ('escape.txt','../outside.txt','.git/HEAD','.env','token.key','.token','tokens.json','auth-token.txt','api_key.txt','.ssh/id_rsa'):
            with self.subTest(path=path),self.assertRaises(Denied):files.read('dev-other',path)

    def test_new_roots_stay_read_only(self):
        paths=self.configured_paths()
        files=Files(paths,Allow())
        with self.assertRaises(Denied):files.create('dev-other','new.txt','not allowed')
        git=Git(paths,Allow())
        with self.assertRaises(Denied):git.command('dev-other',['fetch'],write=True)
        with self.assertRaises(Denied):git.fetch_plan('dev-other','0'*40)
        with self.assertRaises(Denied):Jobs(paths,Allow(),git).start('desktop_classes','dev-other')
        self.assertEqual(files.read('dev-other','readme.txt')['text'],'other project')

    def test_root_disappears_or_is_replaced(self):
        paths=self.configured_paths()
        renamed=self.other.with_name('other-old')
        self.other.rename(renamed)
        with self.assertRaises(Denied):paths.root('dev-other')
        self.other.mkdir()
        with self.assertRaises(Denied):paths.root('dev-other')

    def test_git_common_mismatch_and_invalid_git(self):
        self.config_write([{**self.entry,'common_dir':str(self.repo/'.git')}])
        with self.assertRaises(Denied):self.read_config()
        (self.other/'.git/HEAD').unlink()
        self.config_write([self.entry])
        with self.assertRaises(Denied):self.read_config()

    def test_existing_primary_worktree_read_status(self):
        worktree=self.base/'m8-trade'
        self.rawgit('worktree','add','-q','--detach',str(worktree),'HEAD')
        entry={'id':'primary-test-trade','path':str(worktree),
               'common_dir':str(self.repo/'.git'),'kind':'primary_worktree'}
        paths=self.configured_paths([entry])
        git=Git(paths,Allow())
        self.assertEqual(git.state('primary-test-trade')['head'],self.rawgit('rev-parse','HEAD'))
        self.assertIsNone(git.state('primary-test-trade')['branch'])
        with self.assertRaises(Denied):Files(paths,Allow()).create('primary-test-trade','no.txt','not allowed')

    def test_worktree_backlink_tamper_refused_on_next_operation(self):
        worktree=self.base/'m8-trade'
        self.rawgit('worktree','add','-q','--detach',str(worktree),'HEAD')
        entry={'id':'primary-test-trade','path':str(worktree),'common_dir':str(self.repo/'.git'),'kind':'primary_worktree'}
        paths=self.configured_paths([entry])
        admin=Path((worktree/'.git').read_text().strip()[8:])
        (admin/'gitdir').write_text(str(self.base/'wrong'/'.git'))
        with self.assertRaises(Denied):paths.root('primary-test-trade')

    def test_revoke_root_after_reload(self):
        paths=self.configured_paths()
        self.assertIn('dev-other',paths.roots)
        self.config_write([])
        reloaded=Paths(self.repo,self.service/'workspace',root_config=self.config,development_locations=(self.base,))
        self.assertEqual(set(reloaded.roots),{'project','scratch'})
        with self.assertRaises(Denied):reloaded.root('dev-other')


class ServiceTests(unittest.TestCase):
    def test_official_doctor_accepts_file_key_without_eager_env_profile(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            (base/'fixture.yaml').write_text('config_version: 1\ncontrol_plane:\n  base_url: https://api.openai.com\n  tunnel_id: tunnel_0123456789abcdef0123456789abcdef\nhealth:\n  listen_addr: 127.0.0.1:0\nmcp:\n  commands:\n    - channel: main\n      command: /usr/bin/python3\n')
            key=base/'runtime-key'
            fake='FAKE_RUNTIME_KEY_FOR_LOCAL_DOCTOR_ONLY'
            key.write_text(fake)
            key.chmod(0o600)
            r=subprocess.run([str(__import__('settings').home_dir() / '.local/bin/tunnel-client'),'doctor','--profile','fixture',
                '--profile-dir',str(base),'--control-plane.api-key','file:'+str(key)],
                capture_output=True,text=True,timeout=15,env={'PATH':'/usr/bin:/bin'})
            self.assertEqual(r.returncode,0,'Official doctor should accept the explicit file reference')
            self.assertNotIn(fake,r.stdout+r.stderr)

    def test_desktop_metadata_environment_never_copies_secrets(self):
        result=environment({'DISPLAY':':0','CONTROL_PLANE_API_KEY':'not-real','UNRELATED_PRIVATE_DATA':'not-copied'})
        self.assertEqual(result,{'DISPLAY':':0'})

    def test_no_graphical_session_fails_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            empty=subprocess.CompletedProcess([],0,'','')
            with patch('desktop_session.subprocess.run',return_value=empty):
                result=environment({},runtime=tmp)
            self.assertNotIn('DISPLAY',result)
            self.assertNotIn('WAYLAND_DISPLAY',result)

    def test_owned_wayland_socket_available_after_login(self):
        import tempfile,socket
        with tempfile.TemporaryDirectory() as tmp:
            with socket.socket(socket.AF_UNIX) as local:
                local.bind(str(Path(tmp)/'wayland-0'))
                result=environment({},runtime=tmp)
                self.assertEqual(result['WAYLAND_DISPLAY'],'wayland-0')

    def test_x11_local_session_metadata(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            runtime=Path(tmp)
            (runtime/'gdm').mkdir()
            (runtime/'gdm'/'Xauthority').touch()
            responses=[subprocess.CompletedProcess([],0,'3\n',''),
                       subprocess.CompletedProcess([],0,f'User={os.getuid()}\nActive=yes\nRemote=no\nType=x11\nDisplay=:0\n','')]
            with patch('desktop_session.subprocess.run',side_effect=responses):
                result=environment({},runtime=tmp)
            self.assertEqual(result['DISPLAY'],':0')

    def test_minimal_environment_excludes_secrets_and_overrides(self):
        data=build_environment({'CONTROL_PLANE_API_KEY':'not-real','OPENAI_API_KEY':'not-real',
                                'MCP_COMMAND':'untrusted','TUNNEL_CLIENT_CONFIG':'untrusted',
                                'DISPLAY':':0','XDG_RUNTIME_DIR':'/run/user/1000'})
        self.assertNotIn('CONTROL_PLANE_API_KEY',data)
        self.assertNotIn('OPENAI_API_KEY',data)
        self.assertNotIn('MCP_COMMAND',data)
        self.assertNotIn('TUNNEL_CLIENT_CONFIG',data)
        self.assertEqual(data['DISPLAY'],':0')

    def test_secret_reference_never_key_value_in_argv(self):
        args=command(Path('/run/user/1000/credentials/linux-terminal-commander.service'))
        self.assertIn('file:/run/user/1000/credentials/linux-terminal-commander.service/runtime-api-key',args)
        self.assertIn('127.0.0.1:0',args)
        self.assertNotIn('--allow-remote-ui',args)

    def test_local_secret_modes_and_no_overwrite(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'private'/'runtime-api-key'
            store_secret(target,'FAKE-RUNTIME-KEY-FOR-TESTS-ONLY')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode),0o700)
            with self.assertRaises(FileExistsError):store_secret(target,'ANOTHER-FAKE-TEST-KEY-ONLY')
            self.assertEqual(target.read_text(),'FAKE-RUNTIME-KEY-FOR-TESTS-ONLY')

    def test_local_secret_symlink_admin_and_root_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            real=base/'real'
            real.mkdir(mode=0o700)
            (base/'link').symlink_to(real,target_is_directory=True)
            with self.assertRaises(ValueError):store_secret(base/'link'/'key','FAKE-TEST-RUNTIME-KEY-ONLY')
            with self.assertRaises(ValueError):store_secret(real/'key','sk-admin-not-a-real-key')
            with patch.object(os,'geteuid',return_value=0),self.assertRaises(ValueError):
                store_secret(real/'key','FAKE-TEST-RUNTIME-KEY-ONLY')


if __name__=='__main__':
    unittest.main()
