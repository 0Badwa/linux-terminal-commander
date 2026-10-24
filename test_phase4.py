"""Focused prompt delivery and headless-service approval regressions."""
import asyncio
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from mcp import Client
from mcp.server import MCPServer
from api import register
import codex_prompts as prompts
import desktop_session
from security import Approval, Denied
from test_phase2 import Fixture


class PromptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='commander-prompt-test-')
        self.base = Path(self.tmp.name)
        self.directory = self.base / 'prompts'
        self.patch = patch.object(prompts, 'PROMPT_DIRECTORY', self.directory)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_valid_utf8_separate_process_hash_and_permissions(self):
        content = '# Zadatak\nPročitaj i izvrši.\n'
        with patch('security.Approval.require', side_effect=AssertionError('No local dialog permitted')):
            result = prompts.save_prompt('task-01.md', content)
        path = Path(result['path'])
        read = subprocess.run(['/usr/bin/python3', '-c',
            'import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())', str(path)],
            check=True, capture_output=True)
        self.assertEqual(read.stdout, content.encode())
        self.assertEqual(result['bytes_written'], len(read.stdout))
        self.assertEqual(result['sha256'], hashlib.sha256(read.stdout).hexdigest())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(self.directory.stat().st_uid, os.getuid())
        self.assertEqual([p.name for p in self.directory.iterdir()], ['task-01.md'])

    def test_overwrite_is_refused(self):
        result = prompts.save_prompt('task.md', 'original')
        with self.assertRaisesRegex(Denied, 'already exists'):
            prompts.save_prompt('task.md', 'replacement')
        self.assertEqual(Path(result['path']).read_text(), 'original')
        self.assertEqual(len(list(self.directory.iterdir())), 1)

    def test_strict_filename_policy(self):
        names = ('../escape.md', '/tmp/escape.md', 'sub/task.md', 'task\\x.md', '.hidden.md',
                 'task.txt', 'task.MD', 'task..md', 'task .md', 'task\n.md', 'tašk.md',
                 'a'*121+'.md', 'task.md.sh', 'task;run.md', '', '-task.md', 'task\x00.md')
        for name in names:
            with self.subTest(name=name), self.assertRaisesRegex(Denied, 'basename'):
                prompts.save_prompt(name, 'text')
        self.assertFalse(self.directory.exists())

    def test_size_is_utf8_bytes(self):
        for content in ('a'*(prompts.MAX_PROMPT_BYTES+1), 'č'*(prompts.MAX_PROMPT_BYTES//2+1),
                        '\ud800', '\x00', '', None):
            with self.subTest(size=len(content) if isinstance(content,str) else None), self.assertRaises(Denied):
                prompts.save_prompt('task.md', content)
        result = prompts.save_prompt('limit.md', 'a'*prompts.MAX_PROMPT_BYTES)
        self.assertEqual(result['bytes_written'], prompts.MAX_PROMPT_BYTES)

    def test_existing_and_dangling_symlinks_refused(self):
        self.directory.mkdir(mode=0o700)
        outside = self.base/'outside'
        outside.write_text('untouched')
        for target in (outside, self.base/'absent'):
            link = self.directory/'link.md'
            link.symlink_to(target)
            with self.assertRaisesRegex(Denied, 'already exists'):
                prompts.save_prompt('link.md', 'new')
            link.unlink()
        self.assertEqual(outside.read_text(), 'untouched')
        self.assertFalse((self.base/'absent').exists())

    def test_symlink_directory_and_unsafe_permissions_refused(self):
        outside = self.base/'outside'
        outside.mkdir(mode=0o700)
        self.directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(Denied):
            prompts.save_prompt('task.md', 'text')
        self.assertFalse(list(outside.iterdir()))
        self.directory.unlink()
        self.directory.mkdir(mode=0o755)
        self.directory.chmod(0o755)
        with self.assertRaisesRegex(Denied, '0700'):
            prompts.save_prompt('task.md', 'text')

    def test_wrong_owner_refused(self):
        with patch.object(prompts.os, 'getuid', return_value=os.getuid()+1), self.assertRaisesRegex(Denied, 'local user'):
            prompts.save_prompt('task.md', 'text')

    def test_final_symlink_injected_at_publication(self):
        outside = self.base/'outside'
        outside.write_text('untouched')
        original = prompts._rename_new
        def attack(parent, source, destination):
            os.symlink(outside, destination, dir_fd=parent)
            original(parent, source, destination)
        with patch.object(prompts, '_rename_new', side_effect=attack), self.assertRaisesRegex(Denied, 'already exists'):
            prompts.save_prompt('task.md', 'text')
        self.assertEqual(outside.read_text(), 'untouched')

    def test_temporary_symlink_replacement_refused(self):
        original = prompts._check_directory
        count = 0
        outside = self.base/'outside'
        outside.write_text('untouched')
        def attack(parent, directory):
            nonlocal count
            count += 1
            if count == 2:
                for item in self.directory.iterdir():
                    item.unlink()
                    item.symlink_to(outside)
            original(parent,directory)
        with patch.object(prompts, '_check_directory', side_effect=attack), self.assertRaisesRegex(Denied, 'Temporary prompt changed'):
            prompts.save_prompt('task.md', 'text')
        self.assertEqual(outside.read_text(), 'untouched')
        self.assertFalse((self.directory/'task.md').exists())

    def test_directory_replacement_cannot_escape(self):
        original = prompts._check_directory
        count = 0
        outside = self.base/'outside'
        outside.mkdir(mode=0o700)
        def attack(parent, directory):
            nonlocal count
            count += 1
            if count == 2:
                self.directory.rename(self.base/'moved')
                self.directory.symlink_to(outside, target_is_directory=True)
            original(parent,directory)
        with patch.object(prompts, '_check_directory', side_effect=attack), self.assertRaisesRegex(Denied, 'directory changed'):
            prompts.save_prompt('task.md', 'text')
        self.assertFalse(list(outside.iterdir()))
        self.assertFalse(list((self.base/'moved').iterdir()))

    def test_actionable_no_space_and_permission_errors(self):
        for code, message in ((errno.ENOSPC,'No space'),(errno.EACCES,'not writable')):
            with self.subTest(code=code), patch.object(prompts.os, 'open', side_effect=OSError(code, 'private diagnostic')):
                with self.assertRaisesRegex(Denied, message) as caught:
                    prompts.save_prompt('task.md', 'text')
                self.assertNotIn('private diagnostic', str(caught.exception))

    def test_concurrent_create_publishes_only_one_complete_prompt(self):
        from concurrent.futures import ThreadPoolExecutor
        def create(content):
            try:
                return prompts.save_prompt('same.md', content)
            except Denied:
                return None
        contents = ['A'*8192, 'B'*8192]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, contents))
        self.assertEqual(sum(result is not None for result in results),1)
        self.assertIn((self.directory/'same.md').read_text(), contents)
        self.assertEqual(len(list(self.directory.iterdir())),1)


class DesktopTests(unittest.TestCase):
    def test_empty_logind_display_uses_one_owned_x11_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base/'gdm').mkdir()
            (base/'gdm'/'Xauthority').touch()
            responses = [subprocess.CompletedProcess([],0,'3\n',''),
                subprocess.CompletedProcess([],0,f'User={os.getuid()}\nActive=yes\nRemote=no\nType=x11\nDisplay=\n','')]
            with patch('desktop_session.subprocess.run',side_effect=responses), patch('desktop_session._x11_display',return_value=':0') as fallback:
                result = desktop_session.environment({},runtime=base)
            self.assertEqual(result['DISPLAY'],':0')
            fallback.assert_called_once()

    def test_socket_discovery_refuses_symlinks_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as first, socket.socket(socket.AF_UNIX) as second:
            base = Path(tmp)
            first.bind(str(base/'X0'))
            self.assertEqual(desktop_session._x11_display(base), ':0')
            (base/'X1').symlink_to(base/'X0')
            self.assertEqual(desktop_session._x11_display(base), ':0')
            second.bind(str(base/'X2'))
            self.assertEqual(desktop_session._x11_display(base), '')

    def test_remote_inactive_or_wrong_user_cannot_discover_display(self):
        with tempfile.TemporaryDirectory() as tmp:
            for user,active,remote in ((os.getuid(),'yes','yes'),(os.getuid(),'no','no'),(os.getuid()+1,'yes','no')):
                responses = [subprocess.CompletedProcess([],0,'3\n',''),
                    subprocess.CompletedProcess([],0,f'User={user}\nActive={active}\nRemote={remote}\nType=x11\nDisplay=\n','')]
                with patch('desktop_session.subprocess.run',side_effect=responses), patch('desktop_session._x11_display') as fallback:
                    result=desktop_session.environment({},runtime=tmp)
                self.assertNotIn('DISPLAY',result)
                fallback.assert_not_called()


class PolicyTests(Fixture):
    def test_original_create_and_edit_still_need_local_human_approval(self):
        self.files.approval = Approval()
        with patch('desktop_session.environment',return_value={}):
            with self.assertRaisesRegex(Denied,'Local approval unavailable'):
                self.files.create('scratch','task.md','new')
        (self.paths.files/'existing.md').write_text('old')
        version=self.files.metadata('scratch','existing.md')['version']
        with patch('desktop_session.environment',return_value={}):
            with self.assertRaisesRegex(Denied,'Local approval unavailable'):
                self.files.edit('scratch','existing.md',version,'old','new')
        self.assertFalse((self.paths.files/'task.md').exists())
        self.assertEqual((self.paths.files/'existing.md').read_text(),'old')

    def test_mcp_reports_policy_error_instead_of_unexpected_crash(self):
        async def run():
            mcp=MCPServer('phase4-policy-test')
            register(mcp,self.repo,self.paths.workspace)
            with patch('desktop_session.environment',return_value={}):
                async with Client(mcp) as client:
                    result=await client.call_tool('create_text_file',{'root':'scratch','path':'test.md','content':'text'})
                    self.assertTrue(result.is_error)
                    self.assertIn('Local approval unavailable',result.content[0].text)
        asyncio.run(run())

    def test_mcp_never_exposes_secret_or_unexpected_diagnostics(self):
        async def run():
            mcp=MCPServer('phase4-error-test')
            register(mcp,self.repo,self.paths.workspace)
            async with Client(mcp) as client:
                for error in (Denied('password=FAKE_PRIVATE_DIAGNOSTIC'), RuntimeError('FAKE_PRIVATE_DIAGNOSTIC')):
                    with patch('api.save_prompt',side_effect=error):
                        result=await client.call_tool('save_codex_prompt',{'filename':'task.md','content':'text'})
                    self.assertTrue(result.is_error)
                    self.assertNotIn('FAKE_PRIVATE_DIAGNOSTIC',result.content[0].text)
        asyncio.run(run())

    def test_mcp_prompt_tool_is_write_annotated_and_never_opens_dialog(self):
        async def run():
            mcp=MCPServer('phase4-tool-test')
            register(mcp,self.repo,self.paths.workspace)
            with patch.object(prompts,'PROMPT_DIRECTORY',self.base/'prompts'), patch('security.Approval.require',side_effect=AssertionError('No dialog')):
                async with Client(mcp) as client:
                    tools=(await client.list_tools()).tools
                    tool=next(t for t in tools if t.name=='save_codex_prompt')
                    self.assertFalse(tool.annotations.read_only_hint)
                    self.assertFalse(tool.annotations.destructive_hint)
                    result=await client.call_tool('save_codex_prompt',{'filename':'task.md','content':'# Safe task\n'})
                    self.assertFalse(result.is_error)
                    result=await client.call_tool('save_codex_prompt',{'filename':'../escape.md','content':'text'})
                    self.assertTrue(result.is_error)
                    self.assertIn('basename',result.content[0].text)
        asyncio.run(run())


if __name__ == '__main__':
    unittest.main()
