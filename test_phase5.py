"""Focused Phase 5 tests: disposable fixtures only, no real application commands."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import unittest
from unittest.mock import patch

from mcp import Client
from mcp.server import MCPServer
from api import register
from commander_policy import Policy, atomic_json
from commander_files import PathFiles
from commander_processes import Processes, LOG_LIMIT, clean_environment
from security import Denied
from test_phase2 import Fixture


class Base(Fixture):
    def setUp(self):
        super().setUp()
        self.policy = Policy(self.paths, self.approval, locations=[self.base])
        self.files5 = PathFiles(self.policy)
        self.processes5 = Processes(self.policy)
        self.scratch = self.paths.files

    def tearDown(self):
        for state in self.processes5.list()['sessions']:
            if state['state'] in ('running', 'queued'):
                self.processes5.terminate(state['session_id'])
                self.wait5(state['session_id'])
        for child in self.processes5.children:
            child.wait(timeout=5)
        super().tearDown()

    def wait5(self, ident, maximum=8):
        deadline = time.monotonic()+maximum
        while time.monotonic() < deadline:
            state = self.processes5.status(ident)
            if state['state'] not in ('queued', 'running'):
                return state
            time.sleep(.03)
        self.fail('Session did not terminate in bounded time')

    def text5(self, ident):
        return ''.join(r['text'] for r in self.processes5.output(ident, 0, 16384)['records'])

    def running5(self, ident):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            state = self.processes5.status(ident)
            if state['state'] == 'running':
                return state
            time.sleep(.03)
        self.fail('Session did not start')


class FileTests(Base):
    def test_create_read_hash_mode_and_no_popup(self):
        p = str(self.scratch/'hello.txt')
        with patch.object(self.approval, 'require', side_effect=AssertionError('No popup')):
            result = self.files5.write(p, 'čao\n')
        self.assertEqual(result['mode'], '0o600')
        self.assertEqual(self.files5.read(p)['text'], 'čao')
        self.assertEqual(Path(p).read_bytes(), 'čao\n'.encode())
        self.assertEqual(len(result['version']), 64)

    def test_versioned_append_replace_and_empty_file(self):
        p = str(self.scratch/'a.txt')
        first = self.files5.write(p, '')
        second = self.files5.write(p, 'one', 'append', first['version'])
        third = self.files5.write(p, '', 'replace', second['version'])
        self.assertEqual(Path(p).read_text(), '')
        self.assertNotEqual(first['version'], third['version'])

    def test_stale_version_never_overwrites(self):
        p = str(self.scratch/'a.txt')
        first = self.files5.write(p, 'one')
        Path(p).write_text('external')
        with self.assertRaises(Denied):
            self.files5.write(p, 'replacement', 'replace', first['version'])
        self.assertEqual(Path(p).read_text(), 'external')

    def test_unique_block_and_preserved_mode(self):
        p = str(self.scratch/'a.txt')
        self.files5.write(p, 'one two')
        Path(p).chmod(0o640)
        version = self.files5.info(p)['version']
        result = self.files5.edit(p, 'two', 'three', version)
        self.assertEqual(result['mode'], '0o640')
        self.assertEqual(Path(p).read_text(), 'one three')
        with self.assertRaises(Denied):
            self.files5.edit(p, 'missing', 'new', result['version'])

    def test_create_collision_and_rename_no_overwrite(self):
        a, b = str(self.scratch/'a.txt'), str(self.scratch/'b.txt')
        version = self.files5.write(a, 'one')['version']
        with self.assertRaises(Denied):
            self.files5.write(a, 'replacement')
        self.files5.write(b, 'untouched')
        with self.assertRaises(FileExistsError):
            self.files5.move(a, b, version)
        self.assertEqual(Path(b).read_text(), 'untouched')
        c = str(self.scratch/'c.txt')
        self.files5.move(a, c, version)
        self.assertFalse(Path(a).exists())
        self.assertEqual(Path(c).read_text(), 'one')

    def test_mkdir_listing_pagination_multiple(self):
        directory = str(self.scratch/'newdir')
        self.files5.mkdir(directory)
        self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
        paths = [str(Path(directory)/f'{i}.txt') for i in range(3)]
        for p in paths:
            self.files5.write(p, p[-5:])
        first = self.files5.listing(directory, limit=2)
        second = self.files5.listing(directory, offset=first['next_offset'], limit=2)
        self.assertEqual(len(first['entries'])+len(second['entries']), 3)
        self.assertEqual(len(self.files5.multiple(paths)['files']), 3)

    def test_traversal_symlink_hardlink_protected_system(self):
        p = self.scratch/'safe.txt'
        p.write_text('safe')
        (self.scratch/'sym.txt').symlink_to(p)
        os.link(p, self.scratch/'hard.txt')
        for value in (str(self.scratch/'sym.txt'), str(self.scratch/'hard.txt'),
                      str(self.scratch/'../outside'), '/etc/passwd',
                      str(self.scratch/'.ssh'/'x'), str(self.scratch/'.env'),
                      str(self.scratch/'.config'/'x')):
            with self.subTest(path=value), self.assertRaises(Denied):
                self.files5.read(value)

    def test_original_project_and_new_discovered_project_not_writable(self):
        with self.assertRaises(Denied):
            self.files5.write(str(self.repo/'new.txt'), 'blocked')
        project = self.base/'other-project'
        project.mkdir()
        subprocess.run(['/usr/bin/git', 'init', '-q', str(project)], check=True)
        (project/'a.txt').write_text('readable')
        self.assertEqual(self.files5.read(str(project/'a.txt'))['text'], 'readable')
        with self.assertRaises(Denied):
            self.files5.write(str(project/'b.txt'), 'blocked')

    def test_explicit_project_scope_authorization_and_audit(self):
        project = self.base/'other-project'
        project.mkdir()
        subprocess.run(['/usr/bin/git', 'init', '-q', str(project)], check=True)
        value = [{'path': str(project), 'write': True, 'trusted_terminal': False}]
        with patch.object(self.approval, 'require', side_effect=Denied('human denied')):
            with self.assertRaises(Denied):
                self.policy.set('approved_project_scopes', value)
        self.assertEqual(self.policy.config()['approved_project_scopes'], [])
        self.policy.set('approved_project_scopes', value)
        with patch.object(self.approval, 'require', side_effect=AssertionError('No popup')):
            self.files5.write(str(project/'b.txt'), 'authorized')
        self.assertIn('configuration_approved', (self.policy.state/'audit.jsonl').read_text())
        self.assertNotIn('authorized', (self.policy.state/'audit.jsonl').read_text())

    def test_sensitive_contents_not_written(self):
        with self.assertRaises(Denied):
            self.files5.write(str(self.scratch/'a.txt'), 'api_key=sample-private-value')


class SearchTests(Base):
    def setUp(self):
        super().setUp()
        for i in range(4):
            (self.scratch/f'f{i}.txt').write_text('first\nneedle\nlast\n')

    def test_literal_filename_and_pages(self):
        first = self.files5.search([str(self.scratch)], 'needle', limit=2)
        second = self.files5.search([str(self.scratch)], 'needle', offset=first['next_offset'], limit=2)
        self.assertEqual(len(first['matches']), 2)
        self.assertEqual(len(second['matches']), 2)
        self.assertFalse(set(h['path'] for h in first['matches']) & set(h['path'] for h in second['matches']))
        self.assertEqual(first['matches'][0]['line'], 2)
        found = self.files5.search([str(self.scratch)], 'f[12].txt', kind='filename')
        self.assertEqual(len(found['matches']), 2)

    def test_regex_safe_engine_invalid_and_path_filters(self):
        found = self.files5.search([str(self.scratch)], '^need.*$', regex=True, file_glob='f0*')
        self.assertEqual(len(found['matches']), 1)
        with self.assertRaises(Denied):
            self.files5.search([str(self.scratch)], '(', regex=True)
        with self.assertRaises(Denied):
            self.files5.search([str(self.scratch)], 'x', file_glob='../*')
        # Nested quantifiers use Rust regex, not Python backtracking.
        self.files5.search([str(self.scratch)], '(a+)+$', regex=True)

    def test_excludes_symlink_binary_and_secret(self):
        (self.scratch/'node_modules').mkdir()
        (self.scratch/'node_modules'/'a.txt').write_text('needle')
        (self.scratch/'.env').write_text('needle')
        (self.scratch/'binary.txt').write_bytes(b'needle\x00')
        (self.scratch/'link').symlink_to(self.scratch, target_is_directory=True)
        (self.scratch/'label.txt').write_text('api_key=needle\n')
        result = self.files5.search([str(self.scratch)], 'needle')
        self.assertEqual(len(result['matches']), 4)

    def test_cancellation_and_depth(self):
        ident = 'a'*32
        import threading
        from concurrent.futures import ThreadPoolExecutor
        from security import Paths
        original = Paths.read
        reading, release = threading.Event(), threading.Event()
        def slow_read(*args):
            reading.set()
            release.wait(timeout=2)
            return original(*args)
        self.assertFalse(self.files5.cancel_search(ident)['cancellation_requested'])
        with patch.object(Paths, 'read', slow_read), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.files5.search, [str(self.scratch)], 'needle', search_id=ident)
            self.assertTrue(reading.wait(timeout=2))
            self.assertTrue(self.files5.cancel_search(ident)['cancellation_requested'])
            release.set()
            result = future.result(timeout=3)
        self.assertTrue(result['cancelled'])
        self.assertEqual(self.files5.searches, {})
        self.assertFalse(list(self.policy.state.glob('search-*.cancel')))
        (self.scratch/'sub').mkdir()
        (self.scratch/'sub'/'nested.txt').write_text('needle')
        self.assertEqual(len(self.files5.search([str(self.scratch)], 'needle', max_depth=0)['matches']), 4)


class ProcessTests(Base):
    def test_real_bash_pipeline_redirection_and_host_unchanged(self):
        state = self.processes5.execute('printf "one\\ntwo\\n" | tr a-z A-Z > result.txt; cat result.txt; pwd', str(self.scratch))
        self.assertEqual(state['state'], 'completed')
        self.assertEqual(state['exit_code'], 0)
        self.assertIn('ONE\nTWO\n/work', self.text5(state['session_id']))
        self.assertFalse((self.scratch/'result.txt').exists())

    def test_environment_sanitization_and_real_streams(self):
        with patch.dict(os.environ, {'CONTROL_PLANE_SECRET': 'do-not-pass', 'UNRELATED_PRIVATE_VALUE': 'sentinel-private'}):
            state = self.processes5.execute('printenv; printf "error-line\\n" >&2', str(self.scratch))
        result = self.processes5.output(state['session_id'])
        self.assertEqual({r['stream'] for r in result['records']}, {'stdout', 'stderr'})
        text = self.text5(state['session_id'])
        for secret in ('do-not-pass', 'sentinel-private', 'CONTROL_PLANE_SECRET'):
            self.assertNotIn(secret, text)

    def test_os_boundary_denies_host_files_and_network(self):
        outside = self.base/'outside.txt'
        outside.write_text('host sentinel')
        command = f'cat {outside}; cat /home/exampleuser/.ssh/id_rsa; python3 -c "import socket; socket.create_connection((\'1.1.1.1\',443),.1)"'
        state = self.processes5.execute(command, str(self.scratch))
        self.assertNotEqual(state['exit_code'], 0)
        self.assertNotIn('host sentinel', self.text5(state['session_id']))

    def test_snapshot_excludes_credentials_and_git(self):
        (self.scratch/'.env').write_text('opaque-secret')
        (self.scratch/'normal.txt').write_text('api_key=opaque-secret')
        state = self.processes5.execute('ls -a; cat .env normal.txt', str(self.scratch))
        self.assertNotEqual(state['exit_code'], 0)
        self.assertNotIn('opaque-secret', self.text5(state['session_id']))

    def test_long_detached_poll_input_and_cancel(self):
        before = time.monotonic()
        state = self.processes5.start('printf "started\\n"; sleep 301', str(self.scratch), timeout_seconds=600)
        self.assertLess(time.monotonic()-before, 3)
        self.running5(state['session_id'])
        self.assertEqual(self.processes5.status(state['session_id'])['timeout_seconds'], 600)
        self.processes5.terminate(state['session_id'])
        self.assertEqual(self.wait5(state['session_id'])['state'], 'cancelled')

    def test_timeout_and_nonzero_exit_status(self):
        state = self.processes5.start('sleep 5', str(self.scratch), timeout_seconds=1)
        self.assertEqual(self.wait5(state['session_id'])['state'], 'timed_out')
        state = self.processes5.execute('false', str(self.scratch))
        self.assertEqual(state['exit_code'], 1)

    def test_idle_ttl(self):
        config = {**self.policy.config(), 'idle_timeout': 1}
        with patch.object(self.policy, 'config', return_value=config):
            state = self.processes5.start('sleep 5', str(self.scratch))
        self.assertEqual(self.wait5(state['session_id'])['state'], 'idle_timeout')

    def test_concurrency_and_owned_process_listing(self):
        a = self.processes5.start('sleep 5', str(self.scratch))
        b = self.processes5.start('sleep 5', str(self.scratch))
        self.running5(a['session_id'])
        with self.assertRaises(Denied):
            self.processes5.start('true', str(self.scratch))
        processes = self.processes5.processes('bwrap')['processes']
        self.assertTrue(any(p['session_id'] == a['session_id'] for p in processes))
        with self.assertRaises(Denied):
            self.processes5.terminate(str(os.getpid()))

    def test_pty_interaction(self):
        state = self.processes5.start('printf "Name? "; read value; printf "Hi %s\\n" "$value"', str(self.scratch), pty=True)
        ident = state['session_id']
        self.running5(ident)
        self.processes5.interact(ident, 'Marcus\n')
        self.assertEqual(self.wait5(ident)['exit_code'], 0)
        self.assertIn('Hi Marcus', self.text5(ident))

    def test_pipe_interaction(self):
        state = self.processes5.start('read value; printf "%s\\n" "$value"', str(self.scratch))
        ident = state['session_id']
        self.running5(ident)
        self.processes5.interact(ident, 'input-line\n')
        self.assertEqual(self.wait5(ident)['state'], 'completed')
        self.assertIn('input-line', self.text5(ident))

    def test_pty_has_controlling_terminal(self):
        state = self.processes5.start('python3 -c "import os; f=os.open(\'/dev/tty\',os.O_RDWR); print(os.isatty(f)); os.close(f)"', str(self.scratch), pty=True)
        ident = state['session_id']
        self.assertEqual(self.wait5(ident)['exit_code'], 0)
        self.assertIn('True', self.text5(ident))

    def test_output_pagination_and_truncation(self):
        state = self.processes5.execute('seq 1 40000', str(self.scratch), max_output_bytes=500)
        ident = state['session_id']
        first = self.processes5.output(ident, 0, 50)
        second = self.processes5.output(ident, first['next_offset'], 50)
        self.assertTrue(first['truncated'])
        self.assertGreater(first['retained_from'], 0)
        self.assertEqual(second['next_offset']-first['next_offset'], 50)
        self.assertLessEqual(self.processes5.status(ident)['output_end']-first['retained_from'], LOG_LIMIT)

    def test_output_filtering_split_secrets_and_oversized_line(self):
        state = self.processes5.execute("printf '%s%s\\n' api_ key=sample-value; python3 -c \"print('x'*10000)\"", str(self.scratch))
        text = self.text5(state['session_id'])
        self.assertNotIn('sample-value', text)
        self.assertIn('REDACTED', text)
        self.assertIn('Oversized', text)

    def test_lost_supervisor_reports_orphaned(self):
        state = self.processes5.start('sleep 5', str(self.scratch))
        ident = state['session_id']
        self.running5(ident)
        # Check status against a synthetic mismatched identity, never kill host PIDs.
        with patch('commander_processes.identity', return_value='not-the-worker'):
            self.assertEqual(self.processes5.status(ident)['state'], 'orphaned')
        # Restore the real running state for controlled cleanup.
        path = self.processes5.location(ident)
        value = json.loads((path/'status.json').read_text())
        value['state'] = 'running'
        atomic_json(path/'status.json', value)

    def test_high_risk_denial_before_execution(self):
        with patch.object(self.approval, 'require', side_effect=Denied('local denial')):
            for command in ('rm -rf example', 'git reset --hard', 'sudo true', 'git merge main', 'git stash'):
                with self.subTest(command=command), self.assertRaises(Denied):
                    self.processes5.start(command, str(self.scratch))
        self.assertEqual(self.processes5.list()['sessions'], [])

    def test_trusted_mode_cannot_self_authorize(self):
        with self.assertRaises(Denied):
            self.processes5.start('true', str(self.scratch), mode='trusted', approval_hint='approved')
        self.assertNotIn('CONTROL_PLANE_SECRET', clean_environment('/tmp'))

    def test_trusted_one_time_approval_sanitized_env_and_no_privilege_gain(self):
        project = self.base/'trusted-project'
        project.mkdir()
        subprocess.run(['/usr/bin/git', 'init', '-q', str(project)], check=True)
        self.policy.set('approved_project_scopes', [{'path': str(project), 'write': True, 'trusted_terminal': True}])
        self.policy.set('approval_mode', 'trusted_local_dev')
        with patch.object(self.approval, 'require') as approve:
            with patch.dict(os.environ, {'CONTROL_PLANE_PRIVATE': 'do-not-pass'}):
                state = self.processes5.execute('printf "trusted-ok\\n"; grep NoNewPrivs /proc/self/status; printenv', str(project), mode='trusted')
        self.assertEqual(approve.call_count, 0)
        self.assertEqual(state['exit_code'], 0)
        text = self.text5(state['session_id'])
        self.assertIn('trusted-ok', text)
        self.assertIn('NoNewPrivs:\t1', text)
        self.assertNotIn('do-not-pass', text)
        self.assertFalse((self.processes5.location(state['session_id'])/'plan.json').exists())

    def test_missing_bubblewrap_never_falls_back_to_host(self):
        real = Path.is_file
        with patch.object(Path, 'is_file', lambda p: False if str(p) == '/usr/bin/bwrap' else real(p)):
            with self.assertRaises(Denied):
                self.processes5.start('true', str(self.scratch))
        self.assertEqual(self.processes5.list()['sessions'], [])

    def test_command_limits_and_noncanonical_cwd(self):
        for kwargs in ({'timeout_seconds': 3601}, {'mode': 'unknown'}, {'pty': 'yes'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Denied):
                self.processes5.start('true', str(self.scratch), **kwargs)
        with self.assertRaises(Denied):
            self.processes5.start('true', str(self.scratch)+'/../files')
        with self.assertRaises(Denied):
            self.processes5.start('api_key=sample-value', str(self.scratch))


class ProtocolTests(Base):
    def test_foreground_call_does_not_block_concurrent_status(self):
        async def check():
            mcp = MCPServer('Concurrent Phase 5 fixture')
            register(mcp, self.repo, self.paths.workspace)
            async with Client(mcp) as client:
                running = asyncio.create_task(client.call_tool('exec_command', {
                    'command': 'sleep 1', 'cwd': str(self.scratch)}))
                await asyncio.sleep(.1)
                before = time.monotonic()
                result = await client.call_tool('get_config')
                self.assertFalse(result.is_error)
                self.assertLess(time.monotonic()-before, .7)
                self.assertFalse((await running).is_error)
        asyncio.run(check())

    def test_discovery_original_schemas_and_new_calls(self):
        async def check():
            import server
            baseline = json.loads(Path(__file__).with_name('phase5-original-schemas.json').read_text())
            async with Client(server.mcp) as client:
                tools = (await client.list_tools()).tools
                self.assertEqual(len(tools), 39)
                actual = {t.name: t.model_dump(mode='json') for t in tools}
                for old in baseline:
                    self.assertEqual(actual[old['name']], old)
                result = await client.call_tool('get_config')
                self.assertFalse(result.is_error)
                result = await client.call_tool('exec_command', {'command': 'printf "mcp-ready\\n"', 'cwd': str(server.PHASE2[0].files)})
                self.assertFalse(result.is_error)
                payload = result.structured_content or json.loads(result.content[0].text)
                self.assertEqual(payload['exit_code'], 0)
        asyncio.run(check())


if __name__ == '__main__':
    unittest.main()
