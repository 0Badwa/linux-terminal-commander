"""Phase 5.1 only: disposable fixtures, simulated local consent, no application writes."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time
from unittest.mock import patch

from mcp import Client
from mcp.server import MCPServer
from api import register
from commander_policy import Policy, atomic_json
from commander_processes import identity
from security import Denied
from test_phase5 import Base


class HostTests(Base):
    def activate(self):
        self.policy.set('approval_mode', 'desktop_compatible')

    def test_absent_and_legacy_consent_cannot_self_authorize(self):
        for mode in ('trusted', 'trusted_local_dev', 'desktop_compatible'):
            with self.subTest(mode=mode), self.assertRaises(Denied):
                self.processes5.start('true', str(self.repo), mode=mode, approval_hint='approved')
        atomic_json(self.policy.config_path, {**self.policy.config(), 'approval_mode': 'trusted_local_dev'})
        self.assertFalse(self.policy.host_authorized())
        with self.assertRaises(Denied):
            self.policy.trusted(str(self.repo))
        for key, value in (('host_consent_version', 1), ('approval_mode', 'desktop_compatible')):
            with patch.object(self.approval, 'require', side_effect=Denied('owner denied')):
                with self.assertRaises(Denied):
                    self.policy.set(key, value)
        self.assertFalse(self.policy.host_authorized())
        self.assertEqual(self.processes5.list()['sessions'], [])

    def test_activation_persists_and_default_skips_exact_approval(self):
        with patch.object(self.approval, 'require') as approve:
            self.activate()
        self.assertEqual(approve.call_count, 1)
        self.assertIn('ONE-TIME REAL HOST', approve.call_args.args[1]['warning'])
        restarted = Policy(self.paths, self.approval, locations=[self.base])
        self.assertTrue(restarted.host_authorized())
        self.assertFalse(restarted.describe()['exact_command_approval'])
        with patch.object(self.approval, 'require', side_effect=AssertionError('no per-command popup')):
            result = self.processes5.execute('pwd; git status --short --branch; git rev-parse HEAD', str(self.repo))
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['mode'], 'trusted')
        self.assertIn(str(self.repo), self.text5(result['session_id']))
        self.assertIn(self.rawgit('rev-parse', 'HEAD'), self.text5(result['session_id']))
        self.assertEqual(self.rawgit('status', '--porcelain'), '')

    def test_real_bash_pipeline_and_independent_file_visibility(self):
        self.activate()
        folder = self.base/'ordinary-development'
        folder.mkdir()
        cmd = "printf 'čao\\n' | tr a A > note.txt; pwd; cat note.txt"
        with patch.object(self.approval, 'require', side_effect=AssertionError('no popup')):
            result = self.processes5.execute(cmd, str(folder))
        self.assertEqual(result['exit_code'], 0)
        independent = subprocess.check_output(['/usr/bin/cat', str(folder/'note.txt')], text=True)
        self.assertEqual(independent, 'čAo\n')
        self.assertIn(str(folder), self.text5(result['session_id']))

    def test_path_write_edit_rename_search_without_project_registration(self):
        self.activate()
        folder = self.base/'ordinary-development'
        folder.mkdir()
        a, b = str(folder/'note.txt'), str(folder/'renamed.txt')
        with patch.object(self.approval, 'require', side_effect=AssertionError('no popup')):
            first = self.files5.write(a, 'hello one\n')
            self.assertIn('hello one', self.files5.read(a)['text'])
            second = self.files5.edit(a, 'one', 'two', first['version'])
            with self.assertRaises(Denied):
                self.files5.write(a, 'bad', 'replace', first['version'])
            moved = self.files5.move(a, b, second['version'])
            self.assertEqual(Path(b).read_text(), 'hello two\n')
            self.assertTrue(self.files5.search([str(folder)], 'two')['matches'])
            self.files5.mkdir(str(folder/'new'))
            self.assertTrue(self.files5.listing(str(folder))['entries'])
        self.assertEqual(self.policy.config()['approved_project_scopes'], [])
        self.assertEqual(len(moved['version']), 64)

    def test_host_protected_symlink_and_hardlink_rules(self):
        self.activate()
        plain = self.base/'plain.txt'
        plain.write_text('hello')
        link = self.base/'alias.txt'
        link.symlink_to(plain)
        with self.assertRaises(Denied):
            self.files5.read(str(link))
        os.link(plain, self.base/'hard.txt')
        with self.assertRaises(Denied):
            self.files5.read(str(plain))
        for name in ('.env', 'credentials.json', 'id_ed25519'):
            with self.subTest(name=name), self.assertRaises(Denied):
                self.files5.write(str(self.base/name), 'unrelated')

    def test_host_pty_and_output_paging(self):
        self.activate()
        state = self.processes5.start('read value; printf "Hi %s\\n" "$value"; seq 1 100', str(self.base), pty=True)
        ident = state['session_id']
        self.running5(ident)
        self.processes5.interact(ident, 'Marcus\n')
        self.assertEqual(self.wait5(ident)['exit_code'], 0)
        first = self.processes5.output(ident, 0, 12)
        second = self.processes5.output(ident, first['next_offset'], 12)
        self.assertGreater(second['next_offset'], first['next_offset'])
        self.assertIn('Hi Marcus', self.text5(ident))

    def test_host_timeout_cancel_and_no_orphaned_child(self):
        self.activate()
        timed = self.processes5.start('sleep 30', str(self.base), timeout_seconds=1)
        self.assertEqual(self.wait5(timed['session_id'])['state'], 'timed_out')
        state = self.processes5.start('sleep 60 & wait', str(self.base), timeout_seconds=30)
        ident = state['session_id']
        self.running5(ident)
        time.sleep(.1)
        tree = self.processes5.status(ident)['process_tree']
        self.assertTrue(tree)
        self.processes5.terminate(ident)
        self.assertEqual(self.wait5(ident)['state'], 'cancelled')
        self.assertTrue(all(identity(p['pid']) != p['start'] for p in tree))
        with self.assertRaises(Denied):
            self.processes5.terminate(str(os.getpid()))

    def test_host_user_no_elevation_and_no_inherited_credentials(self):
        self.activate()
        with patch.dict(os.environ, {'CONTROL_PLANE_PRIVATE': 'do-not-inherit'}):
            state = self.processes5.execute('id -un; id -u; grep NoNewPrivs /proc/self/status; printenv', str(self.base))
        self.assertEqual(state['exit_code'], 0)
        text = self.text5(state['session_id'])
        self.assertIn(str(os.getuid()), text)
        self.assertIn('exampleuser', text)
        self.assertIn('NoNewPrivs:\t1', text)
        self.assertNotIn('do-not-inherit', text)
        self.assertFalse((self.processes5.location(state['session_id'])/'plan.json').exists())

    def test_explicit_isolated_and_revoke_keep_host_unchanged(self):
        self.activate()
        state = self.processes5.execute('pwd; printf isolated > hello.txt', str(self.repo), mode='isolated')
        self.assertEqual(state['exit_code'], 0)
        self.assertIn('/work', self.text5(state['session_id']))
        self.assertEqual((self.repo/'hello.txt').read_text(), 'one\ntwo\nthree\n')
        self.policy.set('approval_mode', 'isolated')
        self.assertFalse(self.policy.host_authorized())
        with self.assertRaises(Denied):
            self.processes5.execute('true', str(self.repo), mode='trusted')

    def test_configuration_advisories_do_not_enable_host(self):
        guards = [{'path_prefix': '/tmp/example'}, {'command_pattern': 'git reset'}]
        with patch.object(self.approval, 'require', side_effect=Denied('owner denied')):
            with self.assertRaises(Denied):
                self.policy.set('advisory_guards', guards)
        self.policy.set('advisory_guards', guards)
        self.assertFalse(self.policy.host_authorized())
        self.assertIn('NOT security boundaries', self.policy.describe()['terminal_policy'])

    def test_public_mcp_tools_host_default_and_legacy_19_schemas(self):
        async def check():
            mcp = MCPServer('Phase 5.1 fixture')
            register(mcp, self.repo, self.paths.workspace)
            self.activate()
            async with Client(mcp) as client:
                tools = (await client.list_tools()).tools
                self.assertEqual(len(tools), 36)
                actual = {t.name: t.model_dump(mode='json') for t in tools}
                baseline = json.loads(Path(__file__).with_name('phase5-original-schemas.json').read_text())
                for old in baseline:
                    if old['name'] in actual:
                        self.assertEqual(actual[old['name']], old)
                result = await client.call_tool('exec_command', {'command': 'pwd', 'cwd': str(self.repo)})
                self.assertFalse(result.is_error)
                self.assertIn(str(self.repo), str(result))
        asyncio.run(check())
