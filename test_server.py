import os
import json
from pathlib import Path
import socket
import stat
import subprocess
import unittest
from unittest.mock import patch

from mcp import Client
import server


class ToolTests(unittest.TestCase):
    def test_system_status(self):
        result = server.system_status()
        self.assertIn('Ubuntu', result['ubuntu_version'])
        self.assertEqual(result['hostname'], socket.gethostname())
        self.assertEqual(set(result), {'ubuntu_version', 'hostname', 'current_user'})
        self.assertTrue(result['current_user'])

    def test_project_status(self):
        result = server.project_git_status()
        self.assertRegex(result['head'], r'^[0-9a-f]{40}$')
        self.assertEqual(set(result), {'branch', 'head'})
        self.assertTrue(result['branch'] is None or isinstance(result['branch'], str))

    def test_detached_head(self):
        with patch.object(server, '_git', side_effect=[
            subprocess.CompletedProcess([], 0, 'a'*40+'\n', ''),
            subprocess.CompletedProcess([], 1, '', '')]):
            self.assertEqual(server.project_git_status(), {'branch': None, 'head': 'a'*40})

    def test_git_error(self):
        with patch.object(server, '_git', return_value=subprocess.CompletedProcess([], 128, '', '')):
            with self.assertRaises(RuntimeError):
                server.project_git_status()

    def test_write_probe(self):
        before = server.project_git_status()
        with patch('security.Approval.require'):
            result = server.write_probe()
        path = Path(result['marker_path'])
        try:
            self.assertEqual(path.parent.parent, Path('/tmp'))
            self.assertTrue(path.parent.name.startswith('romans-terminal-mcp-probe-'))
            self.assertEqual(path.name, 'probe.txt')
            self.assertEqual(path.read_bytes(), server.MARKER)
            self.assertEqual(result['bytes_written'], len(server.MARKER))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(before, server.project_git_status())
        finally:
            path.unlink()
            path.parent.rmdir()

    def test_all_tools_refuse_root(self):
        with patch.object(os, 'geteuid', return_value=0):
            for tool in (server.system_status, server.project_git_status, server.write_probe):
                with self.subTest(tool=tool.__name__), self.assertRaises(PermissionError):
                    tool()

    def test_no_arguments(self):
        for tool in (server.system_status, server.project_git_status, server.write_probe):
            with self.subTest(tool=tool.__name__), self.assertRaises(TypeError):
                tool(path='/tmp/unapproved', command='touch forbidden')


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_and_read_calls(self):
        async with Client(server.mcp) as client:
            tools = (await client.list_tools()).tools
            self.assertTrue({'system_status','project_git_status','write_probe'}.issubset({t.name for t in tools}))
            self.assertEqual(len(tools), 39)
            for tool in [t for t in tools if t.name in ('system_status','project_git_status','write_probe')]:
                self.assertFalse(tool.input_schema.get('properties'))
                self.assertFalse(tool.annotations.open_world_hint)
                self.assertEqual(tool.annotations.read_only_hint, tool.name != 'write_probe')
            for name in ('system_status', 'project_git_status'):
                result = await client.call_tool(name)
                self.assertFalse(result.is_error)
                payload = result.structured_content or json.loads(result.content[0].text)
                self.assertEqual(payload, getattr(server, name)())


if __name__ == '__main__':
    unittest.main()
