"""Portable setup smoke tests; no system services or real tunnel altered."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from settings import ROOT, PROFILE_NAME, canonical_project, project_root
from configure import configure


class PortableTests(unittest.TestCase):
    def test_identity_and_project(self):
        import server
        self.assertEqual(server.mcp.name, 'Linux Terminal Commander')
        self.assertEqual(project_root(), ROOT)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'my-project'
            target.mkdir()
            with self.assertRaisesRegex(ValueError, 'Git'):
                canonical_project(target)
            subprocess.run(['git', 'init', '-q', '-b', 'main', str(target)], check=True)
            self.assertEqual(canonical_project(target), target)

    def test_fake_id_refused_without_creating_profile(self):
        with self.assertRaisesRegex(ValueError, 'Invalid tunnel ID'):
            configure(ROOT, 'other-tunnel', client='/usr/bin/false')

    def test_isolated_cpu_limit_does_not_raise_inherited_limit(self):
        import execution
        import resource
        with patch.object(execution.resource, 'getrlimit', return_value=(5, 5)):
            arguments = execution.sandbox([], '/work', ['/usr/bin/true'], timeout=600)
        self.assertIn('--cpu=5', arguments)
        self.assertIn('--fsize=2147483648', arguments)
        self.assertIn('--as=6442450944', arguments)

    def test_template_name_and_private_defaults(self):
        text = (ROOT / 'linux-terminal-commander.service.in').read_text()
        self.assertIn('Linux Terminal Commander', text)
        self.assertIn('@ROOT@', text)
        self.assertIn('NoNewPrivileges=yes', text)
        import server
        self.assertEqual(server.PHASE2[0].roots.keys(), {'project', 'scratch'})
        from commander_policy import Policy
        from security import Approval
        p = Policy(server.PHASE2[0], Approval())
        self.assertEqual(p.config()['approval_mode'], 'isolated')


if __name__ == '__main__':
    unittest.main()
