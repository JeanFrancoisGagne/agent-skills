"""Test canonical argv with public Windows/POSIX paths; never start a reviewer."""
import argparse
import json
from pathlib import Path
import runpy
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent
HELPER = ROOT.parent / 'scripts/autoreview'
helper = runpy.run_path(str(HELPER), run_name='canonical_project_policy_under_test')
PATHS = [
    r'C:\public\repo.with.dots\review',
    'C:\\public\\quote"repo\\review',
    r'C:\public\back\slash.and.dot\review',
    '/srv/public/repo.with.dots/review',
    '/srv/public/quote"repo/review',
    '/srv/public/back\\slash.and.dot/review',
    '/srv/public/naïve.工具/🙂',
]


class PublicWorkspace:
    # Paths are configuration inputs. Quotes forbidden by the Windows filesystem
    # still need correct TOML encoding; these tests create no such directories.
    def __init__(self, text):
        self.text = text

    def resolve(self):
        return self

    def __str__(self):
        return self.text


def overrides(command):
    return [command[index + 1] for index, item in enumerate(command[:-1]) if item == '-c']


def codex_override_tree(values):
    # Codex parse_overrides parses only RHS TOML; apply_toml_override splits LHS
    # on literal dots. Expected project/path content below is independent of it.
    root = {}
    for value in values:
        key, raw = value.split('=', 1)
        parsed = tomllib.loads('value=' + raw)['value']
        destination = root
        parts = key.split('.')
        for part in parts[:-1]:
            destination = destination.setdefault(part, {})
        destination[parts[-1]] = parsed
    return root


class ProjectPolicy(unittest.TestCase):
    def test_literal_workspace_survives_the_real_canonical_argument_seam(self):
        with tempfile.TemporaryDirectory(prefix='project-policy-public.', dir=ROOT) as temporary:
            runtime = Path(temporary) / 'runtime'
            for public_path in PATHS:
                with self.subTest(public_path=public_path):
                    flags = helper['codex_config_isolation_flags'](PublicWorkspace(public_path), runtime)
                    values = overrides(flags)
                    actual = codex_override_tree(values)
                    self.assertEqual(actual['projects'], {public_path: {'trust_level': 'untrusted'}})
                    project_values = [item for item in values if item.partition('=')[0].startswith('projects')]
                    self.assertEqual(len(project_values), 1)
                    self.assertEqual(project_values[0].partition('=')[0], 'projects')
                    self.assertEqual(actual['features']['hooks'], False)
                    self.assertEqual(actual['features']['plugins'], False)
                    self.assertEqual(actual['default_permissions'], 'autoreview')

    def test_codex_command_keeps_explicit_auth_and_permissions_without_strict_flag(self):
        with tempfile.TemporaryDirectory(prefix='project-policy-command.', dir=ROOT) as temporary:
            runtime = Path(temporary) / 'runtime'
            args = argparse.Namespace(codex_bin=sys.executable, web_search=False,
                codex_config=['model_reasoning_summary="none"'], thinking='none', codex_speed='default')
            workspace = PublicWorkspace(PATHS[0])
            auth = ['-c', 'cli_auth_credentials_store="ephemeral"']
            command = helper['codex_command'](args, ROOT, workspace, runtime,
                runtime / 'schema.json', runtime / 'answer.json', 'gpt-6-sol', auth_config=auth)
            actual = codex_override_tree(overrides(command))
            self.assertEqual(actual['projects'], {PATHS[0]: {'trust_level': 'untrusted'}})
            self.assertEqual(actual['cli_auth_credentials_store'], 'ephemeral')
            self.assertEqual(actual['permissions']['autoreview']['filesystem'][':workspace_roots'], 'read')
            self.assertEqual(actual['shell_environment_policy']['inherit'], 'core')
            self.assertEqual(actual['skills']['config'], [])
            for flag in ['--ignore-user-config', '--ignore-rules', '--ephemeral', '--json']:
                self.assertIn(flag, command)
            self.assertNotIn('--strict-config', command)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)
