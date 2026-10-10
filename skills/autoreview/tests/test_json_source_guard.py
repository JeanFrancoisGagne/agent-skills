"""JSON evidence preserves escaped references and refuses decoded credentials."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import runpy
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/autoreview_source_guard.py'
SPEC = importlib.util.spec_from_file_location('json_guard_under_test', SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


def secret_fixture():
    return 'A7f9K2m4Q8v6' + 'N3x5R1p0T9z8'


class JsonEvidenceGuardTests(unittest.TestCase):
    def test_json_context_preserves_escaped_synthetic_call_and_following_code(self):
        source = ('        self.enterContext(patch.dict(os.environ, SAM_KNOWLEDGE_TOKEN="test-token-placeholder"))\n'
                  '        if domain_answers:\n            return response.json()["result"]\n        return post')
        text = json.dumps({'service': [{'source': source}]}, indent=2)
        GUARD.require_safe_source('file source', 'context.json', text)

    def test_json_context_preserves_independent_producer_escaping(self):
        text = '{"source":"configure(token=\\u0022test-token\\u0022)\\nreturn result"}'
        GUARD.require_safe_source('file source', 'context.json', text)

    def test_json_credentials_are_refused_after_decoding(self):
        payloads = (
            {'apiKey': secret_fixture()},
            {'source': 'apiKey = ' + repr(secret_fixture())},
            {'nested': [{'access_token': secret_fixture()}]},
            {'source': 'Authorization: Bearer ' + secret_fixture()},
            {'source': 'postgres://' + 'user:' + secret_fixture() + '@host/db'},
        )
        for payload in payloads:
            with self.subTest(shape=list(payload)):
                text = json.dumps(payload)
                with self.assertRaisesRegex(SystemExit, 'secret-like content'):
                    GUARD.require_safe_source('file source', 'context.json', text)

    def test_json_decoding_checks_unicode_escapes_and_duplicate_keys(self):
        encoded = ''.join('\\u%04x' % ord(char) for char in secret_fixture())
        values = (
            '{"access_token":"' + encoded + '"}',
            '{"access_token":"' + encoded + '","access_token":"test-token"}',
            json.dumps({'source': 'apiKey = ' + repr(secret_fixture())}).replace(secret_fixture(), encoded),
        )
        for text in values:
            with self.subTest(index=values.index(text)):
                with self.assertRaisesRegex(SystemExit, 'secret-like content'):
                    GUARD.require_safe_source('file source', 'context.json', text)

    def test_json_credential_container_and_comment_data_stay_refused(self):
        payloads = (
            {'token': [secret_fixture()]},
            {'source': '# apiKey: ' + secret_fixture()},
            {'source': 'credentials=' + repr(secret_fixture())},
        )
        for payload in payloads:
            with self.subTest(shape=list(payload)):
                with self.assertRaisesRegex(SystemExit, 'secret-like content'):
                    GUARD.require_safe_source('file source', 'context.json', json.dumps(payload))

    def test_malformed_json_keeps_strict_source_scanning(self):
        text = '{"token": "' + secret_fixture() + '"'
        with self.assertRaisesRegex(SystemExit, 'secret-like content'):
            GUARD.require_safe_source('file source', 'context.json', text)

    def test_public_evidence_refuses_original_numeric_credential_spellings(self):
        helper = runpy.run_path(str(SCRIPT.with_name('autoreview')))
        spellings = ('0.' + '0' * 39 + '1', '1e' + '10000000')
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            for key, value in zip(('password', 'token'), spellings):
                text = '{' + json.dumps(key) + ':' + value + '}'
                (repo / 'data.json').write_text(text, encoding='utf-8')
                with self.subTest(key=key):
                    with self.assertRaisesRegex(SystemExit, 'secret-like content'):
                        helper['validate_evidence_file'](repo, 'data.json', '--dataset')


if __name__ == '__main__':
    unittest.main()
