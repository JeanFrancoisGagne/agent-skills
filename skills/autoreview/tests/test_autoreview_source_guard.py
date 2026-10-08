#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "autoreview"
fixture_git = runpy.run_path(str(SCRIPT.with_name("test-review-harness.py")))["fixture_git"]


def git(repo: Path, *args: str) -> str:
    return fixture_git(repo, *args, check=True, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def init_repo(tempdir: Path) -> Path:
    repo = tempdir / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Autoreview Test")
    git(repo, "config", "user.email", "autoreview@example.invalid")
    git(repo, "config", "core.autocrlf", "false")
    return repo


def realistic_secret_value() -> str:
    return "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"

def synthetic_private_key_marker(label: str) -> str:
    # Keep refusal payloads exact without placing a raw key header in the
    # test source, which repository hooks scan before these tests execute.
    return "-----BEGIN " + label + "-----"

def synthetic_database_uri(password: str) -> str:
    return "postgres://" + "reader:" + password + "@host/db"

def synthetic_credential_assignment(
    field: str, value: str, *, separator: str = ": ", quoted: bool = True,
) -> str:
    # Construct the exact hostile fixture only when the test runs, so raw
    # source scanning does not mistake its labelled dummy value for a secret.
    return field + separator + (json.dumps(value) if quoted else value)


class AutoreviewSourceGuardPublicTests(unittest.TestCase):
    def source_reference_cli_fixture(self, repo: Path, relative: str, content: str, phase: str) -> list[str]:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        original = content if phase in {"dataset", "removed", "context"} else "// baseline\n"
        path.write_bytes(original.encode("utf-8"))
        git(repo, "add", relative)
        git(repo, "commit", "-q", "-m", "baseline")
        if phase == "dataset":
            (repo / "change.txt").write_text("changed\n", encoding="utf-8")
            return ["--dataset", relative]
        path.write_bytes(("// replacement\n" if phase == "removed" else content + "\n").encode("utf-8"))
        git(repo, "add", relative)
        return []

    def source_reference_cli_environment(self, root: Path) -> dict[str, str]:
        env = {key: os.environ[key] for key in (
            "PATH", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
        ) if key in os.environ}
        env.update(HOME=str(root), USERPROFILE=str(root),
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        return env

    def assert_source_reference_public_cli(
        self, relative: str, content: str, *, refused: bool, phase: str = "dataset",
    ) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            extra = self.source_reference_cli_fixture(repo, relative, content, phase)
            argv = [sys.executable, str(SCRIPT), "--mode", "local", "--engine", "codex",
                    "--codex-bin", str(root / "missing-reviewer"), *extra]
            # Run the real CLI and scanner. A missing external binary stops an
            # accepted source before any reviewer or provider can execute.
            result = subprocess.run(argv, cwd=repo, env=self.source_reference_cli_environment(root),
                                    text=True, encoding="utf-8", capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            if refused:
                self.assertIn("secret-like content", result.stderr)
                self.assertNotIn("bundle:", result.stdout)
            else:
                self.assertIn("executable not found", result.stderr)
                self.assertIn("bundle:", result.stdout)
                self.assertNotIn("secret-like content", result.stderr)

    def test_public_cli_allows_empty_anchored_environment_selectors(self) -> None:
        sources = (
            "grep -E '^SERVICE_TOKEN=' config.env | tr -d '\r'\n",
            "[ -f config.env ] && grep -E '^SERVICE_TOKEN=' config.env | head -1 | tr -d '\r'\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("install.sh", source, refused=False)

    def test_public_cli_selectors_keep_credential_value_refusals(self) -> None:
        value = realistic_secret_value()
        sources = (
            f"grep -E '^SERVICE_TOKEN={value}' config.env | tr -d '\r'\n",
            f"grep -E '^SERVICE_TOKEN=' config.env\nSERVICE_TOKEN='{value}'\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("install.sh", source, refused=True)

    def test_python_reference_slices_public_cli(self) -> None:
        for expression in ("retained_digest[:16]", "state.digest[start:16:2]"):
            with self.subTest(expression=expression):
                self.assert_source_reference_public_cli(
                    "reader.py", "token = " + expression + "\n", refused=False)
        value = realistic_secret_value()
        for expression in (repr(value) + "[:16]", "retained_digest[" + repr(value) + ":]"):
            with self.subTest(expression=expression):
                self.assert_source_reference_public_cli(
                    "reader.py", "token = " + expression + "\n", refused=True)

    def test_python_reference_affixes_keep_literal_credential_refusals_public_cli(self) -> None:
        value = realistic_secret_value()
        encoded = '"' + ''.join('\\x' + format(ord(char), "02x") for char in value) + '"'
        expressions = (
            repr(value) + ' + retained_digest',
            'retained_digest + ' + repr(value),
            encoded + ' + retained_digest',
            '{"record": ' + repr(value) + ', "checksum": retained_digest}',
            repr(value[:12]) + ' + ' + repr(value[12:]),
            '"realpass9" + retained_digest',
            '"sk_" + "live_" + retained_digest',
            '"f" + "x"',
            repr(synthetic_database_uri("literal-password")) + ' + retained_digest',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                self.assert_source_reference_public_cli("reader.py", "token = " + expression + "\n", refused=True)

    def test_python_reference_affixes_keep_partial_literal_refusals_public_cli(self) -> None:
        for field, expression in (("password", "'hunter-' + suffix"), ("api_key", "'secret-' + suffix")):
            with self.subTest(field=field):
                self.assert_source_reference_public_cli(
                    "reader.py", field + " = " + expression + "\n", refused=True)

    def test_python_keyword_values_public_cli_context_only(self) -> None:
        source = "configure(\n    allow_credentials=True,\n    methods=names,\n)\n"
        self.assert_source_reference_public_cli("reader.py", source, refused=False, phase="context")

    def test_python_keyword_context_keeps_adjacent_credential_refusal(self) -> None:
        value = realistic_secret_value()
        source = f"configure(\n    allow_credentials=True,\n    token={value!r},\n)\n"
        self.assert_source_reference_public_cli("reader.py", source, refused=True, phase="context")

    def test_python_keyword_values_public_cli(self) -> None:
        sources = (
            "configure(\n    allow_credentials=True,\n    methods=names,\n)\n",
            "configure(allow_credentials=False, methods=names)\n",
            "configure(token=current, timeout=duration)\n",
            "é = configure(\n    token=retained[0],\n    timeout=duration,\n)\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("reader.py", source, refused=False)

    def test_python_keyword_values_public_cli_history(self) -> None:
        source = "configure(\n    allow_credentials=True,\n    methods=names,\n)\n"
        for phase in ("staged", "removed", "context"):
            with self.subTest(phase=phase):
                self.assert_source_reference_public_cli("reader.py", source, refused=False, phase=phase)

    def test_python_keyword_values_public_cli_keep_tuple_and_literal_refusals(self) -> None:
        value = realistic_secret_value()
        sources = (
            f"token = current, {value!r}\n",
            'configure(token=("sk_", "live_", current), timeout=duration)\n',
            f"configure(token=current, {value!r})\n",
            f"configure(token=current, # previous token: {value}\n    timeout=duration)\n",
        )
        for source, phase in zip(sources, ("dataset", "staged", "removed", "context")):
            with self.subTest(phase=phase):
                self.assert_source_reference_public_cli("reader.py", source, refused=True, phase=phase)

    def test_delimited_synthetic_fixture_public_cli(self) -> None:
        cases = (
            ("entry.ts", 'const config = { token: "<fixture-service-token>" };\n'),
            ("reader.py", 'api_key = "<sample-client-api-key>"\n'),
        )
        for relative, source in cases:
            with self.subTest(relative=relative):
                self.assert_source_reference_public_cli(relative, source, refused=False)

    def test_delimited_synthetic_fixture_public_cli_keeps_unknown_and_suffix_refusals(self) -> None:
        provider = "sk-proj-" + "A" * 40
        encoded = base64.b64encode(provider.encode()).decode()
        numeric = ", ".join(str(ord(char)) for char in provider)
        cases = (
            'const config = { token: "github-token" };\n',
            'const config = { token: "<github-token>" };\n',
            'const config = { token: "<fixture-abcdefghijklmnopq-token>" };\n',
            'const config = { token: "<fixture-service-password>" };\n',
            'const config = { token: "<fixture-service-token>" + "actual-production-secret" };\n',
            f'const config = {{ token: "<fixture-{provider}-token>" }};\n',
            'const config = { token: "<fixture-'
            + synthetic_database_uri("actual-password")
            + '-token>" };\n',
            f'const config = {{ token: "<fixture-service-token>" + atob("{encoded}") }};\n',
            f'const config = {{ token: "<fixture-service-token>" + String.fromCharCode({numeric}) }};\n',
            'const config = { token: "<fixture-service-token>'
            + synthetic_private_key_marker("OPENSSH PRIVATE KEY")
            + '" };\n',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("entry.ts", source, refused=True)

    def test_fixture_numeric_suffix_public_cli(self) -> None:
        provider = "sk-proj-" + "A" * 40
        numeric = ", ".join(str(ord(char)) for char in provider)
        source = f'const config = {{ token: "<fixture-service-token>" + String.fromCharCode({numeric}) }};\n'
        self.assert_source_reference_public_cli("entry.ts", source, refused=True)

    def test_fixture_base64_suffix_public_cli(self) -> None:
        provider = "sk-proj-" + "A" * 40
        encoded = base64.b64encode(provider.encode()).decode()
        source = f'const config = {{ token: "<fixture-service-token>" + atob("{encoded}") }};\n'
        self.assert_source_reference_public_cli("entry.ts", source, refused=True)

    def test_fixture_marker_numeric_control_public_cli(self) -> None:
        source = 'const config = { token: "<fixture-service-token>" };\n'
        self.assert_source_reference_public_cli("entry.ts", source, refused=False)

    def test_source_reference_public_cli_type_alias(self) -> None:
        source = "export type ProviderUsageAuthToken = _ProviderUsageAuthToken;\n"
        for relative in ("entry.ts", "entry.tsx", "entry.mts", "entry.cts"):
            with self.subTest(relative=relative):
                self.assert_source_reference_public_cli(relative, source, refused=False)

    def test_source_reference_public_cli_header_chain(self) -> None:
        sources = (
            'to' + 'ken = request.headers.get("x-api-key", "")\n',
            'to' + 'ken = request.headers.get("authorization", "").removeprefix("Bearer ").strip()\n',
            'to' + 'ken = (request.headers.get("authorization", "").removeprefix("Bearer ").strip()\n'
            '    or request.headers.get("x-api-key", "") or request.cookies.get("sam_admin_token", ""))\n',
            'to' + 'ken = headers.get("Authorization", "").removeprefix("Bearer ").strip()\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("reader.py", source, refused=False)

    def test_source_reference_public_cli_diff_history(self) -> None:
        sources = (
            ("entry.ts", "export type ProviderUsageAuthToken = _ProviderUsageAuthToken;\n"),
            ("reader.py", 'to' + 'ken = request.headers.get("x-api-key", "").strip()\n'),
        )
        for relative, source in sources:
            for phase in ("staged", "removed", "context"):
                with self.subTest(relative=relative, phase=phase):
                    self.assert_source_reference_public_cli(relative, source, refused=False, phase=phase)

    def test_source_reference_public_cli_refuses_fake_types_and_runtime_values(self) -> None:
        value = realistic_secret_value()
        declaration = "export type ProviderUsageAuthToken = _ProviderUsageAuthToken;\n"
        sources = (
            f'type ProviderUsageAuthToken = "{value}";\n',
            f'type ProviderUsageAuthToken = "' + ''.join('\\x' + format(ord(c), '02x') for c in value) + '";\n',
            f'const ProviderUsageAuthToken = "{value}";\n',
            f'type ProviderUsageAuthToken = _ProviderUsageAuthToken("{value}");\n',
            '// ' + declaration + 'ProviderUsageAuthToken = _ProviderUsageAuthToken;\n',
            '/*\n' + declaration + '*/\nProviderUsageAuthToken = _ProviderUsageAuthToken;\n',
            'const note = `\n' + declaration + '`;\nProviderUsageAuthToken = _ProviderUsageAuthToken;\n',
            declaration + f'const credential = "{value}";\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("entry.ts", source, refused=True)
        for relative in ("entry.js", "evidence.txt"):
            with self.subTest(relative=relative):
                self.assert_source_reference_public_cli(relative, declaration, refused=True)

    def test_source_reference_public_cli_refuses_header_literals_and_receiver_data(self) -> None:
        value = realistic_secret_value()
        expressions = (
            f'request.headers.get("x-api-key", "{value}").strip()',
            f'request.headers.get("authorization", "{value}").removeprefix("Bearer ").strip()',
            f'request.headers.get("authorization", "").removeprefix("{value}").strip()',
            f'read("{value}").headers.get("authorization", "").removeprefix("Bearer ").strip()',
            f'request.headers.get("authorization", "").removeprefix("Bearer ").strip() + "{value}"',
            'request.headers.get("x-api-key", "A7f9" + "K2m4" + "Q8v6")',
            'request.headers.get("authorization", "").removeprefix("Bearer " + current)',
            'request.headers.get("x-api-key", "postgres://reader:actual-password@host/db")',
            'page.get("stolen-key")',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                self.assert_source_reference_public_cli("reader.py", "to" + "ken = " + expression + "\n", refused=True)

    def test_source_reference_public_cli_preserves_decoding_and_parse_bounds(self) -> None:
        value = realistic_secret_value()
        encoded = ''.join('\\x' + format(ord(c), '02x') for c in value)
        sources = (
            'to' + f'ken = request.headers.get("x-api-key", "{encoded}")\n',
            'to' + f'ken = request.headers.get("x-api-key", b"{value}")\n',
            'to' + f'ken = request.headers.get("x-api-key", f"{value}{{current}}")\n',
            'to' + f'ken = request.headers.get("x-api-key", "{value}"\n',
            'to' + f'ken = request.headers.get("x-api-key", ' + 'current + ' * 4096 + repr(value) + ')\n',
        )
        for source in sources:
            with self.subTest(source=source[:80]):
                self.assert_source_reference_public_cli("reader.py", source, refused=True)
        wrapped = 'to' + f'ken = "{value}"'
        for _ in range(9):
            wrapped = "note = " + repr(wrapped)
        self.assert_source_reference_public_cli("reader.py", wrapped + "\n", refused=True)

    def test_source_reference_public_cli_keeps_global_credential_guards(self) -> None:
        alias = "export type ProviderUsageAuthToken = _ProviderUsageAuthToken;\n"
        values = (
            "sk-proj-" + "A" * 40,
            synthetic_private_key_marker("OPENSSH PRIVATE KEY"),
            "postgres://reader:actual-password@host/db",
        )
        for value in values:
            with self.subTest(value=value[:16]):
                self.assert_source_reference_public_cli("entry.ts", alias + f'const note = "{value}";\n', refused=True)
        for phase in ("removed", "context"):
            source = alias + f'const credential = "{realistic_secret_value()}";\n'
            self.assert_source_reference_public_cli("entry.ts", source, refused=True, phase=phase)

    def test_destructured_reference_public_cli(self) -> None:
        # The reported reference is a function binding, not a token value.
        source = (
            'import { vi } from "vitest";\n'
            'const { lookupMock, oauthResolveMock } = vi.hoisted(() => ({\n'
            '  lookupMock: vi.fn(),\n  oauthResolveMock: vi.fn(),\n}));\n'
            'vi.mock("./mcp-oauth.js", () => ({\n'
            + synthetic_credential_assignment('resolveMcpOAuthAccessToken', 'oauthResolveMock', quoted=False)
            + ',\n}));\n'
        )
        self.assert_source_reference_public_cli('mcp-http-fetch.test.ts', source, refused=False)
        renamed = ('const { selected: dispatchIdentity } = lookup();\n'
                   'function resolve() { return { '
                   + synthetic_credential_assignment('apiKey', 'dispatchIdentity', quoted=False)
                   + ' }; }\n')
        self.assert_source_reference_public_cli('runtime.ts', renamed, refused=False)

    def test_destructured_reference_refusals_public_cli(self) -> None:
        reference = synthetic_credential_assignment('resolveMcpOAuthAccessToken', 'oauthResolveMock', quoted=False)
        mock = 'vi.mock("./mcp-oauth.js", () => ({ ' + reference + ' }));\n'
        declaration = 'const { oauthResolveMock } = lookup();\n'
        sources = (
            declaration + 'vi.mock("./mcp-oauth.js", () => ({ '
            + synthetic_credential_assignment('resolveMcpOAuthAccessToken', 'oauthResolveMock') + ' }));\n',
            'const { oauthResolveMock } = { oauthResolveMock: ' + json.dumps(realistic_secret_value()) + ' };\n' + mock,
            'const { oauthResolveMock } = { oauthResolveMock: String.fromCharCode(65, 55, 102, 57) };\n' + mock,
            declaration + 'vi.mock("./mcp-oauth.js", () => ({ ' + reference + '\n ?? '
            + json.dumps(realistic_secret_value()) + ' }));\n',
            'let sourceValue = lookup();\nconst { oauthResolveMock } = sourceValue;\n'
            + 'sourceValue = ' + json.dumps(realistic_secret_value()) + ';\n' + mock,
            'const { oauthResolveMock = lookup() } = lookup();\n' + mock,
            declaration + mock + 'const config = { '
            + synthetic_credential_assignment('apiKey', 'github-token') + ' };\n',
        )
        for index, source in enumerate(sources):
            with self.subTest(index=index):
                self.assert_source_reference_public_cli('mcp-http-fetch.test.ts', source, refused=True)

    def test_source_reference_public_cli_keeps_unknown_mock_literal_refusal(self) -> None:
        source = ('import { it, vi } from "vitest";\n'
                  'it("auth", () => { vi.fn().mockResolvedValue({ '
                  + synthetic_credential_assignment("apiKey", "github-token")
                  + ' }); });\n')
        self.assert_source_reference_public_cli("request-auth.test.ts", source, refused=True)

    def test_compose_same_line_single_quotes_remain_literal(self) -> None:
        source = "  - 'DATABASE_URL: postgres://reader:${DB_PASSWORD:?required}@db/data'\n"
        self.assert_source_reference_public_cli("compose.yml", source, refused=True)

    def test_documentation_comment_references_public_cli(self) -> None:
        cases = (
            ("compose.yml", '# "is a directory". Minting a new token: deployment/onprem/homeassistant/README.md.\n', "dataset"),
            ("compose.yml", '# "is a directory". Minting a new token: deployment/onprem/homeassistant/README.md.\n', "context"),
            ("reader.py", "# Configuring a password: docs/security/overview.rst.\n", "dataset"),
        )
        for relative, content, phase in cases:
            with self.subTest(relative=relative, phase=phase):
                self.assert_source_reference_public_cli(relative, content, refused=False, phase=phase)

    def test_documentation_comment_references_keep_credential_refusals(self) -> None:
        value = realistic_secret_value()
        encoded = base64.b64encode(value.encode()).decode()
        contents = (
            "# Setting a token: " + value + "\n",
            '# Setting a token: "' + value + '"\n',
            "# Setting a token: " + encoded + "\n",
            "# Setting a token: docs/security.md. " + value + "\n",
            "# Setting a token: docs/" + value + ".md\n",
            "token: docs/security.md\n",
        )
        for content in contents:
            with self.subTest(content=content):
                self.assert_source_reference_public_cli("compose.yml", content, refused=True)

    def test_compose_indentless_mount_sequences_public_cli(self) -> None:
        items = "    - data:/data\n    - admin_password:/run/admin_password:ro\n"
        for owner, refused in (("volumes", False), ("environment", True)):
            source = "services:\n  service:\n    " + owner + ":\n" + items
            with self.subTest(owner=owner):
                self.assert_source_reference_public_cli("compose.yml", source, refused=refused)

    def test_compose_required_mount_source_public_cli(self) -> None:
        mount = ("      - ${STATE_DIR:?STATE_DIR required - the copied state}/secrets/"
                 "admin_token:/etc/secrets/admin_token:ro\n")
        for phase in ("dataset", "context"):
            with self.subTest(phase=phase):
                self.assert_source_reference_public_cli(
                    "compose.yml", "services:\n  service:\n    volumes:\n" + mount,
                    refused=False, phase=phase,
                )

    def test_reference_boundaries_keep_secret_refusals(self) -> None:
        opaque = "qjkmnpqrstuvwxyzghijklmno"
        sources = (
            "# Setting a token: docs/" + opaque + ".md\n",
            "services:\n  service:\n    volumes:\n      - ${STATE_DIR:?required #}/admin_password:/" + opaque + "\n",
            "keep: true" + " " * 8193 + "# prose token: docs/security.md\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("compose.yml", source, refused=True)

    def test_reference_boundaries_preserve_public_references(self) -> None:
        sources = (
            "# Configuring a token: docs/security.md\n",
            "services:\n  service:\n    volumes:\n      - ${STATE_DIR:?required}/secrets/admin_token:/etc/secrets/admin_token:ro\n",
            'services:\n  service:\n    volumes:\n      - "${STATE_DIR:?required #}/secrets/admin_token:/etc/secrets/admin_token:ro"\n',
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("compose.yml", source, refused=False)

    def test_documentation_punctuation_keeps_credential_refusals(self) -> None:
        for component in ("qjkmnpqrst-uvwxyzghij", "qjkmnpqrst.uvwxyzghij"):
            with self.subTest(component=component):
                self.assert_source_reference_public_cli(
                    "compose.yml", "# Setting a token: docs/" + component + ".md\n",
                    refused=True,
                )

    def test_compose_required_mount_source_keeps_credential_refusals(self) -> None:
        value = realistic_secret_value()
        encoded = base64.b64encode(value.encode()).decode()
        expressions = (
            "${STATE_DIR:?password=" + value + "}",
            "${STATE_DIR:?password=" + encoded + "}",
            "${STATE_DIR:-" + value + "}",
            "${STATE_DIR:?${OTHER_DIR}}",
        )
        for expression in expressions:
            source = ("services:\n  service:\n    volumes:\n      - " + expression
                      + "/secrets/admin_token:/etc/secrets/admin_token:ro\n")
            with self.subTest(expression=expression):
                self.assert_source_reference_public_cli("compose.yml", source, refused=True)
        source = ("services:\n  service:\n    environment:\n"
                  "      - ${STATE_DIR:?required}/secrets/admin_token:/etc/secrets/admin_token:ro\n")
        self.assert_source_reference_public_cli("compose.yml", source, refused=True)

    def test_compose_mount_lookup_stops_at_outer_sequence(self) -> None:
        source = ("services:\n  service:\n    volumes:\n    - data:/data\n"
                  "    - environment:\n      - admin_password:/run/admin_password:ro\n")
        self.assert_source_reference_public_cli("compose.yml", source, refused=True)

    def test_compose_mount_references_public_cli(self) -> None:
        mount = "      - ~/.state/secrets/admin_password:/etc/secrets/admin_password:ro\n"
        cases = (
            ("compose.yml", "services:\n  service:\n    volumes:\n" + mount, False),
            ("compose.yml", "services:\n  service:\n    environment:\n" + mount, True),
            ("settings.yml", "services:\n  service:\n    volumes:\n" + mount, True),
            ("compose.yml", "services:\n  service:\n    volumes:\n" + mount
             + "      # password=" + realistic_secret_value() + "\n", True),
        )
        for relative, source, refused in cases:
            with self.subTest(relative=relative, source=source):
                self.assert_source_reference_public_cli(relative, source, refused=refused)

    def test_compose_environment_references_public_cli(self) -> None:
        required = "SAM_DB_PASSWORD: ${SAM_DB_PASSWORD" + ":?SAM_DB_PASSWORD required}\n"
        cases = (
            (required, "dataset"),
            (required + "SAM_DB_URL: postgres://reader:${SAM_DB_PASSWORD:?required}@db/data\n", "context"),
            ('SERVICE_SECRET: "${CURRENT_SECRET?set the configured value}"\n', "dataset"),
            ("SERVICE_PASSWORD: ${SERVICE_PASSWORD:-}\n", "staged"),
            ('SERVICE_PASSWORD: "${SERVICE_PASSWORD:-}"\n', "dataset"),
            ("description: operator's service\nDATABASE_URL: postgres://reader:${SERVICE_PASSWORD:?required}@db/data\n", "dataset"),
            ('DATA_SOURCE_NAME: "postgres://reader:${SERVICE_PASSWORD:?required}@db/data"\n', "dataset"),
        )
        for source, phase in cases:
            with self.subTest(phase=phase, source=source):
                self.assert_source_reference_public_cli("compose.yml", source, refused=False, phase=phase)

    def test_compose_environment_references_keep_secret_refusals(self) -> None:
        value = realistic_secret_value()
        encoded = base64.b64encode(value.encode()).decode()
        sources = (
            f"SERVICE_PASSWORD: {value}\n",
            "SERVICE_PASSWORD: ${SERVICE_PASSWORD:-" + value + "}\n",
            "SERVICE_PASSWORD: ${SERVICE_PASSWORD:-" + encoded + "}\n",
            "SERVICE_PASSWORD: ${SERVICE_PASSWORD:?password=" + value + "}\n",
            "SERVICE_PASSWORD: ${SERVICE_PASSWORD:?required} " + value + "\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assert_source_reference_public_cli("compose.yml", source, refused=True)


    def test_destructured_alias_member_write_refusal_public_cli(self) -> None:
        source = (
            "const { sourceValue } = lookup();\n"
            "const { auth: aliasValue } = sourceValue;\n"
            'aliasValue["opaque"] = ' + json.dumps(realistic_secret_value()) + ";\n"
            "function resolve() { return { "
            + synthetic_credential_assignment("apiKey", "sourceValue.auth.opaque", quoted=False)
            + " }; }\n"
        )
        self.assert_source_reference_public_cli("entry.ts", source, refused=True)

    def test_destructured_alias_object_assign_refusal_public_cli(self) -> None:
        source = (
            "const { sourceValue } = lookup();\n"
            "const { auth: aliasValue } = sourceValue;\n"
            "Object.assign(aliasValue, { opaque: " + json.dumps(realistic_secret_value()) + " });\n"
            "function resolve() { return { "
            + synthetic_credential_assignment("apiKey", "sourceValue.auth.opaque", quoted=False)
            + " }; }\n"
        )
        self.assert_source_reference_public_cli("entry.ts", source, refused=True)


    def test_destructured_alias_without_write_public_cli(self) -> None:
        source = (
            "const { sourceValue } = lookup();\n"
            "const { auth: aliasValue } = sourceValue;\n"
            "function resolve() { return { "
            + synthetic_credential_assignment("apiKey", "aliasValue.opaque", quoted=False)
            + " }; }\n"
        )
        self.assert_source_reference_public_cli("entry.ts", source, refused=False)

    def test_public_cli_keeps_unproved_credential_origins_refused(self) -> None:
        unproved = "const " + synthetic_credential_assignment(
            "token", "data.session?.access_token", separator=" = ", quoted=False,
        ) + ";\n"
        original = Path(__file__).with_name("fixtures") / "typescript-benign-references.ts"
        for source in (unproved, original.read_text(encoding="utf-8")):
            with self.subTest(source_kind="unproved external reference or literal-bearing call"):
                self.assert_source_reference_public_cli("entry.ts", source, refused=True)


    def test_public_cli_keeps_mismatched_placeholder_fields_refused(self) -> None:
        for field, value in (("api_key", "test-key"), ("api_secret", "test-secret"),
                             ("access_token", "test-token")):
            source = "const fixture = { " + synthetic_credential_assignment(field, value) + " };\n"
            with self.subTest(field=field):
                self.assert_source_reference_public_cli("entry.ts", source, refused=True)


    def test_destructured_spread_operand_refusal_public_cli(self) -> None:
        source = (
            "const { sourceValue } = lookup();\n"
            "const { auth: aliasValue } = { ...sourceValue };\n"
            'aliasValue["opaque"] = ' + json.dumps(realistic_secret_value()) + ";\n"
            "function resolve() { return { "
            + synthetic_credential_assignment("apiKey", "sourceValue.auth.opaque", quoted=False)
            + " }; }\n"
        )
        self.assert_source_reference_public_cli("entry.ts", source, refused=True)

    def test_destructured_call_receiver_refusal_public_cli(self) -> None:
        source = (
            "const { sourceValue } = lookup();\n"
            "const { auth: aliasValue } = sourceValue.view();\n"
            'aliasValue["opaque"] = ' + json.dumps(realistic_secret_value()) + ";\n"
            "function resolve() { return { "
            + synthetic_credential_assignment("apiKey", "sourceValue.auth.opaque", quoted=False)
            + " }; }\n"
        )
        self.assert_source_reference_public_cli("entry.ts", source, refused=True)


if __name__ == "__main__":
    unittest.main()
