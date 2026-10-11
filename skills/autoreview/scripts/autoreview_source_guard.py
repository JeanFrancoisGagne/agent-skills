from __future__ import annotations

# Captured text is checked before any review engine receives it.
# The lexical owner has no Git, file, capture, or engine dependencies.
import ast
import contextvars
import contextlib
import posixpath
import base64
import binascii
import bisect
import functools
import hashlib
import io
import json
import re
import tokenize
import unicodedata
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Callable, NamedTuple


SECRET_KEY_NAME_PATTERN = (
    r"(?:api[_-]?key|aws[_-]?secret[_-]?access[_-]?key"
    r"|client[_-]?secret|refresh[_-]?token|access[_-]?token"
    r"|auth[_-]?token|id[_-]?token|token|secret|password"
    r"|credentials?|private[_-]?key)"
)

SECRET_SEPARATED_KEY_NAME_PATTERN = (
    rf"(?:[A-Za-z0-9]{{1,64}}"
    rf"(?:[_-][A-Za-z0-9]{{1,64}}){{0,15}}[_-]"
    rf"{SECRET_KEY_NAME_PATTERN})"
)

SECRET_LOWER_KEY_NAME_PATTERN = (
    r"(?-i:[a-z][a-z0-9]*"
    r"(?:apikey|awssecretaccesskey|clientsecret|refreshtoken"
    r"|accesstoken|authtoken|idtoken|token|secret|password"
    r"|credential|credentials|privatekey))"
)

SECRET_CAMEL_KEY_NAME_PATTERN = (
    r"(?-i:[A-Za-z][A-Za-z0-9]*"
    r"(?:ApiKey|APIKey|AwsSecretAccessKey|AWSSecretAccessKey"
    r"|ClientSecret|RefreshToken|AccessToken|AuthToken|IdToken|IDToken"
    r"|Token|Secret|Password"
    r"|Credential|Credentials|PrivateKey))"
)

SECRET_UPPER_KEY_NAME_PATTERN = (
    r"(?-i:[A-Z][A-Z0-9]*"
    r"(?:APIKEY|AWSSECRETACCESSKEY|CLIENTSECRET|REFRESHTOKEN"
    r"|ACCESSTOKEN|AUTHTOKEN|IDTOKEN|TOKEN|SECRET|PASSWORD"
    r"|CREDENTIAL|CREDENTIALS|PRIVATEKEY))"
)

SECRET_ASSIGNMENT_KEY_NAME_PATTERN = (
    rf"(?:{SECRET_SEPARATED_KEY_NAME_PATTERN}"
    rf"|{SECRET_LOWER_KEY_NAME_PATTERN}"
    rf"|{SECRET_CAMEL_KEY_NAME_PATTERN}"
    rf"|{SECRET_UPPER_KEY_NAME_PATTERN}"
    rf"|{SECRET_KEY_NAME_PATTERN})"
)

SECRET_ASSIGNMENT_KEY_PATTERN = (
    rf"(?:[\"']{SECRET_ASSIGNMENT_KEY_NAME_PATTERN}[\"']"
    rf"|(?<![A-Za-z0-9]){SECRET_ASSIGNMENT_KEY_NAME_PATTERN}"
    rf"(?![A-Za-z0-9]))"
)

SECRET_ASSIGNMENT_PATTERN = re.compile(
    rf"(?i){SECRET_ASSIGNMENT_KEY_PATTERN}\s*[:=]\s*"
    r"(?:\"(?P<double_value>[^\"\r\n]{8,})\"|"
    r"'(?P<single_value>[^'\r\n]{8,})'|"
    r"`(?P<backtick_value>[^`\r\n]{8,})`|"
    r"(?P<call_value>[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)(?=[ \t]*\()|"
    r"(?P<reference_value>[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*"
    r"|(?:\?\.)?\[(?:[A-Za-z_$][A-Za-z0-9_$]*"
    r"|[\"'][A-Za-z_$][A-Za-z0-9_$]*[\"']|[0-9]+)\])+)"
    r"(?![A-Za-z0-9_./+=:@#$%&*!?-])|"
    r"(?P<bare_value>[A-Za-z0-9_./+=:@#$%&*!?-]{8,}))"
)

SECRET_ASSIGNMENT_PREFIX_PATTERN = re.compile(
    rf"(?i){SECRET_ASSIGNMENT_KEY_PATTERN}"
    r"\s*(?:=(?!=|>)|:(?![:=]))\s*"
)

SECRET_VALUE_PATTERNS = [
    re.compile(
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?"
        r"PRIVATE KEY(?: BLOCK)?-----"
    ),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
    re.compile(r"\b(?:sk|rk|pk|org|proj)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]

BASIC_AUTHORIZATION_PATTERN = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_])[\"']?authorization[\"']?"
    r"\s*[:=]\s*[\"']?"
    r"basic\s+(?P<credential>[A-Za-z0-9+/]{8,}={0,2})"
    r"(?![A-Za-z0-9+/=])"
)

URI_SCHEME_PATTERN = re.compile(
    r"\b[A-Za-z][A-Za-z0-9+.-]*:(?:\\?/){2}",
    re.IGNORECASE,
)

URI_PASSWORD_REFERENCE_PATTERNS = (
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
    re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$"),
    re.compile(
        r"^\$\{[A-Za-z_$][A-Za-z0-9_$]*"
        r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*"
        r"|\[(?:[0-9]+|[\"'][A-Za-z_$][A-Za-z0-9_$]*[\"'])\])+\}$"
    ),
    re.compile(
        r"^\{[A-Za-z_$][A-Za-z0-9_$]*"
        r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*"
        r"|\[(?:[0-9]+|[\"'][A-Za-z_$][A-Za-z0-9_$]*[\"'])\])+\}$"
    ),
)

URI_CREDENTIAL_REFERENCE_TEXT = (
    r"[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*"
    r"|\[(?:[0-9]+|[\"'][A-Za-z_$][A-Za-z0-9_$]*[\"'])\])*"
)

URI_CREDENTIAL_REFERENCE_PATTERN = re.compile(
    rf"^{URI_CREDENTIAL_REFERENCE_TEXT}$"
)

URI_COMPUTED_REFERENCE_PATTERN = re.compile(
    rf"^{URI_CREDENTIAL_REFERENCE_TEXT}"
    rf"\(\s*{URI_CREDENTIAL_REFERENCE_TEXT}\s*\)$"
)

POWERSHELL_ENV_REFERENCE_PATTERN = re.compile(
    r"^\$env:[A-Za-z_][A-Za-z0-9_]*$",
    re.IGNORECASE,
)

MAX_JAVASCRIPT_INITIALIZER_ROOTS = 32

SECRET_PLACEHOLDER_VALUES = {
    "changeme",
    "decoy-token",
    "dummy",
    "example",
    "fake",
    "gateway-token",
    "matrix_qa_e2ee_cli_gateway",
    "matrix_qa_e2ee_thread",
    "matrix_qa_e2ee_verify_notice",
    "not-a-real",
    "not-a-valid-matrix-recovery-key",
    "placeholder",
    "redacted",
    "sample",
    "secret-token",
    "test-auth-token",
    "test-token-placeholder",
    "token-oversized",
    "clawrouter-e2e-secret",
    "config-token",
    "very-long-browser-token-0123456789",
}

SYNTHETIC_SECRET_PREFIXES = frozenset(
    {"dummy", "example", "fake", "fixture", "mock", "sample", "test"}
)

FETCH_CREDENTIAL_MODE_VALUES = {"include", "omit", "same-origin"}

URI_PASSWORD_PLACEHOLDER_VALUES = {
    "clawrouter-e2e-secret",
    "dummy",
    "example",
    "fake",
    "not-a-real",
    "placeholder",
    "redacted",
    "sample",
    "test-auth-token",
    "test-token-placeholder",
    "token-oversized",
    "very-long-browser-token-0123456789",
}

URI_CREDENTIAL_NAME_PATTERN = re.compile(
    r"(?:api[_-]?key|auth|credential|pass(?:word)?|pwd|secret|token)",
    re.IGNORECASE,
)

SHELL_COMMAND_WRAPPERS = {"command", "env", "sudo"}

NON_SHELL_COMMAND_WORDS = {
    "assert",
    "await",
    "case",
    "catch",
    "class",
    "const",
    "def",
    "else",
    "except",
    "export",
    "finally",
    "for",
    "from",
    "function",
    "if",
    "import",
    "include",
    "interface",
    "let",
    "match",
    "new",
    "print",
    "raise",
    "require",
    "return",
    "switch",
    "throw",
    "try",
    "type",
    "var",
    "while",
    "with",
    "yield",
}

PUBLIC_PROMPT_TARGETS = {"getpass.getpass", "input", "prompt"}

GENERIC_CREDENTIAL_PROMPT_PATTERN = re.compile(
    r"(?i)\s*(?:(?:enter|type|provide)\s+(?:(?:your|the)\s+)?)?"
    r"(?:password|passphrase|api[\s_-]*(?:key|token))"
    r"(?:\s+for\s+(?:the\s+)?"
    r"(?P<service>[A-Za-z][A-Za-z0-9 _-]{0,48}))?"
    r"\s*[:?]?\s*"
)

PROMPT_SECRET_THEME_WORDS = frozenset(
    {
        "admin",
        "autumn",
        "fall",
        "password",
        "secret",
        "spring",
        "summer",
        "vacation",
        "welcome",
        "winter",
    }
)

CSHARP_STANDALONE_REFERENCE_PATTERN = re.compile(
    r"(?:credential|credentials|pass|passwd|password|pwd|secret|token)",
    re.IGNORECASE,
)

CSHARP_METHOD_MODIFIERS_PATTERN = (
    r"(?:(?:async|extern|internal|new|override|partial|private|protected"
    r"|public|sealed|static|unsafe|virtual)\s+)*"
)

CSHARP_ATTRIBUTE_PATTERN = r"(?:\[[^\[\]{};]*\]\s*)*"

CSHARP_TYPE_MODIFIERS_PATTERN = (
    r"(?:(?:abstract|file|internal|new|partial|private|protected|public"
    r"|readonly|ref|sealed|static|unsafe)\s+)*"
)

CSHARP_TYPE_PREFIX_PATTERN = (
    rf"{CSHARP_ATTRIBUTE_PATTERN}"
    rf"{CSHARP_TYPE_MODIFIERS_PATTERN}"
    r"(?:class|interface|namespace|record(?:\s+(?:class|struct))?|struct)\s+"
    r"[A-Za-z_][A-Za-z0-9_.]*(?:<[^{};]+>)?[^{;]*\{"
)

CSHARP_RETURN_TYPE_PATTERN = (
    r"(?:(?:ref\s+(?:readonly\s+)?|scoped\s+)?"
    r"(?:(?:[A-Za-z_][A-Za-z0-9_]*::)?"
    r"[A-Za-z_][A-Za-z0-9_.]*"
    r"(?:<[^{};]+>)?"
    r"|\([^{};]+\))(?:\?|\*|\[[,\s]*\])*)"
)

CSHARP_METHOD_PREFIX_PATTERN = (
    rf"{CSHARP_ATTRIBUTE_PATTERN}"
    rf"{CSHARP_METHOD_MODIFIERS_PATTERN}"
    r"(?!function\b)"
    rf"{CSHARP_RETURN_TYPE_PATTERN}\s+"
    r"[A-Za-z_][A-Za-z0-9_]*(?:<[^(){};]+>)?\s*"
    r"\([^{};]*\)\s*"
    r"(?:where\s+[^{;]+)?\{"
)

CSHARP_EVIDENCE_WINDOW = 8192

SOURCE_CODE_REFERENCE_ROOT_VALUES = {
    "attemptAuthProfileStore",
}

SOURCE_CODE_REFERENCE_ROOT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$?.])(?:"
    + "|".join(
        re.escape(value)
        for value in sorted(SOURCE_CODE_REFERENCE_ROOT_VALUES, key=len, reverse=True)
    )
    + r")(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*"
    r"|(?:\?\.)?\[(?:[A-Za-z_$][A-Za-z0-9_$]*"
    r"|[\"']profiles[\"']|[0-9]+)\])+"
    r"(?![A-Za-z0-9_$])"
)

QUOTED_SECRET_REFERENCE_PATTERNS = (
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\$env:[A-Za-z_][A-Za-z0-9_]*$", re.IGNORECASE),
    re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$"),
    re.compile(r"^\$\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}$"),
    re.compile(r"^\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}$"),
    re.compile(
        r"^\$\{(?:process\.env|os\.environ|env|cfg|config|params|payload|provider|user|"
        r"request|response|result|input|runtime|account|client|options|auth|auth_response|oauth_response|"
        r"token_response|api_response|authentication|credentials|settings|self|this)"
        r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*"
        r"|\[(?:[\"'][A-Za-z_$][A-Za-z0-9_$]*[\"']|[0-9]+)\])+\}$"
    ),
    re.compile(r"^op://[^\r\n]+$"),
)

UNQUOTED_SECRET_REFERENCE_PATTERNS = (
    *QUOTED_SECRET_REFERENCE_PATTERNS,
    re.compile(
        r"^(?:process\.env|os\.environ|env|cfg|config|params|payload|provider|user|"
        r"request|response|result|input|runtime|account|client|options|auth|auth_response|oauth_response|"
        r"token_response|api_response|authentication|credentials|settings|self|this)"
        r"(?:(?:\?\.|[.\[]).*)$"
    ),
    re.compile(
        r"^(?:cached|current|existing|loaded|previous|resolved|saved|stored)_"
        r"(?:api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|client[_-]?secret|"
        r"refresh[_-]?token|access[_-]?token|auth[_-]?token|id[_-]?token|"
        r"token|secret|password)$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^(?:computed|derived|generated|provided|runtime)_"
        r"[A-Za-z0-9_]*(?:api[_-]?key|credential|password|secret|token)"
        r"[A-Za-z0-9_]*(?:ref|reference)$",
        re.IGNORECASE,
    ),
)

BACKTICK_SECRET_REFERENCE_PATTERNS = (
    re.compile(
        r"^op\s+read(?:\s+--no-newline)?\s+(?:"
        r"op://[A-Za-z0-9._~:/@%+=,-]+|"
        r"(?P<op_quote>[\"'])op://[^`\"'\r\n]+(?P=op_quote)"
        r")$"
    ),
)

BACKTICK_TEMPLATE_INTERPOLATION_PATTERN = re.compile(r"\$\{([^{}\r\n]+)\}")

BACKTICK_TEMPLATE_SAFE_LITERAL_PATTERN = re.compile(
    r"(?i)(?:(?:Bearer|Basic)[ \t]+|[ \t:./,_-]*)"
)

BACKTICK_TEMPLATE_FIXTURE_PREFIX_VALUES = {"matrix-qa-"}

SOURCE_CODE_REFERENCE_VALUES = {
    "cliDevice.accessToken",
    "context.driverAccessToken",
    "context.driverPassword",
    "context.observerAccessToken",
    "context.observerPassword",
    "context.sutAccessToken",
    "context.sutPassword",
    "driverAccount.accessToken",
    "driverAccount.password",
    "driverPassword",
    "recoveryDevice.accessToken",
    "recoveryDevice.password",
}

SOURCE_CODE_REFERENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$?.])(?:" + "|".join(
        re.escape(value)
        for value in sorted(SOURCE_CODE_REFERENCE_VALUES, key=len, reverse=True)
    ) + r")(?![A-Za-z0-9_$])"
)

SOURCE_CODE_LIFECYCLE_REFERENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_$?.])"
    r"(?:(?:cached|current|existing|loaded|previous|resolved|saved|stored|successful)"
    r"[A-Za-z0-9_$]*"
    r"(?:ApiKey|Credential|Credentials|Password|Secret|Token)"
    r"|(?:apiKey|credential|credentials|password|secret|token))(?:Info)?"
    r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*"
    r"(?![A-Za-z0-9_$])"
)

def fallback_expression(text: str, *, typescript: bool = False) -> str:
    operator_keywords = (
        r"|as(?![\w$])|satisfies(?![\w$])" if typescript else ""
    )
    operator = re.match(
        r"\s*(?:\|\||&&|\?\?|[=<>!~:+\-*/%&|^?.,]"
        r"|and\b|else\b|if\b|in(?![\w$])|instanceof(?![\w$])"
        r"|is\b|not\b|or\b"
        r"|unless\b"
        + operator_keywords
        + r")",
        text,
    )
    cursor = operator.end() if operator is not None else 0
    stack: list[str] = []
    operand_started = False
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if line_comment:
            if char in "\r\n\u2028\u2029":
                line_comment = False
                if (
                    operand_started
                    and not stack
                    and not javascript_continues_after_line_terminator(
                        text[cursor + 1 :],
                        typescript=typescript,
                    )
                ):
                    break
            cursor += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                cursor += 2
            else:
                cursor += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            cursor += 1
            continue
        regex_end = javascript_regex_literal_end(text, cursor)
        if regex_end is not None:
            cursor = regex_end
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            cursor += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            cursor += 2
            continue
        if char == "#":
            line_comment = True
            cursor += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
            operand_started = True
            cursor += 1
            continue
        if char in pairs:
            stack.append(pairs[char])
            operand_started = True
            cursor += 1
            continue
        if stack and char == stack[-1]:
            stack.pop()
            cursor += 1
            continue
        if not stack and char in ",;)]}":
            break
        if char in "\r\n\u2028\u2029" and operand_started and not stack:
            if not javascript_continues_after_line_terminator(
                text[cursor + 1 :],
                typescript=typescript,
            ):
                break
        if not stack and (char.isalpha() or char in "_$"):
            word_end = cursor + 1
            while word_end < len(text) and (
                text[word_end].isalnum() or text[word_end] in "_$"
            ):
                word_end += 1
            word = text[cursor:word_end]
            word_operators = {"in", "instanceof"}
            if typescript:
                word_operators.update({"as", "satisfies"})
            operand_started = word not in word_operators
            cursor = word_end
            continue
        if not stack and char in "=<>!~:+-*/%&|^?.":
            operand_started = False
        elif not char.isspace():
            operand_started = True
        cursor += 1
    return text[:cursor]

def javascript_continues_after_line_terminator(
    text: str,
    *,
    typescript: bool = False,
) -> bool:
    suffix = text.lstrip()
    if suffix.startswith(("++", "--", "~")) or (
        suffix.startswith("!") and not suffix.startswith("!=")
    ):
        return False
    type_operators = (
        r"|as(?![\w$])|satisfies(?![\w$])" if typescript else ""
    )
    return re.match(
        r"(?:[=<>!:+\-*/%&|^?.,([`]|in(?![\w$])|instanceof(?![\w$])"
        + type_operators
        + r")",
        suffix,
    ) is not None

def top_level_fallback_suffix(
    text: str,
    *,
    allow_chained_assignment: bool = False,
) -> str | None:
    stack: list[tuple[str, bool]] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    outer_group_openers: set[int] = set()
    probe = 0
    while probe < len(text) and text[probe].isspace():
        probe += 1
    while probe < len(text) and text[probe] == "(":
        outer_group_openers.add(probe)
        probe += 1
        while probe < len(text) and text[probe].isspace():
            probe += 1
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    cursor = 0
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
                object_member_context = any(
                    closer == "}"
                    for closer, _is_outer in stack
                )
                remaining = text[cursor + 1 :]
                top_level_statement = (
                    not stack
                    and re.match(
                        r"\s*(?:\|\||&&|\?\?|\+|\?(?!\.)|or\b)",
                        remaining,
                    )
                    is None
                )
                object_sibling = (
                    object_member_context
                    and starts_sibling_assignment(remaining)
                )
                if top_level_statement or object_sibling:
                    return None
            cursor += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                cursor += 2
            else:
                cursor += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            cursor += 1
            continue
        if char == "\\" and next_char:
            cursor += 2
            continue
        regex_end = javascript_regex_literal_end(text, cursor)
        if regex_end is not None:
            cursor = regex_end
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            cursor += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            cursor += 2
            continue
        if char in {'"', "'", "`"}:
            quote = char
            cursor += 1
            continue
        if char in pairs:
            stack.append((pairs[char], cursor in outer_group_openers))
            cursor += 1
            continue
        if stack and char == stack[-1][0]:
            stack.pop()
            cursor += 1
            continue
        fallback_depth = not stack or all(is_outer for _closer, is_outer in stack)
        if fallback_depth:
            if char == "," and not stack:
                sibling = sibling_assignment_match(text[cursor + 1 :])
                if sibling is not None:
                    if not allow_chained_assignment:
                        return None
                    value_start = cursor + 1 + sibling.end()
                    value = fallback_expression(text[value_start:])
                    if fallback_secret_risk(value):
                        return value
                    cursor = value_start + len(value)
                    continue
                if allow_chained_assignment:
                    value_start = cursor + 1
                    value = fallback_expression(text[value_start:])
                    if fallback_secret_risk(value):
                        return value
                    cursor = value_start + len(value)
                    continue
            if text.startswith(("||", "&&", "??"), cursor):
                return text[cursor:]
            if char in {"+", "?"} and not text.startswith("?.", cursor):
                return text[cursor:]
            left_boundary = cursor == 0 or not (
                text[cursor - 1].isalnum() or text[cursor - 1] == "_"
            )
            word = (
                re.match(r"(?:or|and|if|unless)\b", text[cursor:])
                if left_boundary
                else None
            )
            if word is not None:
                return text[cursor:]
            if char in "\n;" and not stack:
                return None
        cursor += 1
    return None

def starts_sibling_assignment(text: str) -> bool:
    return sibling_assignment_match(text) is not None

def sibling_assignment_match(text: str) -> re.Match[str] | None:
    return re.match(
        r"\s*(?:"
        r"\.\.\.[^,\r\n]+(?:,|$)"
        r"|(?:[A-Za-z_$][A-Za-z0-9_$]*"
        r"|[0-9]+(?:\.[0-9]+)?"
        r"|[\"'][^\"'\r\n]+[\"']"
        r"|\[[^\]\r\n]+\]"
        r"|\{[^}\r\n]+\})\s*"
        r"(?::(?![:=])|=(?!=|>)))",
        text,
    )

def top_level_line_assignment_positions(
    text: str,
    positions: set[int],
) -> set[int]:
    top_level: set[int] = set()
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    line_start = 0
    cursor = 0
    while cursor < len(text):
        if (
            cursor in positions
            and not stack
            and not text[line_start:cursor].strip()
        ):
            top_level.add(cursor)
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
                line_start = cursor + 1
            cursor += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                cursor += 2
            else:
                if char == "\n":
                    line_start = cursor + 1
                cursor += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            if char == "\n":
                line_start = cursor + 1
            cursor += 1
            continue
        regex_end = javascript_regex_literal_end(text, cursor)
        if regex_end is not None:
            cursor = regex_end
            continue
        if char == "/" and next_char == "/":
            line_comment = True
            cursor += 2
            continue
        if char == "/" and next_char == "*":
            block_comment = True
            cursor += 2
            continue
        if char == "#" and not javascript_private_member_marker(text, cursor):
            line_comment = True
            cursor += 1
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char == "(":
            stack.append(")")
        elif char == "[":
            stack.append("]")
        elif stack and char == stack[-1]:
            stack.pop()
        if char == "\n":
            line_start = cursor + 1
        cursor += 1
    return top_level

def raw_double_quote_start(
    text: str,
    start: int,
) -> tuple[str, int] | None:
    if (
        not text.startswith('"""', start)
        or "@" in text[max(0, start - 2) : start]
    ):
        return None
    width = 3
    while start + width < len(text) and text[start + width] == '"':
        width += 1
    after = start + width
    delimiter = '"' * width
    return delimiter, after

def raw_double_quote_end(
    text: str,
    start: int,
    width: int,
) -> int | None:
    cursor = start
    while cursor < len(text):
        run_start = text.find('"', cursor)
        if run_start < 0:
            return None
        run_end = run_start + 1
        while run_end < len(text) and text[run_end] == '"':
            run_end += 1
        if run_end - run_start >= width:
            return run_end
        cursor = run_end
    return None

def csharp_quoted_literal_end(
    text: str,
    quote_start: int,
    *,
    verbatim: bool,
    interpolated: bool,
    nesting: int = 0,
) -> int | None:
    if nesting > 64:
        return None
    quote = text[quote_start]
    cursor = quote_start + 1
    interpolation_depth = 0
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if interpolation_depth:
            if char == "/" and next_char == "/":
                line_end = text.find("\n", cursor + 2)
                cursor = len(text) if line_end < 0 else line_end
                continue
            if char == "/" and next_char == "*":
                comment_end = text.find("*/", cursor + 2)
                cursor = len(text) if comment_end < 0 else comment_end + 2
                continue
            if char == '"':
                raw_start = raw_double_quote_start(text, cursor)
                if raw_start is not None:
                    delimiter, content_start = raw_start
                    raw_end = raw_double_quote_end(
                        text,
                        content_start,
                        len(delimiter),
                    )
                    if raw_end is None:
                        return None
                    cursor = raw_end
                    continue
            if char in {'"', "'"}:
                marker = text[max(0, cursor - 2) : cursor]
                nested_end = csharp_quoted_literal_end(
                    text,
                    cursor,
                    verbatim=char == '"' and "@" in marker,
                    interpolated=char == '"' and "$" in marker,
                    nesting=nesting + 1,
                )
                if nested_end is None:
                    return None
                cursor = nested_end
                continue
            if char == "{":
                interpolation_depth += 1
            elif char == "}":
                interpolation_depth -= 1
            cursor += 1
            continue
        if interpolated and char == "{":
            if next_char == "{":
                cursor += 2
                continue
            interpolation_depth = 1
            cursor += 1
            continue
        if interpolated and char == "}" and next_char == "}":
            cursor += 2
            continue
        if verbatim and char == '"' and next_char == '"':
            cursor += 2
            continue
        if not verbatim and char == "\\":
            cursor += 2
            continue
        if char == quote:
            return cursor + 1
        cursor += 1
    return None

@functools.lru_cache(maxsize=8)
def mask_csharp_evidence_prefix(text: str) -> str:
    masked = list(text)

    def mask_span(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "

    cursor = 0
    line_has_content = False
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        line_leading = not line_has_content
        if char == "\n":
            line_has_content = False
            cursor += 1
            continue
        if line_leading and char == "#":
            line_end = text.find("\n", cursor)
            line_end = len(text) if line_end < 0 else line_end
            mask_span(cursor, line_end)
            line_has_content = True
            cursor = line_end
            continue
        if (
            line_leading
            and char == "["
            and re.match(r"\[(?:assembly|module)\s*:", text[cursor:])
        ):
            depth = 0
            end = cursor
            quote: str | None = None
            verbatim_quote = False
            escaped = False
            while end < len(text):
                current = text[end]
                if quote is not None:
                    if escaped:
                        escaped = False
                    elif (
                        verbatim_quote
                        and quote == '"'
                        and text.startswith('""', end)
                    ):
                        end += 2
                        continue
                    elif current == "\\" and not verbatim_quote:
                        escaped = True
                    elif current == quote:
                        quote = None
                        verbatim_quote = False
                elif current in {'"', "'"}:
                    quote = current
                    verbatim_quote = (
                        current == '"'
                        and text[max(cursor, end - 1) : end] == "@"
                    )
                elif current == "[":
                    depth += 1
                elif current == "]":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
                end += 1
            mask_span(cursor, end)
            line_has_content = True
            cursor = end
            continue
        if char == "/" and next_char == "/":
            line_end = text.find("\n", cursor)
            line_end = len(text) if line_end < 0 else line_end
            mask_span(cursor, line_end)
            line_has_content = True
            cursor = line_end
            continue
        if char == "/" and next_char == "*":
            comment_end = text.find("*/", cursor + 2)
            comment_end = len(text) if comment_end < 0 else comment_end + 2
            mask_span(cursor, comment_end)
            line_has_content = True
            cursor = comment_end
            continue
        if char in {'"', "'"}:
            raw_start = raw_double_quote_start(text, cursor)
            if raw_start is not None:
                delimiter, content_start = raw_start
                end = raw_double_quote_end(
                    text,
                    content_start,
                    len(delimiter),
                )
                end = len(text) if end is None else end
                mask_span(cursor, end)
                line_has_content = True
                cursor = end
                continue
            marker = text[max(0, cursor - 2) : cursor]
            end = csharp_quoted_literal_end(
                text,
                cursor,
                verbatim=char == '"' and "@" in marker,
                interpolated=char == '"' and "$" in marker,
            )
            end = len(text) if end is None else end
            mask_span(cursor, min(end, len(text)))
            line_has_content = True
            cursor = end
            continue
        if not char.isspace():
            line_has_content = True
        cursor += 1
    return "".join(masked)

def csharp_verbatim_string_content(text: str, quote_start: int) -> str:
    quote_end = csharp_quoted_literal_end(
        text,
        quote_start,
        verbatim=True,
        interpolated=True,
    )
    end = len(text) if quote_end is None else quote_end - 1
    return text[quote_start + 1 : end]

@functools.lru_cache(maxsize=8)
def mask_shell_heredoc_bodies(text: str) -> str:
    masked = list(text)
    pending: list[tuple[str, bool]] = []
    offset = 0
    code_keywords = {
        "class",
        "const",
        "for",
        "foreach",
        "if",
        "interface",
        "namespace",
        "new",
        "record",
        "return",
        "struct",
        "switch",
        "using",
        "var",
        "while",
    }
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if pending:
            delimiter, strip_tabs = pending[0]
            comparison = content.lstrip("\t") if strip_tabs else content
            for index in range(offset, offset + len(content)):
                masked[index] = " "
            if comparison == delimiter:
                pending.pop(0)
            offset += len(line)
            continue
        for match in re.finditer(
            r"<<(?P<strip>-)?[ \t]*(?P<quote>['\"]?)"
            r"(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)"
            r"(?P=quote)",
            content,
        ):
            quote = match.group("quote")
            prefix = content[: match.start()]
            shell_segment = re.split(r"[;|&]", prefix)[-1].strip()
            first_word = (
                re.match(r"[A-Za-z_][A-Za-z0-9_.-]*", shell_segment)
                if shell_segment
                else None
            )
            shell_like = (
                first_word is not None
                and first_word.group(0) not in code_keywords
                and re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_.-]*"
                    r"(?:[ \t]+[^=(){}\[\];|&]+)*[ \t]*",
                    shell_segment,
                )
                is not None
            )
            if shell_like:
                for index in range(
                    offset + match.start(),
                    offset + match.end(),
                ):
                    masked[index] = " "
                pending.append(
                    (match.group("delimiter"), match.group("strip") is not None)
                )
        offset += len(line)
    return "".join(masked)

@functools.lru_cache(maxsize=8)
def csharp_recognized_scope_intervals(
    text: str,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    masked = mask_csharp_evidence_prefix(mask_shell_heredoc_bodies(text))
    starts: list[int] = []
    ends: list[int] = []
    stack: list[bool] = []
    recognized_start: int | None = None
    for cursor, char in enumerate(masked):
        if char == "{":
            recognized = False
            if recognized_start is None:
                quick_prefix = masked[max(0, cursor - 256) : cursor]
                scope_candidate = ")" in quick_prefix or re.search(
                    r"\b(?:class|interface|namespace|record|struct)\b",
                    quick_prefix,
                )
                if scope_candidate:
                    prefix = masked[max(0, cursor - 4096) : cursor + 1]
                    recognized = (
                        re.search(
                            rf"(?:^|[;}}])\s*"
                            rf"{CSHARP_TYPE_PREFIX_PATTERN}\s*$",
                            prefix,
                            re.DOTALL,
                        )
                        is not None
                        or re.search(
                            rf"(?:^|[;{{}}])\s*"
                            rf"{CSHARP_METHOD_PREFIX_PATTERN}\s*$",
                            prefix,
                            re.DOTALL,
                        )
                        is not None
                    )
            stack.append(recognized)
            if recognized:
                recognized_start = cursor
        elif char == "}" and stack:
            recognized = stack.pop()
            if recognized:
                assert recognized_start is not None
                starts.append(recognized_start)
                ends.append(cursor + 1)
                recognized_start = None
    if recognized_start is not None:
        starts.append(recognized_start)
        ends.append(len(text))
    return tuple(starts), tuple(ends)

def csharp_recognized_scope_at(text: str, position: int) -> bool:
    starts, ends = csharp_recognized_scope_intervals(text)
    index = bisect.bisect_right(starts, position) - 1
    return index >= 0 and position < ends[index]

def csharp_interpolated_string_context(
    text: str,
    quote_start: int,
) -> bool:
    masked = mask_csharp_evidence_prefix(mask_shell_heredoc_bodies(text))
    prefix = masked[
        max(0, quote_start - CSHARP_EVIDENCE_WINDOW) : quote_start
    ]
    statement_start = max(
        prefix.rfind(";"),
        prefix.rfind("}"),
    )
    statement = prefix[statement_start + 1 :]
    marker = re.search(r"(?:\$@|@\$)$", statement)
    if marker is None:
        return False
    quote_end = csharp_quoted_literal_end(
        text,
        quote_start,
        verbatim=True,
        interpolated=True,
    )
    if quote_end is None:
        return False
    terminator = re.match(
        r"\s*(?:[,;)}:\[\].!?]|==|!=|<=|>=|>>>|>>|<<|&&|\|\||\?\?"
        r"|\+\+|--|[+\-*/%&|^<>]|\b(?:as|is)\b)",
        text[quote_end:],
    )
    if terminator is None:
        return False
    expression_prefix = statement[: marker.start()]
    typed_declaration = re.search(
        r"\b(?:bool|byte|char|decimal|double|dynamic|float|int|long|object"
        r"|sbyte|short|string|uint|ulong|ushort|var|"
        r"[A-Z][A-Za-z0-9_.<>,?\[\]]*)\s+"
        r"[A-Za-z_][A-Za-z0-9_]*\s*(?<![=!<>])=(?!=)\s*[^;]*$",
        expression_prefix,
    )
    csharp_statement = (
        re.search(
            r"(?:^|[;{}])\s*(?:return\s+|new\s+"
            r"[A-Za-z_][A-Za-z0-9_.<>,?\[\]]*\b)[^;]*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
        or re.search(
            rf"(?:^|[;}}])\s*{CSHARP_TYPE_PREFIX_PATTERN}.*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
        or re.search(
            rf"(?:^|[;{{}}])\s*{CSHARP_METHOD_PREFIX_PATTERN}.*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
    )
    assignment_operator = re.search(
        r"(?<![=!<>])(?:=|[+\-*/%&|^]=|\?\?=|<<=|>>=|>>>=)\s*$",
        expression_prefix,
    )
    surrounding_prefix = prefix[max(0, statement_start - 4096) : statement_start + 1]
    surrounding_csharp = (
        re.search(
            r"(?:^|[;}\n])\s*using\s+(?:static\s+)?"
            r"[A-Za-z_][A-Za-z0-9_.]*\s*;\s*$",
            surrounding_prefix,
        )
        is not None
        or re.search(
            rf"(?:^|[;}}])\s*{CSHARP_TYPE_PREFIX_PATTERN}.*$",
            surrounding_prefix,
            re.DOTALL,
        )
        is not None
        or re.search(
            r"\b[A-Za-z_][A-Za-z0-9_.]*\([^;\r\n]*\)\s*;\s*$",
            surrounding_prefix,
        )
        is not None
        or re.search(
            rf"(?:^|[;{{}}])\s*{CSHARP_METHOD_PREFIX_PATTERN}.*$",
            surrounding_prefix,
            re.DOTALL,
        )
        is not None
        or re.search(
            r"(?:^|[;}\n])\s*(?:bool|byte|char|decimal|double|dynamic|float"
            r"|int|long|object|sbyte|short|string|uint|ulong|ushort|var|"
            r"[A-Z][A-Za-z0-9_.<>,?\[\]]*)\s+"
            r"[A-Za-z_][A-Za-z0-9_]*\s*(?<![=!<>])=(?!=)[^;]*;\s*$",
            surrounding_prefix,
        )
        is not None
    )
    surrounding_csharp = surrounding_csharp or csharp_recognized_scope_at(
        text,
        quote_start,
    )
    csharp_control_context = (
        re.search(
            r"\b(?:catch|for|foreach|if|lock|switch|while)\s*"
            r"\([^)]*\)\s*\{[^{}]*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
        or re.search(
            r"\bif\s*\([^)]*(?:==|!=|<=|>=|&&|\|\||\bis\b)[^)]*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
        or re.search(
            r"\b(?:do|else|finally|try)\s*\{[^{}]*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
        or (
            surrounding_csharp
            and re.search(
                r"\bif\s*\([^)]*$",
                expression_prefix,
                re.DOTALL,
            )
            is not None
        )
    )
    unmatched_parenthesis = (
        expression_prefix.count("(") > expression_prefix.count(")")
    )
    open_parenthesized_call = (
        unmatched_parenthesis
        and re.search(
            r"\b[A-Za-z_][A-Za-z0-9_.]*\s*\([^()]*$",
            expression_prefix,
            re.DOTALL,
        )
        is not None
    )
    spaced_assignment = (
        re.search(
            r"\b[A-Za-z_][A-Za-z0-9_]*[ \t]+"
            r"(?<![=!<>])=(?!=)[ \t]*$",
            expression_prefix,
        )
        is not None
    )
    standalone_content = csharp_verbatim_string_content(
        text,
        quote_start,
    )
    standalone_fields = re.findall(r"\{([^{}]*)\}", standalone_content)
    standalone_reference_assignment = (
        spaced_assignment
        and bool(standalone_fields)
        and standalone_content.count("{") == len(standalone_fields)
        and standalone_content.count("}") == len(standalone_fields)
        and all(
            CSHARP_STANDALONE_REFERENCE_PATTERN.fullmatch(field)
            is not None
            for field in standalone_fields
        )
    )
    expression_evidence = (
        csharp_statement
        or csharp_control_context
        or typed_declaration is not None
        or "=>" in expression_prefix
        or open_parenthesized_call
        # Standalone spaced assignments are ambiguous with shell commands, so
        # recover only ordinary credential references in this C#-only shape.
        or standalone_reference_assignment
        or (assignment_operator is not None and surrounding_csharp)
    )
    return expression_evidence

def quote_prefix_matches(
    text: str,
    quote_start: int,
    pattern: str,
    *,
    limit: int = 4,
) -> bool:
    prefix_tail = text[max(0, quote_start - limit) : quote_start]
    return re.search(pattern, prefix_tail) is not None

def csharp_interpolated_marker(text: str, quote_start: int) -> bool:
    return text[max(0, quote_start - 2) : quote_start] in {"$@", "@$"}

@functools.lru_cache(maxsize=8)
def csharp_interpolated_verbatim_spans(
    text: str,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    masked = mask_csharp_evidence_prefix(mask_shell_heredoc_bodies(text))
    starts: list[int] = []
    ends: list[int] = []
    for marker in re.finditer(r"(?:\$@|@\$)(?=\")", text):
        quote_start = marker.end()
        if masked[marker.start() : quote_start] != text[marker.start() : quote_start]:
            continue
        quote_end = csharp_quoted_literal_end(
            text,
            quote_start,
            verbatim=True,
            interpolated=True,
        )
        if quote_end is None:
            continue
        starts.append(quote_start)
        ends.append(quote_end)
    return tuple(starts), tuple(ends)

def explicit_csharp_interpolated_context(
    text: str,
    position: int,
) -> tuple[str, int] | None:
    starts, ends = csharp_interpolated_verbatim_spans(text)
    index = bisect.bisect_right(starts, position) - 1
    if index < 0 or position >= ends[index]:
        return None
    quote_start = starts[index]
    if not csharp_interpolated_string_context(text, quote_start):
        return None
    return '"', quote_start

def bounded_line_start(
    text: str,
    position: int,
    *,
    limit: int = 4096,
) -> int:
    search_start = max(0, position - limit)
    found = max(
        text.rfind("\n", search_start, position),
        text.rfind("\r", search_start, position),
    )
    return found if found >= 0 else search_start - 1

def uri_authority_end(
    text: str,
    start: int,
    context: tuple[str, int] | None,
) -> int:
    outer_quote = context[0] if context is not None else None
    quote_start = context[1] if context is not None else -1
    brace_interpolation = (
        outer_quote in {'"', "'", '"""', "'''"}
        and (
            quote_prefix_matches(
                text,
                quote_start,
                r"(?i)(?:^|[^A-Za-z0-9_])(?:f|fr|rf|(?<!@)\$)$",
            )
            or (
                outer_quote == '"'
                and csharp_interpolated_marker(text, quote_start)
                and csharp_interpolated_string_context(text, quote_start)
            )
        )
    )
    interpolation_depth = 0
    interpolation_quote: str | None = None
    escaped = False
    outer_escaped = False
    cursor = start
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if interpolation_quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == interpolation_quote:
                interpolation_quote = None
            cursor += 1
            continue
        if outer_quote is not None and not interpolation_depth:
            if outer_escaped:
                outer_escaped = False
                cursor += 1
                continue
            if char == "\\":
                if next_char in "/?#":
                    break
                outer_escaped = True
                cursor += 1
                continue
        if interpolation_depth:
            if char in {'"', "'", "`"}:
                interpolation_quote = char
            elif char == "{":
                interpolation_depth += 1
            elif char == "}":
                interpolation_depth -= 1
            cursor += 1
            continue
        # Read the complete expression even when its language is unknown.
        # Otherwise '?' or spaces can hide a literal credential before '@'.
        if text.startswith("${", cursor):
            interpolation_depth = 1
            cursor += 2
            continue
        if brace_interpolation and char == "{":
            interpolation_depth = 1
            cursor += 1
            continue
        if char.isspace() or char in "/?#":
            break
        if outer_quote is not None and text.startswith(outer_quote, cursor):
            break
        if outer_quote is None and char in {'"', "'", "`"}:
            break
        cursor += 1
    return cursor

def uri_authority_ranges(
    text: str,
) -> tuple[tuple[int, int, int, tuple[str, int] | None], ...]:
    matches = list(URI_SCHEME_PATTERN.finditer(text))
    contexts = string_contexts_at(
        text,
        {match.start() for match in matches},
    )
    return tuple(
        (
            match.start(),
            match.end(),
            uri_authority_end(
                text,
                match.end(),
                contexts.get(match.start()),
            ),
            contexts.get(match.start()),
        )
        for match in matches
        if not uri_metasyntax_comment_reference(text, match, contexts.get(match.start()))
    )


def uri_metasyntax_comment_reference(text, match, context) -> bool:
    # This fixed notation names grammar slots, not a network authority. Real
    # schemes, hosts, string values and all other userinfo remain credential data.
    notation = "scheme://" + "user:" + "pass@host"
    if context is not None or text[match.start() - 1:match.start()] != chr(96):
        return False
    if not text.startswith(notation + chr(96), match.start()):
        return False
    prefix = text[text.rfind("\n", 0, match.start()) + 1:match.start() - 1]
    return prefix.lstrip().startswith("//")

def credentialed_uri_risk(
    text: str,
    authorities: tuple[
        tuple[int, int, int, tuple[str, int] | None],
        ...,
    ] | None = None,
    *,
    compose_source: bool = False,
) -> bool:
    for authority_range in (
        authorities if authorities is not None else uri_authority_ranges(text)
    ):
        credential = uri_authority_credential(text, authority_range)
        if credential is None:
            continue
        if (
            credential.has_password
            and uri_userinfo_literal_risk(
                credential.username,
                allow_plus_address=True,
            )
            and not uri_password_is_interpolated(
                text,
                credential.scheme_start,
                credential.username,
                credential.host,
                credential.context,
                compose_source=compose_source,
            )
            and not (
                compose_source
                and compose_uri_context(text, credential.scheme_start, credential.context)
                and compose_uri_username_reference(credential.username)
            )
        ):
            return True
        if uri_password_is_interpolated(
            text,
            credential.scheme_start,
            credential.value,
            credential.host,
            credential.context,
            compose_source=compose_source,
        ):
            continue
        if credential.has_password or uri_userinfo_literal_risk(
            credential.value,
            allow_plus_address=True,
        ):
            return True
    return False

class UriAuthorityCredential(NamedTuple):
    username: str
    value: str
    host: str
    has_password: bool
    empty_password: bool
    scheme_start: int
    context: tuple[str, int] | None
    value_start: int
    value_end: int

def uri_authority_credential(
    text: str,
    authority_range: tuple[
        int,
        int,
        int,
        tuple[str, int] | None,
    ],
) -> UriAuthorityCredential | None:
    scheme_start, authority_start, authority_end, context = authority_range
    authority = text[authority_start:authority_end]
    userinfo, authority_separator, host = authority.rpartition("@")
    if not authority_separator:
        return None
    # A variable's operator colon is not the user/password separator.
    # Recognition here only locates credentials; allowance still needs context.
    variable = re.match(r"\$\{[^{}\r\n]*\}", userinfo)
    separator_start = variable.end() if variable is not None else 0
    separator = userinfo.find(":", separator_start)
    username = userinfo if separator < 0 else userinfo[:separator]
    password_separator = "" if separator < 0 else ":"
    password = "" if separator < 0 else userinfo[separator + 1 :]
    has_password = bool(password_separator and password)
    empty_password = bool(password_separator and not password)
    value = password if has_password else (userinfo if not password_separator else username)
    value_start = (
        authority_start + len(username) + 1
        if has_password
        else authority_start
    )
    return UriAuthorityCredential(
        username,
        value,
        host,
        has_password,
        empty_password,
        scheme_start,
        context,
        value_start,
        value_start + len(value),
    )

def interpolated_empty_password_uri_ranges(
    text: str,
    authorities: tuple[
        tuple[int, int, int, tuple[str, int] | None],
        ...,
    ],
) -> tuple[tuple[int, int], ...]:
    safe: list[tuple[int, int]] = []
    for authority_range in authorities:
        credential = uri_authority_credential(text, authority_range)
        if credential is None or not credential.empty_password:
            continue
        if uri_password_is_interpolated(
            text,
            credential.scheme_start,
            credential.value,
            credential.host,
            credential.context,
        ):
            safe.append(
                (credential.value_start, credential.value_end)
            )
    return tuple(safe)

def mask_ranges(
    text: str,
    ranges: tuple[tuple[int, int], ...],
) -> str:
    masked = list(text)
    for start, end in ranges:
        masked[start:end] = " " * (end - start)
    return "".join(masked)

def position_in_ranges(
    position: int,
    ranges: tuple[tuple[int, int], ...],
) -> bool:
    return any(
        start <= position < end
        for start, end in ranges
    )

def secret_assignment_matches(
    pattern: re.Pattern[str],
    text: str,
    masked_text: str,
    safe_ranges: tuple[tuple[int, int], ...],
) -> tuple[re.Match[str], ...]:
    matches: list[re.Match[str]] = []
    spans: set[tuple[int, int]] = set()
    for match in pattern.finditer(text):
        if position_in_ranges(match.start(), safe_ranges):
            continue
        matches.append(match)
        spans.add(match.span())
    for match in pattern.finditer(masked_text):
        if match.span() not in spans:
            matches.append(match)
    return tuple(matches)

def string_contexts_at(
    text: str,
    positions: set[int],
) -> dict[int, tuple[str, int] | None]:
    contexts: dict[int, tuple[str, int] | None] = {}
    quote: str | None = None
    quote_start = -1
    verbatim_quote = False
    escaped = False
    line_comment = False
    block_comment = False
    brace_depth = 0
    class_depths: list[int] = []
    pending_class = False
    cursor = 0
    while cursor < len(text) and len(contexts) < len(positions):
        if cursor in positions:
            contexts[cursor] = explicit_csharp_interpolated_context(
                text,
                cursor,
            ) or (
                None if quote is None else (quote, quote_start)
            )
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            cursor += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                cursor += 2
            else:
                cursor += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif (
                verbatim_quote
                and quote == '"'
                and text.startswith('""', cursor)
            ):
                cursor += 2
                continue
            elif char == "\\" and not verbatim_quote:
                escaped = True
            elif text.startswith(quote, cursor):
                quote_length = len(quote)
                quote = None
                quote_start = -1
                verbatim_quote = False
                cursor += quote_length
                continue
        elif (
            regex_end := javascript_regex_literal_end(text, cursor)
        ) is not None:
            cursor = regex_end
            continue
        elif text.startswith('"""', cursor):
            quote = '"""'
            quote_start = cursor
            cursor += 3
            continue
        elif text.startswith("'''", cursor):
            quote = "'''"
            quote_start = cursor
            cursor += 3
            continue
        elif char == "/" and next_char == "/":
            line_comment = True
            cursor += 2
            continue
        elif char == "/" and next_char == "*":
            block_comment = True
            cursor += 2
            continue
        elif char == "#" and not javascript_private_member_marker(
            text,
            cursor,
            allow_bare=bool(class_depths),
        ):
            line_comment = True
        elif char in {'"', "'", "`"}:
            quote = char
            quote_start = cursor
            verbatim_quote = (
                char == '"'
                and text[max(0, cursor - 2) : cursor] in {"$@", "@$"}
            )
        elif char.isalpha() or char in "_$":
            word_end = cursor + 1
            while word_end < len(text) and (
                text[word_end].isalnum() or text[word_end] in "_$"
            ):
                word_end += 1
            if text[cursor:word_end] == "class":
                pending_class = True
            cursor = word_end
            continue
        elif char == "{":
            brace_depth += 1
            if pending_class:
                class_depths.append(brace_depth)
                pending_class = False
        elif char == "}":
            if class_depths and class_depths[-1] == brace_depth:
                class_depths.pop()
            brace_depth = max(0, brace_depth - 1)
        elif char == ";":
            pending_class = False
        cursor += 1
    for position in positions - contexts.keys():
        contexts[position] = None if quote is None else (quote, quote_start)
    return contexts

def compose_uri_context(
    text: str, position: int, context: tuple[str, int] | None,
) -> bool:
    # YAML scalar boundaries come from this assignment line; a shell quote in
    # an earlier service must not become the quote owner of this URI.
    prefix = text[bounded_line_start(text, position) + 1 : position]
    return (
        not prefix.rstrip().endswith("'")
        and config_assignment_context(text, position, allow_environment_name=True) is not None
    )

def compose_required_uri_reference(value: str) -> re.Match[str] | None:
    # Required-value messages are diagnostics, never password defaults.
    # Nested substitutions, escaping and quoted expressions remain unrecognized.
    return re.fullmatch(
        r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<operator>:?\?)"
        r"[^${}\r\n\"'`\\@]*\}", value,
    )

def compose_environment_reference_ranges(text: str) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    assignments = re.finditer(
        r'(?m)^[ \t]*(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[ \t]*:[ \t]*'
        r'(?P<quote>"?)(?P<value>\$\{[^\r\n]*\})(?P=quote)[ \t]*(?:#.*)?\r?$',
        text,
    )
    for assignment in assignments:
        value = assignment.group("value")
        if len(value) > 8192:
            continue
        reference = compose_required_uri_reference(value) or re.fullmatch(
            r"\$\{[A-Za-z_][A-Za-z0-9_]*(?P<operator>:?-)\}", value,
        )
        if reference is not None:
            # Only the key and reference operator are structural. Diagnostic
            # text remains visible to every credential and decoded-value scan.
            ranges.append((assignment.start("key"), assignment.start("value") + reference.end("operator")))
    return tuple(ranges)

def compose_sequence_owner(text: str, position: int, indent: int) -> str | None:
    prefix = text[max(0, position - 8192) : position]
    prefix = re.sub(r"(?m)^[ \t]*(?:#.*)?\r?\n", "", prefix)
    for line in reversed(prefix.splitlines()):
        line_indent = len(line) - len(line.lstrip(" "))
        if line_indent < indent or (line_indent == indent and not re.match(r"-[ \t]", line.lstrip(" "))):
            owner = re.fullmatch(r"[ ]*(?P<key>[A-Za-z_][A-Za-z0-9_.-]*):[ \t]*(?:!override[ \t]*)?(?:#.*)?", line)
            return owner.group("key") if owner is not None else None
    return None

def compose_mount_source_comment_safe(mount: re.Match[str]) -> bool:
    # A spaced hash ends an unquoted YAML scalar. It cannot become part of
    # a source reference even when a later brace and mount separator exist.
    return bool(mount.group("quote")) or re.search(r"[ \t]#", mount.group("source") or "") is None

def compose_mount_reference_shape(mount: re.Match[str]) -> bool:
    source = mount.group("source") or ""
    return len(source) + len(mount.group("descriptor")) <= 8192 and compose_mount_source_comment_safe(mount) and (
        not source or compose_required_uri_reference(source) is not None
        or re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", source) is not None
    )

def compose_mount_source_ranges(mount: re.Match[str]) -> tuple[tuple[int, int], ...]:
    required = compose_required_uri_reference(mount.group("source") or "")
    if required is None:
        return ()
    # A required source names an environment value. Leave its error diagnostic
    # visible so credentials in that text cannot enter the review bundle.
    return ((mount.start("source"), mount.start("source") + required.end("operator")),)

def compose_mount_reference_ranges(text: str) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    mounts = re.finditer(
        r'(?m)^(?P<indent>[ ]*)-[ \t]+(?P<quote>["\']?)'
        r'(?P<source>\$\{[^\r\n}]*\})?'
        r'(?P<descriptor>(?:~?/|\./|\.\./)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*'
        r':/[A-Za-z0-9_./-]+(?::(?:ro|rw))?)(?P=quote)[ \t]*(?:#.*)?\r?$', text,
    )
    for mount in mounts:
        if not compose_mount_reference_shape(mount):
            continue
        if compose_sequence_owner(text, mount.start(), len(mount.group("indent"))) != "volumes":
            continue
        ranges.extend(compose_mount_source_ranges(mount))
        # A volumes item names filesystem references, not credential values.
        # Mask only assignment-shaped names; target paths and comments stay scanned.
        for prefix in SECRET_ASSIGNMENT_PREFIX_PATTERN.finditer(text, mount.start("descriptor"), mount.end("descriptor")):
            ranges.append((prefix.start(), prefix.end()))
    return tuple(ranges)

def compose_uri_username_reference(value: str) -> bool:
    default = re.fullmatch(
        r"\$\{[A-Za-z_][A-Za-z0-9_]*:?-([A-Za-z0-9_.-]+)\}", value,
    )
    return default is not None and not uri_userinfo_literal_risk(default.group(1))

def compose_required_uri_variable_ranges(
    text: str,
    authorities: tuple[tuple[int, int, int, tuple[str, int] | None], ...],
) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    for authority in authorities:
        credential = uri_authority_credential(text, authority)
        if credential is None or not compose_uri_context(
            text, credential.scheme_start, credential.context,
        ):
            continue
        reference = compose_required_uri_reference(credential.value)
        if reference is not None:
            # The name/operator is a reference, not a password assignment.
            # Keep the diagnostic and the rest of the URI in all content scans.
            ranges.append((credential.value_start, credential.value_start + reference.end("operator")))
    return tuple(ranges)

def uri_password_is_interpolated(
    text: str,
    scheme_start: int,
    password: str,
    host: str,
    context: tuple[str, int] | None,
    *,
    compose_source: bool = False,
) -> bool:
    if (
        compose_source
        and compose_uri_context(text, scheme_start, context)
        and compose_required_uri_reference(password) is not None
    ):
        return True
    if uri_placeholder_password_is_safe(password, host):
        return True
    if context is not None:
        quote, quote_start = context
        if quote == "`":
            if any(
                pattern.fullmatch(password)
                for pattern in URI_PASSWORD_REFERENCE_PATTERNS[1:2]
                + URI_PASSWORD_REFERENCE_PATTERNS[3:4]
            ):
                return True
            return dynamic_uri_expression(password, "${", "}")
        if quote == '"' and (
            quote_prefix_matches(text, quote_start, r"(?<!@)\$$")
            or (
                csharp_interpolated_marker(text, quote_start)
                and csharp_interpolated_string_context(text, quote_start)
            )
        ):
            if URI_PASSWORD_REFERENCE_PATTERNS[2].fullmatch(password):
                return True
            return dynamic_uri_expression(password, "{", "}")
        if quote in {'"', "'", '"""', "'''"} and quote_prefix_matches(
            text,
            quote_start,
            r"(?i)(?:^|[^A-Za-z0-9_])(?:f|fr|rf)$",
        ):
            if any(
                pattern.fullmatch(password)
                for pattern in URI_PASSWORD_REFERENCE_PATTERNS[2:3]
                + URI_PASSWORD_REFERENCE_PATTERNS[4:5]
            ):
                return True
            return dynamic_uri_expression(password, "{", "}")
        if (
            quote == '"'
            and quote_prefix_matches(
                text,
                quote_start,
                r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*$",
                limit=256,
            )
            and URI_PASSWORD_REFERENCE_PATTERNS[0].fullmatch(password)
        ):
            return True
        if (
            quote == '"'
            and config_uri_reference_is_safe(
                text,
                scheme_start,
                password,
                allow_lowercase_key=False,
            )
        ):
            return True
        line_start = bounded_line_start(text, quote_start)
        assignment = text[line_start + 1 : quote_start]
        if (
            quote == '"'
            and POWERSHELL_ENV_REFERENCE_PATTERN.fullmatch(password)
            and powershell_assignment_prefix(assignment)
        ):
            return True
        if quote == '"' and shell_assignment_prefix(assignment):
            return any(
                pattern.fullmatch(password)
                for pattern in URI_PASSWORD_REFERENCE_PATTERNS[:2]
            )
        if quote == '"' and shell_command_prefix(text, quote_start):
            return any(
                pattern.fullmatch(password)
                for pattern in URI_PASSWORD_REFERENCE_PATTERNS[:2]
            )
        return uri_password_is_format_placeholder(
            text,
            password,
            quote,
            quote_start,
        )
    if config_uri_reference_is_safe(
        text,
        scheme_start,
        password,
        allow_lowercase_key=True,
    ):
        return True
    if shell_command_prefix(text, scheme_start) and any(
        pattern.fullmatch(password)
        for pattern in URI_PASSWORD_REFERENCE_PATTERNS[:2]
    ):
        return True
    line_start = bounded_line_start(text, scheme_start)
    assignment = text[line_start + 1 : scheme_start]
    if not shell_assignment_prefix(assignment):
        return False
    return any(
        pattern.fullmatch(password)
        for pattern in URI_PASSWORD_REFERENCE_PATTERNS[:2]
    )

def uri_placeholder_password_is_safe(password: str, host: str) -> bool:
    normalized_password = password.lower()
    if normalized_password in URI_PASSWORD_PLACEHOLDER_VALUES:
        return True
    normalized_host = host.lower()
    if normalized_host.startswith("[") and "]" in normalized_host:
        normalized_host = normalized_host[1 : normalized_host.index("]")]
    elif normalized_host.count(":") == 1:
        normalized_host = normalized_host.split(":", 1)[0]
    localhost = (
        normalized_host in {"127.0.0.1", "::1", "localhost"}
        or normalized_host.endswith(".localhost")
    )
    return localhost and normalized_password in {
        *SECRET_PLACEHOLDER_VALUES,
        "password",
    }

def uri_userinfo_literal_risk(
    value: str,
    *,
    allow_plus_address: bool = False,
) -> bool:
    if value.lower() in URI_PASSWORD_PLACEHOLDER_VALUES:
        return False
    if value.startswith(("$", "{")):
        return True
    credential_name = URI_CREDENTIAL_NAME_PATTERN.search(value) is not None
    structured_username = (
        re.fullmatch(
            r"(?=[^\r\n]*[._-])"
            r"[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)+",
            value,
        )
        is not None
    )
    character_classes = sum(
        (
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        )
    )
    opaque_alphanumeric = (
        re.fullmatch(r"[A-Za-z0-9]{20,}", value) is not None
        and character_classes >= 3
    )
    opaque_hex = (
        re.fullmatch(r"[0-9A-Fa-f]{32,}", value) is not None
        or re.fullmatch(
            r"[0-9A-Fa-f]{8}-"
            r"(?:[0-9A-Fa-f]{4}-){3}"
            r"[0-9A-Fa-f]{12}",
            value,
        )
        is not None
    )
    plus_local, plus_separator, plus_tag = value.rpartition("+")
    local_case_transitions = sum(
        left.islower() != right.islower()
        for left, right in zip(plus_local, plus_local[1:])
        if left.isalpha() and right.isalpha()
    )
    tag_case_transitions = sum(
        left.islower() != right.islower()
        for left, right in zip(plus_tag, plus_tag[1:])
        if left.isalpha() and right.isalpha()
    )
    plus_address_username = (
        bool(plus_separator)
        and (
            plus_local == plus_local.lower()
            or re.search(r"[._-]", plus_local) is not None
        )
        and re.fullmatch(
            r"[A-Za-z]+[0-9]*(?:[._-][A-Za-z]+[0-9]*)*",
            plus_local,
        )
        is not None
        and (
            re.fullmatch(r"[0-9]{1,4}", plus_tag) is not None
            or re.fullmatch(
                r"[A-Za-z]+[0-9]{0,4}"
                r"(?:[._-](?:[A-Za-z]+[0-9]{0,4}|[0-9]{1,4}))*",
                plus_tag,
            )
            is not None
        )
        and local_case_transitions <= (
            8 if re.search(r"[._-]", plus_local) else 4
        )
        and tag_case_transitions <= 4
    )
    opaque_plus_tag = (
        bool(plus_separator)
        and len(plus_local) >= 16
        and len(plus_tag) >= 16
        and re.fullmatch(r"[A-Za-z0-9]+", plus_tag) is not None
        and any(char.isdigit() for char in plus_tag)
        and local_case_transitions >= 6
        and tag_case_transitions >= 6
    )
    return len(value) >= 20 and (
        credential_name
        or opaque_alphanumeric
        or opaque_hex
        or opaque_plus_tag
        or (
            character_classes >= 4
            and not structured_username
            and not (allow_plus_address and plus_address_username)
        )
    )

def uri_named_credential_reference(password: str) -> bool:
    if not any(
        pattern.fullmatch(password)
        for pattern in URI_PASSWORD_REFERENCE_PATTERNS[:3]
    ):
        return False
    name = password
    if name.startswith("${") and name.endswith("}"):
        name = name[2:-1]
    elif name.startswith(("$", "{")):
        name = name[1:-1] if name.startswith("{") else name[1:]
    return (
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None
        and URI_CREDENTIAL_NAME_PATTERN.search(name) is not None
    )

def dynamic_uri_expression(
    password: str,
    prefix: str,
    suffix: str,
) -> bool:
    if not password.startswith(prefix) or not password.endswith(suffix):
        return False
    expression = password[len(prefix) : -len(suffix)]
    return (
        URI_CREDENTIAL_REFERENCE_PATTERN.fullmatch(expression) is not None
        or URI_COMPUTED_REFERENCE_PATTERN.fullmatch(expression) is not None
    )

@functools.lru_cache(maxsize=64)
def quoted_string_end(
    text: str,
    quote: str,
    quote_start: int,
    *,
    doubled_quote_escape: bool = False,
) -> int | None:
    quote_end = quote_start + len(quote)
    if doubled_quote_escape:
        doubled_quote = quote + quote
        while quote_end < len(text):
            if text.startswith(doubled_quote, quote_end):
                quote_end += len(doubled_quote)
            elif text.startswith(quote, quote_end):
                return quote_end + len(quote)
            else:
                quote_end += 1
        return None
    escaped = False
    while quote_end < len(text):
        char = text[quote_end]
        if escaped:
            escaped = False
            quote_end += 1
        elif char == "\\":
            escaped = True
            quote_end += 1
        elif text.startswith(quote, quote_end):
            quote_end += len(quote)
            break
        else:
            quote_end += 1
    else:
        return None
    return quote_end

def uri_password_is_format_placeholder(
    text: str,
    password: str,
    quote: str,
    quote_start: int,
) -> bool:
    quote_end = quoted_string_end(text, quote, quote_start)
    if quote_end is None:
        return False
    prefix_tail = text[max(0, quote_start - 32) : quote_start]
    suffix = text[quote_end : quote_end + 8192]
    formatter = re.search(
        r"(?:\bfmt\.Sprintf|\bformat!)\(\s*$",
        prefix_tail,
    )
    if formatter is not None:
        arguments = re.match(r"\s*,\s*(?P<args>.*?)\s*\)", suffix, re.DOTALL)
        if arguments is not None and format_arguments_are_references(
            arguments.group("args")
        ):
            return password == "%s" or re.fullmatch(
                r"\{(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]*)\}",
                password,
            ) is not None
    if password == "%s":
        python_percent_format = re.match(
            rf"\s*%\s*(?:"
            rf"(?P<single>{URI_CREDENTIAL_REFERENCE_TEXT})\b"
            rf"|\((?P<tuple>[^()]*)\)"
            rf")",
            suffix,
        )
        if python_percent_format is not None:
            arguments = (
                [python_percent_format.group("single")]
                if python_percent_format.group("single") is not None
                else split_top_level_call_arguments(
                    python_percent_format.group("tuple") or ""
                )
            )
            return all(
                argument is not None
                and URI_CREDENTIAL_REFERENCE_PATTERN.fullmatch(argument.strip())
                for argument in arguments
            )
        return False
    field_match = re.fullmatch(
        r"\{(?P<field>[A-Za-z_][A-Za-z0-9_]*|[0-9]*)\}",
        password,
    )
    if field_match is not None:
        field = field_match.group("field")
        format_call = re.match(
            r"\s*\.format\s*\((?P<args>.*?)\)",
            suffix,
            re.DOTALL,
        )
        if format_call is not None and format_arguments_are_references(
            format_call.group("args")
        ):
            return True
    return False

def format_arguments_are_references(arguments: str) -> bool:
    values = split_top_level_call_arguments(arguments)
    if not values or any(not value.strip() for value in values):
        return False
    for value in values:
        expression = value.strip()
        named = re.fullmatch(
            rf"[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
            rf"(?P<value>{URI_CREDENTIAL_REFERENCE_TEXT})",
            expression,
        )
        if named is not None:
            expression = named.group("value")
        if URI_CREDENTIAL_REFERENCE_PATTERN.fullmatch(expression) is None:
            return False
    return True

def config_assignment_context(
    text: str,
    position: int,
    *,
    allow_environment_name: bool = False,
) -> tuple[str, str] | None:
    line_start = bounded_line_start(text, position)
    prefix = text[line_start + 1 : position]
    key_pattern = r"(?:[A-Za-z_][A-Za-z0-9_.-]*)?(?:dsn|uri|url)"
    key_quotes = r'["\']?'
    closing_key_quote = key_quotes
    value_quote = key_quotes
    if allow_environment_name:
        # Compose environment keys can describe URIs without a URL suffix.
        # The caller still requires a complete protected credential reference.
        key_pattern = rf"(?:{key_pattern}|(?-i:[A-Z_][A-Z0-9_]*))"
        # A quote around the whole command is not a quoted mapping key.
        # Match key delimiters and allow only interpolating value quotes.
        key_quotes = r'(?P<key_quote>["\']?)'
        closing_key_quote = r'(?P=key_quote)'
        value_quote = r'"?'
    match = re.fullmatch(
        rf"\s*(?P<comment>#\s*)?(?:-\s+)?{key_quotes}"
        rf"(?P<key>{key_pattern})"
        rf"{closing_key_quote}\s*(?P<separator>[:=])\s*{value_quote}",
        prefix,
        re.IGNORECASE,
    )
    if match is None or (
        match.group("separator") != ":" and match.group("comment") is None
    ):
        return None
    return match.group("key"), match.group("separator")

def config_uri_reference_is_safe(
    text: str,
    position: int,
    password: str,
    *,
    allow_lowercase_key: bool,
) -> bool:
    context = config_assignment_context(text, position)
    if context is None:
        return False
    key, separator = context
    syntactic_reference = any(
        pattern.fullmatch(password)
        for pattern in URI_PASSWORD_REFERENCE_PATTERNS[:2]
    )
    return syntactic_reference and (
        uri_named_credential_reference(password)
        or key == key.upper()
        or (allow_lowercase_key and separator == ":")
    )

def shell_assignment_prefix(text: str) -> bool:
    match = re.fullmatch(
        r"\s*(?:-\s+)?(?P<export>export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=",
        text,
    )
    return match is not None and (
        match.group("export") is not None
        or match.group("name") == match.group("name").upper()
    )

def powershell_assignment_prefix(text: str) -> bool:
    return (
        re.match(
            r"(?i)\s*(?:"
            r"\[[^\]\r\n]+\]\s*\$[A-Za-z_][A-Za-z0-9_]*"
            r"|\$env:[A-Za-z_][A-Za-z0-9_]*)\s*=",
            text,
        )
        is not None
    )

def shell_command_prefix(text: str, position: int) -> bool:
    line_start = bounded_line_start(text, position)
    prefix = text[line_start + 1 : position]
    match = re.fullmatch(
        r"\s*(?P<command>[A-Za-z0-9_./-]+)"
        r"(?:[ \t]+[^ \t\"'`]+)*[ \t]+",
        prefix,
    )
    if match is None:
        return False
    tokens = prefix.split()
    while tokens and tokens[0].rsplit("/", 1)[-1] in SHELL_COMMAND_WRAPPERS:
        wrapper = tokens.pop(0).rsplit("/", 1)[-1]
        while tokens and (
            tokens[0].startswith("-")
            or (wrapper == "env" and "=" in tokens[0])
        ):
            tokens.pop(0)
    if not tokens:
        return False
    command = tokens[0].rsplit("/", 1)[-1]
    return (
        command == command.lower()
        and command not in NON_SHELL_COMMAND_WORDS
        and re.fullmatch(r"[a-z0-9][a-z0-9._+-]*", command) is not None
        and not any(
            token in {"=", "=>", ":", "::"} or token.endswith(("=", "=>"))
            for token in tokens[1:]
        )
    )

def secret_literal_risk(
    expression: str,
    minimum_length: int = 12,
    *,
    javascript_dialect: str | None = None,
) -> bool:
    if credentialed_uri_risk(expression) or basic_authorization_risk(expression) or captured_fixture_secret_value_risk(expression):
        return True
    value_pattern = re.compile(
        rf'"(?P<double>[^"\r\n]{{{minimum_length},}})"'
        rf"|'(?P<single>[^'\r\n]{{{minimum_length},}})'"
        rf"|`(?P<backtick>[^`\r\n]{{{minimum_length},}})`"
        rf"|(?P<bare>[A-Za-z0-9_./+=:@#$%&*!?-]{{{max(20, minimum_length)},}})"
    )
    for match in value_pattern.finditer(expression):
        value = next(group for group in match.groups() if group is not None)
        if value.lower() in SECRET_PLACEHOLDER_VALUES:
            continue
        if match.group("backtick") is not None and any(
            pattern.fullmatch(value)
            for pattern in BACKTICK_SECRET_REFERENCE_PATTERNS
        ):
            continue
        reference_patterns = (
            UNQUOTED_SECRET_REFERENCE_PATTERNS
            if match.group("bare") is not None
            else QUOTED_SECRET_REFERENCE_PATTERNS
        )
        if any(pattern.fullmatch(value) for pattern in reference_patterns):
            continue
        if match.group("bare") is not None:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                continue
            if (
                javascript_dialect is not None
                and SOURCE_CODE_REFERENCE_ROOT_PATTERN.fullmatch(value)
            ):
                continue
            suffix = expression[match.end() :].lstrip()
            if suffix.startswith("("):
                continue
        return True
    return False


def javascript_numeric_fallback_risk(expression: str, dialect: str | None) -> bool:
    if dialect is None:
        return False
    # Credential continuations may assemble numeric bytes without any quoted
    # literal. Reuse the initializer classifier after masking noncode; ordinary
    # call options and sibling assignments keep their existing owners.
    code = javascript_binding_code(expression)
    return (
        re.match(r"\s*(?:\|\||&&|\?\?|[+?])", code) is not None
        and javascript_expression_has_literal(code)
    )

def fallback_secret_risk(
    text: str,
    minimum_length: int = 8,
    *,
    javascript_dialect: str | None = None,
) -> bool:
    expression = fallback_expression(text, typescript=javascript_dialect == "typescript")
    return any((
        secret_literal_risk(
            expression,
            minimum_length=minimum_length,
            javascript_dialect=javascript_dialect,
        ),
        javascript_numeric_fallback_risk(expression, javascript_dialect),
    ))

def delimited_synthetic_secret_fixture(value: str, normalized_key: str) -> bool:
    # Explicit markers bind an existing fixture prefix to this credential
    # field. One short alphabetic role is a label, not opaque credential data.
    # Unknown labels, suffixes and credential constructions keep their scans.
    marker = re.fullmatch(
        r"<(?P<prefix>[a-z]+)-(?:[a-z]{1,16}-)?" + re.escape(normalized_key) + r">",
        value,
    )
    return marker is not None and marker.group("prefix") in SYNTHETIC_SECRET_PREFIXES

def role_marked_synthetic_secret_fixture(value: str, normalized_key: str) -> bool:
    # A short role label plus an explicit fixture marker and the credential kind
    # names synthetic data. Extra bytes and mismatched fields stay refused.
    marker = re.fullmatch(
        r"(?:[a-z]{1,16}-){1,2}(?P<prefix>[a-z]+)-" + re.escape(normalized_key.rsplit("-", 1)[-1]), value,
    )
    return marker is not None and marker.group("prefix") in SYNTHETIC_SECRET_PREFIXES




_CAPTURED_SOURCES = contextvars.ContextVar('captured_source_inputs', default=())
_CAPTURED_SOURCE_PATH = contextvars.ContextVar('captured_source_path', default=None)


@contextlib.contextmanager
def captured_source_context(records):
    # Only the capture owner supplies complete frozen files. No caller flags,
    # environment, live reads or precomputed declarations enter this context.
    sources = {}
    for path, text in records:
        path = str(PurePosixPath(path.replace('\\', '/')))
        if path in sources and sources[path] != text:
            raise SystemExit('conflicting captured source inputs')
        sources[path] = text
    token = _CAPTURED_SOURCES.set(tuple(sorted(sources.items())))
    try:
        yield
    finally:
        _CAPTURED_SOURCES.reset(token)


def javascript_captured_module_path(current, specifier, sources):
    if specifier.startswith('.'):
        candidate = posixpath.normpath(posixpath.join(posixpath.dirname(current), specifier))
        if candidate.startswith('../') or candidate.startswith('/'):
            return None
        paths = [candidate]
        if candidate.endswith('.js'):
            paths.append(candidate[:-3] + '.ts')
        elif not PurePosixPath(candidate).suffix:
            paths.extend(candidate + suffix for suffix in ('.ts', '.js'))
        found = [path for path in paths if path in sources]
        return found[0] if len(found) == 1 else None
    matches = []
    for path, text in sources.items():
        if PurePosixPath(path).name != 'tsconfig.json':
            continue
        try:
            config = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not isinstance(config, dict):
            continue
        options = config.get('compilerOptions', {})
        if not isinstance(options, dict) or options.get('baseUrl') or config.get('extends'):
            continue
        paths = options.get('paths', {})
        if not isinstance(paths, dict):
            continue
        for pattern, targets in paths.items():
            if not isinstance(pattern, str) or pattern.count('*') > 1:
                continue
            if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], str):
                continue
            suffix = ''
            if '*' in pattern:
                before, after = pattern.split('*', 1)
                if not specifier.startswith(before) or not specifier.endswith(after):
                    continue
                suffix = specifier[len(before):len(specifier) - len(after) if after else None]
            elif pattern != specifier:
                continue
            target = targets[0].replace('*', suffix)
            resolved = javascript_captured_module_path(path, target if target.startswith('.') else './' + target, sources)
            if resolved:
                matches.append(resolved)
    return matches[0] if len(set(matches)) == 1 else None



def javascript_captured_function(current, name, sources, depth=0):
    if depth >= 8 or current not in sources:
        return None
    text = sources[current]
    code = javascript_binding_code(text)
    pairs = javascript_scope_pairs(code)
    if pairs is None or javascript_binding_initializers(text, code, name):
        return None
    declarations = [match for match in re.finditer(r'\bfunction\s+' + re.escape(name) + r'(?![\w$])', code)
                    if not any(code[start] == '{' and start < match.start() < end for start, end in pairs.items())]
    if any(re.search(r'\basync\s*$', code[:match.start()]) for match in declarations):
        return None
    if len(declarations) == 1:
        declaration = declarations[0]
        if depth and not re.search(r'\bexport\s*$', code[:declaration.start()]):
            return None
        parts = javascript_local_function_parts(text, code, declaration)
        return (current, name, parts) if parts else None
    if declarations:
        return None
    bindings = []
    pattern = r'(?<![\w$])(?:import|export)\s*\{([^}]+)\}\s*from\s*(["\u0027])([^"\u0027]+)\2'
    for match in re.finditer(pattern, text):
        # Quoted data cannot invent a module binding.
        keyword = code[match.start():match.start() + 6]
        if keyword not in {'import', 'export'} or (depth and keyword != 'export'):
            continue
        for field in match.group(1).split(','):
            field = field.strip()
            if field.startswith('type '):
                continue
            pair = re.fullmatch(r'([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?', field)
            if pair and (pair.group(2) or pair.group(1)) == name:
                path = javascript_captured_module_path(current, match.group(3), sources)
                if path:
                    bindings.append((path, pair.group(1)))
    if len(bindings) != 1:
        return None
    path, original = bindings[0]
    return javascript_captured_function(path, original, sources, depth + 1)


def javascript_captured_return_summary(record):
    if record is None:
        return None
    _, _, (parameters, body) = record
    names = []
    for parameter in split_top_level_call_arguments(parameters):
        field = re.fullmatch(r'\s*([A-Za-z_$][\w$]*)\??\s*(?::[\s\S]+)?', parameter)
        if field is None or '=' in parameter:
            return None
        names.append(field.group(1))
    code = javascript_binding_code(body)
    returned = re.match(r'\s*return\b', code)
    if returned is None:
        return None
    expression = fallback_expression(body[returned.end():], typescript=True).strip()
    remainder = body[returned.end():].strip()
    if remainder not in {expression, expression + ';'}:
        return None
    # A leaf return may select or coalesce parameters. It cannot assign, call,
    # construct, coerce, read a global or hide literal return bytes.
    checked = re.fullmatch(r'typeof\s+([A-Za-z_$][\w$]*)\s*===\s*(["\u0027])(string|number|boolean)\2\s*\?\s*\1\s*:\s*(?:undefined|null)', expression)
    if checked and checked.group(1) in names:
        return ((checked.group(1),), True)
    if javascript_expression_has_literal(expression):
        return None
    pieces = re.split(r'\?\?|\|\|', expression)
    reference = r'[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*'
    if not all(re.fullmatch(reference, part.strip()) and part.strip().split('.')[0].rstrip('?') in names for part in pieces):
        return None
    if any(javascript_prototype_selector(part.strip()) for part in pieces):
        return None
    return (tuple(pieces), False)




def javascript_captured_primitive_result(expression, text):
    current = _CAPTURED_SOURCE_PATH.get()
    sources = dict(_CAPTURED_SOURCES.get())
    call = re.fullmatch(r'\s*([A-Za-z_$][\w$]*)\s*\([\s\S]*\)\s*', expression)
    if not sources or current is None or call is None:
        return False
    code = javascript_binding_code(expression)
    opening = code.find('(')
    if javascript_balanced_binding_end(code, opening, '(', ')') != len(code.rstrip()):
        return False
    sources[current] = text
    summary = javascript_captured_return_summary(javascript_captured_function(current, call.group(1), sources))
    return summary is not None and summary[1]


def javascript_captured_read_only_call(text, code, opening):
    prefix = code[:opening].rstrip()
    target = re.search(r'(?<![\w$.])([A-Za-z_$][\w$]*)$', prefix)
    current = _CAPTURED_SOURCE_PATH.get()
    if target is None or current is None:
        return False
    sources = dict(_CAPTURED_SOURCES.get())
    if not sources:
        return False
    sources[current] = text
    return javascript_captured_return_summary(javascript_captured_function(current, target.group(1), sources)) is not None


def javascript_captured_import_origins(text, code, root):
    current = _CAPTURED_SOURCE_PATH.get()
    sources = dict(_CAPTURED_SOURCES.get())
    if current is None or not sources or not re.search(r'(?<![\w$.])' + re.escape(root) + r'\s*\(', code):
        return []
    sources[current] = text
    record = javascript_captured_function(current, root, sources)
    if record is None or record[0] == current:
        return []
    module, original, _ = record
    raw = sources[module]
    # Follow whole-module local bindings before allowing a captured return.
    # The original function, defaults and decoded literals remain in its scan.
    token = _CAPTURED_SOURCE_PATH.set(module)
    try:
        if javascript_binding_literal_risk(raw, javascript_binding_code(raw), original):
            return None
    finally:
        _CAPTURED_SOURCE_PATH.reset(token)
    return [] if javascript_captured_return_summary(record) is not None else None


_PYTHON_FIXTURE_PLACEHOLDERS = contextvars.ContextVar('python_fixture_placeholders', default=frozenset())



def python_fixture_call_path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = python_fixture_call_path(node.value)
        return base + '.' + node.attr if base else None
    return None


def python_public_placeholder_kind(value):
    # Recorded data needs an explicit public-fixture marker and short role labels.
    # Opaque bytes, provider prefixes and constructed suffixes never match.
    if not isinstance(value, str):
        return None
    matched = re.fullmatch(r'(?:recorded|dummy|example|fake|fixture|mock|sample|test)-(?:[a-z]{1,16}-){0,2}(token|key|password|secret)', value)
    return matched.group(1) if matched else None


def python_fixture_started_calls(method):
    return [node.func.value for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'start' and not node.args and not node.keywords
            and isinstance(node.func.value, ast.Call)]


def python_fixture_setup_values(setup):
    calls = python_fixture_started_calls(setup)
    blocked = {call.args[0].value: call.lineno for call in calls
               if python_fixture_call_path(call.func) == 'patch' and len(call.args) == 1
               and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
               and any(keyword.arg == 'side_effect' and isinstance(keyword.value, ast.Call)
                       and python_fixture_call_path(keyword.value.func) == 'AssertionError'
                       for keyword in call.keywords)}
    cleanup = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == 'addCleanup' and len(node.args) == 1
                  and python_fixture_call_path(node.args[0]) == 'patch.stopall'
                  for node in ast.walk(setup))
    if not cleanup or not {'socket.create_connection', 'urllib.request.urlopen'} <= blocked.keys():
        return frozenset()
    environment = set()
    for call in calls:
        if (python_fixture_call_path(call.func) == 'patch.dict' and len(call.args) == 2
                and python_fixture_call_path(call.args[0]) == 'os.environ'
                and isinstance(call.args[1], ast.Dict)):
            for key, value in zip(call.args[1].keys, call.args[1].values):
                if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and isinstance(value, ast.Constant) and python_public_placeholder_kind(value.value)
                        and re.search(r'(?:^|_)' + python_public_placeholder_kind(value.value) + r'$', key.value, re.I)):
                    environment.add((value.value, python_public_placeholder_kind(value.value), key, value))
    for node in ast.walk(setup):
        if not isinstance(node, ast.Call) or python_fixture_call_path(node.func) != 'httpx.AsyncClient' or node.args:
            continue
        options = {keyword.arg: keyword.value for keyword in node.keywords}
        transport, url, headers = (options.get(key) for key in ('transport', 'base_url', 'headers'))
        if (not isinstance(options.get('trust_env'), ast.Constant) or options['trust_env'].value is not False
                or not isinstance(transport, ast.Call) or python_fixture_call_path(transport.func) != 'httpx.ASGITransport'
                or transport.args or len(transport.keywords) != 1 or transport.keywords[0].arg != 'app'
                or not isinstance(url, ast.Constant) or not isinstance(url.value, str) or not isinstance(headers, ast.Dict)
                or any(line >= node.lineno for line in blocked.values())):
            continue
        parsed = urllib.parse.urlsplit(url.value)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or not parsed.hostname.endswith('.invalid') or parsed.username or parsed.password:
            continue
        for key, value in zip(headers.keys, headers.values):
            if (isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.casefold() == 'authorization'
                    and isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.startswith('Bearer ')
                    and any(entry[:2] == (value.value[7:], 'token') for entry in environment)):
                return frozenset((entry[2], entry[3]) for entry in environment) | {(key, value)}
    return frozenset()



def python_fixture_provider_values(method):
    calls = python_fixture_started_calls(method)
    local_callbacks = {node.name for node in method.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    receivers = {ast.dump(call.args[0], include_attributes=False) for call in calls
                 if python_fixture_call_path(call.func) == 'patch.object' and len(call.args) == 3
                 and isinstance(call.args[1], ast.Constant) and call.args[1].value == 'urlopen'
                 and isinstance(call.args[2], ast.Name) and call.args[2].id in local_callbacks}
    values = set()
    for call in calls:
        if (python_fixture_call_path(call.func) != 'patch.object' or len(call.args) != 3
                or ast.dump(call.args[0], include_attributes=False) not in receivers
                or not isinstance(call.args[1], ast.Constant) or not isinstance(call.args[1].value, str)
                or not isinstance(call.args[2], ast.Constant)):
            continue
        kind = python_public_placeholder_kind(call.args[2].value)
        if kind and re.search(r'(?:^|_)' + kind + r'$', call.args[1].value, re.I):
            values.add((call.args[1], call.args[2]))
    return frozenset(values)



def python_captured_fixture_placeholders(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return frozenset()
    modules = {alias.name for node in tree.body if isinstance(node, ast.Import)
               for alias in node.names if alias.asname is None}
    patch_import = any(isinstance(node, ast.ImportFrom) and node.module == 'unittest.mock'
                       and any(alias.name == 'patch' and alias.asname is None for alias in node.names) for node in tree.body)
    if not {'os', 'httpx', 'unittest'} <= modules or not patch_import:
        return frozenset()
    owners = {'os', 'httpx', 'unittest', 'patch', 'AssertionError'}
    if any(isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in owners
           or isinstance(node, ast.arg) and node.arg in owners for node in ast.walk(tree)):
        return frozenset()
    values = set()
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef) or not any(python_fixture_call_path(base) == 'unittest.IsolatedAsyncioTestCase' for base in cls.bases):
            continue
        setup = next((node for node in cls.body if isinstance(node, ast.AsyncFunctionDef) and node.name == 'asyncSetUp'), None)
        if setup is None:
            continue
        environment = python_fixture_setup_values(setup)
        if not environment:
            continue
        values.update(environment)
        for method in cls.body:
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                values.update(python_fixture_provider_values(method))
    literals = []
    for key, value in values:
        begin = python_literal_source_position(text, value)
        end_node = ast.Constant(lineno=value.end_lineno, col_offset=value.end_col_offset)
        end = python_literal_source_position(text, end_node)
        key_begin = python_literal_source_position(text, key)
        if begin is None or end is None or key_begin is None or not isinstance(value.value, str):
            return None
        literals.append((begin, end, value.value, key_begin))
    return (text, tuple(sorted(literals)))



def captured_fixture_secret_value_risk(text):
    # Approval belongs to the exact isolated-fixture literal occurrence.
    # An equal value in another literal or decoded data receives no approval.
    approved = _PYTHON_FIXTURE_PLACEHOLDERS.get()
    literals = approved[1] if approved and approved[0] == text else ()
    for pattern in SECRET_VALUE_PATTERNS:
        for match in pattern.finditer(text):
            bearer = re.fullmatch(r'(?i)bearer\s+([A-Za-z0-9._-]{20,})', match.group())
            if bearer and any(begin <= match.start() and match.end() <= end and value == match.group()
                              for begin, end, value, _ in literals):
                continue
            return True
    return False


def python_fixture_prefix_ranges(text):
    approved = _PYTHON_FIXTURE_PLACEHOLDERS.get()
    return tuple((key, begin) for begin, _, _, key in approved[1]) if approved and approved[0] == text else ()


def python_fixture_literal_owned(text, context, payload):
    approved = _PYTHON_FIXTURE_PLACEHOLDERS.get()
    if not approved or approved[0] != text:
        return False
    quote, start = context
    token = python_source_literal_token(text, context)
    return token is not None and any(begin <= start < end and payload == value and text[begin:end] == token
                                    for begin, end, value, _ in approved[1])


def synthetic_secret_fixture(value: str, key: str) -> bool:
    normalized = value.casefold()
    kind = re.split(r"[_-]", key.strip("\"'").casefold())[-1]
    if normalized in SECRET_PLACEHOLDER_VALUES:
        return True
    if len(normalized) > 80:
        return False
    camel_split_key = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        "-",
        key.strip("\"'"),
    )
    normalized_key = re.sub(
        r"[^a-z0-9]+",
        "-",
        camel_split_key.casefold(),
    ).strip("-")
    return any((
        any(normalized == f"{prefix}-{normalized_key}"
            for prefix in SYNTHETIC_SECRET_PREFIXES),
        delimited_synthetic_secret_fixture(value, normalized_key),
        role_marked_synthetic_secret_fixture(normalized, normalized_key),
        numbered_synthetic_secret_fixture(normalized, normalized_key),
        field_kind_synthetic_secret_fixture(normalized, normalized_key),
    ))


def safe_secret_assignment_suffix(
    text: str,
    end: int,
    *,
    javascript_dialect: str | None = None,
) -> bool:
    cursor = end
    raw_diff = text.startswith("diff --git ")
    while cursor < len(text):
        while cursor < len(text) and text[cursor] in " \t\r":
            cursor += 1
        if cursor >= len(text):
            return True
        if cursor < len(text) and text[cursor] == "\n":
            cursor += 1
            while cursor < len(text):
                if raw_diff and text[cursor : cursor + 1] in {"+", "-", " "}:
                    cursor += 1
                while cursor < len(text) and text[cursor] in " \t\r":
                    cursor += 1
                if text.startswith("//", cursor) or text.startswith("#", cursor):
                    newline = text.find("\n", cursor)
                    if newline < 0:
                        return True
                    cursor = newline + 1
                    continue
                if text.startswith("/*", cursor):
                    comment_end = text.find("*/", cursor + 2)
                    if comment_end < 0:
                        return False
                    cursor = comment_end + 2
                    continue
                break
            suffix = text[cursor:]
            if (
                suffix.startswith(("||", "&&", "??", "+"))
                or (suffix.startswith("?") and not suffix.startswith("?."))
                or re.match(r"(?:or|and)\b", suffix) is not None
            ):
                return not fallback_secret_risk(
                    suffix,
                    javascript_dialect=javascript_dialect,
                )
            return True
        if text.startswith("//", cursor) or text.startswith("#", cursor):
            cursor = text.find("\n", cursor)
            if cursor < 0:
                return True
            continue
        if text.startswith("/*", cursor):
            comment_end = text.find("*/", cursor + 2)
            if comment_end < 0:
                return False
            cursor = comment_end + 2
            continue
        suffix = text[cursor:]
        if (
            suffix.startswith(("||", "&&", "??", "+"))
            or (suffix.startswith("?") and not suffix.startswith("?."))
            or re.match(r"(?:or|and|if|unless)\b", suffix) is not None
        ):
            return not fallback_secret_risk(
                suffix,
                javascript_dialect=javascript_dialect,
            )
        if text[cursor] in ",;)]}":
            return True
        if text[cursor] in {'"', "'", "`"}:
            after_quote = cursor + 1
            while after_quote < len(text) and text[after_quote] in " \t\r":
                after_quote += 1
            if after_quote >= len(text) or text[after_quote] in ",;)]}":
                return True
            quote = text[cursor]
            cursor += 1
            escaped = False
            while cursor < len(text):
                char = text[cursor]
                cursor += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    break
            continue
        cursor += 1
    return True

def split_top_level_call_arguments(text: str) -> list[str]:
    arguments: list[str] = []
    start = 0
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        regex_end = javascript_regex_literal_end(text, index)
        if regex_end is not None:
            index = regex_end
        elif char == "/" and next_char == "/":
            line_comment = True
            index += 2
        elif char == "/" and next_char == "*":
            block_comment = True
            index += 2
        elif char in {'"', "'", "`"}:
            quote = char
            index += 1
        elif char in pairs:
            stack.append(pairs[char])
            index += 1
        elif stack and char == stack[-1]:
            stack.pop()
            index += 1
        elif char == "," and not stack:
            arguments.append(text[start:index])
            start = index + 1
            index += 1
        else:
            index += 1
    arguments.append(text[start:])
    return arguments

def javascript_private_member_marker(
    text: str,
    index: int,
    *,
    allow_bare: bool = False,
) -> bool:
    next_char = text[index + 1] if index + 1 < len(text) else ""
    return (
        text[index : index + 1] == "#"
        and bool(next_char)
        and (next_char.isalpha() or next_char in "_$")
        and (
            allow_bare
            or (index > 0 and text[index - 1] == ".")
        )
    )

@functools.lru_cache(maxsize=16)
def javascript_control_contexts(text: str) -> frozenset[int]:
    closes: set[int] = set()
    stack: list[str | None] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    last_word: str | None = None
    prior_word: str | None = None
    last_word_is_member = False
    after_dot = False
    cursor = 0
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            cursor += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                block_comment = False
                cursor += 2
            else:
                cursor += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            cursor += 1
            continue
        regex_end = javascript_regex_literal_end(
            text,
            cursor,
            control_conditions=False,
            known_control_closes=closes,
        )
        if regex_end is not None:
            cursor = regex_end
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = False
        elif char == "/" and next_char == "/":
            line_comment = True
            cursor += 2
        elif char == "/" and next_char == "*":
            block_comment = True
            cursor += 2
        elif char in {'"', "'", "`"}:
            quote = char
            cursor += 1
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = False
        elif char.isalpha() or char in "_$":
            word_end = cursor + 1
            while word_end < len(text) and (
                text[word_end].isalnum() or text[word_end] in "_$"
            ):
                word_end += 1
            word = text[cursor:word_end]
            prior_word = last_word if not after_dot else None
            last_word = word
            last_word_is_member = after_dot
            after_dot = False
            cursor = word_end
        elif char == "(":
            control_kind: str | None = None
            if not last_word_is_member:
                if last_word in {"if", "while", "with"}:
                    control_kind = "control"
                elif last_word == "for" or (
                    prior_word == "for" and last_word == "await"
                ):
                    control_kind = "for"
            stack.append(control_kind)
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = False
            cursor += 1
        elif char == ")":
            if not stack:
                cursor += 1
                continue
            if stack.pop() is not None:
                closes.add(cursor)
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = False
            cursor += 1
        elif char == ".":
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = True
            cursor += 1
        elif javascript_private_member_marker(
            text,
            cursor,
            allow_bare=True,
        ):
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = True
            cursor += 1
        elif char == ";":
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = False
            cursor += 1
        elif char.isspace():
            cursor += 1
        else:
            last_word = None
            prior_word = None
            last_word_is_member = False
            after_dot = False
            cursor += 1
    return frozenset(closes)

@functools.lru_cache(maxsize=16)
def javascript_control_condition_closes(text: str) -> frozenset[int]:
    return javascript_control_contexts(text)

def javascript_regex_literal_end(
    text: str,
    start: int,
    *,
    control_conditions: bool = True,
    known_control_closes: set[int] | frozenset[int] | None = None,
) -> int | None:
    if text[start : start + 1] != "/" or text[start + 1 : start + 2] in {
        "/",
        "*",
    }:
        return None
    previous = start - 1
    while previous >= 0 and text[previous].isspace():
        previous -= 1
    if (
        previous >= 2
        and text[previous - 2 : previous + 1] == "..."
        and (previous == 2 or text[previous - 3] != ".")
    ):
        previous = -1
    if previous >= 0 and text[previous] == ")":
        closes_control_condition = (
            previous in known_control_closes
            if known_control_closes is not None
            else (
                control_conditions
                and previous in javascript_control_condition_closes(text)
            )
        )
        if closes_control_condition:
            previous = -1
    if previous >= 0 and text[previous] not in "([{:;,=!?&|+-*%^~<>":
        word_start = previous
        while word_start >= 0 and (
            text[word_start].isalnum() or text[word_start] in "_$"
        ):
            word_start -= 1
        keyword = text[word_start + 1 : previous + 1]
        expression_keyword = keyword in {
            "case",
            "default",
            "delete",
            "do",
            "else",
            "extends",
            "in",
            "instanceof",
            "new",
            "return",
            "throw",
            "typeof",
            "void",
        }
        if (
            not expression_keyword
            or (word_start >= 0 and text[word_start] == ".")
        ):
            return None
    if (
        previous > 0
        and text[previous] in "+-"
        and text[previous - 1] == text[previous]
    ):
        return None
    if text[previous : previous + 1] == "!":
        before = previous - 1
        while before >= 0 and text[before].isspace():
            before -= 1
        if before >= 0 and (
            text[before].isalnum() or text[before] in "_$)]}"
        ):
            return None
    escaped = False
    character_class = False
    cursor = start + 1
    while cursor < len(text):
        char = text[cursor]
        if char in "\r\n":
            return None
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            character_class = True
        elif char == "]" and character_class:
            character_class = False
        elif char == "/" and not character_class:
            cursor += 1
            while cursor < len(text) and text[cursor].isalpha():
                cursor += 1
            return cursor
        cursor += 1
    return None

def regex_tail_end(text: str, start: int, limit: int) -> int | None:
    escaped = False
    character_class = False
    cursor = start
    while cursor < limit:
        char = text[cursor]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            character_class = True
        elif char == "]" and character_class:
            character_class = False
        elif char == "/" and not character_class:
            return cursor + 1
        cursor += 1
    return None

def previous_regex_delimiter(text: str, start: int, lower: int) -> int | None:
    character_class = False
    cursor = start - 1
    while cursor >= lower:
        char = text[cursor]
        backslashes = 0
        previous = cursor - 1
        while previous >= lower and text[previous] == "\\":
            backslashes += 1
            previous -= 1
        escaped = backslashes % 2 == 1
        if not escaped:
            if char == "]":
                character_class = True
            elif char == "[" and character_class:
                character_class = False
            elif char == "/" and not character_class:
                return cursor
        cursor -= 1
    return None

def text_without_ranges(
    text: str,
    start: int,
    end: int,
    ranges: list[tuple[int, int]],
) -> str:
    parts: list[str] = []
    cursor = start
    for range_start, range_end in ranges:
        if range_end <= cursor or range_start >= end:
            continue
        if cursor < range_start:
            parts.append(text[cursor:range_start])
        parts.append(" ")
        cursor = max(cursor, range_end)
    if cursor < end:
        parts.append(text[cursor:end])
    return "".join(parts)

def premature_regex_call_tail(
    text: str,
    call_start: int,
    cursor: int,
) -> tuple[str, int] | None:
    line_end = len(text)
    for delimiter in ("\n", "\r"):
        found = text.find(delimiter, cursor)
        if found >= 0:
            line_end = min(line_end, found)
    line_start = max(
        text.rfind("\n", 0, cursor),
        text.rfind("\r", 0, cursor),
    ) + 1
    search_start = max(call_start, line_start)
    nearest = previous_regex_delimiter(text, cursor, search_start)
    candidates = []
    if nearest is not None:
        candidates.append(nearest)
        previous = previous_regex_delimiter(text, nearest, search_start)
        if previous is not None:
            candidates.append(previous)
    for regex_start in candidates:
        regex_end = regex_tail_end(text, regex_start + 1, line_end)
        if regex_end is None or ")" not in text[regex_start + 1 : regex_end - 1]:
            continue
        depth = 0
        quote: str | None = None
        escaped = False
        line_comment = False
        block_comment = False
        regex_ranges = [(regex_start, regex_end)]
        index = call_start
        while index < len(text):
            char = text[index]
            next_char = text[index + 1] if index + 1 < len(text) else ""
            if line_comment:
                if char == "\n":
                    line_comment = False
                index += 1
                continue
            if block_comment:
                if char == "*" and next_char == "/":
                    block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if index == regex_start:
                index = regex_end
            elif (
                later_regex_end := javascript_regex_literal_end(text, index)
            ) is not None:
                regex_ranges.append((index, later_regex_end))
                index = later_regex_end
            elif char == "/" and next_char == "/":
                line_comment = True
                index += 2
            elif char == "/" and next_char == "*":
                block_comment = True
                index += 2
            # This recovery scans JavaScript; `#name` is a private identifier,
            # so only JavaScript's slash-delimited comment forms apply here.
            elif char in {'"', "'", "`"}:
                quote = char
                index += 1
            elif char == "(":
                depth += 1
                index += 1
            elif char == ")":
                depth -= 1
                index += 1
                if depth == 0:
                    return (
                        (
                            text_without_ranges(
                                text,
                                cursor,
                                index,
                                regex_ranges,
                            ),
                            index,
                        )
                        if index > cursor
                        else None
                    )
            else:
                index += 1
    return None

def safe_credential_lookup_argument(
    call_target: str,
    argument: str,
    argument_index: int,
) -> bool:
    if argument_index != 0:
        return False
    normalized_target = call_target.replace("?.", ".")
    result_lookup = normalized_target in {
        "response.json().get",
        "response.get",
        "result.get",
    }
    if (
        not result_lookup
        and normalized_target not in {"os.getenv", "os.environ.get", "os.environ.pop"}
        and normalized_target != "headers.get"
        and not normalized_target.endswith(".headers.get")
    ):
        return False
    match = re.fullmatch(r"\s*([\"'])([^\"'\r\n]+)\1\s*", argument)
    if match is None:
        return False
    key = match.group(2)
    if result_lookup and any(
        pattern.search(key) for pattern in SECRET_VALUE_PATTERNS
    ):
        return False
    return (
        (
            result_lookup
            and key.casefold()
            in {
                "access_token",
                "api_key",
                "auth_token",
                "client_secret",
                "credential",
                "credentials",
                "id_token",
                "password",
                "refresh_token",
                "secret",
                "token",
            }
        )
        or (
            not result_lookup
            and re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", key) is not None
        )
        or key.casefold() in {"authorization", "proxy-authorization"}
    )

def prompt_service_segment_is_secret_like(segment: str) -> bool:
    suffix = re.search(r"\d{4,}$", segment)
    if suffix is None:
        return False
    prefix = segment[: suffix.start()]
    components = re.findall(
        r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+",
        prefix,
    )
    theme_phrase = bool(components) and all(
        component.casefold() in PROMPT_SECRET_THEME_WORDS
        for component in components
    )
    sequential_letters = len(prefix) >= 8 and all(
        ord(right.casefold()) == ord(left.casefold()) + 1
        for left, right in zip(prefix, prefix[1:])
    )
    return theme_phrase or sequential_letters

def generic_credential_prompt_is_safe(value: str) -> bool:
    match = GENERIC_CREDENTIAL_PROMPT_PATTERN.fullmatch(value)
    if match is None:
        return False
    service = match.group("service")
    if service is None:
        return True
    service = service.strip()
    segments = re.split(r"[ _-]+", service)
    secret_like_version = any(
        prompt_service_segment_is_secret_like(segment)
        for segment in segments
    )
    natural_service = bool(service) and len(segments) <= 5 and all(
        re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,23}", segment) is not None
        and sum(
            left.islower() != right.islower()
            for left, right in zip(segment, segment[1:])
            if left.isalpha() and right.isalpha()
        )
        <= 4
        for segment in segments
    )
    return natural_service and not secret_like_version and not any(
        pattern.search(service) for pattern in SECRET_VALUE_PATTERNS
    )

def public_call_argument_risk(
    call_target: str,
    argument: str,
    argument_index: int,
) -> bool | None:
    normalized_target = call_target.replace("?.", ".")
    target_parts = normalized_target.split(".")
    credential_scope_call = (
        len(target_parts) >= 2
        and target_parts[-2].lstrip("_") in {"credential", "credentials"}
        and target_parts[-1] == "get_token"
    )
    if (
        not credential_scope_call
        and normalized_target not in PUBLIC_PROMPT_TARGETS
    ):
        return None
    if normalized_target == "prompt":
        match = re.fullmatch(r"\s*([\"'])([^\"'\r\n]+)\1\s*", argument)
        if (
            argument_index == 0
            and match is not None
            and generic_credential_prompt_is_safe(match.group(2))
        ):
            return False
        return secret_literal_risk(argument, minimum_length=8)
    if not credential_scope_call and argument_index != 0:
        return None
    literal_argument = argument
    if normalized_target == "getpass.getpass":
        literal_argument = re.sub(
            r"^\s*prompt\s*=\s*",
            "",
            literal_argument,
            count=1,
        )
    match = re.fullmatch(r"\s*([\"'])([^\"'\r\n]+)\1\s*", literal_argument)
    if match is None:
        return None
    value = match.group(2)
    if credential_scope_call:
        decoded_value = value
        for _ in range(8):
            next_value = urllib.parse.unquote(decoded_value)
            if next_value == decoded_value:
                break
            decoded_value = next_value
        else:
            return True
        if any(ord(char) < 32 or ord(char) == 127 for char in decoded_value):
            return True
        if secret_text_risk(decoded_value):
            return True
        if re.fullmatch(
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/\.default",
            decoded_value,
        ):
            return False
        if "://" not in decoded_value:
            return None
        try:
            parsed = urllib.parse.urlsplit(decoded_value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            return None
        valid_authority = (
            parsed.username is None
            and parsed.password is None
            and hostname is not None
            and re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*",
                hostname,
            )
            is not None
            and (port is None or 1 <= port <= 65535)
        )
        valid_scope_uri = (
            parsed.scheme in {"api", "https"}
            and valid_authority
            and parsed.path == "/.default"
            and not parsed.query
            and not parsed.fragment
        )
        return False if valid_scope_uri else None
    return False if generic_credential_prompt_is_safe(value) else None

def call_arguments_risk(
    arguments: str,
    call_target: str,
    *,
    javascript_dialect: str | None = None,
    reference_source: tuple[str, int] | None = None,
) -> bool:
    cursor = 0
    for index, argument in enumerate(split_top_level_call_arguments(arguments)):
        position = arguments.find(argument, cursor)
        cursor = position + len(argument) + 1
        if call_argument_risk(argument, call_target, index, position, javascript_dialect, reference_source):
            return True
    return False


def call_argument_risk(argument, target, index, position, dialect, source) -> bool:
    public_risk = public_call_argument_risk(target, argument, index)
    if public_risk is not None:
        return public_risk
    if javascript_call_argument_reference(argument, source, position, dialect):
        return False
    return not safe_credential_lookup_argument(target, argument, index) and fallback_secret_risk(
        argument, minimum_length=12, javascript_dialect=dialect,
    )


def javascript_call_argument_reference(
    argument: str, source: tuple[str, int] | None, position: int, dialect: str | None,
) -> bool:
    if dialect is None or source is None or position < 0:
        return False
    value = argument.strip()
    if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, value) is None:
        return False
    text, start = source
    offset = position + len(argument) - len(argument.lstrip())
    return declared_javascript_secret_reference(text, start + offset, value)

def safe_secret_call_suffix(
    text: str,
    end: int,
    call_target: str,
    *,
    javascript_dialect: str | None = None,
) -> bool:
    if end >= len(text) or text[end] != "(":
        return False

    def balanced_end(start: int, opener: str, closer: str) -> int | None:
        depth = 0
        quote: str | None = None
        escaped = False
        line_comment = False
        block_comment = False
        index = start
        while index < len(text):
            char = text[index]
            next_char = text[index + 1] if index + 1 < len(text) else ""
            if line_comment:
                if char == "\n":
                    line_comment = False
                index += 1
                continue
            if block_comment:
                if char == "*" and next_char == "/":
                    block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            regex_end = javascript_regex_literal_end(text, index)
            if regex_end is not None:
                index = regex_end
            elif char == "/" and next_char == "/":
                line_comment = True
                index += 2
            elif char == "/" and next_char == "*":
                block_comment = True
                index += 2
            elif char == "#" and not javascript_private_member_marker(
                text,
                index,
            ):
                line_comment = True
                index += 1
            elif char in {'"', "'", "`"}:
                quote = char
                index += 1
            elif char == opener:
                depth += 1
                index += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    return index + 1
                index += 1
            elif depth == 0:
                return None
            else:
                index += 1
        return None

    def safe_call_end(start: int, target: str) -> int | None:
        cursor = balanced_end(start, "(", ")")
        if cursor is None:
            return None
        arguments = text[start + 1 : cursor - 1]
        return (
            None
            if call_arguments_risk(
                arguments,
                target,
                javascript_dialect=javascript_dialect,
                reference_source=(text, start + 1),
            )
            else cursor
        )

    cursor = safe_call_end(end, call_target)
    if cursor is None:
        return False
    regex_recovery = premature_regex_call_tail(text, end, cursor)
    if regex_recovery is not None:
        regex_tail, cursor = regex_recovery
        if secret_literal_risk(regex_tail):
            return False
    chained_target = (
        "response.json()"
        if call_target.replace("?.", ".") == "response.json"
        else "<call-result>"
    )
    while True:
        match = re.match(r"\s*(?:\?\.|\.)[A-Za-z_][A-Za-z0-9_]*", text[cursor:])
        if match is not None:
            member = re.search(r"[A-Za-z_][A-Za-z0-9_]*$", match.group(0))
            assert member is not None
            member_name = member.group(0)
            if chained_target == "response.json()" and member_name == "get":
                chained_target = "response.json().get"
            elif chained_target == "<call-result>" and member_name == "headers":
                chained_target = "<call-result>.headers"
            elif (
                chained_target == "<call-result>.headers"
                and member_name == "get"
            ):
                chained_target = "<call-result>.headers.get"
            else:
                chained_target = "<call-result>"
            cursor += match.end()
            continue
        whitespace = re.match(r"\s*", text[cursor:])
        assert whitespace is not None
        call_start = cursor + whitespace.end()
        if call_start < len(text) and text[call_start] == "(":
            cursor = safe_call_end(call_start, chained_target)
            if cursor is None:
                return False
            chained_target = "<call-result>"
            continue
        if call_start < len(text) and text[call_start] == "[":
            cursor = balanced_end(call_start, "[", "]")
            if cursor is None:
                return False
            chained_target = "<call-result>"
            continue
        return safe_secret_assignment_suffix(text, cursor)

def safe_backtick_literal_segment(value: str) -> bool:
    return bool(
        BACKTICK_TEMPLATE_SAFE_LITERAL_PATTERN.fullmatch(value)
        or value.casefold() in BACKTICK_TEMPLATE_FIXTURE_PREFIX_VALUES
    )

def safe_backtick_interpolation_expression(expression: str) -> bool:
    quoted_reference = "${" + expression + "}"
    if any(
        pattern.fullmatch(quoted_reference)
        for pattern in QUOTED_SECRET_REFERENCE_PATTERNS
    ):
        return True
    return re.fullmatch(r"(?:crypto\.)?randomUUID\(\)", expression) is not None

def safe_backtick_secret_template(value: str) -> bool:
    cursor = 0
    found_interpolation = False
    for match in BACKTICK_TEMPLATE_INTERPOLATION_PATTERN.finditer(value):
        literal = value[cursor : match.start()]
        if not safe_backtick_literal_segment(literal):
            return False
        expression = match.group(1).strip()
        if not safe_backtick_interpolation_expression(expression):
            return False
        found_interpolation = True
        cursor = match.end()
    literal = value[cursor:]
    return found_interpolation and safe_backtick_literal_segment(literal)

def javascript_template_literal_end(
    text: str,
    start: int,
    nesting: int = 0,
) -> int | None:
    if nesting > 64:
        return None
    cursor = start + 1
    expression_depth = 0
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if expression_depth:
            if char == "/" and next_char == "/":
                line_end = text.find("\n", cursor + 2)
                cursor = len(text) if line_end < 0 else line_end
                continue
            if char == "/" and next_char == "*":
                comment_end = text.find("*/", cursor + 2)
                cursor = len(text) if comment_end < 0 else comment_end + 2
                continue
            regex_end = javascript_regex_literal_end(text, cursor)
            if regex_end is not None:
                cursor = regex_end
                continue
            if char in {'"', "'"}:
                string_end = csharp_quoted_literal_end(
                    text,
                    cursor,
                    verbatim=False,
                    interpolated=False,
                )
                if string_end is None:
                    return None
                cursor = string_end
                continue
            if char == "`":
                nested_end = javascript_template_literal_end(
                    text,
                    cursor,
                    nesting + 1,
                )
                if nested_end is None:
                    return None
                cursor = nested_end
                continue
            if char == "{":
                expression_depth += 1
            elif char == "}":
                expression_depth -= 1
            cursor += 1
            continue
        if char == "\\":
            cursor += 2
            continue
        if char == "`":
            return cursor + 1
        if char == "$" and next_char == "{":
            expression_depth = 1
            cursor += 2
            continue
        cursor += 1
    return None

@functools.lru_cache(maxsize=8)
def mask_reference_declaration_evidence(text: str) -> str:
    masked = list(text)

    def mask_span(start: int, end: int) -> None:
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "

    cursor = 0
    while cursor < len(text):
        char = text[cursor]
        next_char = text[cursor + 1] if cursor + 1 < len(text) else ""
        if char == "/" and next_char == "/":
            line_end = text.find("\n", cursor + 2)
            cursor = len(text) if line_end < 0 else line_end
            continue
        if char == "/" and next_char == "*":
            comment_end = text.find("*/", cursor + 2)
            cursor = len(text) if comment_end < 0 else comment_end + 2
            continue
        if char == "#" and not javascript_private_member_marker(text, cursor):
            line_end = text.find("\n", cursor + 1)
            line_end = len(text) if line_end < 0 else line_end
            mask_span(cursor, line_end)
            cursor = line_end
            continue
        regex_end = javascript_regex_literal_end(text, cursor)
        if regex_end is not None:
            mask_span(cursor, regex_end)
            cursor = regex_end
            continue
        if char in {'"', "'"}:
            raw_start = (
                raw_double_quote_start(text, cursor)
                if char == '"'
                else None
            )
            if raw_start is not None:
                delimiter, content_start = raw_start
                raw_end = raw_double_quote_end(
                    text,
                    content_start,
                    len(delimiter),
                )
                cursor = len(text) if raw_end is None else raw_end
                continue
            marker = text[max(0, cursor - 2) : cursor]
            string_end = csharp_quoted_literal_end(
                text,
                cursor,
                verbatim=char == '"' and "@" in marker,
                interpolated=char == '"' and "$" in marker,
            )
            cursor = len(text) if string_end is None else string_end
            continue
        if char != "`":
            cursor += 1
            continue
        template_end = javascript_template_literal_end(text, cursor)
        template_end = len(text) if template_end is None else template_end
        mask_span(cursor, min(template_end, len(text)))
        cursor = template_end
    return mask_csharp_evidence_prefix("".join(masked))

@functools.lru_cache(maxsize=8)
def javascript_reference_spans(text: str) -> frozenset[tuple[int, int]]:
    return frozenset(
        (match.start(), match.end())
        for pattern in (
            SOURCE_CODE_REFERENCE_PATTERN,
            SOURCE_CODE_REFERENCE_ROOT_PATTERN,
            SOURCE_CODE_LIFECYCLE_REFERENCE_PATTERN,
        )
        for match in pattern.finditer(text)
    )

def javascript_comment_end(text: str, cursor: int) -> int | None:
    if text.startswith("//", cursor):
        newline = re.search(r"[\r\n\u2028\u2029]", text[cursor + 2 :])
        return len(text) if newline is None else cursor + 2 + newline.start()
    if text.startswith("/*", cursor):
        end = text.find("*/", cursor + 2)
        return len(text) if end < 0 else end + 2
    return None

def javascript_noncode_end(text: str, cursor: int) -> int | None:
    comment_end = javascript_comment_end(text, cursor)
    if comment_end is not None:
        return comment_end
    if text[cursor] in {'"', "'"}:
        return csharp_quoted_literal_end(text, cursor, verbatim=False, interpolated=False) or len(text)
    if text[cursor] == "`":
        return javascript_template_literal_end(text, cursor) or len(text)
    return javascript_regex_literal_end(text, cursor)

@functools.lru_cache(maxsize=8)
def javascript_binding_code(text: str) -> str:
    # Declarations in strings, comments, regexes or templates cannot establish
    # a source binding. Keep offsets so assignments still scan their raw bytes.
    masked = list(text)
    cursor = 0
    while cursor < len(text):
        end = javascript_noncode_end(text, cursor)
        if end is None:
            cursor += 1
            continue
        masked[cursor:end] = [char if char in "\r\n\u2028\u2029" else " " for char in text[cursor:end]]
        cursor = end
    return "".join(masked)

def typescript_ambient_type_tokens(text, start):
    tokens, stack = [], []
    cursor, limit = start, min(len(text), start + 8192)
    pairs = {"<": ">", "[": "]", "{": "}"}
    while cursor < limit:
        item = typescript_ambient_type_token(text, cursor, limit)
        if item is None:
            return None
        value, end = item
        if value is not None:
            tokens.append((value, cursor, end))
            if not typescript_ambient_token_balance(value, stack, pairs):
                return None
            if value == ";" and not stack:
                return tokens
        cursor = end
    return None


def typescript_ambient_type_token(text, cursor, limit):
    if text[cursor].isspace():
        return None, cursor + 1
    comment = javascript_comment_end(text, cursor)
    if comment is not None:
        return (None, comment) if comment <= limit else None
    if text[cursor] in {"'", '"'}:
        end = csharp_quoted_literal_end(text, cursor, verbatim=False, interpolated=False)
        return (text[cursor:end], end) if end is not None and end <= limit else None
    token = re.match(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*|[<>{}\[\]:;,?&|]", text[cursor:limit])
    return (token.group(), cursor + token.end()) if token is not None else None


def typescript_ambient_token_balance(value, stack, pairs):
    if value in pairs:
        stack.append(pairs[value])
        return len(stack) <= 32
    if value in pairs.values():
        return bool(stack) and stack.pop() == value
    return True


def typescript_type_reference_parse(tokens, cursor):
    result = typescript_type_reference_atom(tokens, cursor)
    if result is None:
        return None
    cursor, literal, members = result
    while cursor < len(tokens) and tokens[cursor][0] in {"|", "&"}:
        result = typescript_type_reference_atom(tokens, cursor + 1)
        if result is None:
            return None
        cursor, next_literal, next_members = result
        literal, members = literal or next_literal, members + next_members
    return cursor, literal, members


def typescript_type_reference_atom(tokens, cursor):
    if cursor >= len(tokens):
        return None
    value = tokens[cursor][0]
    if value == "readonly" and cursor + 1 < len(tokens) and tokens[cursor + 1][0] == "[":
        return typescript_type_reference_list(tokens, cursor + 2, "]")
    if value == "[":
        return typescript_type_reference_list(tokens, cursor + 1, "]")
    if value == "{":
        return typescript_type_reference_object(tokens, cursor + 1)
    return typescript_type_reference_named(tokens, cursor)


def typescript_type_reference_named(tokens, cursor):
    value = tokens[cursor][0]
    literal = value.startswith(("'", '"'))
    if not literal and re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", value) is None:
        return None
    cursor, members = cursor + 1, []
    if cursor < len(tokens) and tokens[cursor][0] == "<":
        result = typescript_type_reference_list(tokens, cursor + 1, ">")
        if result is None:
            return None
        cursor, child_literal, members = result
        literal = literal or child_literal
    while cursor + 1 < len(tokens) and [t[0] for t in tokens[cursor:cursor + 2]] == ["[", "]"]:
        cursor += 2
    return cursor, literal, members


def typescript_type_reference_list(tokens, cursor, closer):
    if cursor >= len(tokens) or (closer == ">" and tokens[cursor][0] == closer):
        return None
    literal, members = False, []
    while cursor < len(tokens) and tokens[cursor][0] != closer:
        result = typescript_type_reference_parse(tokens, cursor)
        if result is None:
            return None
        cursor, child_literal, child_members = result
        literal, members = literal or child_literal, members + child_members
        if cursor < len(tokens) and tokens[cursor][0] == ",":
            cursor += 1
        elif cursor >= len(tokens) or tokens[cursor][0] != closer:
            return None
    return (cursor + 1, literal, members) if cursor < len(tokens) else None


def typescript_type_reference_member(tokens, cursor):
    key, begin, _ = tokens[cursor]
    if not key.startswith(("'", '"')) and re.fullmatch(r"[A-Za-z_$][\w$]*", key) is None:
        return None
    cursor += 1
    if cursor < len(tokens) and tokens[cursor][0] == "?":
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor][0] != ":":
        return None
    end = tokens[cursor][2]
    result = typescript_type_reference_parse(tokens, cursor + 1)
    if result is None:
        return None
    cursor, literal, members = result
    if not literal and not key.startswith(("'", '"')):
        members = members + [(begin, end)]
    return cursor, literal, members


def typescript_type_reference_object(tokens, cursor):
    literal, members = False, []
    while cursor < len(tokens) and tokens[cursor][0] != "}":
        result = typescript_type_reference_member(tokens, cursor)
        if result is None:
            return None
        cursor, child_literal, child_members = result
        literal, members = literal or child_literal, members + child_members
        if cursor < len(tokens) and tokens[cursor][0] in {";", ","}:
            cursor += 1
        elif cursor >= len(tokens) or tokens[cursor][0] != "}":
            return None
    return (cursor + 1, literal, members) if cursor < len(tokens) else None


def typescript_ambient_member_reference_ranges(text):
    # Complete ambient owners have no initializers. Parse raw literal types and
    # buffer only literal-free member prefixes until the whole owner succeeds.
    code = javascript_binding_code(text)
    declaration = re.compile(r"(?m)^[ \t]*(?:export[ \t]+)?declare[ \t]+(?:const|let|var)[ \t]+"
                             r"[A-Za-z_$][\w$]*[ \t]*:[ \t]*")
    ranges = []
    for match in declaration.finditer(code):
        ranges.extend(typescript_ambient_declaration_members(text, code, match))
    return tuple(ranges)


def typescript_ambient_declaration_members(text, code, match):
    if text[match.start():match.end()] != match.group():
        return []
    tokens = typescript_ambient_type_tokens(text, match.end())
    result = typescript_type_reference_parse(tokens, 0) if tokens else None
    if result is None or result[0] != len(tokens) - 1 or tokens[-1][0] != ";" or tokens[-1][2] - match.start() > 8192:
        return []
    return [(start, end) for start, end in result[2] if text[start:end] == code[start:end]]


def typescript_type_reference_ranges(text: str, dialect: str | None) -> tuple[tuple[int, int], ...]:
    if dialect != "typescript":
        return ()
    # Only a complete type-name alias has no runtime value. Compare raw code so
    # comments, strings and templates cannot establish a declaration exemption.
    identifier = r"[A-Za-z_$][A-Za-z0-9_$]*"
    declaration = re.compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?type[ \t]+"
        r"(?P<assignment>" + identifier + r"[ \t]*=[ \t]*)"
        + identifier + r"(?:\." + identifier + r")*;[ \t]*\r?$"
    )
    code = javascript_binding_code(text)
    return typescript_object_member_reference_ranges(text, code) + tuple(
        match.span("assignment") for match in declaration.finditer(text)
        if match.end() - match.start() <= 8192
        and code[match.start() : match.end()] == match.group()
    )

def typescript_object_type_ranges(text: str, code: str) -> tuple[tuple[int, int], ...]:
    declaration = re.compile(
        r"(?m)^[ \t]*(?:export[ \t]+)?type[ \t]+[A-Za-z_$][\w$]*[ \t]*=[ \t]*"
        r"(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*[ \t]*&[ \t]*)?\{",
    )
    ranges = []
    for match in declaration.finditer(code):
        start = match.end() - 1
        end = javascript_balanced_binding_end(code, start, "{", "}")
        if end is not None and end - match.start() <= 8192 and re.match(r"[ \t]*;[ \t]*\r?$", code[end:], re.MULTILINE):
            ranges.append((start, end))
    return tuple(ranges)


def typescript_object_member_reference_ranges(text: str, code: str) -> tuple[tuple[int, int], ...]:
    # Only named type members inside a complete object type have no value.
    # Raw bytes must match masked code, so literal types keep their checks.
    name = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\[\])*"
    member = re.compile(r"(?P<assignment>[A-Za-z_$][\w$]*\??\s*:\s*)"
                        + name + r"(?:\s*\|\s*" + name + r")*\s*;")
    return tuple(
        match.span("assignment") for start, end in typescript_object_type_ranges(text, code)
        for match in member.finditer(text, start, end)
        if text[start:match.start()].rstrip().endswith(("{", ";"))
        and text[match.start():match.end()] == code[match.start():match.end()]
    )


def javascript_object_binding_names(binding: str) -> set[str] | None:
    identifier = r"[A-Za-z_$][A-Za-z0-9_$]*"
    field = identifier + r"(?:\s*:\s*" + identifier + r")?"
    pattern = r"\{\s*" + field + r"(?:\s*,\s*" + field + r")*\s*,?\s*\}"
    if len(binding) > 8192 or re.fullmatch(pattern, binding) is None:
        return None
    return {part.rsplit(":", 1)[-1].strip() for part in binding[1:-1].split(",") if part.strip()}

def javascript_destructured_initializer(
    text: str, code: str, start: int, end: int, root: str,
) -> str | None:
    names = javascript_object_binding_names(text[start:end])
    if names is None or root not in names:
        return None
    assignment = re.match(r"\s*=(?!=|>)", code[end:])
    if assignment is None:
        return None
    expression = fallback_expression(text[end + assignment.end():], typescript=True)
    if end + assignment.end() + len(expression) - start > 8192:
        return None
    return expression or None

def javascript_destructuring_declares_root(binding, code, root) -> bool:
    # Scope projection preserves public keys while renaming local bindings.
    # A key spelling is not a declaration of that original variable.
    names = javascript_object_binding_names(binding)
    return root in names if names is not None else re.search(
        r"(?<![\w$])" + re.escape(root) + r"(?![\w$])", code,
    ) is not None


@functools.lru_cache(maxsize=8)
def javascript_destructured_binding_initializers(text: str, code: str, root: str) -> list[str] | None:
    declarations = re.finditer(r"\b(?P<kind>const|let|var)\s*(?P<opening>[{\[])", code)
    values = []
    for declaration in declarations:
        start = declaration.end() - 1
        closer = {"{": "}", "[": "]"}[code[start]]
        end = javascript_balanced_binding_end(code, start, code[start], closer)
        if end is None:
            return None
        if not javascript_destructuring_declares_root(text[start:end], code[start:end], root):
            continue
        if declaration.group("kind") != "const":
            return None
        expression = javascript_destructured_initializer(text, code, start, end, root)
        if expression is None:
            return None
        # Keep the whole initializer in the existing origin graph. An unrelated
        # field, callback, alias or later write must not hide literal bytes.
        values.append(expression)
    return values

def javascript_scope_pairs(code: str) -> dict[int, int] | None:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    closers = {"(": ")", "[": "]", "{": "}"}
    for position, char in enumerate(code):
        if char in closers:
            stack.append(position)
        elif char in ")]}":
            if not javascript_scope_closes(code, stack, char):
                return None
            pairs[stack.pop()] = position + 1
    return None if stack else pairs


def javascript_scope_closes(code: str, stack: list[int], char: str) -> bool:
    return bool(stack) and {"(": ")", "[": "]", "{": "}"}[code[stack[-1]]] == char


def javascript_scope_owner(code: str, pairs: dict[int, int], position: int) -> int:
    return max((start for start, end in pairs.items()
                if code[start] == "{" and start < position < end), default=-1)


def javascript_parameter_bindings(code: str, start: int, end: int) -> list[tuple[int, str]] | None:
    values = []
    cursor = start
    for parameter in javascript_parameter_parts(code[start:end]):
        names = javascript_parameter_binding(code, cursor, parameter)
        if names is None:
            return None
        values.extend(names)
        cursor += len(parameter) + 1
    return values


def javascript_parameter_binding(code: str, cursor: int, parameter: str) -> list[tuple[int, str]] | None:
    if parameter.lstrip().startswith("{"):
        opening = cursor + len(parameter) - len(parameter.lstrip())
        closing = javascript_balanced_binding_end(code, opening, "{", "}")
        return javascript_pattern_bindings(code[opening:closing], opening) if closing is not None else None
    match = re.match(r"\s*(?:\.\.\.)?(?P<name>[A-Za-z_$][\w$]*)(?![\w$])", parameter)
    if match is None:
        return None if parameter.strip() else []
    return [(cursor + match.start("name"), match.group("name"))]


def javascript_parameter_parts(code: str) -> list[str]:
    parts = []
    depth = 0
    start = 0
    for position, char in enumerate(code):
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= int(javascript_binding_closer(code, position, char))
        elif char == "," and depth == 0:
            parts.append(code[start:position])
            start = position + 1
    return parts + [code[start:]]


def javascript_pattern_bindings(binding: str, start: int) -> list[tuple[int, str]] | None:
    if javascript_object_binding_names(binding) is None:
        # Object-rest syntax establishes lexical names only. It does not prove
        # the resulting carrier's values or permit its mutable escape.
        fields = binding[1:-1].split(',') if binding.startswith('{') and binding.endswith('}') else []
        if not fields or any(not re.fullmatch(r'\s*(?:[A-Za-z_$][\w$]*(?:\s*:\s*[A-Za-z_$][\w$]*)?|\.\.\.[A-Za-z_$][\w$]*)\s*', field) for field in fields):
            return None
        if any('...' in field for field in fields[:-1]):
            return None
    values = []
    cursor = start + 1
    for field in binding[1:-1].split(","):
        name = re.search(r"[A-Za-z_$][\w$]*\s*$", field)
        if name is not None:
            values.append((cursor + name.start(), name.group().strip()))
        cursor += len(field) + 1
    return values



def javascript_declared_function_scope(code, pairs, declaration):
    # Generic type parameters are not invocation arguments. Reuse the bounded
    # type owner so formal value parameters keep their lexical declarations.
    opening = javascript_local_parameter_start(code, declaration.end())
    if opening is None or code[opening:opening + 1] != "(":
        return None
    return javascript_named_function_scope(code, pairs, opening)


def javascript_named_function_bindings(code: str, pairs: dict[int, int]) -> dict[int, tuple[int, str]] | None:
    bindings: dict[int, tuple[int, str]] = {}
    declarations = re.finditer(r"\bfunction(?![\w$])\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)?", code)
    for declaration in declarations:
        parts = javascript_declared_function_scope(code, pairs, declaration)
        if parts is None:
            return None
        body, parameters = parts
        bindings.update((position, (body, name)) for position, name in parameters)
        if declaration.group("name") is not None:
            position = declaration.start("name")
            bindings[position] = (javascript_scope_owner(code, pairs, position), declaration.group("name"))
    return bindings

def javascript_named_function_scope(code: str, pairs: dict[int, int], start: int) -> tuple[int, list[tuple[int, str]]] | None:
    end = pairs.get(start)
    body = javascript_function_body_start(code, end) if end is not None else None
    if body is None or body not in pairs:
        return None
    parameters = javascript_parameter_bindings(code, start + 1, end - 1)
    return (body, parameters) if parameters is not None else None


def javascript_arrow_parameter_bindings(code: str, pairs: dict[int, int]) -> dict[int, tuple[int, str]] | None:
    bindings: dict[int, tuple[int, str]] = {}
    endings = {end: start for start, end in pairs.items() if code[start] == "("}
    for arrow in re.finditer(r"=>\s*\{", code):
        body = arrow.end() - 1
        parameters = javascript_arrow_parameters(code, endings, arrow.start())
        if parameters is None:
            return None
        bindings.update((position, (body, name)) for position, name in parameters)
    return bindings


def javascript_arrow_parameters(code: str, endings: dict[int, int], end: int) -> list[tuple[int, str]] | None:
    prefix = code[:end].rstrip()
    if prefix.endswith(")"):
        return javascript_parenthesized_parameters(code, endings, len(prefix))
    closing = javascript_typed_arrow_parameter_end(code, endings, end)
    if closing is not None:
        return javascript_parenthesized_parameters(code, endings, closing)
    parameter = re.search(r"(?P<name>[A-Za-z_$][\w$]*)$", prefix)
    return [(parameter.start(), parameter.group())] if parameter is not None else None


def javascript_typed_arrow_parameter_end(code: str, endings: dict[int, int], end: int) -> int | None:
    return max((closing for closing in endings
                if closing < end and re.match(r"\s*:", code[closing:end])), default=None)


def javascript_parenthesized_parameters(code: str, endings: dict[int, int], closing: int) -> list[tuple[int, str]] | None:
    start = endings.get(closing)
    return javascript_parameter_bindings(code, start + 1, closing - 1) if start is not None else None


def javascript_method_parameter_bindings(code, pairs):
    bindings = {}
    for start, end in pairs.items():
        if code[start] != '(':
            continue
        name = re.search(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*$', code[:start])
        if name is None or name.group(1) in {'if', 'for', 'while', 'switch', 'catch', 'with', 'function'}:
            continue
        before = code[:name.start()].rstrip()
        if not before or before[-1] not in '{,;}':
            continue
        body = javascript_function_body_start(code, end)
        if body is None or body not in pairs:
            continue
        parameters = javascript_parameter_bindings(code, start + 1, end - 1)
        if parameters is None:
            return None
        bindings.update((position, (body, parameter)) for position, parameter in parameters)
    return bindings


def javascript_scope_declarations(code: str, pairs: dict[int, int], scopes: dict[int, int]) -> dict[int, tuple[int, str]] | None:
    named = javascript_named_function_bindings(code, pairs)
    arrows = javascript_arrow_parameter_bindings(code, pairs)
    methods = javascript_method_parameter_bindings(code, pairs)
    if named is None or arrows is None or methods is None:
        return None
    declarations = named | arrows | methods
    pattern = re.finditer(r"\b(?:const|let)\s+(?P<name>[A-Za-z_$][\w$]*|\{)", code)
    for declaration in pattern:
        names = javascript_lexical_declaration_bindings(code, pairs, scopes, declaration)
        if names is None:
            return None
        declarations.update(names)
    return declarations




def javascript_lexical_scope_owner(scopes, position):
    return max((start for start, end in scopes.items() if start < position < end), default=-1)


def javascript_loop_body_start(code, start):
    prefix = re.match(r'\s*', code[start:]).group()
    # Masked literals can hide the first body statement. A line boundary in
    # this prefix prevents borrowing the next statement as the loop body.
    if re.search(r'[\r\n\u2028\u2029]', prefix):
        return None
    return start + len(prefix)


def javascript_loop_expression_end(code, pairs, body):
    # Child delimiters own their internal lines and semicolons. An exposed
    # line or enclosing closer prevents extending the loop into another scope.
    end, terminator = next(((body + match.start() + 1, match.group())
                            for match in re.finditer(r'[;\r\n\u2028\u2029})\]]', code[body:])
                            if not javascript_code_iteration_enclosed(pairs, body, len(code), body + match.start())), (None, ''))
    return end if terminator == ';' else None


def javascript_loop_statement_end(code, pairs, start):
    body = javascript_loop_body_start(code, start)
    if body is None:
        return None
    if code[body:body + 1] == '{':
        return pairs.get(body)
    # Unsupported statements keep the complete unprojected origin graph.
    # Only a proved body lifetime can separate same-named loop bindings.
    if re.match(r'(?:if|for|while|switch|try|with|do)\b', code[body:]):
        return None
    return javascript_loop_expression_end(code, pairs, body)


def javascript_lexical_scopes(code, pairs):
    scopes = {start: end for start, end in pairs.items() if code[start] == '{'}
    for loop in re.finditer(r'\bfor\s*(?:await\s*)?\(', code):
        closing = pairs.get(loop.end() - 1)
        if closing is None:
            return None
        end = javascript_loop_statement_end(code, pairs, closing)
        if end is None:
            return None
        # The loop keyword owns header and body on one lexical lifetime. Balanced
        # delimiter pairs stay separate for expression and parameter parsing.
        scopes[loop.start()] = end
    return scopes


def javascript_declaration_context(code):
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return None, None, None
    scopes = javascript_lexical_scopes(code, pairs)
    if scopes is None:
        return pairs, None, None
    return pairs, scopes, javascript_scope_declarations(code, pairs, scopes)


def javascript_lexical_declaration_bindings(code: str, pairs: dict[int, int], scopes: dict[int, int], declaration: re.Match) -> dict[int, tuple[int, str]] | None:
    start = declaration.start("name")
    owner = javascript_lexical_scope_owner(scopes, start)
    if code[start] != "{":
        return {start: (owner, declaration.group("name"))}
    end = pairs.get(start)
    names = javascript_pattern_bindings(code[start:end], start) if end is not None else None
    return {position: (owner, name) for position, name in names} if names is not None else None


def javascript_visible_scope_name(code: str, scopes: dict[int, int], names: dict[int, str], position: int) -> str | None:
    owner = javascript_lexical_scope_owner(scopes, position)
    while owner not in names and owner != -1:
        owner = javascript_lexical_scope_owner(scopes, owner)
    return names.get(owner)


def javascript_graph_member_prefix(prefix) -> bool:
    # A spread operand is a lexical binding, while a property name is not.
    # Confusing these leaves same-name local values outside the origin graph.
    return prefix.endswith(".") and not prefix.endswith("...")


def javascript_graph_token_replacement(code: str, match: re.Match, name: str, declared: bool) -> str | None:
    prefix, suffix = code[:match.start()].rstrip(), code[match.end():].lstrip()
    if declared:
        return match.group() + ": " + name if javascript_graph_shorthand(prefix, suffix) else name
    # Only object keys skip lexical projection. A ternary value before its
    # colon must keep the scoped binding and every local credential origin.
    if javascript_graph_member_prefix(prefix) or javascript_initializer_object_key(code, match):
        return None
    if javascript_graph_shorthand(prefix, suffix):
        return match.group() + ": " + name
    return name


def javascript_graph_shorthand(prefix: str, suffix: str) -> bool:
    return prefix.endswith(("{", ",")) and suffix.startswith((",", "}"))


@functools.lru_cache(maxsize=8)
def javascript_scope_graph_replacements(text: str) -> tuple[tuple[int, int, str], ...] | None:
    code = javascript_binding_code(text)
    pairs, scopes, declarations = javascript_declaration_context(code)
    if declarations is None or "__guard_scope_" in code:
        return None
    return javascript_graph_replacements(code, scopes, declarations, javascript_scope_collision_names(code, declarations))


def javascript_scope_collision_names(code: str, declarations: dict[int, tuple[int, str]]) -> dict[str, dict[int, str]]:
    names: dict[str, dict[int, str]] = {}
    for owner, name in declarations.values():
        names.setdefault(name, {})[owner] = f"__guard_scope_{owner + 1}_{name}"
    # Var hoisting and unsupported declarations keep the old strict graph.
    # Only proven lexical collisions receive separate graph identities.
    excluded = set(re.findall(r"\bvar\s+([A-Za-z_$][\w$]*)", code))
    excluded.update(re.findall(r"\bfunction\s*\*?\s+([A-Za-z_$][\w$]*)", code))
    return {name: owners for name, owners in names.items() if len(owners) > 1 and name not in excluded}


def javascript_graph_replacements(code: str, scopes: dict[int, int], declarations, collisions) -> tuple[tuple[int, int, str], ...]:
    replacements = []
    for match in re.finditer(r"[A-Za-z_$][\w$]*", code):
        owners = collisions.get(match.group())
        if owners is None:
            continue
        replacement = javascript_scoped_token_replacement(code, scopes, declarations, owners, match)
        if replacement is not None:
            replacements.append((match.start(), match.end(), replacement))
    return tuple(replacements)


def javascript_scoped_token_replacement(code: str, scopes, declarations, owners, match: re.Match) -> str | None:
    declaration = declarations.get(match.start())
    name = owners[declaration[0]] if declaration is not None else javascript_visible_scope_name(code, scopes, owners, match.start())
    return javascript_graph_token_replacement(code, match, name, declaration is not None) if name is not None else None


def javascript_scoped_reference_graph(text: str, start: int, value: str) -> tuple[str, str]:
    replacements = javascript_scope_graph_replacements(text)
    if not replacements:
        return text, value
    root = re.match(r"[A-Za-z_$][\w$]*", value).group()
    selected = next((replacement for begin, _, replacement in replacements if begin == start), root)
    # This is an origin-graph projection only. Every original literal and suffix
    # remains in the outer scanner, and shorthand keys retain their public names.
    for begin, end, replacement in reversed(replacements):
        text = text[:begin] + replacement + text[end:]
    return text, selected + value[len(root):]



def javascript_parameter_declared(code, root) -> bool:
    # Actual function parameters establish references; spelling a name inside
    # a string, type member or call does not. Defaults retain the origin checks.
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return False
    named = javascript_named_function_bindings(code, pairs)
    arrows = javascript_arrow_parameter_bindings(code, pairs)
    return named is not None and arrows is not None and any(
        name == root for _, name in (named | arrows).values()
    )


def declared_javascript_secret_reference(text: str, start: int, value: str) -> bool:
    reference = re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, value)
    if reference is None:
        return False
    code = javascript_binding_code(text)
    root = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", value).group()
    if code[start : start + len(root)] != root:
        return False
    source_text, source_value = text, value
    text, value = javascript_scoped_reference_graph(text, start, value)
    code = javascript_binding_code(text)
    owned = javascript_code_symbol_expression(text, value)
    if owned is None:
        owned = javascript_code_parameter_occurrence(source_text, start, source_value)
    if owned is not None:
        return owned
    root = re.match(r"[A-Za-z_$][\w$]*", value).group()
    declared = re.search(r"\b(?:const|let|var)\s+" + re.escape(root) + r"(?![\w$])", code)
    if declared is None and not javascript_parameter_declared(code, root) and not javascript_destructured_binding_initializers(text, code, root):
        return False
    return not javascript_binding_literal_risk(text, code, value)




def javascript_expression_has_literal(expression: str) -> bool:
    cursor = 0
    while cursor < len(expression):
        if expression[cursor] in {'"', "'", "`"}:
            return True
        end = javascript_noncode_end(expression, cursor)
        # Comments carry no value. Regex patterns remain literal origins so
        # masking them cannot exempt credential bytes produced by .source.
        if end is not None and javascript_comment_end(expression, cursor) is None:
            return True
        cursor = cursor + 1 if end is None else end
    # Numeric source bytes can construct credentials without a quote delimiter.
    return re.search(r"(?<![\w$])(?:[0-9]|\.[0-9])", javascript_binding_code(expression)) is not None

def javascript_initializer_annotation_complete(assignment) -> bool:
    if ":" not in assignment:
        return True
    # An annotation cannot cross a parameter/body boundary to borrow a later
    # assignment. Balanced inline types keep their existing initializer scan.
    annotation = assignment.split(":", 1)[1].rsplit("=", 1)[0]
    return javascript_scope_pairs(annotation) is not None


def javascript_binding_assignment_end(code, cursor):
    cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
    if code[cursor:cursor + 1] == ':':
        cursor += 1
        begin, needs_type = cursor, True
        while cursor < len(code) and cursor - begin <= 8192:
            cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
            if code[cursor:cursor + 1] == '=':
                break
            if cursor == len(code):
                return None
            end = javascript_type_token_end(code, cursor)
            if end is None:
                return None
            needs_type = code[cursor] in '|&'
            cursor = end
        if needs_type:
            return None
    assignment = re.match(r'(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)', code[cursor:])
    return cursor + assignment.end() if assignment else None


@functools.lru_cache(maxsize=16)
def javascript_binding_annotation_ranges(code):
    pairs, scopes, declarations = javascript_declaration_context(code)
    annotations = []
    for position, (_, bound_name) in (declarations or {}).items():
        tail = position + len(bound_name)
        if code[tail:].lstrip().startswith(':'):
            end = javascript_binding_assignment_end(code, tail)
            if end is not None:
                annotations.append((tail, end))
    return tuple(annotations)

def javascript_binding_initializers(text: str, code: str, root: str | None = None, *, preserve_callable: bool = False) -> list[str]:
    # Balanced annotations establish the initializer boundary only. Their type
    # names do not establish primitive contents or remove runtime literal bytes.
    name = re.escape(root) if root is not None else r'[A-Za-z_$][A-Za-z0-9_$]*'
    values = []
    annotations = javascript_binding_annotation_ranges(code)
    for match in re.finditer(r'(?<![\w$.])' + name + r'(?![\w$])', code):
        if any(begin <= match.start() < end for begin, end in annotations):
            continue
        end = javascript_binding_assignment_end(code, match.end())
        if end is None:
            continue
        expression = fallback_expression(text[end:], typescript=True)
        origins = None if preserve_callable else javascript_arrow_return_origins(expression)
        values.extend([expression] if origins is None else origins)
    return values




def javascript_arrow_return_origins(expression: str) -> list[str] | None:
    code = javascript_binding_code(expression).strip()
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return None
    for arrow in re.finditer(r"=>\s*\{", code):
        body = arrow.end() - 1
        if pairs.get(body) != len(code):
            continue
        # Callable values carry their returned data, as named local functions
        # already do. Diagnostics in a void callback are not its return value.
        raw = expression.strip()
        return javascript_local_return_origins(raw[:arrow.start()], raw[body + 1:-1])
    return None

def javascript_balanced_binding_end(code: str, start: int, opener: str, closer: str) -> int | None:
    depth = 0
    for cursor in range(start, len(code)):
        if code[cursor] == opener:
            depth += 1
        if javascript_binding_closer(code, cursor, closer):
            depth -= 1
        if depth == 0:
            return cursor + 1
    return None


def javascript_binding_closer(code: str, cursor: int, closer: str) -> bool:
    return code[cursor] == closer and not (closer == ">" and code[cursor - 1:cursor] == "=")

def javascript_type_token_end(code: str, cursor: int) -> int | None:
    word = re.match(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", code[cursor:])
    if word is not None:
        return cursor + word.end()
    pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
    if code[cursor] in pairs:
        return javascript_balanced_binding_end(code, cursor, code[cursor], pairs[code[cursor]])
    if code[cursor] in "|&":
        return cursor + 1
    return None

def javascript_typed_function_body_start(code: str, cursor: int) -> int | None:
    needs_type = True
    while cursor < len(code):
        cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
        if cursor == len(code):
            return None
        if code[cursor] == "{" and not needs_type:
            return cursor
        end = javascript_type_token_end(code, cursor)
        if end is None:
            return None
        needs_type = code[cursor] in "|&"
        cursor = end
    return None

def javascript_function_body_start(code: str, end: int) -> int | None:
    header = re.match(r"\s*(?P<typed>:\s*)?", code[end:])
    cursor = end + header.end()
    if header.group("typed") is not None:
        return javascript_typed_function_body_start(code, cursor)
    return cursor if code[cursor:cursor + 1] == "{" else None

def javascript_local_return_origins(parameters: str, body: str) -> list[str]:
    code = javascript_binding_code(body)
    returns = re.finditer(r"(?<![\w$?.])return(?![\w$])", code)
    expressions = [fallback_expression(body[match.end():], typescript=True) for match in returns]
    # Named defaults are followed by the returned binding. Indexed arguments can
    # select any parameter default, so keep every default for that access form.
    if re.search(r"(?<![\w$?.])arguments(?![\w$])", code):
        expressions.extend(javascript_binding_initializers(parameters, javascript_binding_code(parameters)))
    return expressions

def javascript_initializer_value_code(expression: str) -> str:
    code = javascript_binding_code(javascript_inline_type_text(expression))
    # Named TypeScript assertions describe types, not credential value origins.
    # Keep the asserted expression and every runtime member in the origin graph.
    code = re.sub(
        r"(?<![\w$?.])(?:as|satisfies)\s+[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\s*\|\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)*",
        lambda match: " " * len(match.group()),
        code,
    )
    return javascript_grouped_member_code(code)


def javascript_grouped_member_code(code):
    # A plain reference group has the same value as its inner reference.
    # Normalize inner groups first so selected members remain visible at
    # every nesting level; unresolved grouped writes still refuse below.
    reference = r"[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*"
    pattern = re.compile(r"\([ \t]*(?P<root>" + reference + r")[ \t]*\)(?P<members>(?:[ \t]*(?:\?\.|\.)[ \t]*[A-Za-z_$][\w$]*)*)")
    for _ in range(MAX_JAVASCRIPT_INITIALIZER_ROOTS):
        normalized = pattern.sub(lambda match: javascript_grouped_member_replacement(code, match), code)
        if normalized == code:
            return code
        code = normalized
    return code

def javascript_grouped_member_replacement(code, match):
    prefix = code[:match.start()].rstrip()
    callee = re.search(r"[A-Za-z_$][\w$]*$", prefix)
    if prefix.endswith((")", "]")) or (callee is not None and callee.group() not in {"typeof", "return", "throw", "void", "delete", "await"}):
        return match.group()
    # Typed callees and function headers own their parameter parentheses.
    # Keep them before group normalization so invocation/return scans survive.
    if prefix.endswith('>'):
        typed = re.finditer(r'[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*\s*(?:\?\.\s*)?(?P<type><)', prefix)
        for candidate in typed:
            suffix = javascript_code_call_suffix(code, candidate.start('type'))
            if suffix is not None and suffix[0] and suffix[1][1] == len(prefix):
                return match.group()
    offset = match.start("root") - match.start()
    selected = match.group("root") + re.sub(r"[ \t]", "", match.group("members"))
    return " " * offset + selected + " " * (len(match.group()) - offset - len(selected))

def javascript_selected_object_field(field: str, member: str) -> str | None:
    key = re.match(r"\s*(?:([A-Za-z_$][\w$]*)|[\"']([A-Za-z_$][\w$]*)[\"'])\s*:", field)
    if key is not None:
        return javascript_selected_named_field(field, key, member)
    shorthand = field.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", shorthand):
        return shorthand if shorthand == member else ""
    return None


def javascript_selected_named_field(field, key, member):
    name = key.group(1) or key.group(2)
    # This literal changes the inherited member origin, not sibling data.
    if name == "__proto__":
        return None
    return field[key.end():] if name == member else ""

def javascript_selected_object_origins(expression: str, selection: list[str]) -> list[str] | None:
    values = []
    for field in split_top_level_call_arguments(expression.strip()[1:-1]):
        origins = javascript_selected_field_origins(field, selection)
        if origins is None:
            return None
        values.extend(origins)
    # Absence of an own field does not prove an inherited value harmless.
    return values or None

def javascript_selected_field_origins(field, selection):
    field = field.strip()
    if not field:
        return []
    if field.startswith("..."):
        return javascript_selected_value_origins(field[3:], selection)
    value = javascript_selected_object_field(field, selection[0])
    if value is None:
        return None
    return javascript_selected_field_value_origins(value, selection)


def javascript_selected_field_value_origins(value, selection):
    # Selection must retain the field kind for the existing exact fixture
    # contract. Arbitrary values and constructed suffixes keep their origins.
    if not value:
        return []
    if len(selection) == 1 and javascript_selected_fixture_value(value, selection[0]):
        return ["null"]
    return javascript_selected_value_origins(value, selection[1:])


def javascript_selected_fixture_value(value, field):
    literal = re.fullmatch(r"\s*(?P<q>[\"'])(?P<value>[^\"'\r\n]*)(?P=q)\s*", value)
    return literal is not None and synthetic_secret_fixture(literal.group("value"), field)

def javascript_selected_collection_origins(expression, code, selection):
    indexed = javascript_selected_index_reference(code, selection)
    if indexed is not None:
        return indexed
    mapped = javascript_selected_map_parts(expression, code)
    return javascript_selected_map_origins(mapped, selection) if mapped is not None else javascript_selected_call_origins(expression, code, selection)


def javascript_selected_index_reference(code, selection):
    match = re.fullmatch(r"(?P<root>" + URI_CREDENTIAL_REFERENCE_TEXT + r")\s*\[\s*(?P<index>[^\[\]]{1,256})\s*\]", code)
    if match is None:
        return None
    index = match.group("index").strip()
    length = re.escape(match.group("root")) + r"\.length(?:\s*[-+]\s*[01])?"
    if re.fullmatch(r"[0-9]{1,4}|" + length, index) is None:
        return None
    return [match.group("root") + "." + ".".join(selection)]


def javascript_selected_map_parts(expression, code):
    match = re.match(r"(?P<root>" + URI_CREDENTIAL_REFERENCE_TEXT + r")\s*\.map\s*\(", code)
    if match is None:
        return None
    opening = match.end() - 1
    end = javascript_balanced_binding_end(code, opening, "(", ")")
    if end is None or not javascript_reference_filter_suffix(expression[end:]):
        return None
    arrow = javascript_selected_map_arrow(expression[opening + 1:end - 1])
    return (match.group("root"), arrow) if arrow is not None else None


def javascript_selected_map_arrow(expression):
    arrow = re.match(r"\s*\(\s*(?P<value>[A-Za-z_$][\w$]*)(?:\s*,\s*[A-Za-z_$][\w$]*)?\s*\)\s*=>", expression)
    return (arrow.group("value"), expression[arrow.end():].strip()) if arrow is not None else None


def javascript_selected_map_origins(parts, selection):
    receiver, (parameter, body) = parts
    origins = javascript_selected_value_origins(body, selection)
    if origins is None:
        return None
    # Selected callback output carries its input origin. Literal returns remain
    # in this list, so mapping and filtering cannot hide credential construction.
    return [receiver] + [re.sub(r"(?<![\w$.])" + re.escape(parameter) + r"(?![\w$])", receiver, value) for value in origins]


def javascript_reference_filter_suffix(suffix):
    if not suffix.strip():
        return True
    match = re.fullmatch(r"\s*\.filter\s*\(([\s\S]*)\)\s*", suffix)
    if match is None:
        return False
    expression = match.group(1)
    arrow = re.match(r"\s*\(\s*\{\s*[A-Za-z_$][\w$]*(?:\s*:\s*[A-Za-z_$][\w$]*)?\s*\}\s*\)\s*=>", expression)
    return arrow is not None and javascript_reference_filter_predicate(expression[arrow.end():])


def javascript_reference_filter_predicate(expression):
    normalized = javascript_length_comparison_text(javascript_typeof_selector_text(expression))
    return not javascript_expression_has_literal(normalized) and re.fullmatch(r"[A-Za-z0-9_$\s.!=<>|&()]+", normalized) is not None and "=" not in re.sub(r"[!=<>]=+", "", normalized)


def javascript_length_comparison_text(expression):
    pattern = re.compile(r"(?P<ref>" + URI_CREDENTIAL_REFERENCE_TEXT + r"(?:\(\s*\))?\.length)\s*(?:[<>]=?|[!=]==?)\s*[01](?![\w.])")
    code = javascript_binding_code(expression)
    matches = [m for m in pattern.finditer(expression) if code[m.start('ref'):m.end('ref')] == m.group('ref')]
    return mask_ranges(expression, tuple((m.end('ref'), m.end()) for m in matches))



def javascript_selected_call_origins(expression: str, code: str, selection: list[str]) -> list[str] | None:
    call = re.match(r"(?:await\s+)?(?P<callee>" + URI_CREDENTIAL_REFERENCE_TEXT + r")\s*\(", code)
    if call is None:
        return None
    opening = call.end() - 1
    end = javascript_balanced_binding_end(code, opening, "(", ")")
    if end is None or code[end:].strip():
        return None
    # Carry the selected result member to the local callee. Arguments remain
    # independent value inputs, so their literal/alias checks still run.
    return [call.group("callee").replace("?.", ".") + "." + ".".join(selection)] + \
        [argument for argument in split_top_level_call_arguments(expression[opening + 1:end - 1]) if argument.strip()]

def javascript_selected_value_origins(expression: str, selection: list[str], depth: int = 0) -> list[str] | None:
    if depth >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    if not selection:
        return [expression]
    expression = expression.strip()
    code = javascript_initializer_value_code(expression).strip()
    if code.startswith("(") and javascript_balanced_binding_end(code, 0, "(", ")") == len(code):
        return javascript_selected_value_origins(expression[1:-1], selection, depth + 1)
    nullable = javascript_selected_nullable_origins(expression, selection, depth)
    return nullable if nullable is not None else javascript_selected_structured_origins(expression, code, selection)


def javascript_selected_structured_origins(expression, code, selection) -> list[str] | None:
    if code.startswith("{") and javascript_balanced_binding_end(code, 0, "{", "}") == len(code):
        return javascript_selected_object_origins(expression[:len(code)], selection)
    indexed = javascript_selected_index_reference(code, selection)
    if indexed is not None:
        return indexed
    if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, code):
        return [code.replace("?.", ".") + "." + ".".join(selection)]
    conditional = javascript_conditional_value_origins(expression, selection)
    return conditional if conditional is not None else javascript_selected_collection_origins(expression, code, selection)



def javascript_conditional_delimiters(code: str) -> tuple[int, int] | None:
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return None
    question = None
    nested = 0
    for cursor, marker in javascript_top_level_conditional_markers(code, pairs):
        if marker == "?":
            question = javascript_conditional_question(question, cursor)
            nested += 1
        elif marker == ":":
            nested -= 1
            result = javascript_conditional_pair(question, cursor, nested)
            if result is not None:
                return result
    return None


def javascript_conditional_question(question: int | None, cursor: int) -> int:
    return cursor if question is None else question


def javascript_conditional_pair(question: int | None, colon: int, nested: int) -> tuple[int, int] | None:
    return (question, colon) if nested == 0 and question is not None else None


def javascript_top_level_conditional_markers(code: str, pairs: dict[int, int]):
    cursor = 0
    while cursor < len(code):
        if cursor in pairs:
            cursor = pairs[cursor]
            continue
        marker = javascript_conditional_marker(code, cursor)
        if marker is not None:
            yield cursor, marker
        cursor += 1


def javascript_conditional_marker(code: str, cursor: int) -> str | None:
    if code[cursor] == "?" and code[cursor + 1:cursor + 2] not in {"?", "."} and code[cursor - 1:cursor] != "?":
        return "?"
    return ":" if code[cursor] == ":" else None


def javascript_selected_numeric_comparison(condition):
    # A comparison returns Boolean, so its operand cannot become selected bytes.
    # Only closed numeric comparisons qualify; literal value branches stay intact.
    reference = URI_CREDENTIAL_REFERENCE_TEXT
    return re.fullmatch(r'\s*' + reference + r'\s*(?:===|!==|==|!=|<=|>=|<|>)\s*[+-]?[0-9]+(?:\.[0-9]+)?\s*', condition) is not None


def javascript_conditional_value_origins(expression: str, selection: list[str]) -> list[str] | None:
    expression = javascript_inline_type_text(expression)
    code = javascript_binding_code(expression)
    delimiters = javascript_conditional_delimiters(code)
    if delimiters is None:
        return None
    question, colon = delimiters
    condition = expression[:question].strip()
    condition = "false" if javascript_selected_numeric_comparison(condition) else javascript_length_comparison_text(javascript_metadata_comparison_text(javascript_typeof_selector_text(condition)))
    if javascript_expression_has_literal(condition):
        return None
    values = [condition]
    for branch in (expression[question + 1:colon], expression[colon + 1:]):
        origins = [branch.strip()] if branch.strip() in {"undefined", "null"} else javascript_selected_value_origins(branch, selection)
        if origins is None:
            return None
        values.extend(origins)
    return values

def javascript_binding_value_origins(text: str, code: str, reference: str) -> list[str] | None:
    parts = re.findall(r"[A-Za-z_$][\w$]*|[0-9]+", reference)
    root, selection = parts[0], parts[1:]
    if len(parts) > MAX_JAVASCRIPT_INITIALIZER_ROOTS or (
        javascript_selected_mutation_risk(text, code, parts) if selection
        else javascript_unsupported_binding_origin(text, code, root)
    ):
        return None
    return javascript_binding_selected_origins(text, code, root, selection, parts)


def javascript_binding_selected_origins(text, code, root, selection, parts) -> list[str] | None:
    if root == "undefined" and javascript_unshadowed_undefined(code):
        return []
    local_origins = javascript_local_function_origins(text, code, root)
    if local_origins is None:
        return None
    values = javascript_binding_selected_assignments(text, code, parts)
    if values is None:
        return None
    selected = javascript_selected_expressions(local_origins, selection)
    if selected is None:
        return None
    return values + selected


@functools.lru_cache(maxsize=8)
def javascript_unshadowed_undefined(code: str) -> bool:
    pairs, scopes, declarations = javascript_declaration_context(code)
    if declarations is None or re.search(r"\bvar\s+undefined(?![\w$])", code):
        return False
    # The builtin absence value has no initializer. Type unions such as
    # `value: Type | undefined = ...` do not assign to this identifier.
    return not any(name == "undefined" for _, name in declarations.values())

def javascript_alias_assignments(code):
    # Declaration and later assignments establish the same alias relation.
    # Keep compact ternary roots visible and retain the existing operators.
    return re.finditer(
        r"(?<![\w$.])(?P<alias>[A-Za-z_$][\w$]*)\s*(?::[^=;\r\n]+)?"
        + r"(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)", code,
    )


@functools.lru_cache(maxsize=8)
def javascript_binding_alias_edges(text: str, code: str) -> dict[str, set[str]]:
    assignments = javascript_alias_assignments(code)
    edges: dict[str, set[str]] = {}
    for assignment in assignments:
        expression = fallback_expression(text[assignment.end():], typescript=True)
        value = javascript_initializer_value_code(expression).strip()
        # Quoted member keys describe an alias path, not credential bytes.
        # Keep them for mutation refusal while type assertions stay masked.
        if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, value) or re.fullmatch(
            URI_CREDENTIAL_REFERENCE_TEXT, expression.strip(),
        ):
            source = re.match(r"[A-Za-z_$][\w$]*", value).group()
            edges.setdefault(source, set()).add(assignment.group("alias"))
    return edges

def javascript_expression_uses_root(expression: str, root: str) -> bool:
    if root not in expression:
        return False
    code = javascript_initializer_value_code(expression)
    pairs, scopes, declarations = javascript_declaration_context(code)
    if declarations is None:
        return True
    owned = [(position, owner) for position, (owner, name) in declarations.items() if name == root]
    references = re.finditer(
        r"(?<![\w$.])(?:[.]{3})?(?P<reference>" + re.escape(root) + r"(?![\w$])"
        r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)", code,
    )
    for reference in references:
        # Parameters created by an enclosing method are not captured outer inputs.
        # Free references and unresolved scopes still carry the mutable root.
        if any(reference.start() == position or owner < reference.start() < scopes.get(owner, -1)
               for position, owner in owned):
            continue
        if not javascript_initializer_object_key(code, reference) and (
            reference.group('reference') != root or re.match(r'\s*\(', code[reference.end():]) is None
        ):
            return True
    return False




def javascript_possible_destructured_alias_names(
    binding: str, expression: str, kind: str, span: int,
) -> set[str] | None:
    if kind not in {"const", "let"} or span > 8192:
        return None
    # Calls and spreads may return an input object. Track their simple output
    # bindings as possible aliases; the origin graph still scans every input.
    return javascript_object_binding_names(binding)


def javascript_destructured_aliases(text: str, code: str, root: str) -> set[str] | None:
    declarations = re.finditer(r"\b(?P<kind>const|let|var)\s*(?P<opening>[{\[])", code)
    aliases: set[str] = set()
    for declaration in declarations:
        start = declaration.end() - 1
        closer = {"{": "}", "[": "]"}[code[start]]
        end = javascript_balanced_binding_end(code, start, code[start], closer)
        if end is None:
            return None
        assignment = re.match(r"\s*=(?!=|>)", code[end:])
        if assignment is None:
            continue
        expression = fallback_expression(text[end + assignment.end():], typescript=True)
        if not javascript_expression_uses_root(expression, root):
            continue
        names = javascript_possible_destructured_alias_names(
            text[start:end], expression, declaration.group("kind"),
            end + assignment.end() + len(expression) - start,
        )
        if names is None:
            return None
        aliases.update(names)
    return aliases


def javascript_binding_alias_roots(text: str, code: str, root: str) -> set[str] | None:
    edges = javascript_binding_alias_edges(text, code)
    aliases = {root}
    pending = [root]
    while pending:
        source = pending.pop()
        # Destructuring can expose the same mutable member through another name.
        # Apply the existing write checks and root limit to every proven alias.
        destructured = javascript_destructured_aliases(text, code, source)
        if destructured is None:
            return None
        for alias in edges.get(source, set()) | destructured:
            if javascript_ignorable_alias(text, code, alias, edges, aliases):
                continue
            if len(aliases) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
                return None
            aliases.add(alias)
            pending.append(alias)
    return aliases

def javascript_ignorable_alias(text, code, alias, edges, aliases) -> bool:
    return alias in aliases or (alias not in edges
        and javascript_destructured_aliases(text, code, alias) == set()
        and not javascript_alias_mutation_risk(code, alias, ""))


def javascript_member_write_expressions(text, code, alias) -> list[str] | None:
    pairs = javascript_scope_pairs(code)
    values = []
    references = re.finditer(r"(?<![\w$.])" + re.escape(alias) + r"(?![\w$])", code)
    for reference in references:
        value = javascript_member_write_expression(text, code, reference.end(), pairs)
        if value is None:
            return None
        values.extend(value)
    return values

def javascript_member_write_expression(text, code, start: int, pairs) -> list[str] | None:
    members = javascript_mutation_members(code, start)
    if members is None:
        return None
    end, computed = members
    if javascript_unresolved_grouped_write(code, pairs, end):
        return None
    assignment = re.match(r"\s*(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)", code[end:])
    if end == start or assignment is None:
        return []
    if computed:
        return None
    return [fallback_expression(text[end + assignment.end():], typescript=True)]


def javascript_mutation_alias_writes(text, code, root: str) -> list[str] | None:
    aliases = javascript_binding_alias_roots(text, code, root)
    if aliases is None or any(javascript_object_mutation_risk(code, alias) for alias in aliases):
        return None
    return javascript_alias_write_values(text, code, aliases)


def javascript_alias_write_values(text, code, aliases) -> list[str] | None:
    values = []
    for alias in aliases:
        writes = javascript_member_write_expressions(text, code, alias)
        if writes is None:
            return None
        values.extend(writes)
    return values


def javascript_mutation_origin_expressions(text, code, root: str) -> list[str] | None:
    # This scan proves literal absence in a write value, not binding immutability.
    # Include all initializers and member writes, including simple let copies.
    # A local class can return bytes through a method or getter. Its origin
    # is unresolved here, so a write cannot claim literal absence from it.
    if re.search(r"\bclass\s+" + re.escape(root) + r"(?![\w$])", code):
        return None
    writes = javascript_mutation_alias_writes(text, code, root)
    returned = javascript_local_function_origins(text, code, root)
    if writes is None or returned is None:
        return None
    values = javascript_binding_initializers(text, code, root) + returned + writes
    return javascript_mutation_destructured_inputs(text, code, root, values)


def javascript_mutation_destructured_inputs(text, code, root, values) -> list[str] | None:
    declarations = re.finditer(r"\b(?P<kind>const|let|var)\s*(?P<opening>[{\[])", code)
    for declaration in declarations:
        start = declaration.end() - 1
        end = javascript_balanced_binding_end(code, start, code[start], {"{": "}", "[": "]"}[code[start]])
        if end is None:
            return None
        if not re.search(r"(?<![\w$])" + re.escape(root) + r"(?![\w$])", code[start:end]):
            continue
        value = javascript_destructured_initializer(text, code, start, end, root)
        if declaration.group("kind") == "var" or value is None:
            return None
        values.append(value)
    return values


def javascript_mutation_value_literal_risk(text, code, expressions) -> bool:
    pending = javascript_binding_proven_references(text, code, expressions)
    checked = set()
    while pending:
        root = pending.pop()
        if root in checked:
            continue
        if len(checked) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
            return True
        values = javascript_mutation_origin_expressions(text, code, root.split(".")[0])
        links = javascript_binding_proven_references(text, code, values) if values is not None else None
        if links is None:
            return True
        checked.add(root)
        pending.update(links - checked)
    return pending is None


def javascript_mutation_members(code: str, cursor: int) -> tuple[int, bool] | None:
    computed = False
    # Computed keys can contain nested brackets and statement bodies. Balance
    # the masked code so a semicolon cannot hide the following assignment.
    while member := re.match(r"\s*(?:\.\s*[A-Za-z_$][\w$]*|(?P<computed>\[))", code[cursor:]):
        cursor += member.end()
        if member.group("computed") is not None:
            end = javascript_balanced_binding_end(code, cursor - 1, "[", "]")
            if end is None:
                return None
            cursor = end
            computed = True
    return cursor, computed

def javascript_alias_write_risk(code: str, start: int, alias: str, original: str) -> bool:
    members = javascript_mutation_members(code, start)
    if members is None:
        return True
    end, computed = members
    if end == start:
        return False
    if alias == original and not computed:
        return False
    return re.match(r"\s*(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)", code[end:]) is not None

def javascript_object_mutation_risk(code: str, alias: str) -> bool:
    operations = re.finditer(r"(?<![\w$.])(?:Object|Reflect)(?![\w$])", code)
    for operation in operations:
        members = javascript_mutation_members(code, operation.end())
        if members is None:
            return True
        end, _ = members
        if end == operation.end():
            continue
        if re.match(r"\s*\(\s*" + re.escape(alias) + r"(?![\w$])", code[end:]):
            return True
    return False

def javascript_alias_mutation_risk(code: str, alias: str, original: str) -> bool:
    references = re.finditer(r"(?<![\w$.])" + re.escape(alias) + r"(?![\w$])", code)
    # An object operation or a write through another binding can change the
    # returned member without changing its initializer. Refuse unproved origins.
    return any(javascript_alias_write_risk(code, reference.end(), alias, original)
               for reference in references) or javascript_object_mutation_risk(code, alias)

def javascript_binding_mutation_risk(text: str, code: str, root: str) -> bool:
    writes = javascript_mutation_alias_writes(text, code, root)
    return writes is None or javascript_mutation_value_literal_risk(text, code, writes)

def javascript_unsupported_binding_origin(text: str, code: str, root: str) -> bool:
    return javascript_destructured_binding_initializers(text, code, root) is None \
        or javascript_binding_mutation_risk(text, code, root)

def javascript_binding_selected_assignments(text: str, code: str, parts: list[str]) -> list[str] | None:
    destructured = javascript_destructured_binding_initializers(text, code, parts[0])
    if destructured is None:
        return None
    values = list(destructured)
    for width in range(1, len(parts) + 1):
        reference = ".".join(parts[:width])
        for expression in javascript_binding_initializers(text, code, reference):
            origins = javascript_selected_value_origins(expression, parts[width:])
            if origins is None:
                return None
            values.extend(origins)
    return values

def javascript_selected_expressions(expressions: list[str], selection: list[str]) -> list[str] | None:
    values = []
    for expression in expressions:
        origins = javascript_selected_value_origins(expression, selection)
        if origins is None:
            return None
        values.extend(origins)
    return values

def javascript_local_parameter_start(code: str, cursor: int) -> int | None:
    # Generic type parameters precede the value parameters. Reuse the bounded
    # type owner; defaults and returned values still come from original source.
    cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
    if code[cursor:cursor + 1] == "<":
        return javascript_type_token_end(code, cursor)
    return cursor

def javascript_local_function_parts(text: str, code: str, match: re.Match) -> tuple[str, str] | None:
    cursor = javascript_local_parameter_start(code, match.end())
    parameters = re.match(r"\s*\(", code[cursor:]) if cursor is not None else None
    if parameters is None:
        return None
    start = cursor + parameters.end() - 1
    end = javascript_balanced_binding_end(code, start, "(", ")")
    if end is None:
        return None
    # Skip balanced return types before finding the actual function body.
    body_start = javascript_function_body_start(code, end)
    if body_start is None:
        return None
    body_end = javascript_balanced_binding_end(code, body_start, "{", "}")
    if body_end is None:
        return None
    return text[start + 1:end - 1], text[body_start + 1:body_end - 1]

def javascript_local_function_origins(text: str, code: str, root: str) -> list[str] | None:
    declarations = re.finditer(
        r"\bfunction(?![\w$])\s*\*?\s*" + re.escape(root) + r"(?![\w$])", code,
    )
    expressions = []
    for declaration in declarations:
        parts = javascript_local_function_parts(text, code, declaration)
        if parts is None:
            return None
        expressions.extend(javascript_local_return_origins(*parts))
    return expressions if expressions else javascript_captured_import_origins(text, code, root)


def javascript_initializer_object_key(code: str, match: re.Match) -> bool:
    return code[:match.start()].rstrip().endswith(("{", ",")) and code[match.end():].lstrip().startswith(":")

def javascript_initializer_references(expression: str) -> set[str]:
    code = javascript_initializer_value_code(expression)
    # A ternary question mark starts a value branch. A dot still separates
    # member suffixes; spread operands retain their complete value selection.
    roots = re.finditer(
        r"(?<![\w$.])(?:\.\.\.)?(?P<root>[A-Za-z_$][A-Za-z0-9_$]*"
        r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)(?![\w$])", code,
    )
    return {match.group("root").replace("?.", ".") for match in roots
            if not javascript_initializer_object_key(code, match)}

def javascript_binding_links(text: str, code: str, root: str, checked_count: int) -> set[str] | None:
    if checked_count >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    expressions = javascript_binding_value_origins(text, code, root)
    if expressions is None:
        return None
    return javascript_binding_proven_references(text, code, expressions, owner=root)





def javascript_declared_kind_comparison_text(text, expression) -> str:
    # A named Kind return type and matching resolver declaration establish a
    # control selector binding. Keep longer literal values and suffixes scanned.
    pattern = re.compile(r"(?P<ref>[A-Za-z_$][\w$]*)\s*===\s*([\"'])[a-z]{3,7}\2")
    code = javascript_binding_code(text)
    spans = [match.span() for match in pattern.finditer(expression)
             if javascript_declared_kind_selector(text, code, match.group("ref"))]
    return javascript_selector_literal_mask(expression, spans)


def javascript_declared_kind_selector(text, code, root) -> bool:
    declaration = re.compile(r"\bconst\s+" + re.escape(root) + r"\s*=\s*(?P<callee>[A-Za-z_$][\w$]*)\s*\(")
    for match in declaration.finditer(code):
        callee = match.group("callee")
        function = re.compile(r"\bfunction\s+" + re.escape(callee) + r"\s*\(")
        for named in function.finditer(code):
            end = javascript_balanced_binding_end(code, named.end() - 1, "(", ")")
            kind = root[:1].upper() + root[1:] + "Kind"
            if end is not None and re.match(r"\s*:\s*" + re.escape(kind) + r"\s*\{", code[end:]):
                return True
    return False


def javascript_selected_nullable_origins(expression, selection, depth) -> list[str] | None:
    code = javascript_initializer_value_code(expression)
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return None
    cursor = 0
    while cursor < len(code):
        if cursor in pairs:
            cursor = pairs[cursor]
            continue
        if code[cursor:cursor + 2] in {"??", "||"}:
            return javascript_selected_branch_origins(expression[:cursor], expression[cursor + 2:], selection, depth)
        cursor += 1
    return None


def javascript_selected_branch_origins(left, right, selection, depth) -> list[str] | None:
    left_values = javascript_selected_value_origins(left, selection, depth + 1)
    right_values = javascript_selected_value_origins(right, selection, depth + 1)
    return None if left_values is None or right_values is None else left_values + right_values



def javascript_conditional_colon_ranges(text: str) -> tuple[tuple[int, int], ...]:
    # A quoted ternary branch is not an object credential key. Object depth
    # keeps its property colons separate from the surrounding conditional.
    code = javascript_binding_code(text)
    colons = javascript_conditional_colon_positions(code)
    return tuple(match.span() for match in SECRET_ASSIGNMENT_PREFIX_PATTERN.finditer(text)
                 if javascript_quoted_conditional_key(match, colons))


def javascript_quoted_conditional_key(match, colons) -> bool:
    return match.group().lstrip().startswith(('"', "'")) and match.start() + match.group().rfind(":") in colons


def javascript_conditional_colon_positions(code) -> set[int]:
    depth = 0
    questions = []
    colons = set()
    for cursor, char in enumerate(code):
        depth += int(char in "([{") - int(char in ")]}")
        if javascript_conditional_marker(code, cursor) == "?":
            questions.append(depth)
        elif char == ":" and questions and questions[-1] == depth:
            questions.pop()
            colons.add(cursor)
    return colons



def field_kind_synthetic_secret_fixture(value: str, normalized_key: str) -> bool:
    kind = normalized_key.rsplit("-", 1)[-1]
    return kind in {"key", "token", "secret", "password", "credential", "credentials"} and any(
        value == f"{prefix}-{kind}" for prefix in SYNTHETIC_SECRET_PREFIXES
    )


def numbered_synthetic_secret_fixture(value: str, normalized_key: str) -> bool:
    # The public fixture count is exact. An arbitrary numeric or opaque suffix
    # is credential data and cannot use this allowance.
    marker = re.fullmatch(r"(?P<prefix>[a-z]+)-(?:[a-z]{1,16}-)?"
                          + re.escape(normalized_key.rsplit("-", 1)[-1]) + r"-1234567890", value)
    return marker is not None and marker.group("prefix") in SYNTHETIC_SECRET_PREFIXES


def javascript_fixture_origin_text(expression) -> str:
    spans = []
    for match in SECRET_ASSIGNMENT_PATTERN.finditer(expression):
        value = match.group("double_value") or match.group("single_value")
        key = re.split(r"\s*[:=]\s*", match.group(), maxsplit=1)[0]
        if value is not None and synthetic_secret_fixture(value, key) and safe_secret_assignment_suffix(expression, match.end(), javascript_dialect="typescript"):
            spans.append(match.span())
    return javascript_selector_literal_mask(expression, spans)


def javascript_selected_mutation_risk(text, code, parts) -> bool:
    # Selected members ignore sibling metadata writes, but whole replacements,
    # computed writes and Object/Reflect operations still need a proved origin.
    code = javascript_initializer_value_code(code)
    aliases = javascript_selected_alias_paths(text, code, parts)
    if javascript_selected_mutation_context_risk(text, code, aliases):
        return True
    expressions = []
    for alias, selection in aliases.items():
        if javascript_object_mutation_risk(code, alias):
            return True
        values = javascript_selected_alias_writes(text, code, alias, selection)
        if values is None:
            return True
        expressions.extend(values)
    return javascript_mutation_value_literal_risk(text, code, expressions)


def javascript_selected_mutation_context_risk(text, code, aliases):
    return aliases is None or javascript_prototype_writes(text, code, aliases) or javascript_selected_argument_escape(text, aliases)


def javascript_selected_argument_escape(text, aliases):
    # An unproved callee can mutate a receiver or any argument carrying the
    # selected object. Selected metadata cannot prove those uses harmless.
    code, _, _, _, context = javascript_prototype_context(text)
    if context is None:
        return True
    return any(javascript_selected_alias_argument_escape(text, code, context, alias, selection)
               for alias, selection in aliases.items())

def javascript_selected_alias_argument_escape(text, code, context, alias, selection):
    _, declarations, _, templates = context
    references = re.compile(r"(?<![\w$])" + re.escape(alias) + r"(?![\w$])")
    # Template masking preserves public names, while code binds local aliases.
    # Reuse the selector owner so a scoped mutable input cannot escape here.
    template_references = javascript_selector_use_pattern(alias)
    if any(template_references.search(template) for template in templates):
        return True
    for reference in references.finditer(code):
        if javascript_selected_argument_nonvalue(code, reference, declarations):
            continue
        if javascript_selected_reference_call_escape(text, code, context, reference, selection):
            return True
    return False

def javascript_selected_argument_nonvalue(code, reference, declarations):
    return reference.start() in declarations or javascript_graph_member_prefix(code[:reference.start()].rstrip()) or javascript_initializer_object_key(code, reference)


def javascript_selected_argument_receiver(code, start, selection):
    members = javascript_mutation_members(code, start)
    if members is None or selection is None:
        return True
    end, computed = members
    path = re.findall(r"[A-Za-z_$][\w$]*", code[start:end])
    return computed or (len(path) < len(selection) and selection[:len(path)] == path)


def javascript_selected_reference_call_escape(text, code, context, reference, selection):
    calls, _, pairs, _ = context
    argument = javascript_selected_argument_receiver(code, reference.end(), selection)
    return (argument and any(start < reference.start() < end and not javascript_captured_read_only_call(text, code, start) for start, end in calls)) or javascript_selected_receiver_call(text, code, pairs, reference.end(), selection is None)


def javascript_selected_receiver_call(text, code, pairs, start, carrier):
    # Member calls execute with the original object as receiver. A bare producer
    # call is checked through its returned origins, not a synthetic result member.
    members = javascript_mutation_members(code, start)
    if members is None:
        return True
    end, _ = members
    return javascript_selected_grouped_receiver_call(text, code, end, carrier or end > start)

def javascript_selected_unproved_carriers(text, code, root, proved):
    carriers = javascript_destructured_aliases(text, code, root)
    if carriers is None:
        return None
    for assignment in javascript_alias_assignments(code):
        alias = assignment.group("alias")
        expression = fallback_expression(text[assignment.end():], typescript=True)
        if alias not in proved and javascript_expression_uses_root(expression, root):
            # A proved scalar result cannot carry the mutable input to a callee.
            # Keep its initializer and the original input in their origin scans.
            if not (javascript_selected_scalar_metadata(expression) or javascript_captured_primitive_result(expression, text) or javascript_selected_assignment_value_paths(expression, root, []) == []):
                carriers.add(alias)
    return carriers - set(proved)





def javascript_selected_carrier_risk(text, code, root, carriers):
    return any(javascript_unproved_alias_mutation(text, code, alias, root) for alias in carriers)


def javascript_selected_grouped_receiver_call(text, code, end, receiver):
    while closing := re.match(r"\s*\)", code[end:]):
        end += closing.end()
        members = javascript_mutation_members(code, end)
        if members is None:
            return True
        cursor, _ = members
        receiver = receiver or cursor > end
        end = cursor
    return receiver and re.match(r"\s*(?:\?\.\s*)?(?:\(|`)", text[end:]) is not None


def javascript_selected_interpolated_templates(text):
    # Template masking removes executable interpolation references. Retain raw
    # template origins and decline selected proof when an object may cross them.
    templates, cursor = [], 0
    while cursor < len(text):
        end = javascript_noncode_end(text, cursor)
        if end is None:
            cursor += 1
            continue
        if text[cursor] == "`" and "${" in text[cursor:end]:
            templates.append(text[cursor:end])
        cursor = end
    return tuple(templates)


def javascript_selected_argument_context(text, code):
    pairs, scopes, declarations = javascript_declaration_context(code)
    if declarations is None:
        return None
    calls = tuple((start, end) for start, end in pairs.items()
                  if code[start] == "(" and javascript_selected_argument_callee(code[:start]))
    return calls, frozenset(declarations), pairs, javascript_selected_interpolated_templates(text)

def javascript_selected_argument_callee(prefix):
    prefix = prefix.rstrip()
    name = re.search(r"[A-Za-z_$][\w$]*$", prefix)
    if name is not None and name.group() in {"if", "while", "for", "switch", "catch", "with", "typeof", "void", "delete", "function"}:
        return False
    return re.search(r"(?:[\w$)\]>]|\?\.)$", prefix) is not None


def javascript_selected_alias_paths(text, code, parts) -> dict[str, list[str]] | None:
    aliases = {parts[0]: parts[1:]}
    pending = [parts[0]]
    while pending:
        root = pending.pop()
        additions = javascript_selected_alias_additions(text, code, root, aliases[root])
        if additions is None:
            return None
        for alias, selection in additions.items():
            if not javascript_add_selected_alias(aliases, pending, alias, selection):
                return None
    return aliases


def javascript_unproved_alias_mutation(text, code, alias, root):
    # Unproved aliases may be carriers, destructured members or shallow copies.
    # Refuse their writes and callee escapes without evaluating local functions.
    writes = javascript_member_write_expressions(text, code, alias)
    return writes is None or bool(writes) or javascript_alias_mutation_risk(code, alias, root) or javascript_selected_argument_escape(text, {alias: None})


def javascript_add_selected_alias(aliases, pending, alias, selection) -> bool:
    if alias in aliases:
        return aliases[alias] == selection
    if len(aliases) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return False
    aliases[alias] = selection
    pending.append(alias)
    return True




def javascript_unproved_selected_alias(text, code, root, proved) -> bool:
    pending, seen = [root], {root}
    while pending:
        source = pending.pop()
        carriers = javascript_selected_unproved_carriers(text, code, source, proved)
        if carriers is None or javascript_selected_carrier_risk(text, code, root, carriers):
            return True
        for alias in sorted(carriers - seen):
            if len(seen) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
                return True
            seen.add(alias)
            pending.append(alias)
    return False


def javascript_selected_alias_additions(text, code, root, selection) -> dict[str, list[str]] | None:
    additions = {}
    for assignment in javascript_alias_assignments(code):
        path = javascript_selected_assignment_path(text, assignment, root, selection)
        if path is None:
            continue
        alias = assignment.group("alias")
        if alias in additions and additions[alias] != path:
            return None
        additions[alias] = path
    destructured = javascript_destructured_aliases(text, code, root)
    return None if javascript_selected_alias_addition_risk(text, code, root, additions, destructured) else additions

def javascript_selected_assignment_value_paths(expression, root, selection, depth=0):
    # Only value branches can carry an object identity. Conditions and unrelated
    # branches retain their literal scans, without becoming receiver aliases.
    if depth >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    value = javascript_grouped_reference_code(expression).strip()
    code = javascript_binding_code(value)
    if code.startswith('(') and javascript_balanced_binding_end(code, 0, '(', ')') == len(code):
        return javascript_selected_assignment_value_paths(value[1:-1], root, selection, depth + 1)
    conditional = javascript_conditional_value_origins(value, [])
    branches = conditional[1:] if conditional is not None else javascript_selected_nullable_origins(value, [], depth)
    if branches is not None:
        paths = [javascript_selected_assignment_value_paths(branch, root, selection, depth + 1) for branch in branches]
        return None if None in paths else [path for branch_paths in paths for path in branch_paths]
    if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, value) is None:
        return None if javascript_expression_uses_root(value, root) else []
    parts = value.replace('?.', '.').split('.')
    return [selection[len(parts[1:]):]] if parts[0] == root and selection[:len(parts[1:])] == parts[1:] else []


def javascript_selected_assignment_path(text, assignment, root, selection):
    expression = fallback_expression(text[assignment.end():], typescript=True)
    paths = javascript_selected_assignment_value_paths(expression, root, selection)
    return paths[0] if paths and all(path == paths[0] for path in paths) else None


def javascript_selected_alias_addition_risk(text, code, root, additions, destructured) -> bool:
    if destructured is None or javascript_unproved_selected_alias(text, code, root, additions):
        return True
    return any(javascript_alias_mutation_risk(code, alias, root) for alias in destructured)



def javascript_selected_alias_writes(text, code, alias, selection) -> list[str] | None:
    pairs = javascript_scope_pairs(code)
    values = []
    for match in re.finditer(r"(?<![\w$.])" + re.escape(alias) + r"(?![\w$])", code):
        origins = javascript_selected_alias_write(text, code, match.end(), selection, pairs)
        if origins is None:
            return None
        values.extend(origins)
    return values

def javascript_unresolved_grouped_write(code, pairs, start):
    # A grouped expression that the normalizer cannot prove may return an
    # alias. Refuse its writes, including calls and computed destinations.
    if pairs is None:
        return True
    scope = javascript_selector_enclosing_scope(pairs, start)
    if scope < 0 or code[scope] != "(":
        return False
    suffix = code[pairs[scope]:]
    return re.match(r"(?:\s*\)|\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*|\s*\[[^\r\n]*?\])*\s*(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)", suffix) is not None

def javascript_selected_alias_write(text, code, start, selection, pairs) -> list[str] | None:
    members = javascript_mutation_members(code, start)
    if members is None:
        return None
    end, computed = members
    if javascript_unresolved_grouped_write(code, pairs, end):
        return None
    assignment = re.match(r"\s*(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)", code[end:])
    if end == start or assignment is None:
        return []
    if computed:
        return None
    path = re.findall(r"[A-Za-z_$][\w$]*", code[start:end])
    expression = fallback_expression(text[end + assignment.end():], typescript=True)
    return javascript_selected_write_origins(expression, path, selection)



def javascript_selected_scalar_metadata(expression):
    # Only proved scalar metadata can ignore a sibling write. Function, object
    # and unresolved values can execute during later receiver use or coercion.
    expression = expression.strip()
    if javascript_syntax_boolean_expression(expression) or expression == "null":
        return True
    if expression[:1] in {"'", '"'}:
        return csharp_quoted_literal_end(expression, 0, verbatim=False, interpolated=False) == len(expression)
    return re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", expression) is not None

def javascript_selected_write_origins(expression, path, selection) -> list[str] | None:
    if "__proto__" in path or "prototype" in path:
        return None
    if selection[:len(path)] == path:
        return javascript_selected_value_origins(expression, selection[len(path):])
    if path[:len(selection)] == selection:
        return [expression]
    return [] if javascript_selected_scalar_metadata(expression) else None

def javascript_inline_type_text(expression: str) -> str:
    # A pure object assertion has type names only. Preserve the asserted value
    # and every runtime suffix; quoted or computed members receive no mask.
    pattern = re.compile(r"\bas\s*\{(?:\s*[A-Za-z_$][\w$]*\??\s*:\s*[A-Za-z_$][\w$]*(?:\s*\|\s*[A-Za-z_$][\w$]*)*\s*;?)+\s*\}(?:\s*\|\s*(?:undefined|null))?")
    code = javascript_binding_code(expression)
    return mask_ranges(expression, [match.span() for match in pattern.finditer(expression)
                                   if match.group() == code[match.start():match.end()]])


def javascript_metadata_comparison_text(expression) -> str:
    # Closed word selectors on role/mode members are control metadata. A
    # credential member, opaque bytes or a constructed suffix is not a selector.
    pattern = re.compile(r"(?P<ref>[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)\s*(?:===|!==)\s*(?P<q>[\"'])(?P<value>[a-z]{3,8})(?P=q)")
    code = javascript_binding_code(expression)
    spans = [match.span() for match in pattern.finditer(expression)
             if code[match.start("ref"):match.end("ref")] == match.group("ref")
             and re.search(r"(?:\.mode|\.role|Role)$", match.group("ref"))]
    return javascript_selector_literal_mask(expression, spans)



def javascript_named_selector_metadata_uses(text, owner) -> bool:
    if not owner or not owner.endswith("Source") or "." in owner:
        return False
    code = javascript_binding_code(text)
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return False
    names = javascript_selector_field_names(code, owner)
    return names is not None and javascript_selector_uses_metadata(text, code, pairs, names)


def javascript_selector_field_names(code, owner):
    # Follow property copies before classifying a literal as metadata. A renamed
    # field must keep its later reads visible, just like the original field.
    names = {owner, re.sub(r"^__guard_scope_[0-9]+_", "", owner)}
    while len(names) <= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        additions = javascript_selector_field_copies(code, names) - names
        if not additions:
            return names
        names.update(additions)
    return None


def javascript_selector_field_copies(code, names):
    values = "|".join(re.escape(name) for name in sorted(names))
    receiver = r"(?:[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*(?:\?\.|\.))?"
    pattern = re.compile(r"[{},]\s*(?P<field>[A-Za-z_$][\w$]*)\s*:\s*" + receiver + r"(?:" + values + r")\s*(?=[,}])")
    return {match.group("field") for match in pattern.finditer(code)
            if match.group("field").endswith("Source")}


def javascript_selector_uses_metadata(text, code, pairs, names):
    return all(javascript_selector_metadata_use(text, code, pairs, use, name, names)
               for name in sorted(names) for use in javascript_selector_use_pattern(name).finditer(code))

def javascript_selector_use_pattern(owner):
    public = re.sub(r"^__guard_scope_[0-9]+_", "", owner)
    names = "|".join(re.escape(name) for name in dict.fromkeys((owner, public)))
    return re.compile(r"(?<![\w$])(?:" + names + r")(?![\w$])")

def javascript_selector_metadata_use(text, code, pairs, use, owner, names) -> bool:
    # Type keys declare a source shape, never a runtime selector use. Keep the
    # outer literal scan; this only supplies the existing metadata-use proof.
    scope = javascript_selector_enclosing_scope(pairs, use.start())
    if any(start <= use.start() < end for start, end in typescript_object_type_ranges(text, code)):
        return True
    if scope >= 0 and code[scope] == "{" and code[:scope].rstrip().endswith(":"):
        parent = javascript_selector_enclosing_scope(pairs, scope)
        if javascript_selector_parameter_scope(code, pairs, parent):
            return True
    prefix, suffix = code[:use.start()].rstrip(), code[use.end():].lstrip()
    if re.search(r"\bconst\s*$", prefix) and suffix.startswith("="):
        return True
    if javascript_selector_control_use(text, code, use):
        return True
    return javascript_selector_structural_use(code, pairs, use, owner, names)



def javascript_selector_control_use(text, code, use) -> bool:
    prefix, suffix = code[:use.start()].rstrip(), code[use.end():].lstrip()
    receiver = r"(?:[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*(?:\?\.|\.))?"
    if re.search(r"!\s*" + receiver + r"$", prefix) and re.match(r"(?:&&|\|\||[),;])", suffix):
        return True
    comparison = re.match(r"\s*(?:===|!==)\s*(?P<q>[\"'])(?P<value>[a-z]{1,7})(?P=q)\s*(?=&&|\|\||[)?,;])", text[use.end():])
    return comparison is not None and comparison.group("value") not in PROMPT_SECRET_THEME_WORDS


def javascript_selector_structural_use(code, pairs, use, owner, names) -> bool:
    prefix, suffix = code[:use.start()].rstrip(), code[use.end():].lstrip()
    scope = javascript_selector_enclosing_scope(pairs, use.start())
    if suffix.startswith(":"):
        return javascript_selector_key_definition(code, pairs, scope, prefix)
    return scope >= 0 and code[scope] == "{" and javascript_selector_property_value(prefix, suffix, names)

def javascript_selector_key_definition(code, pairs, scope, prefix) -> bool:
    # A ternary branch also ends in a colon. Only a brace-delimited key
    # position proves output metadata; branch values retain their origins.
    if scope < 0 or code[scope] != "{" or not prefix.endswith(("{", ",")) or re.match(r"\s*=(?!=)", code[pairs[scope]:]) is not None:
        return False
    # A destructured key reads the field into another binding. It is not
    # evidence that the originating literal remains output metadata.
    parent = javascript_selector_enclosing_scope(pairs, scope)
    return not javascript_selector_parameter_scope(code, pairs, parent)

def javascript_selector_parameter_scope(code, pairs, scope) -> bool:
    if scope < 0 or code[scope] != "(":
        return False
    prefix, suffix = code[:scope].rstrip(), code[pairs[scope]:].lstrip()
    return re.search(r"\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*$", prefix) is not None or javascript_selector_parameter_tail(suffix)

def javascript_selector_parameter_tail(suffix) -> bool:
    return suffix.startswith(("=>", "{")) or re.match(r":\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\s*\|\s*[A-Za-z_$][\w$]*)*\s*(?:=>|\{)", suffix) is not None

def javascript_selector_enclosing_scope(pairs, position):
    return max((start for start, end in pairs.items() if start < position < end), default=-1)


def javascript_selector_property_value(prefix, suffix, names) -> bool:
    if not suffix.startswith((",", "}")):
        return False
    fields = "|".join(re.escape(name) for name in sorted(names))
    receiver = r"(?:[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*(?:\?\.|\.))?"
    return prefix.endswith(("{", ",")) or re.search(r"\b(?:" + fields + r")\s*:\s*" + receiver + r"$", prefix) is not None

def javascript_named_conditional_selector_text(text, expression, owner) -> str:
    if not javascript_named_selector_metadata_uses(text, owner):
        return expression
    pattern = re.compile(r"(?P<ref>[A-Za-z_$][\w$]*)\s*\?\s*(?P<q>[\"'])(?P<value>[a-z]{1,7})(?P=q)\s*:")
    code = javascript_binding_code(expression)
    spans = [match.span() for match in pattern.finditer(expression)
             if code[match.start("ref"):match.end("ref")] == match.group("ref")
             and re.fullmatch(re.escape(match.group("value")) + r"[A-Z][A-Za-z]*", re.sub(r"^__guard_scope_[0-9]+_", "", match.group("ref")))
             and match.group("value") not in PROMPT_SECRET_THEME_WORDS]
    return javascript_selector_literal_mask(expression, spans)



def javascript_boolean_predicate(expression) -> bool:
    # A comparison followed by conjunctions and a final negation returns only
    # falsey absence or Boolean values. Its checked selectors never become bytes.
    ref = URI_CREDENTIAL_REFERENCE_TEXT
    comparison = r"(?:" + ref + r"\s*===\s*(?:" + ref + r"|\s+))"
    return re.fullmatch(r"\s*" + comparison + r"(?:\s*&&\s*(?:" + ref + r"|" + comparison + r"))*\s*&&\s*!" + ref + r"\s*", expression) is not None


def javascript_typeof_selector_text(expression: str) -> str:
    # typeof's closed language result words select a branch; they are not its
    # returned bytes. Keep every operand and branch in the origin graph.
    operand = r"(?:" + URI_CREDENTIAL_REFERENCE_TEXT + r"|\(\s*" + URI_CREDENTIAL_REFERENCE_TEXT + r"\s*\)(?:\?\.|\.)[A-Za-z_$][\w$]*)"
    pattern = re.compile(r"\btypeof\s+" + operand
                         + r"\s*(?:===|!==|==|!=)\s*(?P<q>[\"'])(?:undefined|object|boolean|number|bigint|string|symbol|function)(?P=q)")
    code = javascript_binding_code(expression)
    spans = [match.span() for match in pattern.finditer(expression)
             if code[match.start():match.start() + 6] == "typeof"]
    return javascript_selector_literal_mask(expression, spans)


def javascript_selector_literal_mask(expression, spans) -> str:
    # Only the literal part of a proved selector is erased. References and
    # operators remain visible to alias, later-write and constructor checks.
    result = list(expression)
    for start, end in spans:
        for match in re.finditer(r"[\"'][^\"'\r\n]*[\"']", expression[start:end]):
            result[start + match.start():start + match.end()] = "null" + " " * (len(match.group()) - 4)
    return "".join(result)


def javascript_reason_selector_text(text, expression) -> str:
    pattern = re.compile(r"(?P<ref>[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*\.reason)"
                         + r"\s*===\s*(?P<q>[\"'])(?P<value>[a-z]{1,16}(?:_[a-z]{1,16}){1,3})(?P=q)")
    code = javascript_binding_code(text)
    spans = [match.span() for match in pattern.finditer(expression)
             if javascript_matching_reason_case(text, code, match.group("ref"), match.group("value"))]
    return javascript_selector_literal_mask(expression, spans)


def javascript_matching_reason_case(text, code, reference, value) -> bool:
    # A matching case in an actual switch on the same reason reference binds
    # this comparison to a named status selector. Opaque values do not match.
    pattern = re.compile(r"\bswitch\s*\(\s*" + re.escape(reference) + r"\s*\)\s*\{")
    for match in pattern.finditer(code):
        end = javascript_balanced_binding_end(code, match.end() - 1, "{", "}")
        if end is not None and end - match.start() <= 8192:
            case = re.compile(r"\bcase\s*([\"'])" + re.escape(value) + r"\1\s*:")
            if any(code[item.start():item.start() + 4] == "case" for item in case.finditer(text, match.end(), end)):
                return True
    return False


def javascript_named_discriminator_text(expression, owner) -> str:
    if not owner:
        return expression
    pattern = re.compile(r"(?P<key>\bkind)\s*:\s*(?P<q>[\"'])(?P<value>[a-z]{1,16}(?:-[a-z]{1,16}){1,3})(?P=q)\s+as\s+const\b")
    code = javascript_binding_code(expression)
    spans = [match.span() for match in pattern.finditer(expression)
             if code[match.start("key"):match.end("key")] == "kind"
             and javascript_discriminator_matches_owner(owner, match.group("value"))]
    return javascript_selector_literal_mask(expression, spans)


def javascript_discriminator_matches_owner(owner, value) -> bool:
    # A const kind tag must spell the named binding's prefix. This admits a
    # named metadata selector, not a free literal or a resolver argument.
    normalized = re.sub(r"[^a-z]", "", owner.casefold())
    prefix = value.replace("-", "")
    return normalized.startswith(prefix) and normalized[len(prefix):] in {"issuer", "kind", "type"}


def javascript_origin_selector_text(text, expression, owner=None) -> str:
    selected = javascript_fixture_origin_text(javascript_inline_type_text(expression))
    selected = javascript_typeof_selector_text(selected)
    selected = javascript_metadata_comparison_text(selected)
    selected = javascript_named_conditional_selector_text(text, selected, owner)
    selected = javascript_reason_selector_text(text, selected)
    selected = javascript_declared_kind_comparison_text(text, selected)
    return javascript_named_discriminator_text(selected, owner)


def javascript_source_assignment_ranges(text, dialect, ranges) -> tuple[tuple[int, int], ...]:
    if dialect is None:
        return ()
    colons = javascript_conditional_colon_ranges(text)
    prefixes = SECRET_ASSIGNMENT_PREFIX_PATTERN.finditer(mask_ranges(text, ranges + colons))
    return colons + javascript_reference_assignment_ranges(text, prefixes)


def javascript_reference_assignment_ranges(text, prefixes) -> tuple[tuple[int, int], ...]:
    code = javascript_binding_code(text)
    return tuple(prefix.span() for prefix in prefixes
                 if javascript_safe_reference_assignment(text, code, prefix))


def javascript_reference_assignment_expression(text, code, prefix):
    # The conditional reference proof owns value branches. Type annotations
    # and ordinary expressions retain their existing literal/value checks.
    if code[prefix.start():prefix.end()] != prefix.group():
        return None
    expression = fallback_expression(text[prefix.end():], typescript=True)
    if len(expression) > 8192 or re.search(r"\?|&&|\|\|", expression) is None:
        return None
    owner = re.match(r"[A-Za-z_$][\w$]*", prefix.group().strip())
    return javascript_origin_selector_text(text, expression, owner.group() if owner else None)


def javascript_safe_reference_assignment(text, code, prefix) -> bool:
    selected = javascript_reference_assignment_expression(text, code, prefix)
    return selected is not None and javascript_proven_reference_expression(text, prefix.end(), selected)


def javascript_syntax_boolean_expression(expression):
    # Prove result syntax only. Mutable method calls retain their value origins.
    parts = list(re.finditer(r"(?:^|\|\||&&)(?P<part>.*?)(?=\|\||&&|$)", expression, re.DOTALL))
    return bool(parts) and len(parts) <= MAX_JAVASCRIPT_INITIALIZER_ROOTS and (
        sum(part.end() - part.start() for part in parts) == len(expression)
    ) and all(javascript_syntax_boolean_part(part.group("part")) for part in parts)


def javascript_syntax_boolean_part(part):
    reference = URI_CREDENTIAL_REFERENCE_TEXT
    comparison = reference + r"\s*(?:===|!==|==|!=|<=|>=|<|>)\s*" + reference
    return re.fullmatch(r"\s*(?:" + comparison + r"|!{1,2}\s*" + reference + r"|true|false)\s*", part) is not None


def javascript_prototype_writes(text, code, selected=()):
    code, natives, roots, unsafe, _ = javascript_prototype_context(text)
    return unsafe or javascript_prototype_mutations(text, code, roots, natives, selected)


@functools.lru_cache(maxsize=8)
def javascript_prototype_context(text):
    # Reuse immutable source facts across selected fields. Target-specific
    # mutation checks stay outside this eight-entry source cache.
    code = javascript_prototype_discovery_code(text)
    natives = javascript_prototype_native_aliases(code)
    roots = javascript_prototype_origin_roots(text, code, natives) if natives is not None else None
    unsafe = javascript_prototype_context_risk(code, natives, roots)
    arguments = javascript_selected_argument_context(text, code)
    return code, frozenset(natives or ()), frozenset(roots or ()), unsafe, arguments


def javascript_prototype_context_risk(code, natives, roots):
    return roots is None or javascript_prototype_unproved_receiver(code) or javascript_prototype_escapes(code, roots, natives) or javascript_prototype_unresolved_native(code, natives)

@functools.lru_cache(maxsize=8)
def javascript_prototype_discovery_code(text):
    # Normalize constant member selectors only for mutation discovery, retaining
    # offsets and unresolved keys. Origin selector proof would recurse here.
    code = javascript_initializer_value_code(text)
    pattern = re.compile(r"(?P<optional>\?\.)?\[\s*([\"'])(?P<key>[A-Za-z_$][\w$]*)\2\s*\]")
    projected = list(code)
    for match in pattern.finditer(text):
        opening = match.start() + (2 if match.group("optional") else 0)
        if code[opening:opening + 1] == "[" and re.search(r"[\w$)\]}\"'`/>]\s*$", text[:match.start()]):
            member = "." + match.group("key")
            projected[match.start():match.end()] = member + " " * (len(match.group()) - len(member))
    return javascript_grouped_member_code(javascript_prototype_member_code("".join(projected)))


def javascript_prototype_member_code(code):
    pattern = re.compile(r"(?<![\w$?.])[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*)+")
    projected = list(code)
    for match in pattern.finditer(code):
        member = re.sub(r"\s|\?", "", match.group())
        projected[match.start():match.end()] = member + " " * (len(match.group()) - len(member))
    return "".join(projected)

def javascript_prototype_native_aliases(code):
    # Native method copies can escape through calls without member assignments.
    # Keep all bounded alias edges; mutation-only alias pruning would lose them.
    edges = javascript_binding_alias_edges(code, code)
    aliases = {"Object", "Reflect", "RegExp", "globalThis"}
    pending = list(aliases)
    while pending:
        root = pending.pop()
        destructured = javascript_destructured_aliases(code, code, root)
        if destructured is None:
            return None
        additions = (edges.get(root, set()) | destructured) - aliases
        if len(aliases | additions) > MAX_JAVASCRIPT_INITIALIZER_ROOTS:
            return None
        aliases.update(additions)
        pending.extend(additions)
    return aliases

def javascript_prototype_selector_ranges(code):
    return re.finditer(r"\.(?:__proto__|constructor|prototype|getPrototypeOf)(?![\w$])", code)


def javascript_prototype_selector(reference):
    return any(javascript_prototype_selector_ranges(reference))


def javascript_prototype_unproved_receiver(code):
    # Only identifier-rooted chains have a proved receiver. Literal/call
    # receivers cannot borrow a selected-field provenance exemption.
    selectors = {member.start() for member in javascript_prototype_selector_ranges(code)}
    references = re.finditer(r"(?<![\w$.])" + URI_CREDENTIAL_REFERENCE_TEXT, code)
    proved = {reference.start() + member.start() for reference in references
              for member in javascript_prototype_selector_ranges(reference.group())}
    return not selectors <= proved


def javascript_prototype_initial_roots(code):
    return frozenset({"Object", "Reflect", "RegExp", "globalThis"} | {
        reference.split(".")[0] for reference in javascript_initializer_references(code)
        if javascript_prototype_selector(reference)
    })


def javascript_prototype_origin_roots(text, code, natives):
    roots = set(javascript_prototype_initial_roots(code))
    for _ in range(MAX_JAVASCRIPT_INITIALIZER_ROOTS):
        additions = javascript_prototype_origin_additions(text, code, roots, natives)
        if additions is None or len(roots | additions) > MAX_JAVASCRIPT_INITIALIZER_ROOTS:
            return None
        if additions <= roots:
            return roots
        roots.update(additions)
    return None


def javascript_prototype_origin_additions(text, code, roots, natives):
    additions = {match.group("alias") for match in javascript_alias_assignments(code)
                 if javascript_prototype_value_origin(fallback_expression(code[match.end():], typescript=True), roots, natives)}
    returned = javascript_prototype_return_aliases(text, code, roots, natives)
    return None if returned is None else additions | returned


def javascript_prototype_return_aliases(text, code, roots, natives):
    additions = set()
    for name in set(re.findall(r"\bfunction\s*\*?\s+([A-Za-z_$][\w$]*)", code)):
        returned = javascript_local_function_origins(text, code, name)
        if returned is None:
            return None
        if any(javascript_prototype_value_origin(value, roots, natives) for value in returned):
            additions.add(name)
    return additions

def javascript_prototype_reference_origin(reference, roots, natives):
    return reference in natives or reference.split(".")[0] in roots - {"Object", "Reflect", "RegExp"}


def javascript_prototype_value_origin(value, roots, natives):
    code = javascript_prototype_discovery_code(value)
    references = javascript_initializer_references(code)
    if any(javascript_prototype_selector(reference) for reference in references):
        return True
    # Bare native values carry prototype ownership through aliases and returns.
    # Direct native calls keep the namespace checks in prototype_escapes.
    if any(javascript_prototype_reference_origin(reference, roots, natives) for reference in references):
        return True
    return any(re.search(r"(?<![\w$.])" + re.escape(root) + r"\s*(?:\[|\()", code) for root in natives)


def javascript_prototype_mutations(text, code, roots, natives, selected):
    if any(javascript_mutation_alias_writes(text, code, root) != [] for root in roots):
        return True
    targets = roots | set(selected)
    for native in natives:
        if any(javascript_prototype_operation(code, native, target) for target in targets):
            return True
    return False


def javascript_prototype_operation(code, native, target):
    for operation in re.finditer(r"(?<![\w$.])" + re.escape(native) + r"(?![\w$])", code):
        members = javascript_mutation_members(code, operation.end())
        if members is None:
            return True
        if re.match(r"\s*\(\s*" + re.escape(target) + r"(?![\w$])", code[members[0]:]):
            return True
    return False


def javascript_prototype_escapes(code, roots, natives):
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return True
    if javascript_prototype_query_escape(code, pairs):
        return True
    # Native namespaces and their aliases cannot escape through unproved calls.
    # Direct native member calls retain their existing mutation/query checks.
    return any(
        javascript_prototype_alias_escape(code, pairs, root, native_namespace=root in natives)
        for root in roots - {"Object", "Reflect", "RegExp"}
    ) or any(
        javascript_prototype_alias_escape(code, pairs, root, native_namespace=True) for root in natives
    )


def javascript_prototype_query_escape(code, pairs):
    for query in re.finditer(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.getPrototypeOf(?![\w$])", code):
        call = re.match(r"\s*\(", code[query.end():])
        if call is None:
            return True
        end = pairs.get(query.end() + call.end() - 1)
        if javascript_prototype_query_result_escape(code, pairs, query.start(), end):
            return True
    return False


def javascript_prototype_query_result_escape(code, pairs, start, end):
    if end is None or javascript_prototype_value_escape(code, pairs, start, end):
        return True
    return code[end:].lstrip().startswith((".", "[", "?.")) or javascript_unresolved_grouped_write(code, pairs, end)


def javascript_prototype_unresolved_native(code, natives):
    for native in natives:
        for reference in re.finditer(r"(?<![\w$.])" + re.escape(native) + r"(?![\w$])", code):
            members = javascript_mutation_members(code, reference.end())
            if members is None or members[1]:
                return True
            if re.match(r"\s*\?\.\s*[\[(]", code[reference.end():]):
                return True
    return False

def javascript_prototype_alias_escape(code, pairs, root, *, native_namespace=False):
    for reference in re.finditer(r"(?<![\w$.])" + re.escape(root) + r"(?![\w$])", code):
        members = javascript_mutation_members(code, reference.end())
        if members is None or javascript_prototype_value_escape(code, pairs, reference.start(), members[0]):
            return True
        if not native_namespace and javascript_prototype_unproved_invocation(code, reference.start(), members[0]):
            return True
    return False


def javascript_prototype_unproved_invocation(code, start, end):
    # A declaration is not a call. Extracted, grouped and receiver-changing
    # invocations can escape a returned prototype; decline this value proof.
    if re.search(r"\bfunction\s*\*?\s*$", code[:start]):
        return False
    return re.match(r"\s*\)*\s*\(", code[end:]) is not None

def javascript_prototype_value_escape(code, pairs, start, end):
    # Admit only proved syntax roles. Calls, containers and operand wrappers
    # cannot carry a bare prototype/native value through an unproved callee.
    prefix, suffix = code[:start].rstrip(), code[end:].lstrip()
    if javascript_prototype_scalar_role(prefix, suffix):
        return False
    if re.match(r"(?:\?\.)?\s*\(", suffix) or re.search(r"\bfunction\s*\*?\s*$", prefix):
        return False
    return not javascript_prototype_binding_role(code, start, end)


def javascript_prototype_scalar_role(prefix, suffix):
    comparison = r"(?:[!=]==?|[<>]=?)"
    return re.search(comparison + r"$", prefix) is not None or re.match(comparison, suffix) is not None


def javascript_prototype_declared_bindings(code):
    return (assignment for assignment in javascript_alias_assignments(code)
            if re.search(r"\b(?:const|let|var)\s*$", code[:assignment.start("alias")]))


def javascript_prototype_binding_role(code, start, end):
    for assignment in javascript_prototype_declared_bindings(code):
        if start == assignment.start("alias"):
            return True
        if assignment.end() <= start and not code[assignment.end():start].strip():
            value = fallback_expression(code[assignment.end():], typescript=True)
            if value.strip() == code[start:end].strip():
                return True
    return False


def javascript_proven_reference_expression(text, start, expression) -> bool:
    owned = javascript_scoped_code_expression(text, start, expression)
    if owned is not None:
        return owned
    if javascript_expression_has_literal(expression):
        return False
    if any((javascript_boolean_predicate(expression), javascript_syntax_boolean_expression(expression))):
        return True
    code = javascript_grouped_reference_code(expression)
    roots = list(re.finditer(r"(?<![\w$.])(?P<root>[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)", code))
    return len(roots) <= MAX_JAVASCRIPT_INITIALIZER_ROOTS and all(
        javascript_initializer_object_key(code, root)
        or javascript_scoped_value_reference(text, start + root.start(), root.group()) for root in roots
    )





def javascript_code_imported_name(text, code, root):
    pattern = r'\bimport\s+(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\*\s+as\s+([A-Za-z_$][\w$]*)|\{([^}]+)\})?\s+from\s*(["\x27])[^"\x27]+\4'
    for match in re.finditer(pattern, text):
        if code[match.start():match.start() + 6] != 'import':
            continue
        names = [match.group(1), match.group(2)]
        for field in (match.group(3) or '').split(','):
            bound = re.fullmatch(r'\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*', field)
            if bound:
                names.append(bound.group(2) or bound.group(1))
        if root in names:
            return True
    return False


@functools.lru_cache(maxsize=128)
def javascript_code_parameter(code, root):
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return False
    owners = [javascript_named_function_bindings(code, pairs),
              javascript_arrow_parameter_bindings(code, pairs),
              javascript_method_parameter_bindings(code, pairs)]
    return all(owner is not None for owner in owners) and any(
        name == root and position < body
        for owner in owners for position, (body, name) in owner.items())


def javascript_code_method_container(expression):
    expression = expression.strip()
    code = javascript_binding_code(expression)
    if not (code.startswith('{') and javascript_balanced_binding_end(code, 0, '{', '}') == len(code)):
        return False
    fields = [field for field in split_top_level_call_arguments(expression[1:-1]) if field.strip()]
    if not fields:
        return False
    for field in fields:
        code = javascript_binding_code(field.strip())
        method = re.match(r'(?:async\s+)?[A-Za-z_$][\w$]*\s*\(', code)
        if method is None:
            return False
        end = javascript_balanced_binding_end(code, method.end() - 1, '(', ')')
        body = javascript_function_body_start(code, end) if end is not None else None
        if body is None or javascript_balanced_binding_end(code, body, '{', '}') != len(code):
            return False
    return True



def javascript_code_callable_argument_escape(text, aliases):
    # A bound receiver-free function call does not mutate its containing object.
    # Passing that object or an ancestor as data keeps the strict escape rule.
    code, _, _, _, context = javascript_prototype_context(text)
    if context is None:
        return True
    calls, declarations, _, templates = context
    for alias, selection in aliases.items():
        if any(javascript_selector_use_pattern(alias).search(template) for template in templates):
            return True
        for reference in re.finditer(r'(?<![\w$])' + re.escape(alias) + r'(?![\w$])', code):
            if javascript_selected_argument_nonvalue(code, reference, declarations) or (
                    re.search(r'\btypeof\s*$', code[:reference.start()])
                    and not re.match(r'\s*(?:\?\.|\.|\[)', code[reference.end():])):
                continue
            if javascript_selected_argument_receiver(code, reference.end(), selection) and any(
                    start < reference.start() < end and not javascript_captured_read_only_call(text, code, start)
                    for start, end in calls):
                return True
    return False


def javascript_code_callable_selection(text, code, parts, selected):
    if not selected or not all(javascript_code_callable_reference(text, value, receiver=True) for value in selected):
        return False
    aliases = {parts[0]: parts[1:]}
    for _ in range(MAX_JAVASCRIPT_INITIALIZER_ROOTS):
        added = False
        for assignment in javascript_alias_assignments(code):
            value = fallback_expression(text[assignment.end():], typescript=True).strip()
            alias = assignment.group('alias')
            if value in aliases and alias not in aliases:
                aliases[alias] = aliases[value]
                added = True
        if not added:
            break
    else:
        return False
    if aliases is None or javascript_prototype_writes(text, code, aliases) or javascript_code_callable_argument_escape(text, aliases):
        return False
    for root, selection in aliases.items():
        if javascript_object_mutation_risk(code, root):
            return False
        carriers = javascript_selected_unproved_carriers(text, code, root, aliases)
        if carriers is None:
            return False
        # A top-level spread allocates another container. It does not alias
        # the source container's callable field; nested carriers remain held.
        retained = set()
        for carrier in carriers:
            values = javascript_binding_initializers(text, code, carrier)
            source_reference = re.compile(r'(?<![\w$.])' + re.escape(root) + r'(?![\w$])')
            def copied_or_code(value):
                if re.fullmatch(r'\s*\{\s*\.\.\.\s*' + re.escape(root) + r'\s*,?\s*\}\s*', value) or javascript_code_method_container(value):
                    return True
                references = list(source_reference.finditer(javascript_binding_code(value)))
                return bool(references) and all(re.match(r'\s*(?:\?\.|\.)', value[reference.end():]) for reference in references)
            if not values or not all(copied_or_code(value) for value in values):
                retained.add(carrier)
        if javascript_selected_carrier_risk(text, code, root, retained):
            return False
    return True





def javascript_code_callable_reference(text, expression, ancestors=frozenset(), receiver=False):
    # Own data fields only receive the code-symbol route when their exact
    # initializer resolves a function declaration or arrow. Parameters and unknown
    # object values retain the mutable selected-value proof.
    expression = javascript_grouped_reference_code(expression).strip()
    if javascript_code_arrow_origins(expression) is not None:
        return not receiver or re.search(r'(?<![\w$.])this(?![\w$])', javascript_binding_code(expression)) is None
    if not re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, expression):
        return False
    identity = (_CAPTURED_SOURCE_PATH.get(), text, expression)
    if identity in ancestors or len(ancestors) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return False
    ancestors = ancestors | {identity}
    code = javascript_binding_code(text)
    parts = expression.replace('?.', '.').split('.')
    root, selection = parts[0], parts[1:]
    if not selection and re.search(r'\bfunction\s+' + re.escape(root) + r'(?![\w$])', code):
        parts = javascript_local_function_parts(text, code, re.search(r'\bfunction\s+' + re.escape(root) + r'(?![\w$])', code))
        return not javascript_binding_initializers(text, code, root) and (not receiver or parts is not None and re.search(r'(?<![\w$.])this(?![\w$])', javascript_binding_code(parts[1])) is None)
    if not selection and javascript_code_imported_name(text, code, root):
        captured = javascript_captured_function(_CAPTURED_SOURCE_PATH.get(), root, dict(_CAPTURED_SOURCES.get()))
        return captured is not None and (not receiver or re.search(r'(?<![\w$.])this(?![\w$])', javascript_binding_code(captured[2][1])) is None)
    values = javascript_binding_initializers(text, code, root, preserve_callable=True)
    selected = javascript_selected_expressions(values, selection)
    return bool(selected) and all(javascript_code_callable_reference(text, value, ancestors, receiver) for value in selected)




def javascript_code_selected_write(expression, selection):
    # Imported/formal symbols are code references. Record actual own writes;
    # an omitted sibling is not a supplied value. Data objects keep the stricter
    # own-property and inherited-value owner below.
    expression = expression.strip()
    code = javascript_initializer_value_code(expression)
    if selection and code.startswith('{') and javascript_balanced_binding_end(code, 0, '{', '}') == len(code):
        values = []
        for field in split_top_level_call_arguments(expression[1:-1]):
            value = javascript_selected_object_field(field.strip(), selection[0])
            if value is None:
                return None
            if value:
                selected = javascript_code_selected_write(value, selection[1:])
                if selected is None:
                    return None
                values.extend(selected)
        return values
    return javascript_selected_value_origins(expression, selection)


def javascript_code_symbol_writes(text, code, root, selection):
    pairs, values = javascript_scope_pairs(code), []
    if pairs is None:
        return None
    for match in re.finditer(r'(?<![\w$.])' + re.escape(root) + r'(?![\w$])', code):
        first = re.match(r'\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)', code[match.end():])
        if first is not None and selection and first.group(1) != selection[0] and first.group(1) not in {'__proto__', 'prototype', 'constructor'}:
            continue
        members = javascript_mutation_members(code, match.end())
        if members is None:
            return None
        end, computed = members
        assignment = re.match(r'\s*(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)', code[end:])
        if end == match.end() or assignment is None:
            continue
        path = re.findall(r'[A-Za-z_$][\w$]*', code[match.end():end])
        if computed or {'__proto__', 'prototype'} & set(path) or javascript_unresolved_grouped_write(code, pairs, end):
            return None
        if selection[:len(path)] != path and path[:len(selection)] != selection:
            continue
        expression = fallback_expression(text[end + assignment.end():], typescript=True)
        origins = javascript_code_selected_write(expression, selection[len(path):]) if selection[:len(path)] == path else [expression]
        if origins is None:
            return None
        values.extend(origins)
    return values


def javascript_captured_code_import(text, root):
    current, sources = _CAPTURED_SOURCE_PATH.get(), dict(_CAPTURED_SOURCES.get())
    if current is None:
        return None
    code, bindings = javascript_binding_code(text), []
    pattern = r'\bimport\s*\{([^}]+)\}\s*from\s*(["\x27])([^"\x27]+)\2'
    for match in re.finditer(pattern, text):
        if code[match.start():match.start() + 6] != 'import':
            continue
        for field in match.group(1).split(','):
            bound = re.fullmatch(r'\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*', field)
            if bound and (bound.group(2) or bound.group(1)) == root:
                path = javascript_captured_module_path(current, match.group(3), sources)
                if path:
                    bindings.append((path, bound.group(1)))
    return bindings[0] if len(bindings) == 1 else None


def javascript_code_iteration_enclosed(pairs, start, end, position):
    return any(begin <= position < finish for begin, finish in pairs.items()
               if start <= begin < end)


def javascript_code_iteration_split(code, pairs, start, end):
    for match in re.finditer(r'(?<![\w$.])(?:of|in)(?![\w$])', code[start:end]):
        position = start + match.start()
        if javascript_code_iteration_enclosed(pairs, start, end, position):
            continue
        separators = re.finditer(';', code[start:position])
        if any(not javascript_code_iteration_enclosed(pairs, start, end, start + value.start()) for value in separators):
            return None
        return position
    return None


def javascript_code_iteration_target(text, code, start, end, root):
    # One masked declaration span trims the raw binding too. Punctuators can
    # follow var/let/const without spaces; public object keys are not bindings.
    prefix = re.match(r'^\s*(?:const|let|var)(?![\w$])\s*', code[start:end])
    binding = text[start + (prefix.end() if prefix is not None else 0):end].strip()
    target = javascript_initializer_value_code(binding).strip()
    if target.startswith(('{', '[')):
        return javascript_destructuring_declares_root(binding, target, root)
    reference = re.match(r'[A-Za-z_$][\w$]*', target)
    return reference is not None and reference.group() == root

def javascript_code_iteration_rebinding(text, code, pairs, root):
    # of/in assign an existing target without an equals token. Unproved loop
    # values must not borrow the original parameter or imported CODE identity.
    for loop in re.finditer(r'\bfor\s*(?:await\s*)?\(', code):
        start = loop.end()
        end = pairs.get(start - 1)
        if end is None:
            return True
        split = javascript_code_iteration_split(code, pairs, start, end - 1)
        if split is not None and javascript_code_iteration_target(text, code, start, split, root):
            return True
    return False


def javascript_code_destructured_target_write(text, code, start, end, root, owned_declaration):
    # Annotation members name types; they cannot replace a runtime binding.
    if any(begin <= start < finish for begin, finish in javascript_binding_annotation_ranges(code)):
        return False
    if code[start] not in '{[':
        return False
    if owned_declaration and re.search(r'\bconst\s*$', code[:start]):
        return False
    return javascript_binding_assignment_end(code, end) is not None and javascript_destructuring_declares_root(text[start:end], code[start:end], root)


def javascript_code_unproved_rebinding(text, code, root, owned_declaration=False):
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return True
    return javascript_code_destructured_rebinding(text, code, pairs, root, owned_declaration) or javascript_code_iteration_rebinding(text, code, pairs, root)


def javascript_code_destructured_rebinding(text, code, pairs, root, owned_declaration=False):
    # Only the proved original const binding owns its destructuring declaration.
    # A var declaration can replace a formal; retain that captured body write.
    return any(javascript_code_destructured_target_write(text, code, start, end, root, owned_declaration)
               for start, end in pairs.items())


def javascript_closed_string_normalizer(parameters, body, root):
    if re.fullmatch(r'\s*' + re.escape(root) + r'\s*(?::\s*unknown\s*)?', parameters) is None:
        return False
    # Only this complete checked primitive body proves a native string result.
    # Extra writes, callbacks or literal-return branches keep the formal unproved.
    name = re.escape(root)
    pattern = (r'\s*if\s*\(\s*typeof\s+' + name + r'\s*!==\s*(["\x27])string\1\s*\)\s*'
               r'\{\s*return\s+undefined\s*;\s*\}\s*const\s+([A-Za-z_$][\w$]*)\s*=\s*'
               + name + r'\s*\.\s*trim\s*\(\s*\)\s*;\s*return\s+\2\s*\?\s*\2\s*:\s*undefined\s*;?\s*')
    return re.fullmatch(pattern, body) is not None


def javascript_code_guarded_string_member(text, reference):
    selected = re.fullmatch(r'([A-Za-z_$][\w$]*)\.trim', reference)
    if selected is None:
        return False
    code = javascript_binding_code(text)
    declarations = re.finditer(r'\bfunction\s+[A-Za-z_$][\w$]*', code)
    for declaration in declarations:
        parts = javascript_local_function_parts(text, code, declaration)
        if parts is None:
            continue
        if javascript_closed_string_normalizer(*parts, selected.group(1)):
            sources = (text,) + tuple(source for _, source in _CAPTURED_SOURCES.get())
            return not any(javascript_prototype_writes(source, javascript_binding_code(source)) for source in sources)
    return False


def javascript_code_unproved_callable_invocation(text, reference, called, roles):
    root = reference.replace('?.', '.').split('.')[0]
    return bool(called) and (_CAPTURED_SOURCE_PATH.get(), text, root) in roles and not javascript_code_guarded_string_member(text, reference)



def javascript_code_captured_argument_owner(text, code, opening, module=None, seen=frozenset()):
    prefix = code[:opening].rstrip()
    target = re.search(r'(?<![\w$.])([A-Za-z_$][\w$]*)$', prefix)
    if target is None or re.search(r'\bfunction\s*$', prefix[:target.start()]):
        return None
    projected, name = (module, target.group(1)) if module is not None else javascript_scoped_reference_graph(text, target.start(), target.group(1))
    if name in seen:
        return None
    projected_code = javascript_binding_code(projected)
    declarations = list(re.finditer(r'\bfunction\s+' + re.escape(name) + r'(?![\w$])', projected_code))
    if len(declarations) == 1:
        parts = javascript_local_function_parts(projected, projected_code, declarations[0])
        return (projected, parts) if parts is not None else False
    if declarations:
        return False
    initializers = javascript_binding_initializers(projected, projected_code, name, preserve_callable=True)
    if len(initializers) != 1:
        return False if any(re.search(r'\bfunction\b|=>', value) for value in initializers) else None
    value = initializers[0].strip()
    if re.fullmatch(r'[A-Za-z_$][\w$]*', value):
        return javascript_code_captured_argument_owner(value + '(', value + '(', len(value), module=projected, seen=seen | {name})
    function = re.match(r'(?:async\s+)?function(?:\s+[A-Za-z_$][\w$]*)?', javascript_binding_code(value))
    if function is not None:
        parts = javascript_local_function_parts(value, javascript_binding_code(value), function)
        return (projected, parts) if parts is not None else False
    arrow = javascript_code_arrow_parts(value)
    if arrow is None:
        return False if '=>' in javascript_binding_code(value) else None
    value_code = javascript_binding_code(value)
    for marker in re.finditer(r'=>\s*', value_code):
        start = marker.end()
        if value_code[start:start + 1] == '{' and javascript_balanced_binding_end(value_code, start, '{', '}') == len(value_code):
            return projected, (arrow[0], value[start + 1:-1])
    return projected, (arrow[0], 'return ' + value[value_code.find('=>') + 2:])


def javascript_code_argument_selection(argument, aliases):
    argument = javascript_grouped_reference_code(argument).strip()
    if not re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, argument):
        return None
    parts = argument.replace('?.', '.').split('.')
    selected = aliases.get(parts[0])
    suffix = parts[1:]
    return selected[len(suffix):] if selected is not None and selected[:len(suffix)] == suffix else None


def javascript_code_selected_alias_paths(text, code, root, selection):
    # CODE controls can derive primitive values without aliasing their owner.
    # Follow only reference-preserving paths when checking captured member writes.
    aliases = {root: selection}
    pending = [root]
    while pending:
        owner = pending.pop()
        for assignment in javascript_alias_assignments(code):
            path = javascript_selected_assignment_path(text, assignment, owner, aliases[owner])
            if path is None:
                continue
            if not javascript_add_selected_alias(aliases, pending, assignment.group('alias'), path):
                return None
    return aliases


def javascript_code_captured_parameter_values(text, code, root, selection, ancestors, module=None, seen=frozenset()):
    # Runtime parameters add no captured bytes. Local callees can add bytes by
    # writing the selected member, so retain their writes and actual value inputs.
    key = (root, tuple(selection))
    if key in seen:
        return []
    if len(seen) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    seen = seen | {key}
    aliases = javascript_code_selected_alias_paths(text, code, root, selection)
    context = javascript_selected_argument_context(text, code)
    if aliases is None or context is None:
        return None
    values = []
    for alias, member in aliases.items():
        writes = javascript_code_symbol_writes(text, code, alias, member)
        if writes is None:
            return None
        values.extend(writes)
    for opening, end in context[0]:
        arguments = split_top_level_call_arguments(text[opening + 1:end - 1])
        selected = [(i, javascript_code_argument_selection(value, aliases)) for i, value in enumerate(arguments)]
        selected = [(i, member) for i, member in selected if member]
        if not selected:
            continue
        owner = javascript_code_captured_argument_owner(text, code, opening, module=module)
        if owner is False:
            return None
        if owner is None:
            continue
        projected, (parameters, body) = owner
        formals = javascript_parameter_parts(javascript_binding_code(parameters))
        body_code = javascript_binding_code(body)
        for index, member in selected:
            if index >= len(formals):
                return None
            formal = re.match(r'^\s*([A-Za-z_$][\w$]*)\s*(?::|=|$)', formals[index])
            if formal is None:
                return None
            writes = javascript_code_captured_parameter_values(body, body_code, formal.group(1), member, ancestors, module=projected, seen=seen)
            if writes is None:
                return None
            if writes:
                values.extend(arguments)
                values.extend(writes)
    return values


def javascript_code_symbol_reference(text, reference, called=False, ancestors=frozenset(), unproved_callables=frozenset(), external_argument=False):
    # This proves captured source syntax, not the contents or purity of runtime
    # parameters. Source-owned writes, defaults and captured returns retain all
    # literal origins. Data objects keep the selected-value/mutation proof.
    identity = (_CAPTURED_SOURCE_PATH.get(), text, reference, called)
    if identity in ancestors or len(ancestors) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    ancestors = ancestors | {identity}
    code = javascript_binding_code(text)
    parts = reference.replace('?.', '.').split('.')
    root, selection = parts[0], parts[1:]
    # This role comes from the exact captured callable header, including arrows.
    # Unresolved actual arguments cannot establish an invoked formal identity;
    # they must not borrow the separate direct-runtime-parameter allowance.
    if javascript_code_unproved_callable_invocation(text, reference, called, unproved_callables):
        return False
    global_reference = (SOURCE_CODE_REFERENCE_ROOT_PATTERN.fullmatch(reference) is not None or any(pattern.fullmatch(reference) for pattern in UNQUOTED_SECRET_REFERENCE_PATTERNS)) and not javascript_binding_initializers(text, code, root)
    destructured = javascript_destructured_binding_initializers(text, code, root)
    # A const destructuring of a proved code reference retains that source role.
    # Literal objects, defaults and unresolved carriers cannot borrow it.
    destructured_symbol = bool(destructured) and not javascript_binding_initializers(text, code, root) and all(
        re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, expression.strip()) is not None
        and javascript_code_symbol_expression(text, expression, ancestors) is True
        for expression in destructured)
    symbolic = javascript_code_parameter(code, root) or javascript_code_imported_name(text, code, root) or global_reference or destructured_symbol
    writes = (javascript_code_symbol_writes(text, code, root, selection) if symbolic
              else javascript_selected_alias_writes(text, code, root, selection)) if selection else []
    if writes is None:
        return None
    declarations = list(re.finditer(r'\bfunction\s+' + re.escape(root) + r'(?![\w$])', code))
    captured_callable = declarations or symbolic or called or external_argument
    if captured_callable and javascript_code_unproved_rebinding(text, code, root, owned_declaration=destructured_symbol):
        return False
    rebindings = javascript_binding_initializers(text, javascript_initializer_value_code(text), root, preserve_callable=bool(called)) if captured_callable else []
    if rebindings:
        rebindings = javascript_selected_expressions(rebindings, selection)
        if rebindings is None:
            return False
        # The CODE allowance belongs to the original binding, not captured
        # replacements. Prove body writes before every binding fast path.
        replacement = javascript_code_symbol_values(text, rebindings, ancestors, selection[-1] if selection else None, owner=root, called=called, unproved_callables=unproved_callables, external_argument=external_argument)
        if replacement is not True:
            return replacement
    if destructured_symbol:
        if selection and javascript_selected_mutation_risk(text, code, parts):
            return False
        return javascript_code_symbol_values(text, destructured + writes, ancestors, selection[-1] if selection else None, root, called=called, unproved_callables=unproved_callables, external_argument=external_argument)
    if javascript_code_parameter(code, root):
        effects = javascript_code_captured_parameter_values(text, code, root, selection, ancestors) if selection else []
        if effects is None:
            return False
        values = javascript_binding_initializers(text, code, root)
        values = javascript_selected_expressions(values, selection)
        return javascript_code_symbol_values(text, values + writes + effects, ancestors, selection[-1] if selection else None, root, called=called, unproved_callables=unproved_callables, external_argument=external_argument) if values is not None else None
    if declarations and selection:
        # A function object can escape to a captured mutator just like an object.
        # Prove its selected member before borrowing the return-origin role.
        if javascript_selected_mutation_risk(text, code, parts):
            return False
        origins = javascript_binding_selected_origins(text, code, root, selection, parts)
        if origins is None:
            return None
        return javascript_code_symbol_values(text, origins + writes, ancestors, selected_key=selection[-1], owner=root, called=called, unproved_callables=unproved_callables, external_argument=external_argument)
    if declarations and not selection:
        if len(declarations) != 1:
            return None
        if not called:
            return True
        function = javascript_local_function_parts(text, code, declarations[0])
        if function is None:
            return None
        remaining_calls = max(int(called) - 1, 0)
        roles = javascript_code_return_parameter_roles(text, function[0], called, unproved_callables)
        if roles is None:
            return None
        result = javascript_code_symbol_values(text, javascript_local_return_origins(*function), ancestors, called=remaining_calls, unproved_callables=roles, external_argument=external_argument)
        # A captured declaration establishes a code call, not runtime purity.
        # Keep actual literal/data refusals; unresolved runtime results add no
        # submitted value bytes to this source reference.
        return False if result is False else None if remaining_calls and result is None else True
    if javascript_code_imported_name(text, code, root):
        binding = javascript_captured_code_import(text, root)
        if binding is not None and called and not selection:
            module, original = binding
            raw = dict(_CAPTURED_SOURCES.get())[module]
            token = _CAPTURED_SOURCE_PATH.set(module)
            try:
                declaration = re.search(r'\bfunction\s+' + re.escape(original) + r'(?![\w$])', javascript_binding_code(raw))
                position = declaration.end() - len(original) if declaration else 0
                projected, owned_name = javascript_scoped_reference_graph(raw, position, original)
                result = javascript_code_symbol_reference(projected, owned_name, called, ancestors)
            finally:
                _CAPTURED_SOURCE_PATH.reset(token)
            if result is not True:
                return result
        return javascript_code_symbol_values(text, writes, ancestors, selection[-1] if selection else None, called=called, unproved_callables=unproved_callables, external_argument=external_argument)

    if global_reference:
        return javascript_code_symbol_values(text, writes, ancestors, selection[-1] if selection else None, called=called, unproved_callables=unproved_callables, external_argument=external_argument)
    values = javascript_binding_initializers(text, code, root, preserve_callable=bool(called))
    if not values:
        # An undeclared external reference submits code, not runtime contents.
        # Own declarations and unresolved or mutated carriers cannot borrow that
        # role; retain every captured write before admitting external syntax.
        if javascript_short_reference_declared(text, code, root) or javascript_unsupported_binding_origin(text, code, root):
            return False if called else None
        return javascript_code_symbol_values(text, writes, ancestors, selection[-1] if selection else None, called=called, unproved_callables=unproved_callables, external_argument=external_argument) if called or external_argument else None
    selected = javascript_selected_expressions(values, selection)
    if selection:
        # A property of a source-owned call result is still code syntax. This
        # does not license own data objects, unknown calls or literal returns.
        call_pattern = r'\s*(?:await\s+)?[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*'
        def source_call(branch):
            branch_code = javascript_binding_code(branch)
            callee = re.match(call_pattern, branch_code)
            suffix = javascript_code_call_suffix(branch_code, callee.end()) if callee else None
            return suffix is not None and suffix[0]
        origins = [javascript_code_value_branch_origins(value) for value in values]
        branches = [branch for value_origins in origins if value_origins is not None for branch in value_origins]
        call_result = None not in origins and any(source_call(branch) for branch in branches) and all(
            javascript_code_symbol_expression(text, branch, ancestors, root, unproved_callables=unproved_callables, external_argument=external_argument) is True for branch in branches)
        if call_result:
            projection = javascript_code_symbol_values(text, selected + writes, ancestors, selected_key=selection[-1], owner=root, unproved_callables=unproved_callables, external_argument=external_argument) if selected is not None else None
            if projection is False:
                return False
            # CODE origins retain the balanced call and complete returns. DATA
            # projection otherwise turns a selected result into callee.member.
            selected = values
        elif selected is None:
            literal = any(javascript_expression_has_literal(javascript_origin_selector_text(text, value, root)) for value in values)
            data = any(javascript_initializer_value_code(value).strip().startswith(('{', '[')) for value in values)
            return False if literal or data and javascript_binding_literal_risk(text, code, reference) else None
    # An object literal is data unless selection resolves a positively owned
    # code symbol. This does not replace its mutable-carrier proof.
    if not selection and any(javascript_initializer_value_code(value).strip().startswith(('{', '[')) for value in values):
        # Data origins keep the existing alias/mutation/literal refusal even
        # when a declaration returns them through a source-code call.
        return False if javascript_binding_literal_risk(text, code, root) else None
    object_member = bool(selection) and any(javascript_initializer_value_code(value).strip().startswith('{') for value in values)
    callable_member = object_member and javascript_code_callable_selection(text, code, parts, selected)
    if object_member and called and not callable_member:
        return False if javascript_binding_literal_risk(text, code, reference) else None
    if selection and not callable_member and javascript_selected_mutation_risk(text, code, parts):
        # Resolved aliases and call results keep captured mutation/escape checks.
        return False
    return javascript_code_symbol_values(text, selected + writes, ancestors, owner=root, called=called, unproved_callables=unproved_callables, external_argument=external_argument or object_member and not called and not callable_member)













def javascript_code_symbol_values(text, expressions, ancestors, selected_key=None, owner=None, called=False, unproved_callables=frozenset(), external_argument=False):
    decisions = []
    for expression in expressions:
        literal = re.fullmatch(r'\s*(["\x27])([A-Za-z0-9_-]+)\1\s*', expression)
        # Fixture approval belongs to this exact selected origin. Invoked aliases
        # otherwise retain call context through the common expression owner.
        if selected_key and literal and synthetic_secret_fixture(literal.group(2), selected_key):
            decisions.append(True)
        else:
            decisions.append(javascript_code_symbol_expression(text, expression, ancestors, owner, called=called, unproved_callables=unproved_callables, external_argument=external_argument))
    return javascript_code_decisions(decisions)




def javascript_grouped_reference_code(expression):
    # The existing selector owner preserves offsets. Transfer only its actual
    # code-span changes, leaving strings, templates, regexes and comments raw.
    expression = javascript_inline_type_text(expression)
    code = javascript_binding_code(expression)
    selected = javascript_initializer_value_code(expression)
    return ''.join(selected[index] if char != selected[index] else expression[index]
                   for index, char in enumerate(code))


def javascript_code_arrow_origins(expression):
    parts = javascript_code_arrow_parts(expression)
    return None if parts is None else parts[1]


def javascript_code_module_selector_text(expression):
    # Only a literal relative module specifier at the import keyword is code
    # metadata. Never erase URI, encoded, constructed or opaque value origins.
    pattern = re.compile(r'''\bimport\s*\(\s*(?P<q>["'])(?P<path>(?:\.{1,2}/)+(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:js|ts|mjs|cjs))(?P=q)\s*\)''')
    code = javascript_binding_code(expression)
    spans = [match.span() for match in pattern.finditer(expression)
             if code[match.start():match.start() + 6] == "import"
             and not any(documentation_component_risk(part) for part in match.group("path").split("/"))]
    return javascript_selector_literal_mask(expression, spans)



def javascript_code_decisions(decisions):
    return False if False in decisions else None if None in decisions else True


def javascript_code_conditional_values(text, branches, ancestors, called, unproved_callables=frozenset(), external_argument=False):
    # The selector chooses a callable; it is not itself invoked. Preserve the
    # invoked identity only on value branches, including nested conditionals.
    selector = javascript_code_symbol_expression(text, branches[0], ancestors, unproved_callables=unproved_callables, external_argument=True)
    values = javascript_code_symbol_values(text, branches[1:], ancestors, called=called, unproved_callables=unproved_callables, external_argument=external_argument)
    return javascript_code_decisions((selector, values))


def javascript_code_value_branch_origins(expression, depth=0):
    # Project possible values without treating selectors as receiver identities.
    # Raw literals remain in each branch for the common value-origin scan.
    if depth >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    value = javascript_grouped_reference_code(expression).strip()
    code = javascript_binding_code(value)
    if code.startswith('(') and javascript_balanced_binding_end(code, 0, '(', ')') == len(code):
        return javascript_code_value_branch_origins(value[1:-1], depth + 1)
    conditional = javascript_conditional_value_origins(value, [])
    branches = conditional[1:] if conditional is not None else javascript_selected_nullable_origins(value, [], depth)
    if branches is None:
        return [value]
    origins = [javascript_code_value_branch_origins(branch, depth + 1) for branch in branches]
    return None if None in origins else [value for branch in origins for value in branch]


def javascript_code_call_argument_spans(code, roots):
    # Only syntactic call arguments get the external-code role. A bare undeclared
    # credential reference cannot borrow it, nor can an owned data initializer.
    spans = []
    for root in roots:
        cursor = root.end()
        for _ in range(MAX_JAVASCRIPT_INITIALIZER_ROOTS):
            part = javascript_code_call_part(code, cursor)
            if part is None or part[0] is None:
                break
            end, type_span = part
            opening = code.find('(', type_span[1] if type_span is not None else cursor, end)
            if opening >= 0:
                spans.append((opening + 1, end - 1))
            cursor = end
    return spans


def javascript_code_callable_value_root(code):
    # A prefix cannot prove a callable value: operators can select another
    # function. Consume the complete supported reference/call grammar instead.
    root = re.match(r'\s*(?:await\s+)?(?P<root>[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)', code)
    if root is None:
        return None
    cursor = root.end()
    for _ in range(MAX_JAVASCRIPT_INITIALIZER_ROOTS):
        part = javascript_code_call_part(code, cursor)
        if part is None:
            return None
        end, _ = part
        if end is None:
            return root if not code[cursor:].strip() else None
        cursor = end
    return None


def javascript_code_return_parameter_roles(text, parameters, called, inherited):
    if not called:
        return inherited
    code = javascript_binding_code(parameters)
    bindings = javascript_parameter_bindings(code, 0, len(code))
    if bindings is None or len(bindings) > MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    return inherited | frozenset((_CAPTURED_SOURCE_PATH.get(), text, name) for _, name in bindings)


def javascript_code_arrow_parts(expression):
    # A typed arrow header names a function. Only its actual returned expression
    # carries value bytes; module selectors retain their separate literal scan.
    raw = expression.strip()
    code = javascript_binding_code(raw)
    header = re.match(r"(?:async\s*)?\(", code)
    if header is None:
        return None
    end = javascript_balanced_binding_end(code, header.end() - 1, "(", ")")
    if end is None:
        return None
    cursor = end + len(code[end:]) - len(code[end:].lstrip())
    if code[cursor:cursor + 1] == ":":
        cursor += 1
        while cursor < len(code) and cursor - end <= 8192:
            cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
            if code[cursor:cursor + 2] == "=>":
                break
            token_end = javascript_type_token_end(code, cursor)
            if token_end is None:
                return None
            cursor = token_end
    if code[cursor:cursor + 2] != "=>":
        return None
    body = raw[cursor + 2:].strip()
    if body.startswith("{"):
        body_code = javascript_binding_code(body)
        return (raw[header.end():end - 1], javascript_local_return_origins(raw[header.end():end - 1], body[1:-1])) if javascript_balanced_binding_end(body_code, 0, "{", "}") == len(body_code) else None
    return (raw[header.end():end - 1], [body]) if body else None

def javascript_code_callable_group_origin(expression):
    for _ in range(MAX_JAVASCRIPT_INITIALIZER_ROOTS):
        expression = expression.strip()
        code = javascript_binding_code(expression)
        if not code.startswith('('):
            return expression
        end = javascript_balanced_binding_end(code, 0, '(', ')')
        if end is None:
            return None
        if end != len(code):
            return expression
        expression = expression[1:-1]
    return None


def javascript_code_call_type_span(code, cursor):
    if code[cursor:cursor + 1] != '<':
        return cursor, None
    end = javascript_type_token_end(code, cursor)
    return None if end is None or end - cursor > 8192 else (end, (cursor, end))


def javascript_code_call_arguments(code, cursor, type_span, optional):
    cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
    if code[cursor:cursor + 1] != '(':
        return None if optional or type_span else (None, None)
    end = javascript_balanced_binding_end(code, cursor, '(', ')')
    return None if end is None else (end, type_span)


def javascript_code_call_part(code, cursor):
    cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
    optional = code[cursor:cursor + 2] == '?.'
    if optional:
        cursor += 2
        cursor += len(code[cursor:]) - len(code[cursor:].lstrip())
    typed = javascript_code_call_type_span(code, cursor)
    return None if typed is None else javascript_code_call_arguments(code, typed[0], typed[1], optional)


def javascript_code_call_continuation(code, cursor, depth):
    # A post-call member selector remains the selected-value owner's concern.
    # Count only actual subsequent invocation syntax here.
    if re.match(r'\s*(?:\?\.\s*)?[<(]', code[cursor:]) is None:
        return 0, None
    return javascript_code_call_suffix(code, cursor, depth)


def javascript_code_call_suffix(code, cursor, depth=0):
    # Consecutive calls consume returned callable identities. The same bounded
    # suffix owner keeps optional/type syntax from dropping an invocation layer.
    if depth >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    part = javascript_code_call_part(code, cursor)
    if part is None:
        return None
    end, type_span = part
    if end is None:
        return 0, None
    remaining = javascript_code_call_continuation(code, end, depth + 1)
    return None if remaining is None else (1 + remaining[0], type_span)


def javascript_code_symbol_expression(text, expression, ancestors=frozenset(), owner=None, called=False, unproved_callables=frozenset(), external_argument=False):
    expression = javascript_code_callable_group_origin(expression)
    if expression is None:
        return None
    expression = javascript_origin_selector_text(text, expression, owner)
    arrow = javascript_code_arrow_parts(expression)
    if arrow is not None:
        roles = javascript_code_return_parameter_roles(text, arrow[0], called, unproved_callables)
        return None if roles is None else javascript_code_symbol_values(text, arrow[1], ancestors, owner=owner, called=max(int(called) - 1, 0), unproved_callables=roles, external_argument=external_argument)
    expression = javascript_code_module_selector_text(expression)
    expression = javascript_grouped_reference_code(expression)
    branches = javascript_conditional_value_origins(expression, [])
    if branches is not None:
        return javascript_code_conditional_values(text, branches, ancestors, called, unproved_callables)
    nullable = javascript_selected_nullable_origins(expression, [], 0)
    if nullable is not None:
        # Keep nested selector ownership while both possible values retain
        # the same invocation and literal-origin checks.
        return javascript_code_symbol_values(text, nullable, ancestors, owner=owner, called=called, unproved_callables=unproved_callables, external_argument=external_argument)
    if javascript_syntax_boolean_expression(expression):
        return True
    if expression.strip() == '{}' or re.fullmatch(r'\s*(?:null|undefined|true|false|[+-]?(?:[0-9]+(?:\.[0-9]+)?))\s*', expression):
        return True
    if javascript_expression_has_literal(expression):
        return False
    code = javascript_grouped_reference_code(expression)
    roots = list(re.finditer(r'(?<![\w$.])(?P<root>[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)', code))
    if not roots or len(roots) > 2 * MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return False
    # External reference leaves carry no captured values to expand. Keep the
    # original bound for owned declarations and a separate bounded lexical scan.
    source_code = javascript_binding_code(text)
    owned_roots = {root.group('root').replace('?.', '.').split('.')[0] for root in roots}
    if sum(javascript_short_reference_declared(text, source_code, root) for root in owned_roots) > MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return False
    value_root = javascript_code_callable_value_root(code) if called else None
    if called and value_root is None:
        return False
    argument_spans = javascript_code_call_argument_spans(code, roots)
    decisions, type_spans = [], []
    for root in roots:
        if any(start <= root.start() < end for start, end in type_spans):
            continue
        if javascript_initializer_object_key(code, root) or root.group() in {'typeof', 'await', 'void'} or (root.group() == 'import' and re.match(r'\s*\(\s*null\s*\)', code[root.end():])):
            continue
        suffix = javascript_code_call_suffix(code, root.end())
        if suffix is None:
            return None
        calls, type_span = suffix
        if type_span is not None:
            type_spans.append(type_span)
        # Only the initializer's value callee inherits the outer invocation.
        # Argument references and conditional selectors are not called by it.
        if value_root is not None and root.start() == value_root.start('root'):
            calls += int(called)
        decisions.append(javascript_code_symbol_reference(text, root.group(), calls, ancestors, unproved_callables=unproved_callables, external_argument=external_argument or any(start <= root.start() < end for start, end in argument_spans)))
    return javascript_code_decisions(decisions)







def javascript_code_parameter_occurrence(text, start, expression):
    # An unrelated overload can leave the module graph unproved. Reuse the
    # complete enclosing function's lexical graph for this exact source read.
    # Defaults, shadowed locals and writes still pass the same value checks.
    if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, expression.strip()) is None:
        return None
    code = javascript_binding_code(text)
    position = start + len(text[start:]) - len(text[start:].lstrip())
    if code[position:position + len(expression.strip())] != expression.strip():
        return None
    pairs = javascript_scope_pairs(code)
    if pairs is None:
        return None
    owners = []
    declarations = re.finditer(r'\bfunction(?![\w$])\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)?', code)
    for declaration in declarations:
        scope = javascript_declared_function_scope(code, pairs, declaration)
        if scope is not None:
            body, parameters = scope
            if body < start < pairs.get(body, body):
                owners.append((body, declaration.start(), pairs[body]))
    if not owners:
        return None
    _, begin, end = max(owners)
    fragment = text[begin:end]
    if javascript_scope_graph_replacements(fragment) is None:
        return None
    position = start + len(text[start:]) - len(text[start:].lstrip()) - begin
    projected, reference = javascript_scoped_reference_graph(fragment, position, expression.strip())
    return javascript_code_symbol_expression(projected, reference)




def javascript_scoped_code_expression(text, start, expression):
    expression = javascript_length_comparison_text(javascript_origin_selector_text(text, expression))
    code = javascript_grouped_reference_code(expression)
    roots = list(re.finditer(r'(?<![\w$.])(?P<root>[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)*)', javascript_initializer_value_code(code)))
    if len(roots) > MAX_JAVASCRIPT_INITIALIZER_ROOTS:
        return None
    scoped, _ = javascript_scoped_reference_graph(text, start, 'undefined')
    original, cursor, replacements = javascript_binding_code(text), start, []
    for root in roots:
        if javascript_initializer_object_key(code, root) or root.group() in {'typeof', 'await', 'void', 'null', 'undefined', 'true', 'false'}:
            continue
        value = root.group()
        base = value.replace('?.', '.').split('.')[0]
        position = original.find(base, cursor, start + 8192)
        if position < 0:
            return None
        _, selected = javascript_scoped_reference_graph(text, position, value)
        replacements.append((root.start(), root.end(), selected))
        cursor = position + len(base)
    for begin, end, selected in reversed(replacements):
        code = code[:begin] + selected + code[end:]
    result = javascript_code_symbol_expression(scoped, code)
    return javascript_code_parameter_occurrence(text, start, expression) if result is None else result




def javascript_scoped_value_reference(text, start, value) -> bool:
    scoped, selected = javascript_scoped_reference_graph(text, start, value)
    owned = javascript_code_symbol_expression(scoped, selected)
    if owned is None:
        owned = javascript_code_parameter_occurrence(text, start, value)
    return owned if owned is not None else not javascript_binding_literal_risk(scoped, javascript_binding_code(scoped), selected.replace("?.", "."))



def javascript_binding_proven_references(text, code, expressions, owner=None) -> set[str] | None:
    expressions = [javascript_origin_selector_text(text, expression, owner)
                   for expression in expressions if not javascript_imported_entropy_origin(text, code, expression)]
    if any(javascript_expression_has_literal(expression) for expression in expressions):
        return None
    return set().union(*(javascript_initializer_references(expression) for expression in expressions))


def javascript_imported_entropy_origin(text: str, code: str, expression: str) -> bool:
    generated = re.fullmatch(
        r"\s*(?P<root>[A-Za-z_$][\w$]*)\.randomBytes\(\s*[1-9][0-9]*\s*\)"
        r"\.toString\(\s*(?P<quote>[\"'])(?:hex|base64)(?P=quote)\s*\)\s*", expression,
    )
    if generated is None:
        return False
    root = generated.group("root")
    imported = re.search(r"\bimport\s+(?:\*\s+as\s+)?(?P<name>" + re.escape(root) + r")\s+from\s*([\"'])node:crypto\2", text)
    if imported is None or code[imported.start("name"):imported.end("name")] != root:
        return False
    return javascript_entropy_namespace_intact(text, code, root, imported.start("name"))


def javascript_entropy_namespace_intact(text, code, root, import_position: int) -> bool:
    # A byte count is an entropy size only for the unshadowed builtin import.
    # Rebinding, bare aliases and mutation keep every original literal check.
    references = re.finditer(r"(?<![\w$.])" + re.escape(root) + r"(?![\w$])", code)
    if any(reference.start() != import_position and not code[reference.end():].lstrip().startswith(".") for reference in references):
        return False
    return not javascript_binding_initializers(text, code, root + ".randomBytes") and not javascript_binding_mutation_risk(text, code, root)

def javascript_binding_literal_risk(text: str, code: str, root: str) -> bool:
    # A declared root can hide literal bytes behind aliases or later assignments.
    # Count value-bearing expansions; an empty imported/parameter reference
    # has no local value to expand. Cycles and the expansion cap still refuse.
    pending = [(root, frozenset())]
    checked: set[str] = set()
    expanded: set[str] = set()
    while pending:
        root, ancestors = pending.pop()
        if root in ancestors:
            return True
        if root in checked:
            continue
        links = javascript_bounded_value_links(text, code, root, len(expanded))
        if links is None:
            return True
        checked.add(root)
        javascript_record_value_expansion(expanded, root, links)
        pending.extend((reference, ancestors | {root}) for reference in sorted(links))
    return False



def javascript_record_value_expansion(expanded, root, links) -> None:
    if links:
        expanded.add(root)


def javascript_bounded_value_links(text, code, root, expanded_count) -> set[str] | None:
    links = javascript_binding_links(text, code, root, 0)
    return None if links and expanded_count >= MAX_JAVASCRIPT_INITIALIZER_ROOTS else links


def javascript_source_whitespace(char: str) -> bool:
    return (
        char in "\t\v\f \r\n\u2028\u2029\ufeff"
        or unicodedata.category(char) == "Zs"
    )

def safe_javascript_reference_suffix(
    text: str,
    end: int,
    *,
    typescript: bool,
) -> bool:
    line_terminators = "\r\n\u2028\u2029"
    cursor = end
    saw_newline = False
    while cursor < len(text):
        while cursor < len(text) and javascript_source_whitespace(text[cursor]):
            saw_newline = saw_newline or text[cursor] in line_terminators
            cursor += 1
        if text.startswith("//", cursor):
            newline = re.search(r"[\r\n\u2028\u2029]", text[cursor + 2 :])
            if newline is None:
                return True
            cursor += 2 + newline.start()
            saw_newline = True
            continue
        if text.startswith("/*", cursor):
            comment_end = text.find("*/", cursor + 2)
            if comment_end < 0:
                return True
            comment = text[cursor : comment_end + 2]
            saw_newline = saw_newline or any(
                terminator in comment for terminator in line_terminators
            )
            cursor = comment_end + 2
            continue
        break
    if cursor >= len(text):
        return True
    if text[cursor] in ";}])" or text[cursor] == ",":
        return True
    if saw_newline and (
        text.startswith(("++", "--"), cursor)
        or text[cursor] == "~"
        or (text[cursor] == "!" and not text.startswith("!=", cursor))
    ):
        return True
    continuation_keyword = re.match(
        (
            r"(?:as|in|instanceof|satisfies)(?![\w$])"
            if typescript
            else r"(?:in|instanceof)(?![\w$])"
        ),
        text[cursor:],
    )
    continuation = (
        text[cursor] in "=<>!~:+-*/%&|^?.,([`"
        or continuation_keyword is not None
    )
    if continuation:
        return not fallback_secret_risk(
            text[cursor:],
            javascript_dialect="typescript" if typescript else "javascript",
        )
    return saw_newline

def bare_code_reference(
    text: str,
    start: int,
    end: int,
    separator: str,
    value: str,
) -> bool:
    camel_reference = re.fullmatch(
        r"[a-z][A-Za-z0-9]*[A-Z][A-Za-z0-9]*",
        value,
    )
    snake_reference = re.fullmatch(
        r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+",
        value,
    )
    line_start = max(text.rfind("\n", 0, start), text.rfind("\r", 0, start))
    masked_text = mask_reference_declaration_evidence(text)
    declaration = masked_text[line_start + 1 : start]
    pascal_type_reference = re.fullmatch(
        r"[A-Z][A-Za-z]*(?:Credential|Credentials|Options|Config|Type|Enum)",
        value,
    )
    if separator == ":" and pascal_type_reference is not None:
        type_prefix = masked_text[
            max(0, start - 2048) : start
        ]
        if re.search(
            r"\b(?:class|interface|record|struct|type)\b"
            r"[^{};\r\n]*\{[^}]*$",
            type_prefix,
            re.DOTALL,
        ):
            return True
        # TS/JS named-function parameter annotations use PascalCase type names.
        function_prefix = re.search(
            r"\bfunction\b[^()\r\n]*\((?P<parameters>[^()]*)$",
            declaration,
        )
        annotation_suffix = re.match(
            r"[ \t\r\n]*(?P<terminator>[,)=])",
            text[end:],
        )
        if (
            function_prefix is not None
            and re.fullmatch(
                r"\s*(?:\.\.\.\s*)?",
                split_top_level_call_arguments(
                    function_prefix.group("parameters")
                )[-1],
            )
            and annotation_suffix is not None
        ):
            if annotation_suffix.group("terminator") != "=":
                return True
            return not fallback_secret_risk(
                text[end + annotation_suffix.end() :],
                minimum_length=8,
            )
    if camel_reference is None and snake_reference is None:
        return False
    return bool(
        re.search(r"\b(?:const|let|var)\s+$", declaration)
        or re.search(
            r"\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*=\s*\{[^{}]*$",
            declaration,
            re.DOTALL,
        )
    )

def python_control_reference_ranges(text: str) -> tuple[tuple[int, int], ...]:
    # A proved control-header colon never assigns its following body. Keep all
    # condition and body bytes in the credential scan, including walrus writes.
    rows = re.finditer(r"(?m)^[ \t]*(?:if|elif|while)[ \t]+[^\r\n]{1,8192}:[ \t]*(?:#[^\r\n]*)?\r?$", text)
    return tuple(span for row in rows if (span := python_control_header_colon(text, row)) is not None) + python_annotated_scalar_ranges(text)


def python_annotated_scalar_ranges(text):
    # Only parsed annotations with no credential data receive this syntax role.
    # Strings, calls and adjacent assignments keep their original value scan.
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return ()
    return tuple(span for node in ast.walk(tree)
                 for span in python_annotated_node_ranges(text, node))

def python_annotated_node_ranges(text, node):
    return tuple(span for target, annotation, value in python_annotated_node_values(node)
                 if (span := python_annotated_scalar_span(text, target, annotation, value)) is not None)


def python_annotated_node_values(node):
    # Positional defaults align to the last arguments; keyword-only defaults
    # retain their own slots. Both allowance and refusal scan these same values.
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = node.args.posonlyargs + node.args.args
        defaults = [None] * (len(args) - len(node.args.defaults)) + node.args.defaults
        pairs = list(zip(args, defaults)) + list(zip(node.args.kwonlyargs, node.args.kw_defaults))
        return tuple((arg, arg.annotation, value) for arg, value in pairs if arg.annotation is not None)
    if isinstance(node, ast.AnnAssign):
        return ((node.target, node.annotation, node.value),)
    return ()

def python_annotation_reference_type(annotation):
    allowed = (ast.Name, ast.Attribute, ast.Subscript, ast.Tuple, ast.Load, ast.BinOp, ast.BitOr)
    return annotation is not None and all(isinstance(node, allowed) for node in ast.walk(annotation))

def python_annotation_boolean_type(annotation):
    if isinstance(annotation, ast.Name):
        return annotation.id == 'bool'
    return isinstance(annotation, ast.Subscript) and isinstance(annotation.slice, ast.Name) and annotation.slice.id == 'bool'

def python_annotated_scalar_value(annotation, value):
    if value is None:
        return True
    if not isinstance(value, ast.Constant):
        return False
    return value.value is None or isinstance(value.value, bool) and python_annotation_boolean_type(annotation)

def python_annotated_scalar_span(text, target, annotation, value):
    if not python_annotation_reference_type(annotation) or not python_annotated_scalar_value(annotation, value):
        return None
    start = python_literal_source_position(text, target)
    end = python_literal_source_position(text, annotation)
    if end - start > 8192:
        return None
    prefix = SECRET_ASSIGNMENT_PREFIX_PATTERN.search(text, start, end)
    return prefix.span() if prefix is not None and prefix.group().rstrip().endswith(':') else None

def python_annotated_assignment_literal_risk(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return False
    return any(python_annotated_credential_value_risk(text, target, annotation, value)
               for node in ast.walk(tree)
               for target, annotation, value in python_annotated_node_values(node))

def python_annotated_assignment_key(target):
    if isinstance(target, ast.arg):
        return target.arg
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def python_annotated_credential_value_risk(text, target, annotation, value):
    if python_annotated_scalar_value(annotation, value):
        return False
    key = python_annotated_assignment_key(target)
    if key is None or SECRET_ASSIGNMENT_PREFIX_PATTERN.fullmatch(key + " = ") is None:
        return False
    source = ast.get_source_segment(text, value)
    # A type name must never replace a credential value in the refusal check.
    # Function defaults and annotated assignments share this actual-value owner.
    return source is None or len(source) > 8192 or secret_text_risk(key + " = " + source, python_source=True)

def python_control_header_colon(text, row):
    header = row.group().strip()
    if header.startswith("elif "):
        header = "if " + header[5:]
    try:
        tree = ast.parse(header + "\n    pass")
    except (SyntaxError, ValueError, RecursionError):
        return None
    if len(tree.body) != 1 or not isinstance(tree.body[0], (ast.If, ast.While)):
        return None
    colon = row.start() + row.group().rfind(":", 0, row.group().find("#") if "#" in row.group() else len(row.group()))
    return python_control_prefix_span(text, row, colon)

def python_control_prefix_span(text, row, colon):
    if string_contexts_at(text, {colon})[colon] is not None:
        return None
    prefixes = SECRET_ASSIGNMENT_PREFIX_PATTERN.finditer(row.group())
    return next(((row.start() + p.start(), colon + 1) for p in prefixes
                 if p.end() >= colon - row.start() + 1 and p.group().rstrip().endswith(":")), None)


def python_assignment_in_code(text: str, position: int) -> bool:
    line_start = text.rfind("\n", 0, position) + 1
    column = position - line_start
    if column >= 8192:
        return False
    # A credential name inside a comment is data, not a Python assignment.
    # Only inspect this bounded physical line; unknown syntax stays strict.
    source = text[line_start : line_start + 8192].split("\n", 1)[0]
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.end[0] > 1 or token.end[1] > column:
                return token.type != tokenize.COMMENT
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return False

def python_assignment_expression(
    text: str, start: int, *, mapping_entry: bool,
) -> tuple[str, ast.expr] | None:
    # Parse one value, not the next mapping entry or statement. Partial hunks
    # and expressions beyond this bound retain the existing strict scanner.
    source = text[start : start + 8192]
    lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    stack: list[str] = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    end: int | None = None
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            row, column = token.start
            position = offsets[min(row - 1, len(offsets) - 1)] + column
            if token.type == tokenize.COMMENT:
                # AST nodes omit comments. Keep the raw strict scan for any
                # expression whose discarded comment could contain a credential.
                return None
            if token.type == tokenize.OP:
                if token.string in pairs:
                    stack.append(pairs[token.string])
                elif token.string in ")]}":
                    if not stack:
                        end = position
                        break
                    if stack.pop() != token.string:
                        return None
                elif not stack and (
                    token.string == ";" or (mapping_entry and token.string == ",")
                ):
                    end = position
                    break
            elif token.type in {tokenize.NEWLINE, tokenize.ENDMARKER} and not stack:
                end = position
                break
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    if end is None or (end >= len(source) and start + len(source) < len(text)):
        return None
    # A delimiter can end the value before its physical statement ends.
    # Unchecked comments or continuations must keep the raw assignment scan.
    remainder = source[end:]
    physical_tail = remainder.split("\n", 1)[0]
    if ("#" in physical_tail or "\\" in physical_tail
            or ("\n" not in remainder and start + len(source) < len(text))):
        return None
    expression = source[:end].strip()
    try:
        return expression, ast.parse(expression, mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        return None

def python_mapping_selector(value: object) -> bool:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        return False
    # Selectors have field-name syntax. Opaque values and long unstructured
    # words remain literals; no receiver or project field names are allowlisted.
    # Check decoded literals before field-name syntax can exempt selectors.
    return not secret_literal_risk(value) and not uri_userinfo_literal_risk(value) and (
        len(value) < 12 or "_" in value or re.search(r"[a-z][A-Z]", value) is not None
    )

def python_mapping_call(part: ast.Call) -> bool:
    return (
        isinstance(part.func, ast.Attribute) and part.func.attr == "get"
        and 1 <= len(part.args) <= 2 and not part.keywords
    )

def python_call_field_selector(part: ast.Call, index: int, argument: ast.expr) -> bool:
    if index != 0:
        return False
    if not python_mapping_call(part):
        return False
    if not isinstance(argument, ast.Constant):
        return False
    return python_mapping_selector(argument.value)

def python_call_computed_reference(raw: str, target: str, argument: ast.expr) -> bool:
    if not isinstance(argument, ast.BinOp):
        return False
    if any(isinstance(child, ast.Constant) and python_literal_data_risk(child.value)
           for child in ast.walk(argument)):
        return False
    # This delegates reference arithmetic to the existing argument owner.
    # The literal walk still rejects data used to construct credential values.
    return not call_arguments_risk(raw, target)

def python_header_lookup_receiver(part: ast.AST) -> bool:
    if not isinstance(part, ast.Call) or not python_mapping_call(part):
        return False
    receiver = part.func.value
    if isinstance(receiver, ast.Attribute):
        return receiver.attr == "headers"
    return isinstance(receiver, ast.Name) and receiver.id == "headers"

def python_hyphenated_header_selector(value: object) -> bool:
    if not isinstance(value, str) or "-" not in value:
        return False
    if secret_literal_risk(value) or uri_userinfo_literal_risk(value):
        return False
    # A hyphenated header name locates a value. Keep the existing selector
    # length and decoded-credential checks before removing field separators.
    return python_mapping_selector(value.replace("-", ""))

def python_header_field_selector(part: ast.Call, index: int, argument: ast.expr) -> bool:
    if index != 0 or not python_header_lookup_receiver(part):
        return False
    if not isinstance(argument, ast.Constant):
        return False
    return python_hyphenated_header_selector(argument.value)

def python_bearer_prefix_call(part: ast.Call) -> bool:
    return (
        isinstance(part.func, ast.Attribute) and part.func.attr == "removeprefix"
        and len(part.args) == 1 and not part.keywords
    )

def python_bearer_prefix_argument(part: ast.Call, index: int, argument: ast.expr) -> bool:
    if index != 0 or not python_bearer_prefix_call(part):
        return False
    if not isinstance(argument, ast.Constant) or argument.value != "Bearer ":
        return False
    # This is a public authentication prefix, not a credential. Both walks
    # still inspect the lookup receiver, selector and every default argument.
    return python_header_lookup_receiver(part.func.value)

def python_call_reference_argument(
    expression: str, part: ast.Call, index: int, argument: ast.expr,
) -> bool:
    target = ast.get_source_segment(expression, part.func) or ""
    raw = ast.get_source_segment(expression, argument) or ""
    # Header/environment lookups use their established credential-lookup owner;
    # generic mapping-field heuristics must not override its accepted selector.
    if safe_credential_lookup_argument(target, raw, index):
        return True
    if any((
        python_call_field_selector(part, index, argument),
        python_header_field_selector(part, index, argument),
        python_bearer_prefix_argument(part, index, argument),
    )):
        return True
    return python_call_computed_reference(raw, target, argument)

def python_public_argument_index(target: str, index: int, keyword: str | None) -> int:
    if keyword is None:
        return index
    # Python keywords identify parameters independently of their source order.
    # Only the existing getpass prompt contract accepts a named public literal.
    return 0 if target == "getpass.getpass" and keyword == "prompt" else -1

def python_public_literal_argument(
    expression: str, part: ast.Call, index: int, argument: ast.expr,
    keyword: str | None = None,
) -> bool:
    if not isinstance(argument, ast.Constant):
        return False
    target = ast.get_source_segment(expression, part.func) or ""
    index = python_public_argument_index(target, index, keyword)
    if index != 0:
        return False
    raw = ast.get_source_segment(expression, argument) or ""
    if keyword is not None:
        raw = f"{keyword}={raw}"
    return public_call_argument_risk(target, raw, index) is False

def python_call_literal_nodes(expression: str, part: ast.Call):
    yield part.func
    for index, argument in enumerate(part.args):
        if (not python_call_reference_argument(expression, part, index, argument)
                and not python_public_literal_argument(expression, part, index, argument)):
            yield argument
    for index, keyword in enumerate(part.keywords, start=len(part.args)):
        if not python_public_literal_argument(expression, part, index, keyword.value, keyword.arg):
            yield keyword.value

def python_reference_literal_children(expression: str, part: ast.AST):
    if isinstance(part, ast.Call):
        # Public constants pass their existing argument owner before either walk.
        # Remaining literal arguments keep the strict construction check.
        return python_call_literal_nodes(expression, part)
    if isinstance(part, ast.Subscript):
        if python_reference_selector(part.slice):
            return (part.value,)
    return ast.iter_child_nodes(part)

def python_reference_selector(part: ast.AST) -> bool:
    if not isinstance(part, ast.Constant):
        return False
    # Numeric sequence indexes locate retained values; they are not byte data.
    return type(part.value) is int or python_mapping_selector(part.value)

def python_literal_data_risk(value: object) -> bool:
    return value is not None and value != "" and value != b""

def python_secrets_module_import(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.Import) and any(
            alias.name == "secrets" and alias.asname is None for alias in node.names
        ) for node in tree.body
    )

def python_secrets_import_binding_risk(node: ast.AST, alias: ast.alias) -> bool:
    if alias.name == "*":
        return True
    bound = alias.asname or alias.name.split(".")[0]
    if bound != "secrets":
        return False
    return not all((isinstance(node, ast.Import), alias.name == "secrets", alias.asname is None))

def python_secrets_binding_risk(node: ast.AST) -> bool:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return any(python_secrets_import_binding_risk(node, alias) for alias in node.names)
    if isinstance(node, ast.arg):
        return node.arg == "secrets"
    # These bindings occupy string fields, not Name(Store) nodes.
    # A shadowed receiver cannot prove that token_hex comes from stdlib.
    if isinstance(node, (
        ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
        ast.ExceptHandler, ast.MatchAs, ast.MatchStar,
    )):
        return node.name == "secrets"
    if isinstance(node, ast.MatchMapping):
        return node.rest == "secrets"
    return False

def python_secrets_reference_risk(node: ast.AST, parents: dict) -> bool:
    if not isinstance(node, ast.Name) or node.id != "secrets":
        return False
    attribute = parents.get(node)
    call = parents.get(attribute)
    return not all((
        isinstance(node.ctx, ast.Load), isinstance(attribute, ast.Attribute),
        getattr(attribute, "attr", None) == "token_hex",
        isinstance(getattr(attribute, "ctx", None), ast.Load),
        isinstance(call, ast.Call), getattr(call, "func", None) is attribute,
    ))

def python_secrets_namespace_risk(node: ast.AST) -> bool:
    function = getattr(node, "func", None)
    return any((
        all((isinstance(node, ast.Call), isinstance(function, ast.Name),
             getattr(function, "id", None) in {"exec", "eval", "globals", "locals", "vars", "__import__", "setattr"})),
        all((isinstance(node, ast.Attribute), getattr(node, "attr", None) == "token_hex",
             isinstance(getattr(node, "ctx", None), ast.Store))),
    ))

def python_stdlib_random_byte_source(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return False
    if not python_secrets_module_import(tree):
        return False
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    # A method spelling alone is not provenance. Require the stdlib import and
    # refuse rebinding, module escape or dynamic namespace mutation anywhere.
    return not any(any((
        python_secrets_binding_risk(node), python_secrets_reference_risk(node, parents),
        python_secrets_namespace_risk(node),
    )) for node in ast.walk(tree))

def python_secrets_token_hex_call(part: ast.AST) -> bool:
    if not isinstance(part, ast.Call):
        return False
    function = part.func
    return all((
        isinstance(function, ast.Attribute),
        isinstance(getattr(function, "value", None), ast.Name),
        getattr(getattr(function, "value", None), "id", None) == "secrets",
        getattr(function, "attr", None) == "token_hex",
    ))

def python_random_byte_parameter(part: ast.Call) -> ast.expr | None:
    if all((len(part.args) == 1, not part.keywords)):
        return part.args[0]
    if all((not part.args, len(part.keywords) == 1)):
        keyword = part.keywords[0]
        if keyword.arg == "nbytes":
            return keyword.value
    return None

def python_random_byte_count_call(part: ast.AST) -> bool:
    if not python_secrets_token_hex_call(part):
        return False
    argument = python_random_byte_parameter(part)
    if not isinstance(argument, ast.Constant):
        return False
    return argument.value is None or (type(argument.value) is int and argument.value >= 0)

def python_reference_literal_risk(
    expression: str, node: ast.AST, *, random_byte_metadata: bool = False,
) -> bool:
    pending = [node]
    while pending:
        part = pending.pop()
        if python_random_byte_count_call(part):
            if not random_byte_metadata:
                return True
            pending.append(part.func)
        elif isinstance(part, ast.Constant):
            if python_literal_data_risk(part.value):
                return True
        else:
            pending.extend(python_reference_literal_children(expression, part))
    return False

def python_call_literal_risk(
    expression: str, node: ast.AST, *, random_byte_metadata: bool = False,
) -> bool:
    # Calls may read named selectors, but literal arguments can assemble
    # credentials from short fragments. Never exempt those assignments.
    return any(
        python_reference_literal_risk(expression, part, random_byte_metadata=random_byte_metadata)
        for part in ast.walk(node) if isinstance(part, ast.Call)
    )

def python_named_reference(part: ast.AST) -> bool:
    return isinstance(part, ast.Name) or (
        isinstance(part, ast.Attribute) and python_named_reference(part.value)
    )

def python_string_reference_risk(value: str, selector: bool) -> bool:
    if uri_userinfo_literal_risk(value):
        return True
    if selector and python_mapping_selector(value):
        return False
    # Reference exemptions accept selectors, not assembled credential data.
    # Several short values can carry one secret across a container or branch.
    return bool(value)

def python_constant_reference_risk(part: ast.Constant, selector: bool) -> bool | None:
    if isinstance(part.value, str):
        return python_string_reference_risk(part.value, selector)
    if part.value is None:
        return False
    if isinstance(part.value, (bool, int, float)):
        return not selector
    return None

def python_computed_reference_risk(part: ast.AST) -> bool | None:
    # Literal fragments can reconstruct a credential. Never evaluate them.
    literal = any(isinstance(child, ast.Constant) and isinstance(child.value, (str, bytes))
                  for child in ast.walk(part))
    return True if literal else None

def python_dictionary_key_literal_risk(part: ast.Dict) -> bool:
    # Iteration exposes decoded keys in source order. Check their joined value
    # before field selectors can hide one credential across several fragments.
    keys = [key.value for key in part.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)]
    return secret_literal_risk("".join(keys))

def python_dictionary_reference_children(part: ast.Dict):
    # Numeric dictionary keys are data; numeric subscript indexes keep their
    # existing owner. Ordinary string field groups still carry references.
    selectors = not python_dictionary_key_literal_risk(part)
    children = [(key, selectors and isinstance(key, ast.Constant) and isinstance(key.value, str))
                for key in part.keys if key is not None]
    return children + [(value, False) for value in part.values]

def python_sequence_reference_children(part: ast.AST):
    fields = {
        ast.List: ("elts",), ast.Tuple: ("elts",), ast.Set: ("elts",),
        ast.IfExp: ("test", "body", "orelse"), ast.UnaryOp: ("operand",),
        ast.BoolOp: ("values",), ast.Compare: ("left", "comparators"),
    }.get(type(part))
    if fields is None:
        return None
    children = []
    for field in fields:
        value = getattr(part, field)
        children.extend(value if isinstance(value, list) else [value])
    return [(child, False) for child in children]

def python_call_reference_children(
    expression: str, part: ast.Call, *, random_byte_metadata: bool = False,
):
    if not isinstance(part.func, (ast.Name, ast.Attribute)):
        return None
    if random_byte_metadata and python_random_byte_count_call(part):
        return [(part.func, False)]
    # Traverse every receiver and unchecked argument. Public prompt literals
    # keep their argument contract; normalization cannot hide receiver data.
    return [(argument, False) for argument in python_call_literal_nodes(expression, part)]

def python_slice_reference_children(part: ast.Slice):
    # Integer bounds select retained bytes, not credential data. String bounds
    # and value-producing expressions still pass the ordinary literal walk.
    return [(bound, all((isinstance(bound, ast.Constant), type(getattr(bound, "value", None)) is int)))
            for bound in (part.lower, part.upper, part.step) if bound is not None]

def python_index_miss_comparison(part: ast.Compare) -> bool:
    # find() uses a negative index for absence. The zero in this predicate
    # selects retained source; it cannot contribute credential bytes.
    # Other numeric data and every string comparison keep the strict walk.
    return all((
        python_named_reference(part.left), len(part.ops) == 1,
        isinstance(part.ops[0], ast.Lt), len(part.comparators) == 1,
        isinstance(part.comparators[0], ast.Constant),
        type(getattr(part.comparators[0], "value", None)) is int,
        getattr(part.comparators[0], "value", None) == 0,
    ))


def python_comparison_reference_children(part: ast.Compare):
    if python_index_miss_comparison(part):
        return [(part.left, False), (part.comparators[0], True)]
    return python_sequence_reference_children(part)


def python_reference_children(
    expression: str, part: ast.AST, *, random_byte_metadata: bool = False,
):
    if isinstance(part, ast.Attribute):
        return [(part.value, False)]
    if isinstance(part, ast.Subscript):
        return [(part.value, False), (part.slice, True)]
    if isinstance(part, ast.Call):
        return python_call_reference_children(expression, part, random_byte_metadata=random_byte_metadata)
    owner = {
        ast.Dict: python_dictionary_reference_children,
        ast.Slice: python_slice_reference_children,
        ast.Compare: python_comparison_reference_children,
    }.get(type(part), python_sequence_reference_children)
    return owner(part)

def python_reference_children_risk(children, inspect, depth: int) -> bool | None:
    risks = [inspect(child, selector=selector, depth=depth + 1) for child, selector in children]
    if True in risks:
        return True
    return None if None in risks else False

def python_boolean_literal_with_comma(expression: str, node: ast.AST) -> bool:
    if not isinstance(node, ast.Tuple):
        return False
    if len(node.elts) != 1:
        return False
    literal = node.elts[0]
    # Hunk context can omit the call opener. A single bare boolean plus
    # comma keeps scalar literal checks; parentheses or more data keep
    # the strict tuple walk. No assignment or source bytes are exempted.
    return all((
        isinstance(literal, ast.Constant),
        type(getattr(literal, "value", None)) is bool,
        re.fullmatch(r"(?:True|False)[ \t\r\n]*,", expression) is not None,
    ))

def python_reference_risk(
    expression: str, node: ast.expr, *, random_byte_metadata: bool = False,
) -> bool | None:
    def inspect(part: ast.AST, *, selector: bool = False, depth: int = 0) -> bool | None:
        if depth > 64:
            return None
        if isinstance(part, ast.Constant):
            return python_constant_reference_risk(part, selector)
        if python_named_reference(part):
            return False
        if isinstance(part, (ast.BinOp, ast.JoinedStr)):
            return python_computed_reference_risk(part)
        children = python_reference_children(expression, part, random_byte_metadata=random_byte_metadata)
        if children is None:
            return None
        return python_reference_children_risk(children, inspect, depth)

    # Literal assignments retain field-matched fixture and literal checks.
    # This path recognizes reference expressions, never diagnostic prose.
    if any((isinstance(node, ast.Constant), python_boolean_literal_with_comma(expression, node))):
        return None
    try:
        if python_call_literal_risk(expression, node, random_byte_metadata=random_byte_metadata):
            return True
        return inspect(node)
    except RecursionError:
        return None

def python_public_call_literals(expression: str, part: ast.Call):
    for index, argument in enumerate(part.args):
        if python_public_literal_argument(expression, part, index, argument):
            yield argument
    for index, keyword in enumerate(part.keywords, start=len(part.args)):
        if python_public_literal_argument(expression, part, index, keyword.value, keyword.arg):
            yield keyword.value

def python_literal_source_position(expression: str, literal: ast.AST) -> int:
    lines = expression.splitlines(keepends=True)
    # AST columns count UTF-8 bytes; scanner positions count characters.
    column = len(lines[literal.lineno - 1].encode("utf-8")[:literal.col_offset].decode("utf-8"))
    return sum(len(line) for line in lines[:literal.lineno - 1]) + column

def python_public_literal_quotes(expression: str, node: ast.AST) -> set[int]:
    positions = set()
    for part in ast.walk(node):
        if isinstance(part, ast.Call):
            for literal in python_public_call_literals(expression, part):
                positions.add(python_literal_source_position(expression, literal))
    return positions

def python_literal_prefix_index(contexts) -> dict[int, set[int]]:
    positions = {}
    for position, context in contexts.items():
        if context is not None:
            positions.setdefault(context[1], set()).add(position)
    return positions

def python_public_literal_prefix_positions(text: str, prefix, expression: str, node: ast.AST,
                                          literal_prefixes) -> set[int]:
    source = text[prefix.end():prefix.end() + 8192]
    start = prefix.end() + len(source) - len(source.lstrip())
    quotes = {start + position for position in python_public_literal_quotes(expression, node)}
    # Only matches inside constants accepted by the public argument owner are
    # checked here. Every other assignment and literal keeps its normal scan.
    return set().union(*(literal_prefixes.get(quote, ()) for quote in quotes))

def python_source_literal_token(text: str, context: tuple[str, int]) -> str | None:
    quote, start = context
    # A complete delimiter must fit the existing 8192-character parse bound.
    # Excluding backslashes from the second branch keeps matching linear.
    delimiter = re.escape(quote)
    closing = re.compile(r"(?:\\[\s\S]|(?!" + delimiter + r")[^\\])*" + delimiter)
    end = closing.match(text, start + len(quote), min(len(text), start + 8192))
    if end is None:
        return None
    prefix = re.search(r"(?i)(?<!\w)(br|rb|fr|rf|[rubf])$", text[max(0, start - 3) : start])
    return (prefix.group(1) if prefix else "") + text[start : end.end()]

def python_source_literal_value(token: str | None) -> str | None:
    if token is None:
        return None
    try:
        node = ast.parse(token, mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        return None
    # Parsing only a scalar string decodes escapes without executing source.
    # Bytes and formatted strings keep the existing strict scan.
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

def python_reviewed_literal_prefixes(text: str, contexts, depth: int) -> set[int] | None:
    reviewed: set[int] = set()
    for positions in python_literal_prefix_index(contexts).values():
        context = contexts[next(iter(positions))]
        payload = python_source_literal_value(python_source_literal_token(text, context))
        if payload is None:
            continue
        if python_fixture_literal_owned(text, context, payload):
            reviewed.update(positions)
            continue
        # Recheck all decoded content inside this delimiter before reviewing
        # its prefixes. Eight quoting layers bound repeated decoding work.
        if depth >= 8:
            return None
        if secret_text_risk(payload, python_source=True, _python_literal_depth=depth + 1):
            return None
        reviewed.update(positions)
    return reviewed


def python_null_uuid_operands(zero: ast.AST, count: ast.AST) -> bool:
    return all((
        isinstance(zero, ast.Constant), getattr(zero, "value", None) == "0",
        isinstance(count, ast.Constant), type(getattr(count, "value", None)) is int,
        getattr(count, "value", None) == 32,
    ))


def python_null_uuid_repeat(part: ast.AST) -> bool:
    if not all((isinstance(part, ast.BinOp), isinstance(getattr(part, "op", None), ast.Mult))):
        return False
    return any(python_null_uuid_operands(zero, count)
               for zero, count in ((part.left, part.right), (part.right, part.left)))


def python_volume_fixture_entries(part: ast.Dict):
    if len(part.keys) != 2 or any(not isinstance(key, ast.Constant) for key in part.keys):
        return None
    keys = [key.value for key in part.keys]
    if set(keys) != {"token", "volume_name"}:
        return None
    index = keys.index("token")
    return part.keys[index], part.values[index], part.values[keys.index("volume_name")]


def python_volume_fixture_prefix(part: ast.AST) -> bool:
    prefix = part.value if isinstance(part, ast.Constant) else None
    if not isinstance(prefix, str):
        return False
    return all((
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}-", prefix) is not None,
        not secret_literal_risk(repr(prefix)),
    ))


def python_volume_fixture_name(part: ast.AST) -> bool:
    if not all((isinstance(part, ast.BinOp), isinstance(getattr(part, "op", None), ast.Add))):
        return False
    return python_volume_fixture_prefix(part.left) and python_null_uuid_repeat(part.right)


def python_volume_fixture_token(part: ast.Dict) -> ast.Constant | None:
    entries = python_volume_fixture_entries(part)
    if entries is None:
        return None
    key, token, name = entries
    return key if python_null_uuid_repeat(token) and python_volume_fixture_name(name) else None


def python_statement_reference_starts(text: str, start: int, end: int) -> tuple[set[int], set[int]]:
    source = text[start:end]
    start += len(source) - len(source.lstrip())
    source = source.strip()
    if not source or len(source) > 8192:
        return set(), set()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return set(), set()
    keywords = {
        start + python_literal_source_position(source, part)
        for part in ast.walk(tree) if isinstance(part, ast.keyword)
    }
    return keywords, python_statement_fixture_starts(source, start, tree)


def python_statement_fixture_starts(source: str, start: int, tree: ast.Module) -> set[int]:
    fixtures = set()
    # Only a complete two-field volume identity proves this null UUID is
    # fixture metadata. Bare token repeats, duplicate keys and suffix data
    # keep their normal checks; no UUID value is globally exempted.
    for part in ast.walk(tree):
        if isinstance(part, ast.Dict):
            token = python_volume_fixture_token(part)
            if token is not None:
                fixtures.add(start + python_literal_source_position(source, token))
    return fixtures


def python_assignment_statement_starts(text: str, assignment_prefixes) -> tuple[set[int], set[int]]:
    # Only complete bounded statements establish keyword commas and paired
    # fixture identities. Unknown syntax keeps every original literal check.
    if not assignment_prefixes:
        return set(), set()
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    keywords: set[int] = set()
    fixtures: set[int] = set()
    start = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.NEWLINE:
                end = offsets[min(token.start[0] - 1, len(offsets) - 1)] + token.start[1]
                local_keywords, local_fixtures = python_statement_reference_starts(text, start, end)
                keywords.update(local_keywords)
                fixtures.update(local_fixtures)
                start = end + len(token.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return keywords, fixtures


def python_assignment_reference_prefixes(text: str, prefix, contexts, literal_prefixes,
                                         keyword_starts=(), *, random_byte_metadata: bool = False) -> set[int] | None:
    # Empty results leave unknown expressions in the raw scan. None preserves
    # an explicit risky-expression refusal at the decision owner.
    if contexts[prefix.start()] is not None or not python_assignment_in_code(text, prefix.start()):
        return set()
    parsed = python_assignment_expression(
        text, prefix.end(), mapping_entry=any((prefix.group().rstrip().endswith(":"),
                           prefix.start() in keyword_starts)),
    )
    if parsed is None:
        return set()
    expression, node = parsed
    risk = python_reference_risk(expression, node, random_byte_metadata=random_byte_metadata)
    if risk is True:
        return None
    if risk is False:
        references = {prefix.start()}
        references.update(python_public_literal_prefix_positions(
            text, prefix, expression, node, literal_prefixes,
        ))
        return references
    return set()

def python_supported_resolver_import(part: ast.AST) -> bool:
    return all((
        isinstance(part, ast.ImportFrom), getattr(part, "module", None) == "core.secrets",
        getattr(part, "level", None) == 0,
        any(alias.name == "resolve_secret" and alias.asname is None
            for alias in getattr(part, "names", ())),
    ))


def python_resolver_binding_risk(part: ast.AST) -> bool:
    if isinstance(part, ast.Name):
        return part.id == "resolve_secret" and isinstance(part.ctx, (ast.Store, ast.Del))
    if isinstance(part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.arg)):
        return getattr(part, "name", getattr(part, "arg", None)) == "resolve_secret"
    if isinstance(part, (ast.Import, ast.ImportFrom)):
        return python_resolver_import_risk(part)
    return python_resolver_dynamic_binding(part)


def python_resolver_import_risk(part: ast.AST) -> bool:
    for alias in part.names:
        if alias.name == "*":
            return True
        bound = alias.asname or alias.name.split(".")[0]
        if bound == "resolve_secret" and not all((
            python_supported_resolver_import(part), alias.name == "resolve_secret", alias.asname is None,
        )):
            return True
    return False


def python_resolver_dynamic_binding(part: ast.AST) -> bool:
    if isinstance(part, (ast.Global, ast.Nonlocal)):
        return "resolve_secret" in part.names
    if isinstance(part, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        return part.name == "resolve_secret"
    if isinstance(part, ast.MatchMapping):
        return part.rest == "resolve_secret"
    if isinstance(part, ast.Call) and isinstance(part.func, ast.Name):
        return part.func.id in {"exec", "eval", "globals", "locals", "vars", "__import__"}
    return python_resolver_namespace_access(part)


def python_resolver_namespace_access(part: ast.AST) -> bool:
    return all((
        isinstance(part, ast.Attribute), getattr(part, "attr", None) == "modules",
        isinstance(getattr(part, "value", None), ast.Name),
        getattr(getattr(part, "value", None), "id", None) == "sys",
    ))


def python_statement_blocks(tree: ast.Module):
    for part in ast.walk(tree):
        for _, value in ast.iter_fields(part):
            if python_statement_block(value):
                yield value


def python_statement_block(value: object) -> bool:
    return all((isinstance(value, list), bool(value))) and all(
        isinstance(item, ast.stmt) for item in value
    )


def python_resolver_block_calls(text: str, block) -> set[int]:
    bound = False
    positions = set()
    for statement in block:
        if python_supported_resolver_import(statement):
            bound = True
        expression = getattr(statement, "value", None)
        if bound and python_resolver_call_name(expression):
            positions.add(python_literal_source_position(text, expression.func))
    return positions


def python_resolver_call_name(part: ast.AST | None) -> bool:
    return all((
        isinstance(part, ast.Call), isinstance(getattr(part, "func", None), ast.Name),
        getattr(getattr(part, "func", None), "id", None) == "resolve_secret",
    ))


def python_resolver_reference_risk(part: ast.AST, parent: ast.AST | None) -> bool:
    if isinstance(part, ast.Name) and part.id == "resolve_secret":
        if not isinstance(part.ctx, ast.Load):
            return True
        # Passing or mutating the imported function loses its lookup contract.
        # Only a direct call receiver keeps this source proof.
        return not isinstance(parent, ast.Call) or parent.func is not part
    return python_resolver_binding_risk(part)


def python_resolver_tree_binding_risk(tree: ast.Module) -> bool:
    parents = {child: part for part in ast.walk(tree) for child in ast.iter_child_nodes(part)}
    return any(python_resolver_reference_risk(part, parents.get(part)) for part in ast.walk(tree))


def python_bound_resolver_calls(text: str) -> set[int]:
    if "resolve_secret" not in text:
        return set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    # The supplied API contract owns this exact import. A local function,
    # method, alias, rebinding or incomplete hunk cannot prove that contract.
    if python_resolver_tree_binding_risk(tree):
        return set()
    positions = set()
    for block in python_statement_blocks(tree):
        positions.update(python_resolver_block_calls(text, block))
    return positions


def python_resolver_boolean_option(keyword: ast.keyword) -> bool:
    return all((
        keyword.arg in {"required", "audit"}, isinstance(keyword.value, ast.Constant),
        type(getattr(keyword.value, "value", None)) is bool,
    ))


def python_resolver_selector(part: ast.AST) -> bool:
    if not isinstance(part, ast.Constant) or not isinstance(part.value, str):
        return False
    return all((
        python_structured_environment_selector(part.value),
        not secret_literal_risk(part.value),
        safe_credential_lookup_argument("os.getenv", repr(part.value), 0),
    ))


def python_structured_environment_selector(value: str) -> bool:
    # The argument names an environment field. Opaque single words and long
    # encoded components cannot establish that role, even with an import.
    return re.fullmatch(r"[A-Z][A-Z0-9]{0,18}(?:_[A-Z][A-Z0-9]{0,18})+", value) is not None


def python_bound_resolver_assignment(text: str, prefix, positions: set[int]) -> bool:
    source = text[prefix.end():prefix.end() + 8192]
    start = prefix.end() + len(source) - len(source.lstrip())
    if start not in positions:
        return False
    parsed = python_assignment_expression(text, prefix.end(), mapping_entry=False)
    if parsed is None:
        return False
    _, call = parsed
    if not all((python_resolver_call_name(call), len(getattr(call, "args", ())) == 1)):
        return False
    return python_resolver_selector(call.args[0]) and all(
        python_resolver_boolean_option(keyword) for keyword in call.keywords
    )


def python_named_assignment_literal_risk(text) -> bool:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return False
    return any(python_named_credential_value_risk(text, node) for node in ast.walk(tree) if isinstance(node, ast.NamedExpr))


def python_named_credential_value_risk(text, node) -> bool:
    assignment = node.target.id + " = "
    if SECRET_ASSIGNMENT_PREFIX_PATTERN.fullmatch(assignment) is None:
        return False
    value = ast.get_source_segment(text, node.value)
    return value is None or secret_text_risk(assignment + value, python_source=True)


def python_reviewed_reference_prefixes(text, contexts, depth):
    return None if python_named_assignment_literal_risk(text) else python_reviewed_literal_prefixes(text, contexts, depth)


def python_source_reference_preflight(text: str, assignment_prefixes, depth: int) -> set[int] | None:
    contexts = string_contexts_at(text, {prefix.start() for prefix in assignment_prefixes})
    references = python_reviewed_reference_prefixes(text, contexts, depth)
    if any((references is None, python_annotated_assignment_literal_risk(text))):
        return None
    literal_prefixes = python_literal_prefix_index(contexts)
    keyword_starts, fixture_starts = python_assignment_statement_starts(text, assignment_prefixes)
    references.update(fixture_starts)
    random_byte_metadata = python_stdlib_random_byte_source(text)
    resolver_calls = python_bound_resolver_calls(text)
    for prefix in assignment_prefixes:
        if any((prefix.start() in fixture_starts, python_bound_resolver_assignment(text, prefix, resolver_calls))):
            references.add(prefix.start())
            continue
        assignment = python_assignment_reference_prefixes(
            text, prefix, contexts, literal_prefixes, keyword_starts, random_byte_metadata=random_byte_metadata,
        )
        if assignment is None:
            return None
        references.update(assignment)
    return references

def basic_authorization_risk(text: str) -> bool:
    for match in BASIC_AUTHORIZATION_PATTERN.finditer(text):
        encoded = match.group("credential")
        padded = encoded + "=" * (-len(encoded) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if b":" in decoded:
            return True
    return False

def shell_environment_selector_ranges(text: str) -> tuple[tuple[int, int], ...]:
    # An anchored grep pattern with no value selects an environment field.
    # Mask only that field, so neighbouring values keep every credential check.
    pattern = re.compile(
        r"""(?m)(?:^|[;&|])[ \t]*(?:/(?:[A-Za-z0-9_.-]+/)*)?grep"""
        r"""(?:[ \t]+(?:-E|--extended-regexp))*[ \t]+(?P<quote>['"])"""
        r"""\^(?P<name>[A-Za-z_][A-Za-z0-9_]{0,127})=(?P=quote)(?=[ \t\r\n;&|]|$)"""
    )
    return tuple((match.start("name"), match.end("name") + 1)
                 for match in pattern.finditer(text))

def documentation_comment_prefix(text: str, position: int) -> str | None:
    start = max(0, position - 8192)
    boundary = max(text.rfind("\n", start, position), text.rfind("\r", start, position))
    if boundary < 0 and start > 0:
        return None
    return text[boundary + 1 : position]

def documentation_component_risk(component: str) -> bool:
    # URI userinfo allows some single-class strings. A document name cannot
    # justify publishing a long opaque value after a credential label.
    return uri_userinfo_literal_risk(component) or len(re.sub(r"[^A-Za-z0-9]", "", component)) >= 20

def documentation_comment_reference(text: str, prefix: re.Match[str]) -> bool:
    before = documentation_comment_prefix(text, prefix.start())
    if before is None or re.fullmatch(r"[ \t]*#[^\r\n]*[A-Za-z][^\r\n]*[ \t]", before) is None:
        return False
    suffix = text[prefix.end() : prefix.end() + 8193].partition("\n")[0]
    reference = re.fullmatch(
        r"(?P<path>(?:\.{1,2}/)?(?:[A-Za-z0-9_.-]+/)+"
        r"[A-Za-z0-9_.-]+\.(?:md|rst|adoc))\.?[ \t]*\r?", suffix,
    )
    if len(suffix) > 8192 or reference is None:
        return False
    # A prose link is a file reference, not the value of the named credential.
    # Keep opaque components, trailing content and every other comment scanned.
    stem = reference.group("path").rsplit(".", 1)[0]
    return not any(documentation_component_risk(part) for part in stem.split("/"))

def documentation_comment_reference_ranges(text: str) -> tuple[tuple[int, int], ...]:
    return tuple((prefix.start(), prefix.end())
                 for prefix in SECRET_ASSIGNMENT_PREFIX_PATTERN.finditer(text)
                 if documentation_comment_reference(text, prefix))

def javascript_sequential_redaction_fixture_ranges(text, dialect):
    if dialect is None:
        return ()
    # A fixed alphabet/count sequence plus an actual negative redaction assertion
    # identifies test data. Changed payloads and assertion text in comments fail.
    value = "sk-or-v1-" + "abcdef" + "0123456789"
    if not javascript_negative_redaction_assertion(text, value):
        return ()
    matches = tuple(re.finditer(re.escape(value) + r"(?![\w-])", text))
    contexts = string_contexts_at(text, {m.start() for m in matches})
    return tuple(span for m in matches if (span := javascript_redaction_fixture_span(text, m, contexts[m.start()])) is not None)


def javascript_negative_redaction_assertion(text, value):
    assertion = re.compile(r"\bexpect\([^()\r\n]{1,256}\)\.not\.toContain\(\s*([\"'])" + re.escape(value) + r"\1\s*\)")
    code = javascript_binding_code(text)
    return any(code[m.start():m.start() + 6] == "expect" for m in assertion.finditer(text))


def javascript_redaction_fixture_span(text, match, context):
    if context is None or text[match.end():match.end() + 1] != context[0]:
        return None
    suffix = text[match.end() + 1:].lstrip()
    if not suffix.startswith((")", ",", ";")):
        return None
    prefix = javascript_redaction_fixture_prefix(text, context[1], match.start())
    return (prefix.start() if prefix is not None else match.start(), match.end())


def javascript_redaction_fixture_prefix(text, start, end):
    return next((p for p in SECRET_ASSIGNMENT_PREFIX_PATTERN.finditer(text, start, end) if p.end() == end), None)


def secret_assignment_suffix_text(text, prefix):
    context = string_contexts_at(text, {prefix.start()})[prefix.start()]
    if context is None:
        return text[prefix.end():]
    token = python_source_literal_token(text, context)
    if token is None:
        return text[prefix.end():]
    quote, start = context
    end = start + len(token) - token.index(quote) - len(quote)
    return text[prefix.end():end]


def javascript_reference_prefix_literal_risk(text, prefix, dialect) -> bool:
    if dialect is None:
        return False
    selected = javascript_reference_assignment_expression(text, javascript_binding_code(text), prefix)
    if selected is None:
        return False
    # A declined conditional proof must keep its literal refusal. Its raw
    # suffix cannot recover a scoped value hidden behind another operand.
    if len(selected) > 8192:
        return True
    if javascript_expression_has_literal(selected):
        return False
    return not javascript_proven_reference_expression(text, prefix.end(), selected)

def short_bare_secret_reference(match, value) -> bool:
    return match.group("bare_value") is not None and len(value) < 12 and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value) is not None

def safe_short_secret_reference(text, match, value, dialect) -> bool:
    if not safe_secret_assignment_suffix(text, match.end(), javascript_dialect=dialect):
        return False
    if dialect is None:
        return True
    code = javascript_binding_code(text)
    # A short name is still a value origin when source declares it. Follow
    # that binding through the same bounded graph as longer references so
    # aliases cannot hide credential bytes behind the spelling length.
    return not javascript_short_reference_declared(text, code, value) or declared_javascript_secret_reference(text, match.end() - len(value), value)

def javascript_short_reference_declared(text, code, value) -> bool:
    return re.search(r"\b(?:const|let|var)\s+" + re.escape(value) + r"(?![\w$])", code) is not None or javascript_parameter_declared(code, value) or bool(javascript_destructured_binding_initializers(text, code, value))

def secret_text_risk(
    text: str,
    *,
    javascript_dialect: str | None = None,
    go_source: bool = False,
    compose_source: bool = False,
    python_source: bool = False,
    _python_literal_depth: int = 0,
) -> bool:
    uri_authorities = uri_authority_ranges(text)
    fixture_ranges = javascript_sequential_redaction_fixture_ranges(text, javascript_dialect)
    fixture_scan_text = mask_ranges(text, fixture_ranges)
    if credentialed_uri_risk(text, uri_authorities, compose_source=compose_source) or basic_authorization_risk(text) or captured_fixture_secret_value_risk(fixture_scan_text):
        return True
    safe_assignment_ranges = interpolated_empty_password_uri_ranges(
        text,
        uri_authorities,
    )
    safe_assignment_ranges += fixture_ranges
    safe_assignment_ranges += shell_environment_selector_ranges(text)
    safe_assignment_ranges += documentation_comment_reference_ranges(text)
    safe_assignment_ranges += typescript_type_reference_ranges(text, javascript_dialect)
    safe_assignment_ranges += typescript_ambient_member_reference_ranges(text)

    if compose_source:
        safe_assignment_ranges += compose_required_uri_variable_ranges(text, uri_authorities)
        safe_assignment_ranges += compose_environment_reference_ranges(text)
        safe_assignment_ranges += compose_mount_reference_ranges(text)
    if python_source:
        safe_assignment_ranges += python_control_reference_ranges(text) + python_fixture_prefix_ranges(text)
    safe_assignment_ranges += javascript_source_assignment_ranges(text, javascript_dialect, safe_assignment_ranges)
    assignment_scan_text = mask_ranges(text, safe_assignment_ranges)
    assignment_prefixes = secret_assignment_matches(
        SECRET_ASSIGNMENT_PREFIX_PATTERN,
        text,
        assignment_scan_text,
        safe_assignment_ranges,
    )
    python_references: set[int] = set()
    if python_source:
        python_references = python_source_reference_preflight(text, assignment_prefixes, _python_literal_depth)
        if python_references is None:
            return True
    chained_assignment_positions = top_level_line_assignment_positions(
        text,
        {prefix.start() for prefix in assignment_prefixes},
    )
    source_reference_spans = (
        javascript_reference_spans(text)
        if javascript_dialect is not None
        else frozenset()
    )
    for prefix in assignment_prefixes:
        if prefix.start() in python_references:
            continue
        if javascript_dialect is not None:
            code = javascript_binding_code(text)
            if code[prefix.start():prefix.end()] == prefix.group():
                expression = fallback_expression(text[prefix.end():], typescript=True)
                if not javascript_expression_has_literal(expression) and javascript_scoped_code_expression(text, prefix.end(), expression) is False:
                    return True

        if javascript_reference_prefix_literal_risk(text, prefix, javascript_dialect):
            return True
        fallback = top_level_fallback_suffix(
            secret_assignment_suffix_text(text, prefix),
            allow_chained_assignment=(
                re.search(r"=(?!=|>)\s*$", prefix.group(0)) is not None
                and prefix.start() in chained_assignment_positions
            ),
        )
        if fallback is not None and fallback_secret_risk(
            fallback,
            javascript_dialect=javascript_dialect,
        ):
            return True
    for match in secret_assignment_matches(
        SECRET_ASSIGNMENT_PATTERN,
        text,
        assignment_scan_text,
        safe_assignment_ranges,
    ):
        if match.start() in python_references:
            continue
        quoted = any(
            match.group(name) is not None
            for name in ("double_value", "single_value", "backtick_value")
        )
        value = (
            match.group("double_value")
            or match.group("single_value")
            or match.group("backtick_value")
            or match.group("reference_value")
            or match.group("call_value")
            or match.group("bare_value")
        )
        if value is None:
            continue
        key = re.split(r"\s*[:=]\s*", match.group(0), maxsplit=1)[0]
        separator_match = re.search(r"[:=]", match.group(0))
        assert separator_match is not None
        separator = separator_match.group(0)
        if (
            key.strip("\"'").lower() == "credentials"
            and value.lower() in FETCH_CREDENTIAL_MODE_VALUES
            and safe_secret_assignment_suffix(
                text,
                match.end(),
                javascript_dialect=javascript_dialect,
            )
        ):
            continue
        if (
            match.group("backtick_value") is not None
            and (
                any(
                    pattern.fullmatch(value)
                    for pattern in BACKTICK_SECRET_REFERENCE_PATTERNS
                )
                or safe_backtick_secret_template(value)
            )
            and safe_secret_assignment_suffix(
                text,
                match.end(),
                javascript_dialect=javascript_dialect,
            )
        ):
            continue
        if value.endswith("-") and synthetic_secret_fixture(value[:-1], key):
            # A fixture prefix may be completed by the standard random generator.
            # Keep its numeric argument exact; scan every following suffix.
            generated = re.match(
                r"[ \t]*\+[ \t]*secrets\.token_hex\([ \t]*[1-9][0-9]*[ \t]*\)",
                text[match.end() :],
            )
            if generated is not None and safe_secret_assignment_suffix(
                text,
                match.end() + generated.end(),
                javascript_dialect=javascript_dialect,
            ):
                continue
            return True
        if synthetic_secret_fixture(value, key):
            if safe_secret_assignment_suffix(
                text,
                match.end(),
                javascript_dialect=javascript_dialect,
            ):
                continue
            return True
        if go_source and not quoted and re.fullmatch(
            r"&[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value
        ):
            # Only verified Go paths treat address-of identifiers as references.
            # Require a boundary so calls, indexes and literals stay refused.
            if (
                re.match(r"[ \t]*(?:\r?\n|[,;)\]}]|$)", text[match.end() :])
                and safe_secret_assignment_suffix(
                    text, match.end(), javascript_dialect=javascript_dialect
                )
            ):
                continue
            return True
        if short_bare_secret_reference(match, value):
            if safe_short_secret_reference(text, match, value, javascript_dialect):
                continue
            return True
        if (
            match.group("bare_value") is not None
            and bare_code_reference(
                text,
                match.start(),
                match.end(),
                separator,
                value,
            )
            and safe_secret_assignment_suffix(
                text,
                match.end(),
                javascript_dialect=javascript_dialect,
            )
        ):
            continue
        if not quoted:
            source_start = match.end() - len(value)
            source_end = match.end() - (1 if value.endswith("!") else 0)
            if (
                (
                    (source_start, source_end) in source_reference_spans
                    or (
                        javascript_dialect is not None
                        and SOURCE_CODE_REFERENCE_ROOT_PATTERN.fullmatch(value)
                    )
                    or (
                        javascript_dialect is not None
                        and declared_javascript_secret_reference(text, source_start, value)
                    )
                )
                and safe_javascript_reference_suffix(
                    text,
                    match.end(),
                    typescript=javascript_dialect == "typescript",
                )
            ):
                continue
        reference_patterns = (
            QUOTED_SECRET_REFERENCE_PATTERNS
            if quoted
            else UNQUOTED_SECRET_REFERENCE_PATTERNS
        )
        call_target = re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|\?\.)[A-Za-z_][A-Za-z0-9_]*)*",
            value,
        )
        suffix = text[match.end() :]
        # Crossing a newline can misread the next shell subshell as this value's call.
        whitespace = re.match(r"[ \t]*", suffix)
        assert whitespace is not None
        call_start = match.end() + whitespace.end()
        if (
            call_start > match.end()
            and text[call_start : call_start + 1] == "("
        ):
            if (
                call_target
                and call_target.group(0).replace("?.", ".")
                in PUBLIC_PROMPT_TARGETS
                and safe_secret_call_suffix(
                    text,
                    call_start,
                    call_target.group(0),
                    javascript_dialect=javascript_dialect,
                )
            ):
                continue
            return True
        if (
            not quoted
            and call_target
            and text[call_start : call_start + 1] == "("
        ):
            if safe_secret_call_suffix(
                text,
                call_start,
                value,
                javascript_dialect=javascript_dialect,
            ):
                continue
            return True
        if any(pattern.fullmatch(value) for pattern in reference_patterns):
            if safe_secret_assignment_suffix(
                text,
                match.end(),
                javascript_dialect=javascript_dialect,
            ):
                continue
            return True
        return True
    return False



def require_no_secret_values(
    label: str,
    text: str,
    *,
    javascript_dialect: str | None = None,
    go_source: bool = False,
    compose_source: bool = False,
    python_source: bool = False,
) -> None:
    if secret_text_risk(
        text, javascript_dialect=javascript_dialect, go_source=go_source,
        compose_source=compose_source,
        python_source=python_source,
    ):
        raise SystemExit(
            "refusing to include secret-like content in review bundle; "
            f"clean or redact {label} before running autoreview"
        )

def javascript_review_dialect(rel: str) -> str | None:
    suffix = Path(rel).suffix.lower()
    if suffix in {".cts", ".mts", ".ts", ".tsx"}:
        return "typescript"
    if suffix in {".cjs", ".js", ".jsx", ".mjs"}:
        return "javascript"
    return None

def compose_review_path(rel: str) -> bool:
    return re.fullmatch(
        r"(?:docker-)?compose(?:\.[A-Za-z0-9_-]+)*\.ya?ml", Path(rel).name,
    ) is not None

def unified_diff_contents(patch: str) -> tuple[str, str]:
    old_content: list[str] = []
    new_content: list[str] = []
    in_hunk = False
    prefix_columns = 1
    for line in patch.splitlines():
        hunk_header = re.match(r"^(@{2,})", line)
        if hunk_header:
            old_content.append(";")
            new_content.append(";")
            in_hunk = True
            prefix_columns = len(hunk_header.group(1)) - 1
            continue
        if line.startswith("diff --"):
            old_content.append(";")
            new_content.append(";")
            in_hunk = False
            continue
        prefix = line[:prefix_columns]
        if in_hunk and len(prefix) == prefix_columns and set(prefix) <= {"+", "-", " "}:
            content = line[prefix_columns:]
            if set(prefix) == {" "}:
                old_content.append(content)
                new_content.append(content)
            elif "+" in prefix and "-" not in prefix:
                new_content.append(content)
            elif "-" in prefix and "+" not in prefix:
                old_content.append(content)
            else:
                old_content.append(content)
                new_content.append(content)
    return "\n".join(old_content), "\n".join(new_content)

def unified_diff_metadata(patch: str) -> str:
    metadata: list[str] = []
    in_hunk = False
    prefix_columns = 1
    for line in patch.splitlines():
        hunk_header = re.match(r"^(@{2,})", line)
        if hunk_header:
            metadata.append(line)
            in_hunk = True
            prefix_columns = len(hunk_header.group(1)) - 1
            continue
        if line.startswith("diff --"):
            metadata.append(line)
            in_hunk = False
            continue
        prefix = line[:prefix_columns]
        hunk_content = (
            in_hunk
            and len(prefix) == prefix_columns
            and set(prefix) <= {"+", "-", " "}
        )
        if not hunk_content:
            metadata.append(line)
    return "\n".join(metadata)

def git_c_unquote(value: str) -> str | None:
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return None
    escapes = {
        "a": 7,
        "b": 8,
        "f": 12,
        "n": 10,
        "r": 13,
        "t": 9,
        "v": 11,
        "\\": 92,
        '"': 34,
    }
    decoded = bytearray()
    cursor = 1
    while cursor < len(value) - 1:
        char = value[cursor]
        if char != "\\":
            decoded.extend(char.encode("utf-8"))
            cursor += 1
            continue
        cursor += 1
        if cursor >= len(value) - 1:
            return None
        escape = value[cursor]
        if escape in escapes:
            decoded.append(escapes[escape])
            cursor += 1
            continue
        octal = re.match(r"[0-7]{1,3}", value[cursor:-1])
        if octal is None:
            return None
        decoded.append(int(octal.group(0), 8))
        cursor += octal.end()
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None

def diff_marker_path(value: str) -> str | None:
    if value == "/dev/null":
        return None
    if value.startswith('"'):
        decoded = git_c_unquote(value)
        if decoded is None:
            return None
        value = decoded
    if not value.startswith(("a/", "b/")):
        return None
    return value[2:]

def diff_section_paths(section: str) -> tuple[str | None, str | None]:
    old_path: str | None = None
    new_path: str | None = None
    for line in section.splitlines():
        if line.startswith("@@"):
            break
        if line.startswith("--- "):
            old_path = diff_marker_path(line[4:])
        elif line.startswith("+++ "):
            new_path = diff_marker_path(line[4:])
    return old_path, new_path

def diff_section_source_contents(section: str) -> list[tuple[str | None, str]]:
    paths = diff_section_paths(section)
    # Omitted lines can close a quoted block. Hunk fragments are not adjacent
    # source, so scan every old/new fragment without carrying quote state across gaps.
    hunks = re.split(r"(?m)(?=^@@)", section)[1:]
    return [(rel, content) for hunk in hunks
            for rel, content in zip(paths, unified_diff_contents(hunk))]


class JsonObjectMembers(tuple):
    """Preserve every object member, including overwritten duplicate keys."""


class JsonNumber(str):
    """Retain numeric spelling so decoding cannot shorten credential literals."""


def json_nonfinite_constant(value: str):
    raise ValueError('nonfinite JSON number')


def json_scalar_spelling(value: Any) -> str:
    return str(value) if isinstance(value, JsonNumber) else json.dumps(value)


def json_member_risk(key: str, value: Any, depth: int) -> bool:
    if secret_text_risk(key):
        return True
    prefix = json.dumps(key) + ': '
    if SECRET_ASSIGNMENT_PREFIX_PATTERN.fullmatch(prefix):
        # A credential-labelled container cannot prove a reference. Keep its
        # literal data refused; ordinary members retain independent decoding.
        if isinstance(value, (JsonObjectMembers, list)):
            return True
        if secret_text_risk(prefix + json_scalar_spelling(value)):
            return True
    return json_value_risk(value, depth + 1)


def json_bound_source_path(value):
    # A complete captured-source record supplies its language and exact bytes.
    # Duplicate members and unbound strings retain ordinary decoded-data checks.
    if len(value) != 4 or {key for key, _ in value} != {"path", "bytes", "sha256", "source"}:
        return None
    fields = dict(value)
    if not all(isinstance(fields[key], str) for key in ("path", "source", "sha256")):
        return None
    return json_valid_source_binding(fields)


def json_valid_source_binding(fields):
    path, source = fields["path"], fields["source"]
    if javascript_review_dialect(path) is None and Path(path).suffix != ".py":
        return None
    data = json_source_utf8_bytes(source)
    if data is None or not json_source_content_matches(fields, data):
        return None
    return path


def json_source_utf8_bytes(source):
    try:
        return source.encode("utf-8")
    except UnicodeError:
        return None


def json_source_content_matches(fields, data) -> bool:
    return isinstance(fields["bytes"], JsonNumber) and fields["bytes"] == str(len(data)) and fields["sha256"] == hashlib.sha256(data).hexdigest()


def json_bound_source_member_risk(key, child, depth, source_path):
    if key != "source" or source_path is None:
        return json_member_risk(key, child, depth)
    try:
        require_safe_source("captured source", source_path, child)
    except SystemExit:
        return True
    return False


def json_members_risk(value: JsonObjectMembers, depth: int) -> bool:
    source_path = json_bound_source_path(value)
    return any(json_bound_source_member_risk(key, child, depth, source_path) for key, child in value)


def json_list_risk(value: list, depth: int) -> bool:
    return any(json_value_risk(child, depth + 1) for child in value)


def json_value_risk(value: Any, depth: int = 0) -> bool:
    if depth > 64:
        return True
    if isinstance(value, JsonObjectMembers):
        return json_members_risk(value, depth)
    if isinstance(value, list):
        return json_list_risk(value, depth)
    if isinstance(value, str):
        return secret_text_risk(value)
    return False


def json_source_risk(text: str) -> bool:
    try:
        value = json.loads(text, object_pairs_hook=JsonObjectMembers,
                           parse_constant=json_nonfinite_constant,
                           parse_int=JsonNumber, parse_float=JsonNumber)
    except RecursionError:
        return True
    except ValueError:
        return secret_text_risk(text)
    # Escaped quotes delimit data, not source tokens. Scan all decoded members
    # independently so one safe field cannot hide another field's credential.
    return json_value_risk(value)


def require_safe_source(label: str, rel: str, text: str) -> None:
    require_no_secret_values("source path", rel)
    if Path(rel).suffix == '.json':
        if json_source_risk(text):
            raise SystemExit('refusing to include secret-like content in review bundle; '
                             f'clean or redact {label} before running autoreview')
        return
    token = _PYTHON_FIXTURE_PLACEHOLDERS.set(python_captured_fixture_placeholders(text) if Path(rel).suffix == '.py' else None)
    source_token = _CAPTURED_SOURCE_PATH.set(rel.replace("\\", "/"))
    try:
        require_no_secret_values(label, text, javascript_dialect=javascript_review_dialect(rel),
                                 go_source=Path(rel).suffix == '.go', compose_source=compose_review_path(rel),
                                 python_source=Path(rel).suffix == '.py')
    finally:
        _CAPTURED_SOURCE_PATH.reset(source_token)
        _PYTHON_FIXTURE_PLACEHOLDERS.reset(token)




def require_safe_diff(paths: list[str], patch: str, units: list[str]) -> None:
    require_no_secret_values("diff metadata", unified_diff_metadata(patch))
    sections = [unit for unit in units if unit.startswith("diff --git ")]
    if not sections:
        for content in unified_diff_contents(patch):
            require_no_secret_values("diff source", content)
        return
    expected = set(paths)
    for section in sections:
        require_safe_diff_section(expected, section)


def require_safe_diff_section(expected: set[str], section: str) -> None:
    for rel, content in diff_section_source_contents(section):
        require_safe_source("diff source", rel if rel in expected else "", content)
