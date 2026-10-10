from __future__ import annotations

# Captured text is checked before any review engine receives it.
# The lexical owner has no Git, file, capture, or engine dependencies.
import ast
import base64
import binascii
import bisect
import functools
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
    )

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
    if credentialed_uri_risk(expression) or basic_authorization_risk(expression) or any(
        pattern.search(expression) for pattern in SECRET_VALUE_PATTERNS
    ):
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

def synthetic_secret_fixture(value: str, key: str) -> bool:
    normalized = value.casefold()
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
        masked[cursor:end] = ["\n" if char == "\n" else " " for char in text[cursor:end]]
        cursor = end
    return "".join(masked)

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
    return tuple(
        match.span("assignment") for match in declaration.finditer(text)
        if match.end() - match.start() <= 8192
        and code[match.start() : match.end()] == match.group()
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
        if not re.search(r"(?<![\w$])" + re.escape(root) + r"(?![\w$])", code[start:end]):
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
        return None
    values = []
    cursor = start + 1
    for field in binding[1:-1].split(","):
        name = re.search(r"[A-Za-z_$][\w$]*\s*$", field)
        if name is not None:
            values.append((cursor + name.start(), name.group().strip()))
        cursor += len(field) + 1
    return values


def javascript_named_function_bindings(code: str, pairs: dict[int, int]) -> dict[int, tuple[int, str]] | None:
    bindings: dict[int, tuple[int, str]] = {}
    declarations = re.finditer(r"\bfunction\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)?\s*\(", code)
    for declaration in declarations:
        parts = javascript_named_function_scope(code, pairs, declaration.end() - 1)
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


def javascript_scope_declarations(code: str, pairs: dict[int, int]) -> dict[int, tuple[int, str]] | None:
    named = javascript_named_function_bindings(code, pairs)
    arrows = javascript_arrow_parameter_bindings(code, pairs)
    if named is None or arrows is None:
        return None
    declarations = named | arrows
    pattern = re.finditer(r"\b(?:const|let)\s+(?P<name>[A-Za-z_$][\w$]*|\{)", code)
    for declaration in pattern:
        names = javascript_lexical_declaration_bindings(code, pairs, declaration)
        if names is None:
            return None
        declarations.update(names)
    return declarations


def javascript_lexical_declaration_bindings(code: str, pairs: dict[int, int], declaration: re.Match) -> dict[int, tuple[int, str]] | None:
    start = declaration.start("name")
    owner = javascript_scope_owner(code, pairs, start)
    if code[start] != "{":
        return {start: (owner, declaration.group("name"))}
    end = pairs.get(start)
    names = javascript_pattern_bindings(code[start:end], start) if end is not None else None
    return {position: (owner, name) for position, name in names} if names is not None else None


def javascript_visible_scope_name(code: str, pairs: dict[int, int], names: dict[int, str], position: int) -> str | None:
    owner = javascript_scope_owner(code, pairs, position)
    while owner not in names and owner != -1:
        owner = javascript_scope_owner(code, pairs, owner)
    return names.get(owner)


def javascript_graph_token_replacement(code: str, match: re.Match, name: str, declared: bool) -> str | None:
    prefix, suffix = code[:match.start()].rstrip(), code[match.end():].lstrip()
    if declared:
        return match.group() + ": " + name if javascript_graph_shorthand(prefix, suffix) else name
    if prefix.endswith(".") or suffix.startswith(":"):
        return None
    if javascript_graph_shorthand(prefix, suffix):
        return match.group() + ": " + name
    return name


def javascript_graph_shorthand(prefix: str, suffix: str) -> bool:
    return prefix.endswith(("{", ",")) and suffix.startswith((",", "}"))


@functools.lru_cache(maxsize=8)
def javascript_scope_graph_replacements(text: str) -> tuple[tuple[int, int, str], ...] | None:
    code = javascript_binding_code(text)
    pairs = javascript_scope_pairs(code)
    declarations = javascript_scope_declarations(code, pairs) if pairs is not None else None
    if declarations is None or "__guard_scope_" in code:
        return None
    return javascript_graph_replacements(code, pairs, declarations, javascript_scope_collision_names(code, declarations))


def javascript_scope_collision_names(code: str, declarations: dict[int, tuple[int, str]]) -> dict[str, dict[int, str]]:
    names: dict[str, dict[int, str]] = {}
    for owner, name in declarations.values():
        names.setdefault(name, {})[owner] = f"__guard_scope_{owner + 1}_{name}"
    # Var hoisting and unsupported declarations keep the old strict graph.
    # Only proven lexical collisions receive separate graph identities.
    excluded = set(re.findall(r"\bvar\s+([A-Za-z_$][\w$]*)", code))
    excluded.update(re.findall(r"\bfunction\s*\*?\s+([A-Za-z_$][\w$]*)", code))
    return {name: owners for name, owners in names.items() if len(owners) > 1 and name not in excluded}


def javascript_graph_replacements(code: str, pairs: dict[int, int], declarations, collisions) -> tuple[tuple[int, int, str], ...]:
    replacements = []
    for match in re.finditer(r"[A-Za-z_$][\w$]*", code):
        owners = collisions.get(match.group())
        if owners is None:
            continue
        replacement = javascript_scoped_token_replacement(code, pairs, declarations, owners, match)
        if replacement is not None:
            replacements.append((match.start(), match.end(), replacement))
    return tuple(replacements)


def javascript_scoped_token_replacement(code: str, pairs, declarations, owners, match: re.Match) -> str | None:
    declaration = declarations.get(match.start())
    name = owners[declaration[0]] if declaration is not None else javascript_visible_scope_name(code, pairs, owners, match.start())
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


def declared_javascript_secret_reference(text: str, start: int, value: str) -> bool:
    reference = re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, value)
    if reference is None:
        return False
    code = javascript_binding_code(text)
    root = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", value).group()
    if code[start : start + len(root)] != root:
        return False
    text, value = javascript_scoped_reference_graph(text, start, value)
    code = javascript_binding_code(text)
    root = re.match(r"[A-Za-z_$][\w$]*", value).group()
    declared = re.search(r"\b(?:const|let|var)\s+" + re.escape(root) + r"(?![\w$])", code)
    if declared is None and not javascript_destructured_binding_initializers(text, code, root):
        return False
    return not javascript_binding_literal_risk(text, code, value)

def javascript_expression_has_literal(expression: str) -> bool:
    cursor = 0
    while cursor < len(expression):
        if expression[cursor] in {'"', "'", "`"}:
            return True
        end = javascript_noncode_end(expression, cursor)
        cursor = cursor + 1 if end is None else end
    # Numeric source bytes can construct credentials without a quote delimiter.
    # Mask comments and regexes before checking literal token starts.
    return re.search(r"(?<![\w$])(?:[0-9]|\.[0-9])", javascript_binding_code(expression)) is not None

def javascript_binding_initializers(text: str, code: str, root: str | None = None) -> list[str]:
    name = re.escape(root) if root is not None else r"[A-Za-z_$][A-Za-z0-9_$]*"
    assignments = re.finditer(
        r"(?<![\w$?.])" + name
        + r"\s*(?::[^=;\r\n]+)?(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)",
        code,
    )
    values = []
    for match in assignments:
        expression = fallback_expression(text[match.end():], typescript=True)
        origins = javascript_arrow_return_origins(expression)
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
    code = javascript_binding_code(expression)
    # Named TypeScript assertions describe types, not credential value origins.
    # Keep the asserted expression and any following runtime operands in the graph.
    return re.sub(
        r"(?<![\w$?.])(?:as|satisfies)\s+[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*",
        lambda match: " " * len(match.group()),
        code,
    )

def javascript_selected_object_field(field: str, member: str) -> str | None:
    key = re.match(r"\s*(?:([A-Za-z_$][\w$]*)|[\"']([A-Za-z_$][\w$]*)[\"'])\s*:", field)
    if key is not None:
        return field[key.end():] if (key.group(1) or key.group(2)) == member else ""
    shorthand = field.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", shorthand):
        return shorthand if shorthand == member else ""
    return None

def javascript_selected_object_origins(expression: str, selection: list[str]) -> list[str] | None:
    values = []
    for field in split_top_level_call_arguments(expression.strip()[1:-1]):
        if not field.strip():
            continue
        value = javascript_selected_object_field(field, selection[0])
        if value is None:
            return None
        if not value:
            continue
        origins = javascript_selected_value_origins(value, selection[1:])
        if origins is None:
            return None
        values.extend(origins)
    return values

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
        split_top_level_call_arguments(expression[opening + 1:end - 1])

def javascript_selected_value_origins(expression: str, selection: list[str]) -> list[str] | None:
    if not selection:
        return [expression]
    expression = expression.strip()
    code = javascript_initializer_value_code(expression).strip()
    if code.startswith("{") and javascript_balanced_binding_end(code, 0, "{", "}") == len(code):
        return javascript_selected_object_origins(expression, selection)
    if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, code):
        return [code.replace("?.", ".") + "." + ".".join(selection)]
    conditional = javascript_conditional_value_origins(expression, selection)
    if conditional is not None:
        return conditional
    return javascript_selected_call_origins(expression, code, selection)


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


def javascript_conditional_value_origins(expression: str, selection: list[str]) -> list[str] | None:
    code = javascript_binding_code(expression)
    delimiters = javascript_conditional_delimiters(code)
    if delimiters is None:
        return None
    question, colon = delimiters
    condition = expression[:question].strip()
    if re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, condition) is None:
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
    if len(parts) > MAX_JAVASCRIPT_INITIALIZER_ROOTS or javascript_unsupported_binding_origin(text, code, root):
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
    pairs = javascript_scope_pairs(code)
    declarations = javascript_scope_declarations(code, pairs) if pairs is not None else None
    if declarations is None or re.search(r"\bvar\s+undefined(?![\w$])", code):
        return False
    # The builtin absence value has no initializer. Type unions such as
    # `value: Type | undefined = ...` do not assign to this identifier.
    return not any(name == "undefined" for _, name in declarations.values())

@functools.lru_cache(maxsize=8)
def javascript_binding_alias_edges(text: str, code: str) -> dict[str, set[str]]:
    assignments = re.finditer(
        r"(?<![\w$?.])(?P<alias>[A-Za-z_$][\w$]*)\s*(?::[^=;\r\n]+)?"
        + r"(?:\?\?|\|\||&&|<<|>>>?|[+\-*/%&|^])?=(?!=|>)", code,
    )
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
    code = javascript_initializer_value_code(expression)
    references = re.finditer(
        r"(?<![\w$?.])(?:[.]{3})?(?P<reference>" + re.escape(root) + r"(?![\w$])"
        r"(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)", code,
    )
    # Bare call names do not carry receivers. Spread operands and member calls do.
    # Keep their value roots so an unproved alias initializer reaches refusal.
    return any(not javascript_initializer_object_key(code, reference)
               and (reference.group("reference") != root or re.match(r"\s*\(", code[reference.end():]) is None)
               for reference in references)


def javascript_proven_destructured_alias_names(
    binding: str, expression: str, kind: str, span: int,
) -> set[str] | None:
    if kind != "const" or span > 8192:
        return None
    value = javascript_initializer_value_code(expression).strip()
    if not (re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, value)
            or re.fullmatch(URI_CREDENTIAL_REFERENCE_TEXT, expression.strip())):
        return None
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
        names = javascript_proven_destructured_alias_names(
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
            if alias in aliases:
                continue
            if len(aliases) >= MAX_JAVASCRIPT_INITIALIZER_ROOTS:
                return None
            aliases.add(alias)
            pending.append(alias)
    return aliases

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
    operations = re.finditer(r"(?<![\w$?.])(?:Object|Reflect)(?![\w$])", code)
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
    references = re.finditer(r"(?<![\w$?.])" + re.escape(alias) + r"(?![\w$])", code)
    # An object operation or a write through another binding can change the
    # returned member without changing its initializer. Refuse unproved origins.
    return any(javascript_alias_write_risk(code, reference.end(), alias, original)
               for reference in references) or javascript_object_mutation_risk(code, alias)

def javascript_binding_mutation_risk(text: str, code: str, root: str) -> bool:
    aliases = javascript_binding_alias_roots(text, code, root)
    return aliases is None or any(javascript_alias_mutation_risk(code, alias, root) for alias in aliases)

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

def javascript_local_function_parts(text: str, code: str, match: re.Match) -> tuple[str, str] | None:
    parameters = re.match(r"\s*\(", code[match.end():])
    if parameters is None:
        return None
    start = match.end() + parameters.end() - 1
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
    return expressions

def javascript_initializer_object_key(code: str, match: re.Match) -> bool:
    return code[:match.start()].rstrip().endswith(("{", ",")) and code[match.end():].lstrip().startswith(":")

def javascript_initializer_references(expression: str) -> set[str]:
    code = javascript_initializer_value_code(expression)
    # Spread operands are value roots; member names retain their value selection.
    roots = re.finditer(
        r"(?<![\w$?.])(?:\.\.\.)?(?P<root>[A-Za-z_$][A-Za-z0-9_$]*"
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
    return javascript_binding_proven_references(text, code, expressions)


def javascript_binding_proven_references(text, code, expressions) -> set[str] | None:
    expressions = [expression for expression in expressions if not javascript_imported_entropy_origin(text, code, expression)]
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
    # Cycles and exhausted bounds cannot establish a safe reference allowance.
    pending = [(root, frozenset())]
    checked: set[str] = set()
    while pending:
        root, ancestors = pending.pop()
        if root in ancestors:
            return True
        if root in checked:
            continue
        links = javascript_binding_links(text, code, root, len(checked))
        if links is None:
            return True
        checked.add(root)
        pending.extend((reference, ancestors | {root}) for reference in sorted(links))
    return False

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
    headers = tuple(re.finditer(
        r"(?m)^[ \t]*(?:if|elif|while)[ \t]+(?:not[ \t]+)?"
        r"(?P<reference>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
        r"[ \t]*(?P<colon>:)[ \t]*(?:#[^\r\n]*)?\r?$", text,
    ))
    contexts = string_contexts_at(text, {header.start("reference") for header in headers})
    # A control-header colon does not assign the next line to its condition.
    # Mask only the reference/header colon; rescan the untouched body for secrets.
    return tuple(
        (header.start("reference"), header.end("colon"))
        for header in headers
        if contexts[header.start("reference")] is None
    )

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

def python_reference_children(
    expression: str, part: ast.AST, *, random_byte_metadata: bool = False,
):
    if isinstance(part, ast.Attribute):
        return [(part.value, False)]
    if isinstance(part, ast.Subscript):
        return [(part.value, False), (part.slice, True)]
    if isinstance(part, ast.Call):
        return python_call_reference_children(expression, part, random_byte_metadata=random_byte_metadata)
    if isinstance(part, ast.Dict):
        return python_dictionary_reference_children(part)
    if isinstance(part, ast.Slice):
        return python_slice_reference_children(part)
    return python_sequence_reference_children(part)

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
        # Recheck all decoded content inside this delimiter before reviewing
        # its prefixes. Eight quoting layers bound repeated decoding work.
        if depth >= 8:
            return None
        if secret_text_risk(payload, python_source=True, _python_literal_depth=depth + 1):
            return None
        reviewed.update(positions)
    return reviewed

def python_statement_keyword_starts(text: str, start: int, end: int) -> set[int]:
    source = text[start:end]
    start += len(source) - len(source.lstrip())
    source = source.strip()
    if not source or len(source) > 8192:
        return set()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return set()
    return {
        start + python_literal_source_position(source, part)
        for part in ast.walk(tree) if isinstance(part, ast.keyword)
    }

def python_has_assignment_keyword(assignment_prefixes) -> bool:
    return any(prefix.group().rstrip().endswith("=") for prefix in assignment_prefixes)

def python_keyword_assignment_starts(text: str, assignment_prefixes) -> set[int]:
    # Only complete bounded statements establish keyword commas. Unknown
    # syntax keeps tuple scanning, including every literal after a comma.
    if not python_has_assignment_keyword(assignment_prefixes):
        return set()
    offsets = [0]
    for line in text.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    starts: set[int] = set()
    start = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.NEWLINE:
                end = offsets[min(token.start[0] - 1, len(offsets) - 1)] + token.start[1]
                starts.update(python_statement_keyword_starts(text, start, end))
                start = end + len(token.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return starts

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

def python_source_reference_preflight(text: str, assignment_prefixes, depth: int) -> set[int] | None:
    contexts = string_contexts_at(text, {prefix.start() for prefix in assignment_prefixes})
    references = python_reviewed_literal_prefixes(text, contexts, depth)
    if references is None:
        return None
    literal_prefixes = python_literal_prefix_index(contexts)
    keyword_starts = python_keyword_assignment_starts(text, assignment_prefixes)
    random_byte_metadata = python_stdlib_random_byte_source(text)
    for prefix in assignment_prefixes:
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
    if credentialed_uri_risk(text, uri_authorities, compose_source=compose_source) or basic_authorization_risk(text) or any(
        pattern.search(text) for pattern in SECRET_VALUE_PATTERNS
    ):
        return True
    safe_assignment_ranges = interpolated_empty_password_uri_ranges(
        text,
        uri_authorities,
    )
    safe_assignment_ranges += shell_environment_selector_ranges(text)
    safe_assignment_ranges += documentation_comment_reference_ranges(text)
    safe_assignment_ranges += typescript_type_reference_ranges(text, javascript_dialect)
    if compose_source:
        safe_assignment_ranges += compose_required_uri_variable_ranges(text, uri_authorities)
        safe_assignment_ranges += compose_environment_reference_ranges(text)
        safe_assignment_ranges += compose_mount_reference_ranges(text)
    if python_source:
        safe_assignment_ranges += python_control_reference_ranges(text)
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
        fallback = top_level_fallback_suffix(
            text[prefix.end() :],
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
        if (
            match.group("bare_value") is not None
            and len(value) < 12
            and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", value)
        ):
            if safe_secret_assignment_suffix(
                text,
                match.end(),
                javascript_dialect=javascript_dialect,
            ):
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


def json_members_risk(value: JsonObjectMembers, depth: int) -> bool:
    return any(json_member_risk(key, child, depth) for key, child in value)


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
    require_no_secret_values(
        label, text,
        javascript_dialect=javascript_review_dialect(rel),
        go_source=Path(rel).suffix == ".go",
        compose_source=compose_review_path(rel),
        python_source=Path(rel).suffix == ".py",
    )


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
