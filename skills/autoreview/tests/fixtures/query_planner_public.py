#!/usr/bin/env python3
"""Turn a human question into an ordered list of tsquery candidates.

`websearch_to_tsquery` joins every term with AND, so the natural-language
questions AGENTS.md instructs SAM to ask drive the result set toward zero. The
planner produces progressively broader tiers; the caller runs them in order and
stops at the first non-empty one, then reports which tier answered.
"""
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field

# Grammar words that carry no retrieval signal. English + French, because the
# corpus is bilingual (Quebec legal documents, iMessage, email).
STOPWORDS = {
    # English interrogative / auxiliary scaffolding
    "what", "which", "who", "whom", "whose", "when", "where", "why", "how",
    "did", "does", "do", "is", "are", "was", "were", "be", "been", "being",
    "say", "says", "said", "tell", "told", "about", "the", "a", "an", "of",
    "to", "for", "in", "on", "at", "by", "with", "from", "that", "this",
    "there", "their", "it", "its", "and", "or", "any", "all", "can", "could",
    "would", "should", "will", "shall", "have", "has", "had", "me", "my",
    "you", "your", "we", "our", "us", "please", "know", "anything", "something",
    # French equivalents
    "quoi", "quel", "quelle", "quels", "quelles", "qui", "quand", "ou",
    "pourquoi", "comment", "est", "sont", "etait", "etaient", "ete", "dit",
    "dire", "propos", "le", "la", "les", "un", "une", "des", "du", "de",
    "au", "aux", "dans", "sur", "par", "avec", "pour", "que", "qu", "ce",
    "cette", "ces", "il", "elle", "ils", "elles", "nous", "vous", "je",
    "mon", "ma", "mes", "son", "sa", "ses", "leur", "leurs", "et", "ou",
}


# Bilingual + alias expansion. Verified corpus splits (2026-07-25):
#   garde* 5,494 / custody 1,206 · pension alimentaire 821 / child support 88
#   jugement 1,903 / judgment 1,104 · CDPQ 1,122 / Caisse de depot 343
#   Element AI 5,468 / ElementAI 1,350 / EAI 1,162
# Implemented in Python, NOT as a Postgres synonym dictionary: that template is
# single-token->single-token (so a multi-word key can never fire), needs a .syn
# file in /usr/share/postgresql/16/tsearch_data which is on no mounted volume
# (destroyed on container recreate, and a missing dict makes EVERY query throw),
# and config changes are inert against already-stored tsvectors.
TERM_MAP: dict[str, list[str]] = {
    "custody": ["garde"],
    "garde": ["custody"],
    "support": ["pension"],
    "alimony": ["pension", "alimentaire"],
    "judgment": ["jugement"],
    "jugement": ["judgment"],
    "judgement": ["jugement"],
    "motion": ["requete"],
    "requete": ["motion"],
    "agreement": ["entente"],
    "entente": ["agreement"],
    "settlement": ["reglement", "entente"],
    "hearing": ["audience"],
    "audience": ["hearing"],
    "lawyer": ["avocat"],
    "avocat": ["lawyer"],
    "court": ["cour", "tribunal"],
    "tribunal": ["court"],
    "affidavit": ["declaration"],
    "interrogation": ["interrogatoire"],
    "interrogatoire": ["interrogation"],
    "daycare": ["garderie"],
    "garderie": ["daycare"],
    "school": ["ecole"],
    "ecole": ["school"],
    "invoice": ["facture"],
    "facture": ["invoice"],
    "cdpq": ["caisse"],
    "elementai": ["element"],
    "eai": ["element"],
}


@dataclass
class QueryTier:
    """One search attempt: a conjunction of groups, each group a disjunction.

    `groups = [["custody", "garde"], ["schedule"]]` means
    (custody OR garde) AND schedule.

    The grouping is NOT cosmetic. websearch_to_tsquery gives OR *lower*
    precedence than the implicit AND, so the flat string
    "custody OR garde schedule" compiles to `custody | (garde & schedule)` -
    every document mentioning custody matches regardless of schedule
    (1,296 rows instead of 533). Callers must AND the groups themselves,
    one websearch_to_tsquery() call per group.
    """
    groups: list[list[str]]

    def tsquery_groups(self) -> list[str]:
        return [" OR ".join(_query_term(term) for term in group) for group in self.groups]

    def sql(self, column: str = "ts_vector", config: str = "english") -> tuple[str, list]:
        """Return (sql_fragment, params) matching this tier."""
        frag = " AND ".join(
            f"{column} @@ websearch_to_tsquery('{config}', %s)" for _ in self.groups)
        return frag, self.tsquery_groups()

    def rank_expr(self, column: str = "ts_vector", config: str = "english") -> tuple[str, list]:
        """Return (sql_expression, params) scoring a row against this tier."""
        parts = [f"ts_rank({column}, websearch_to_tsquery('{config}', %s))"
                 for _ in self.groups]
        return " + ".join(parts), self.tsquery_groups()

    def __str__(self) -> str:
        return " ".join(g[0] if len(g) == 1 else "(" + " OR ".join(g) + ")"
                        for g in self.groups)

    def __contains__(self, needle: str) -> bool:      # convenience for tests
        return needle in str(self).lower()

    def lower(self) -> str:
        return str(self).lower()

    def split(self, *a, **k) -> list[str]:
        return str(self).split(*a, **k)


@dataclass
class QueryPlan:
    """Ordered search strategy for one user query."""
    tiers: list[QueryTier]
    dropped: list[str] = field(default_factory=list)
    original: str = ""


# The default PostgreSQL parser retains signed numbers, scientific notation
# and unsigned dotted versions. Other words keep the existing token rules.
_NUMERIC_TOKEN = re.compile(
    r"((?<![\w'.-])(?:[+-]?\.[0-9]+(?:[eE][+-]?[0-9]+)?|"
    r"[0-9]+(?:\.[0-9]+){2,}|"
    r"[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?![\w'-]|\.[0-9]))")


def _query_term(term: str) -> str:
    # A leading minus is a websearch NOT operator outside quotes. Signed
    # numeric values must require their own lexeme, not exclude another one.
    if term[:1] in ("+", "-") and _NUMERIC_TOKEN.fullmatch(term):
        return '"' + term + '"'
    return term


def _word_tokens(raw: str) -> list[str]:
    return "".join(c if c.isalnum() or c in "'-" else " " for c in raw).split()


def _numeric_text(token: str) -> str:
    # PostgreSQL treats a leading sign plus point as separators, then parses
    # unsigned digits/exponent. Keep that lexeme, not a detached '-' group.
    if token.startswith(("-.", "+.")):
        return token[2:]
    return token.removeprefix(".")


def _tokenize(raw: str) -> list[str]:
    # PostgreSQL indexes a decimal as one lexeme. Splitting its point makes
    # every tier require integer lexemes that the original does not contain.
    return [token for index, part in enumerate(_NUMERIC_TOKEN.split(raw))
            for token in ([_numeric_text(part)] if index % 2 else _word_tokens(part))]


def strip_accents(text: str) -> str:
    """'créance' -> 'creance'. NFD then drop combining marks."""
    return "".join(c for c in unicodedata.normalize("NFD", text)
                   if not unicodedata.combining(c))


# TERM_MAP is safe for LEXICAL expansion because expansion is additive: the
# alternatives are OR-ed, so a wrong alternative adds rows without removing
# any. Semantic translation REPLACES the term, which is destructive, and the
# same map is dangerous there because it maps high-frequency English polysemes:
# "customer support ticket" -> "customer pension ticket", "tennis court
# booking" -> "tennis cour booking", "target audience" -> "target hearing".
# Measured over 15 realistic queries, unrestricted replacement changed fused
# rank 1 in 9 of them, usually for the worse.
#
# So replacement uses its own, much smaller vocabulary: terms whose sense is
# unambiguous in BOTH languages. Directionality matters and is deliberate -
# "tribunal" always means court, but "court" often does not mean tribunal.
TRANSLATE_MAP: dict[str, str] = {
    "custody": "garde",
    "garde": "custody",
    "daycare": "garderie",
    "garderie": "daycare",
    "judgment": "jugement",
    "judgement": "jugement",
    "jugement": "judgment",
    "lawyer": "avocat",
    "avocat": "lawyer",
    "alimony": "pension alimentaire",
    "interrogatoire": "interrogation",
    "affidavit": "declaration",
    # One-way only: the French side is unambiguous, the English side is not.
    "requete": "motion",
    "entente": "agreement",
    "tribunal": "court",
    "facture": "invoice",
    "ecole": "school",
    # "audience" is deliberately absent in BOTH directions: it is ambiguous in
    # both languages (a court hearing in French, the people watching in
    # English), so "target audience for the launch" became "target hearing for
    # the launch". Ambiguity on either side disqualifies a term from
    # replacement; it stays in TERM_MAP, where OR-ing it is harmless.
}


def translate_query(raw: str) -> str | None:
    """The same question phrased in the corpus's other language, or None.

    Lexical search does not need this - it ORs both spellings into one tsquery
    (see expand_term). Semantic search does, because a query becomes a single
    point in vector space and "custody schedule" lands somewhere different from
    "horaire de garde", so which documents come back depends on which language
    was typed. Embedding the translated form gives a second point and lets RRF
    merge what each one reaches.

    Terms are REPLACED rather than appended. Appending yields a string that is
    mostly the original, so its vector sits almost on top of the base leg's -
    paying for an embedding that returns the rows we already had.

    None when no term maps: an untranslated query embedded twice adds no recall
    and would let RRF count the same ranking twice.
    """
    out: list[str] = []
    changed = False
    for token in re.findall(r"\w+|\W+", raw, flags=re.UNICODE):
        mapped = TRANSLATE_MAP.get(strip_accents(token.lower())) if token.strip() else None
        if mapped:
            out.append(mapped)
            changed = True
        else:
            out.append(token)
    return "".join(out) if changed else None


_ACCENT_VARIANTS: dict[str, list[str]] | None = None


def _accent_variants() -> dict[str, list[str]]:
    """folded lowercase -> accented spellings ATTESTED in this corpus.

    Built by accent_variants.py from crm_contacts, kg_entities and
    search_index.title (8,142 entries). Loaded once and cached; a search must
    never pay a file read per term.

    Attested rather than generated: substituting every vowel gives 2^n
    candidates that mostly spell nothing, and exhaustive enumeration was
    measured to return ZERO rows beyond the two-form union.

    A missing or corrupt file degrades to today's behaviour. The map is a
    generated artifact, and a search that raises is worse than one that is
    merely narrow.
    """
    global _ACCENT_VARIANTS
    if _ACCENT_VARIANTS is None:
        path = os.environ.get(
            "SAM_ACCENT_VARIANTS",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "accent_variants.json"))
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            _ACCENT_VARIANTS = loaded if isinstance(loaded, dict) else {}
        except Exception:
            _ACCENT_VARIANTS = {}
    return _ACCENT_VARIANTS


def reset_accent_variants() -> None:
    """Drop the cached map. For tests and for a reload after a rebuild."""
    global _ACCENT_VARIANTS
    _ACCENT_VARIANTS = None


def _alternatives(term: str) -> list[str]:
    """All spellings/languages worth searching for one term, `term` first.

    Two independent sources of splitting:
      - accents: 22% of rows carry them and the spellings retrieve DISJOINT
        sets (creance 2 rows vs creance-with-accent 460). Installing `unaccent`
        does not help - tsvectors are already stored, and REINDEX rebuilds them
        from those stored values. Folding must happen query-side.
      - language/alias: see TERM_MAP.

    Folding used to run in ONE direction: the stripped form was added only when
    the typed term already carried an accent. So "Geneviève" also searched
    "Genevieve", while "Genevieve" searched nothing else -- and the two return
    near-disjoint sets (Chretien 202 rows, Chretien-with-accent 50, ZERO
    shared). Which half of his own corpus JF saw depended on whether he reached
    for the accent key.

    The typed term stays first: callers rely on that order, and demoting it
    would reorder results for queries that already worked.
    """
    alts = [term]
    folded = strip_accents(term)
    if folded != term:
        alts.append(folded)
    else:
        # The missing direction. Only spellings this corpus actually uses --
        # OR-ed, so a wrong one adds rows and removes none, but an invented one
        # would widen every query for nothing.
        for accented in _accent_variants().get(folded.lower(), []):
            if accented.lower() not in {a.lower() for a in alts}:
                alts.append(accented)
    for extra in TERM_MAP.get(folded.lower(), []):
        if extra.lower() not in {a.lower() for a in alts}:
            alts.append(extra)
    return alts


def _expand(terms: list[str]) -> list[list[str]]:
    """One group per term, alternatives inside the group."""
    return [_alternatives(t) for t in terms]


def _floor_terms(n: int, requested: int | None) -> int:
    """How few terms the cascade may degrade to.

    Collapsing a multi-term question to one term discards its topic:
    "custody arrangements Zamboni" fell through to bare "Zamboni" and answered
    with a ride-on toy advert. "No such document" has to stay reachable, so a
    query asking for three things keeps at least two.
    """
    if requested is not None:
        return requested
    return 1 if n <= 2 else 2


def plan_fts_query(raw: str, df_lookup=None, min_terms: int | None = None) -> QueryPlan:
    """Build the tier list for `raw`, most specific first.

    `df_lookup(term) -> int` returns how many documents contain the term. When
    supplied, the planner emits a cascade: each tier drops the *least
    selective* surviving term (highest document frequency), so a strict AND
    that returns nothing degrades toward the rare, meaningful words - the
    opposite of truncating the query arbitrarily.
    """
    tokens = _tokenize(raw)
    content = [t for t in tokens if t.lower() not in STOPWORDS]
    dropped = [t for t in tokens if t.lower() in STOPWORDS]

    # Nothing but grammar - fall back to the original so we never search "".
    if not content:
        fallback = raw.strip()
        if not fallback:
            return QueryPlan(tiers=[], dropped=[], original=raw)
        return QueryPlan(tiers=[QueryTier([[fallback]])], dropped=[], original=raw)

    # Tier order is precision-first. Expansion and term-dropping both BUY
    # recall at the COST of precision, so they must never pre-empt a query
    # that already works: OR-ing 'entente' into "separation agreement" (1,848
    # exact matches) pushed an unrelated bankruptcy report above the actual
    # Separation Agreement. The caller stops at the first tier with hits, so
    # a precise query never reaches the broader ones.
    #
    #   tier 0 : content terms, verbatim              (highest precision)
    #   tier 1 : + accent/bilingual alternatives      (recall)
    #   tier 2+: drop least-selective term, cascading (last resort)
    verbatim = QueryTier([[t] for t in content])
    tiers = [verbatim]

    expanded_groups = _expand(content)
    if any(len(g) > 1 for g in expanded_groups):
        tiers.append(QueryTier(expanded_groups))

    floor = _floor_terms(len(content), min_terms)
    if df_lookup is not None and len(content) > floor:
        # Order by descending document frequency = ascending usefulness.
        ranked = sorted(content, key=lambda t: -df_lookup(t))
        surviving = list(content)
        for victim in ranked:
            if len(surviving) <= floor:
                break
            surviving = [t for t in surviving if t != victim]
            if surviving:
                tiers.append(QueryTier(_expand(surviving)))

    return QueryPlan(tiers=tiers, dropped=dropped, original=raw)
