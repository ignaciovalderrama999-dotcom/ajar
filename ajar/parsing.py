"""Optional structural analysis via tree-sitter.

When the optional tree-sitter parsers are installed, ajar understands the real
structure of Python / JavaScript / TypeScript / TSX code and can tell that a
pattern sits inside a *comment* or a *string literal*. That kills the most
common class of false positive — a keyword mentioned in a comment or a doc
string being reported as a real vulnerability.

If the parsers are not installed, every function here quietly returns ``None``
and ajar falls back to plain pattern scanning. So the feature is "pro by
default" (``pip install ajar[full]``) without ever being a hard requirement.

Template literals (JS/TS backtick strings) are deliberately *not* masked: they
routinely contain interpolated code (``${...}``) that real rules must still see
(e.g. template-literal SQL injection).
"""

from __future__ import annotations

from functools import cache

# file suffix -> tree-sitter language key
_SUFFIX_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
}

_COMMENT_TYPES = {"comment"}
# non-template string literals (template strings hold interpolated code)
_STRING_TYPES = {"string"}


def _raw_language(lang: str):
    try:
        if lang == "python":
            import tree_sitter_python as m

            return m.language()
        if lang == "javascript":
            import tree_sitter_javascript as m

            return m.language()
        if lang == "typescript":
            import tree_sitter_typescript as m

            return m.language_typescript()
        if lang == "tsx":
            import tree_sitter_typescript as m

            return m.language_tsx()
    except Exception:
        return None
    return None


@cache
def _get_parser(lang: str):
    try:
        from tree_sitter import Language, Parser
    except Exception:
        return None
    raw = _raw_language(lang)
    if raw is None:
        return None
    try:
        return Parser(Language(raw))
    except Exception:
        return None


def parsers_available() -> bool:
    """True if at least the Python parser can be loaded."""
    return _get_parser("python") is not None


def _in(ranges: list[tuple[int, int, int, int]], row: int, byte_col: int) -> bool:
    for sr, sc, er, ec in ranges:
        if (sr, sc) <= (row, byte_col) < (er, ec):
            return True
    return False


class Regions:
    """Comment and string spans for one file, in (row, byte-column) space.

    Rows are 0-indexed lines; columns are UTF-8 byte offsets within the line,
    matching tree-sitter's coordinate system.
    """

    def __init__(
        self,
        comments: list[tuple[int, int, int, int]],
        strings: list[tuple[int, int, int, int]],
    ):
        self._comments = comments
        self._strings = strings

    def in_comment(self, row: int, byte_col: int) -> bool:
        return _in(self._comments, row, byte_col)

    def in_string(self, row: int, byte_col: int) -> bool:
        return _in(self._strings, row, byte_col)


def analyze(text: str, suffix: str) -> Regions | None:
    """Return comment/string regions for a supported file, else ``None``."""
    lang = _SUFFIX_LANG.get(suffix.lower())
    if lang is None:
        return None
    parser = _get_parser(lang)
    if parser is None:
        return None
    try:
        tree = parser.parse(text.encode("utf-8"))
    except Exception:
        return None

    comments: list[tuple[int, int, int, int]] = []
    strings: list[tuple[int, int, int, int]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in _COMMENT_TYPES:
            comments.append((*node.start_point, *node.end_point))
            continue
        if node.type in _STRING_TYPES:
            strings.append((*node.start_point, *node.end_point))
            continue  # do not descend into a string literal
        stack.extend(node.children)
    return Regions(comments, strings)
