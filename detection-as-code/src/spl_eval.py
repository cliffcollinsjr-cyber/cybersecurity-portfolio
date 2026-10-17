r"""Deliberately narrow SPL evaluator for the generated Sigma->Splunk query — [DEMO].

This is NOT Splunk. It understands only the shape the pySigma Splunk backend emits
for the rules in this repo, and raises on anything else:

    <base search> [| regex <field>="<pcre>"]...

Base search: field=value, field!=value, field IN ("a", "b"), NOT, OR, parentheses,
implicit AND. Splunk precedence is honoured (NOT > OR > AND, i.e. `a b OR c` is
`a AND (b OR c)`). Values are case-insensitive with * wildcards. Regex strings use
SPL quoting (\\ -> \, \" -> "); Python `re` stands in for PCRE, which is equivalent
for the constructs used here ((?i), (?:), \\s, classes, {n,}).
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(
    r'\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<comma>,)|(?P<str>"(?:[^"\\]|\\.)*")'
    r"|(?P<op>!=|=)|(?P<word>[^\s()=,!\"]+))"
)


def _unquote(s: str) -> str:
    assert s[0] == s[-1] == '"'
    return re.sub(r"\\(.)", r"\1", s[1:-1])


def _tokens(text: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise NotImplementedError(f"Cannot tokenize SPL at: {text[pos:]!r}")
        kind = m.lastgroup
        val = m.group(kind)
        out.append((kind, _unquote(val) if kind == "str" else val))
        pos = m.end()
    return out


def _wild(value: str, actual: Any) -> bool:
    if actual is None:
        return False
    pat = "".join(".*" if c == "*" else re.escape(c) for c in value)
    return re.fullmatch(pat, str(actual), re.IGNORECASE | re.DOTALL) is not None


class _Parser:
    def __init__(self, toks: list[tuple[str, str]]):
        self.t, self.i = toks, 0

    def peek(self, k: int = 0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else (None, None)

    def take(self, kind: str | None = None):
        tok = self.peek()
        if kind and tok[0] != kind:
            raise NotImplementedError(f"Expected {kind}, got {tok}")
        self.i += 1
        return tok

    # AND (implicit) binds loosest in SPL search, then OR, then NOT.
    def parse_and(self):
        terms = [self.parse_or()]
        while self.peek()[0] not in (None, "rp"):
            if self.peek() == ("word", "AND"):
                self.take()
            terms.append(self.parse_or())
        return lambda e: all(t(e) for t in terms)

    def parse_or(self):
        terms = [self.parse_not()]
        while self.peek() == ("word", "OR"):
            self.take()
            terms.append(self.parse_not())
        return lambda e: any(t(e) for t in terms)

    def parse_not(self):
        if self.peek() == ("word", "NOT"):
            self.take()
            inner = self.parse_not()
            return lambda e: not inner(e)
        return self.parse_atom()

    def parse_atom(self):
        kind, val = self.peek()
        if kind == "lp":
            self.take()
            inner = self.parse_and()
            self.take("rp")
            return inner
        if kind != "word":
            raise NotImplementedError(f"Unexpected token {kind}:{val}")
        field = self.take()[1]
        if self.peek() == ("word", "IN"):
            self.take()
            self.take("lp")
            values = []
            while True:
                k, v = self.take()
                if k not in ("str", "word"):
                    raise NotImplementedError(f"Bad IN value {k}:{v}")
                values.append(v)
                if self.peek()[0] == "comma":
                    self.take()
                    continue
                self.take("rp")
                break
            return lambda e, f=field, vs=tuple(values): any(_wild(v, e.get(f)) for v in vs)
        if self.peek()[0] == "op":
            op = self.take()[1]
            k, v = self.take()
            if k not in ("str", "word"):
                raise NotImplementedError(f"Bad value {k}:{v}")
            if op == "=":
                return lambda e, f=field, v=v: _wild(v, e.get(f))
            return lambda e, f=field, v=v: e.get(f) is not None and not _wild(v, e.get(f))
        raise NotImplementedError(f"Bare search terms are not supported: {field!r}")


_REGEX_CMD = re.compile(r'^regex\s+(?P<field>[A-Za-z_][\w.]*)\s*(?P<op>!?=)\s*(?P<re>"(?:[^"\\]|\\.)*")\s*$')


def split_query(spl: str) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (base_search, [(field, op, python_regex), ...])."""
    # Pipes inside quoted strings must not split the query.
    parts, buf, in_str, esc = [], "", False, False
    for ch in spl:
        if in_str:
            buf += ch
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str, buf = True, buf + ch
        elif ch == "|":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    parts.append(buf)
    base, cmds = parts[0], []
    for p in parts[1:]:
        m = _REGEX_CMD.match(p.strip())
        if not m:
            raise NotImplementedError(f"Unsupported SPL command: {p.strip()!r}")
        cmds.append((m["field"], m["op"], _unquote(m["re"])))
    return base, cmds


def compile_spl(spl: str):
    base, cmds = split_query(spl)
    parser = _Parser(_tokens(base))
    pred = parser.parse_and()
    if parser.peek()[0] is not None:
        raise NotImplementedError(f"Trailing SPL tokens: {parser.t[parser.i:]}")
    regexes = [(f, op, re.compile(rx)) for f, op, rx in cmds]

    def matches(event: dict[str, Any]) -> bool:
        if not pred(event):
            return False
        for f, op, rx in regexes:
            val = event.get(f)
            if val is None:
                return False  # Splunk `regex` drops events lacking the field
            hit = rx.search(str(val)) is not None
            if hit != (op == "="):
                return False
        return True

    return matches
