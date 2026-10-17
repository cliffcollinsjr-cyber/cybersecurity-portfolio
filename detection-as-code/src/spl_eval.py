r"""Deliberately narrow SPL evaluator for the generated Sigma->Splunk query — [DEMO].

This is NOT Splunk. It understands only the shape the pySigma Splunk backend emits
for the rules in this repo, and raises on anything else:

    <base search> [| regex <field>="<pcre>"]...
    <base search> | rex field=F "(?<M>pcre)" | eval C=if(isnotnull(M), "true", "false") | search ...

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
# `| rex field=F "(?<Name>pcre)"` -- one named group spanning the whole pattern,
# exactly as the pySigma Splunk backend emits for regex values inside OR/NOT.
_REX_CMD = re.compile(r'^rex\s+field=(?P<field>[A-Za-z_][\w.]*)\s+(?P<re>"(?:[^"\\]|\\.)*")\s*$')
_REX_BODY = re.compile(r'^\(\?<(?P<name>[A-Za-z_]\w*)>(?P<re>.*)\)$', re.DOTALL)
# `| eval C=if(isnotnull(M), "true", "false")`
_EVAL_CMD = re.compile(
    r'^eval\s+(?P<out>[A-Za-z_]\w*)=if\(isnotnull\((?P<src>[A-Za-z_]\w*)\),\s*"true",\s*"false"\)\s*$'
)
_SEARCH_CMD = re.compile(r'^search\s+(?P<expr>.+)$', re.DOTALL)


def split_pipeline(spl: str) -> list[str]:
    """Split on top-level pipes (pipes inside quoted strings do not split)."""
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
    return [p.strip() for p in parts]


def split_query(spl: str) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (base_search, [(field, op, python_regex), ...]) for `| regex`-only queries."""
    parts = split_pipeline(spl)
    base, cmds = parts[0], []
    for p in parts[1:]:
        m = _REGEX_CMD.match(p)
        if not m:
            raise NotImplementedError(f"Unsupported SPL command: {p!r}")
        cmds.append((m["field"], m["op"], _unquote(m["re"])))
    return base, cmds


def _compile_search(expr: str):
    parser = _Parser(_tokens(expr))
    pred = parser.parse_and()
    if parser.peek()[0] is not None:
        raise NotImplementedError(f"Trailing SPL tokens: {parser.t[parser.i:]}")
    return pred


def compile_spl(spl: str):
    """Compile `<base> [| regex ...] [| rex ... | eval ... | search ...]` to a predicate.

    Each stage takes the (copied) event and either drops it (returns None) or passes
    it on, possibly with fields added by rex/eval, mirroring Splunk's pipeline.
    """
    parts = split_pipeline(spl)
    stages = []

    pred0 = _compile_search(parts[0])
    stages.append(lambda e, p=pred0: e if p(e) else None)

    for part in parts[1:]:
        if m := _REGEX_CMD.match(part):
            f, op, rx = m["field"], m["op"], re.compile(_unquote(m["re"]))

            def st(e, f=f, op=op, rx=rx):
                val = e.get(f)
                if val is None:
                    return None  # Splunk `regex` drops events lacking the field
                return e if (rx.search(str(val)) is not None) == (op == "=") else None

        elif m := _REX_CMD.match(part):
            body = _REX_BODY.match(_unquote(m["re"]))
            if not body:
                raise NotImplementedError(f"Unsupported rex pattern: {part!r}")
            f, name, rx = m["field"], body["name"], re.compile(body["re"])

            def st(e, f=f, name=name, rx=rx):
                val = e.get(f)
                hit = None if val is None else rx.search(str(val))
                if hit is not None:
                    e = {**e, name: hit.group(0)}
                return e

        elif m := _EVAL_CMD.match(part):
            out, src = m["out"], m["src"]

            def st(e, out=out, src=src):
                return {**e, out: "true" if e.get(src) is not None else "false"}

        elif m := _SEARCH_CMD.match(part):
            p = _compile_search(m["expr"])

            def st(e, p=p):
                return e if p(e) else None

        else:
            raise NotImplementedError(f"Unsupported SPL command: {part!r}")
        stages.append(st)

    def matches(event: dict[str, Any]) -> bool:
        e: dict[str, Any] | None = dict(event)
        for st in stages:
            e = st(e)
            if e is None:
                return False
        return True

    return matches
