"""Minimal, explicit Sigma rule evaluator for fixture tests — [DEMO].

pySigma parses the rule (and applies processing pipelines); this module walks the
resulting condition tree and evaluates it against a flat event dict. It supports
exactly what the rules in this repo need and raises NotImplementedError on
anything else, so an unsupported construct fails the tests instead of silently
evaluating wrong.

Semantics implemented (Sigma specification v2):
  * AND / OR / NOT, "1 of" / "all of" selectors (pySigma expands these)
  * plain strings with * and ? wildcards, case-insensitive
    (endswith / startswith / contains are wildcards after pySigma parsing)
  * cased strings (|cased) compared case-sensitively
  * |re regular expressions (search semantics, flags from |re|i|m|s and inline)
  * integers (e.g. EventID=1 added by the sysmon pipeline)
  * a field missing from the event never matches a value
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)


def load_rule(path: str | Path, pipeline: ProcessingPipeline | None = None) -> SigmaRule:
    """Parse a Sigma rule; optionally apply a processing pipeline (e.g. sysmon)."""
    collection = SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8"))
    errors = [e for r in collection.rules for e in r.errors]
    if errors:
        raise ValueError(f"Sigma rule errors in {path}: {errors}")
    (rule,) = collection.rules
    if pipeline is not None:
        pipeline.apply(rule)
    return rule


def _sigma_string_regex(value: SigmaString) -> re.Pattern[str]:
    parts: list[str] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
        else:  # placeholders etc.
            raise NotImplementedError(f"Unsupported SigmaString part: {part!r}")
    flags = re.DOTALL
    if not isinstance(value, SigmaCasedString):
        flags |= re.IGNORECASE
    return re.compile("".join(parts), flags)


def _value_matches(value: Any, event_value: Any) -> bool:
    if event_value is None:
        return False
    if isinstance(value, SigmaRegularExpression):
        value.compile()  # pySigma validation: raises on an invalid regex
        flags = 0
        for flag in value.flags:
            flags |= SigmaRegularExpression.sigma_to_python_flags[flag]
        return re.search(str(value.regexp), str(event_value), flags) is not None
    if isinstance(value, SigmaString):
        return _sigma_string_regex(value).fullmatch(str(event_value)) is not None
    if isinstance(value, SigmaNumber):
        try:
            return int(event_value) == value.number
        except (TypeError, ValueError):
            return str(event_value) == str(value.number)
    raise NotImplementedError(f"Unsupported Sigma value type: {type(value).__name__}")


def _eval(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        (arg,) = node.args
        return not _eval(arg, event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _value_matches(node.value, event.get(node.field))
    raise NotImplementedError(f"Unsupported condition node: {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """True if any condition of the rule matches the event."""
    return any(_eval(cond.parsed, event) for cond in rule.detection.parsed_condition)


def rule_fields(rule: SigmaRule) -> set[str]:
    """Field names referenced by the rule's (possibly pipeline-mapped) detection."""
    fields: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, ConditionFieldEqualsValueExpression):
            fields.add(node.field)
        for a in getattr(node, "args", None) or []:
            walk(a)

    for cond in rule.detection.parsed_condition:
        walk(cond.parsed)
    return fields


def matching_events(rule: SigmaRule, events: Iterable[dict[str, Any]]) -> list[str]:
    return [e["event_id"] for e in events if rule_matches(rule, e)]
