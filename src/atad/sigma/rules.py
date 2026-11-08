# Copyright (C) 2026 ATAD Team (Hoor Fawaz, Danah Fawaz)
# SPDX-License-Identifier: LicenseRef-ATAD-SAL-1.0

"""Loading Sigma rules and compiling their detection logic.

Supported (covers every rule in SigmaHQ's Windows process, network, file,
Security-log and Linux folders at the time of writing):

* selections as maps (AND of fields), lists of maps (OR), lists of plain
  values (keywords, searched in the whole record);
* values with ``*`` / ``?`` wildcards, ``null``, lists (OR);
* modifiers ``contains``, ``startswith``, ``endswith``, ``all``, ``re`` (with
  ``i``, ``m``, ``s``), ``cidr``, ``windash``, ``base64offset``, ``base64``,
  ``fieldref``, ``exists``, ``lt``/``lte``/``gt``/``gte``;
* conditions with ``and``, ``or``, ``not``, parentheses, ``1 of x*``,
  ``all of x*``, ``1 of them``, ``all of them`` and a list of conditions.

Not supported (the rule is listed as skipped with the reason): aggregations
in the condition (``| count()``), correlation rules, other modifiers.
Matching is case-insensitive except ``re``, as in the Sigma specification.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

Event = dict[str, Any]
Pred = Callable[[Event], bool]

KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr",
                   "windash", "base64offset", "base64", "fieldref", "exists", "lt", "lte", "gt",
                   "gte", "cased"}
_DASHES = ["-", "/", "\u2013", "\u2014", "\u2015"]  # hyphen, slash, en dash, em dash, horizontal bar


class SigmaError(ValueError):
    """A rule that cannot be used, with the reason."""


@dataclass
class SigmaRule:
    id: str
    title: str
    status: str
    level: str
    author: str
    description: str
    references: list[str]
    tags: list[str]
    falsepositives: list[str]
    logsource: dict[str, str]
    path: str
    sha256: str
    match: Pred = field(repr=False, default=lambda e: False)


@dataclass
class LoadReport:
    rules: list[SigmaRule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (file or title, reason)
    files: int = 0


# ------------------------------------------------------------------ values


def _wildcard_regex(value: str) -> str:
    """Sigma wildcards: * and ?, with \\ escaping them."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    return "".join(out)


def _b64_offsets(value: str) -> list[str]:
    """The three base64 forms of ``value`` at offsets 0, 1 and 2 (Sigma base64offset)."""
    raw = value.encode("utf-8")
    out = []
    for i in range(3):
        enc = base64.b64encode(b" " * i + raw).decode()
        start = (0, 2, 3)[i]
        end = len(enc) - ((0, 3, 2)[(len(raw) + i) % 3])
        out.append(enc[start:end])
    return out


def _as_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _value_pred(field_name: str, modifiers: list[str], raw: Any) -> Pred:
    """Predicate for one field and ONE value."""
    mods = set(modifiers)
    if "exists" in mods:
        want = bool(raw) if isinstance(raw, bool) else str(raw).lower() == "true"
        return lambda e: (e.get(field_name) not in (None, "")) == want
    if "fieldref" in mods:
        other = str(raw)
        return lambda e: (e.get(field_name) is not None and e.get(other) is not None
                          and _as_text(e[field_name]).lower() == _as_text(e[other]).lower())
    if raw is None:
        return lambda e: e.get(field_name) in (None, "")
    if mods & {"lt", "lte", "gt", "gte"}:
        try:
            limit = float(raw)
        except (TypeError, ValueError):
            raise SigmaError(f"{field_name}: numeric comparison with a non-number") from None
        op = next(iter(mods & {"lt", "lte", "gt", "gte"}))
        cmp = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}[op]

        def num(e: Event) -> bool:
            try:
                return cmp(float(e.get(field_name)), limit)
            except (TypeError, ValueError):
                return False
        return num

    if "re" in mods:
        flags = (re.IGNORECASE if "i" in mods else 0) | (re.MULTILINE if "m" in mods else 0) \
            | (re.DOTALL if "s" in mods else 0)
        try:
            rx = re.compile(str(raw), flags)
        except re.error as exc:
            raise SigmaError(f"{field_name}: bad regular expression ({exc})") from None
        return _field_test(field_name, lambda text: rx.search(text) is not None)
    if "cidr" in mods:
        try:
            net = ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            raise SigmaError(f"{field_name}: bad CIDR {raw!r}") from None

        def in_net(text: str) -> bool:
            try:
                return ipaddress.ip_address(text.split("%", maxsplit=1)[0]) in net
            except ValueError:
                return False
        return _field_test(field_name, in_net)

    values = [_as_text(raw)]
    if "base64offset" in mods:
        values = [v for x in values for v in _b64_offsets(x)]
    elif "base64" in mods:
        values = [base64.b64encode(x.encode()).decode() for x in values]
    if "windash" in mods:
        values = [v for x in values for v in
                  ({x} | {x.replace("-", d, 1) if x.startswith("-") else x.replace(" -", " " + d)
                          for d in _DASHES})]
    if "contains" in mods:
        pats = [".*" + _wildcard_regex(v) + ".*" for v in values]
    elif "startswith" in mods:
        pats = [_wildcard_regex(v) + ".*" for v in values]
    elif "endswith" in mods:
        pats = [".*" + _wildcard_regex(v) for v in values]
    else:
        pats = [_wildcard_regex(v) for v in values]
    flags = 0 if "cased" in mods else re.IGNORECASE
    rx = re.compile("^(?:" + "|".join(pats) + ")$", flags | re.DOTALL)
    return _field_test(field_name, lambda text: rx.match(text) is not None)


def _field_test(field_name: str, test: Callable[[str], bool]) -> Pred:
    def pred(e: Event) -> bool:
        v = e.get(field_name)
        if v is None:
            return False
        if isinstance(v, (list, tuple, set)):
            return any(test(_as_text(x)) for x in v)
        return test(_as_text(v))
    return pred


def _field_pred(key: str, value: Any) -> Pred:
    name, *modifiers = key.split("|")
    unknown = [m for m in modifiers if m not in KNOWN_MODIFIERS]
    if unknown:
        raise SigmaError(f"unsupported modifier(s): {', '.join(unknown)}")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"{name}: empty value list")
    preds = [_value_pred(name, modifiers, v) for v in values]
    if "all" in modifiers:
        return lambda e: all(p(e) for p in preds)
    return lambda e: any(p(e) for p in preds)


def _keywords_pred(words: list[Any]) -> Pred:
    rxs = [re.compile(".*" + _wildcard_regex(_as_text(w)) + ".*", re.IGNORECASE | re.DOTALL) for w in words]

    def pred(e: Event) -> bool:
        text = e.get("_keywords_text") or ""
        return any(rx.match(text) for rx in rxs)
    return pred


def _selection(body: Any) -> Pred:
    if isinstance(body, dict):
        preds = [_field_pred(str(k), v) for k, v in body.items()]
        return lambda e: all(p(e) for p in preds)
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            preds = [_selection(x) for x in body]
            return lambda e: any(p(e) for p in preds)
        if all(not isinstance(x, (dict, list)) for x in body):
            return _keywords_pred(body)
        raise SigmaError("selection mixes maps and plain values")
    if isinstance(body, (str, int)):
        return _keywords_pred([body])
    raise SigmaError(f"unsupported selection type {type(body).__name__}")


# ---------------------------------------------------------------- condition

_TOKEN = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|\d+\s+of\b|all\s+of\b|any\s+of\b|[\w*.\-]+)", re.IGNORECASE)


def _tokenize(cond: str) -> list[str]:
    tokens, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"cannot read condition near {cond[pos:pos + 20]!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(cond) and cond[pos].isspace():
            pos += 1
    return tokens


def _both(a: Pred, b: Pred) -> Pred:
    return lambda e: a(e) and b(e)


def _either(a: Pred, b: Pred) -> Pred:
    return lambda e: a(e) or b(e)


def compile_condition(cond: str, selections: dict[str, Pred]) -> Pred:
    if "|" in cond:
        raise SigmaError("aggregation in condition (| count() etc.) is not supported")
    tokens = _tokenize(cond)
    pos = 0

    def peek() -> str | None:
        return tokens[pos].lower() if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def names(pattern: str) -> list[str]:
        if pattern.lower() == "them":
            found = [n for n in selections if not n.startswith("_")]
        else:
            rx = re.compile("^" + _wildcard_regex(pattern) + "$")
            found = [n for n in selections if rx.match(n)]
        if not found:
            raise SigmaError(f"condition refers to {pattern!r}, which matches no selection")
        return found

    def primary() -> Pred:
        tok = peek()
        if tok is None:
            raise SigmaError("condition ends too early")
        if tok == "(":
            take()
            inner = expr()
            if peek() != ")":
                raise SigmaError("missing ')' in condition")
            take()
            return inner
        if tok == "not":
            take()
            p = primary()
            return lambda e: not p(e)
        m = re.match(r"(\d+|all|any)\s+of$", tok)
        if m:
            take()
            if pos >= len(tokens):
                raise SigmaError("'of' without a selection name")
            preds = [selections[n] for n in names(take())]
            q = m.group(1)
            if q == "all":
                return lambda e: all(p(e) for p in preds)
            need = 1 if q == "any" else int(q)
            return lambda e: sum(1 for p in preds if p(e)) >= need
        name = take()
        if name not in selections:
            raise SigmaError(f"condition refers to unknown selection {name!r}")
        return selections[name]

    def term() -> Pred:
        left = primary()
        while peek() == "and":
            take()
            right = primary()
            left = _both(left, right)
        return left

    def expr() -> Pred:
        left = term()
        while peek() == "or":
            take()
            right = term()
            left = _either(left, right)
        return left

    result = expr()
    if pos != len(tokens):
        raise SigmaError(f"unexpected {tokens[pos]!r} in condition")
    return result


# ------------------------------------------------------------------- loading

LEVELS = ("informational", "low", "medium", "high", "critical")
# libyaml's C loader when available: about ten times faster on large rule sets.
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def compile_rule(doc: dict, path: str, sha: str) -> SigmaRule:
    if not isinstance(doc, dict):
        raise SigmaError("not a mapping")
    if "correlation" in doc:
        raise SigmaError("correlation rules are not supported")
    for key in ("title", "logsource", "detection"):
        if key not in doc:
            raise SigmaError(f"missing '{key}'")
    det = doc["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("detection has no condition")
    status = str(doc.get("status") or "experimental").lower()
    if status in ("deprecated", "unsupported"):
        raise SigmaError(f"rule status is {status}")
    selections = {name: _selection(body) for name, body in det.items()
                  if name not in ("condition", "timeframe")}
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    preds = [compile_condition(str(c), selections) for c in conds]
    level = str(doc.get("level") or "medium").lower()
    if level not in LEVELS:
        level = "medium"
    author = doc.get("author") or ""
    return SigmaRule(
        id=str(doc.get("id") or ""), title=str(doc["title"]), status=status, level=level,
        author=str(author), description=str(doc.get("description") or ""),
        references=[str(x) for x in doc.get("references") or []],
        tags=[str(x) for x in doc.get("tags") or []],
        falsepositives=[str(x) for x in doc.get("falsepositives") or []],
        logsource={k: str(v).lower() for k, v in (doc.get("logsource") or {}).items()
                   if k in ("product", "category", "service")},
        path=path, sha256=sha, match=lambda e: any(p(e) for p in preds))


def load_rules(path: Path) -> LoadReport:
    report = LoadReport()
    files = [path] if path.is_file() else sorted(
        p for p in path.rglob("*") if p.suffix.lower() in (".yml", ".yaml") and p.is_file())
    for f in files:
        report.files += 1
        data = f.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        try:
            docs = [d for d in yaml.load_all(data.decode("utf-8", "replace"), Loader=_LOADER)
                    if d is not None]
        except yaml.YAMLError as exc:
            report.skipped.append((str(f), f"invalid YAML ({str(exc).splitlines()[0]})"))
            continue
        for d in docs:
            try:
                report.rules.append(compile_rule(d, str(f), sha))
            except SigmaError as exc:
                title = d.get("title") if isinstance(d, dict) else None
                report.skipped.append((title or str(f), str(exc)))
    return report
