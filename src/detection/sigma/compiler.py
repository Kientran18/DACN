"""Biên dịch một rule Sigma (dict đã parse YAML) thành bộ đánh giá trên một sự kiện. Tập con của Sigma specification v2.

Ngữ nghĩa (docs/implementation/SIGMA_RULES.md mục 3):
- So khớp chuỗi mặc định không phân biệt hoa/thường; wildcard `*` `?`, escape bằng `\\` trước `*` `?` `\\`.
- Logic ba giá trị: True / False / None (chưa biết). Field có trong schema của loại sự kiện nhưng vắng trong hàng -> None
  (INSUFFICIENT_TELEMETRY), không coi là lành tính. Field không thuộc loại sự kiện của hàng -> điều kiện là False.
- Không hỗ trợ thì từ chối khi nạp (SigmaRuleError + mã SIG-E*), không đánh giá gần đúng.
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .errors import SigmaRuleError
from .fieldmap import resolve_logsource

NA = object()          # field không thuộc loại sự kiện của hàng (không áp dụng)
MISSING = object()     # field thuộc loại sự kiện nhưng vắng trong hàng

MATCH_TYPES = {"contains", "startswith", "endswith", "re", "cidr", "exists", "fieldref", "lt", "lte", "gt", "gte"}
TRANSFORMS = {"windash", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16"}
FLAGS = {"all", "cased", "i", "m", "s"}
DEFAULT_REGEX_MAX_LENGTH = 1000
_DASHES = "-/–—―"
_WINDASH = re.compile(r"\B[-/]\b")


class Event:
    """Một sự kiện nhìn từ phía Sigma: values = field -> giá trị; defined = field thuộc loại sự kiện này."""

    def __init__(self, values: Dict[str, object], defined):
        self.values, self.defined = values, set(defined)

    def get(self, name: str):
        if name not in self.defined:
            return NA
        v = self.values.get(name)
        return MISSING if v is None else v


# -- logic ba giá trị -------------------------------------------------------------------------------------------------
def _and(vals):
    vals = list(vals)
    if any(v is False for v in vals):
        return False
    return None if any(v is None for v in vals) else True


def _or(vals):
    vals = list(vals)
    if any(v is True for v in vals):
        return True
    return None if any(v is None for v in vals) else False


# -- giá trị ----------------------------------------------------------------------------------------------------------
def _as_text(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _wildcard_regex(value: str, windash: bool) -> str:
    """Chuỗi Sigma (có wildcard) -> regex. windash: dấu - hoặc / ở đầu từ khớp mọi dạng gạch (như pySigma)."""
    marks = {m.start() for m in _WINDASH.finditer(value)} if windash else set()
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif i in marks:
            out.append("[" + re.escape(_DASHES) + "]")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _encode(text: str, transforms: List[str]) -> List[str]:
    """base64 / base64offset (kèm wide/utf16*) -> các chuỗi literal cần tìm (không còn wildcard)."""
    data = text.encode("utf-8")
    for t in transforms:
        if t in ("wide", "utf16le"):
            data = text.encode("utf-16-le")
        elif t == "utf16be":
            data = text.encode("utf-16-be")
        elif t == "utf16":
            data = b"\xff\xfe" + text.encode("utf-16-le")
    if "base64" in transforms:
        return [base64.b64encode(data).decode()]
    starts, ends = (0, 2, 3), (None, -3, -2)          # giống SigmaBase64OffsetModifier của pySigma
    return [base64.b64encode(i * b" " + data).decode()[starts[i]:ends[(len(data) + i) % 3]] for i in range(3)]


@dataclass
class FieldMatcher:
    name: str
    tests: List[Callable[[object, Event], Optional[bool]]]
    all_mode: bool
    null_test: bool = False
    exists: Optional[bool] = None       # modifier exists: true/false

    def evaluate(self, e: Event) -> Tuple[Optional[bool], Optional[str]]:
        """Trả (kết quả, tên field nếu kết quả là 'chưa biết' do field vắng)."""
        v = e.get(self.name)
        if self.null_test:
            return (v is NA or v is MISSING or v == ""), None
        if self.exists is not None:
            return (v is not NA and v is not MISSING) == self.exists, None
        if v is NA:
            return False, None
        if v is MISSING:
            return None, self.name
        results = [t(v, e) for t in self.tests]
        return (_and(results) if self.all_mode else _or(results)), None


def _compile_field(key: str, values, allowed_fields: List[str], regex_max: Optional[int]) -> FieldMatcher:
    parts = str(key).split("|")
    name, mods = parts[0], parts[1:]
    if name not in allowed_fields:
        raise SigmaRuleError("SIG-E003", f"field '{name}' không có trong telemetry của logsource")
    unknown = [m for m in mods if m not in MATCH_TYPES | TRANSFORMS | FLAGS]
    if unknown:
        raise SigmaRuleError("SIG-E004", f"modifier không hỗ trợ: {unknown} (field {name})")
    match = [m for m in mods if m in MATCH_TYPES]
    transforms = [m for m in mods if m in TRANSFORMS]
    flags = {m for m in mods if m in FLAGS}
    if len(match) > 1:
        raise SigmaRuleError("SIG-E004", f"nhiều kiểu so khớp {match} trên field {name}")
    mt = match[0] if match else "equals"
    enc = [t for t in transforms if t in ("base64", "base64offset")]
    if len(enc) > 1 or ("base64offset" in enc and mt != "contains"):
        raise SigmaRuleError("SIG-E004", f"base64offset phải đi với contains (field {name})")
    if any(t in transforms for t in ("wide", "utf16le", "utf16be", "utf16")) and not enc:
        raise SigmaRuleError("SIG-E004", f"wide/utf16* chỉ dùng cùng base64/base64offset (field {name})")
    if flags & {"i", "m", "s"} and mt != "re":
        raise SigmaRuleError("SIG-E004", f"cờ i/m/s chỉ dùng với re (field {name})")
    if transforms and mt in ("re", "cidr", "exists", "fieldref", "lt", "lte", "gt", "gte"):
        raise SigmaRuleError("SIG-E004", f"không kết hợp {transforms} với {mt} (field {name})")
    vals = values if isinstance(values, list) else [values]
    if not vals:
        raise SigmaRuleError("SIG-E001", f"field {name} có danh sách giá trị rỗng")
    if any(isinstance(v, (dict, list)) for v in vals):
        raise SigmaRuleError("SIG-E001", f"giá trị field {name} phải là giá trị đơn")
    if any(v is None for v in vals):
        if mods or len(vals) > 1:
            raise SigmaRuleError("SIG-E004", f"null chỉ dùng một mình, không modifier (field {name})")
        return FieldMatcher(name, [], False, null_test=True)
    if mt == "exists":
        if len(vals) != 1:
            raise SigmaRuleError("SIG-E004", f"exists cần đúng một giá trị true/false (field {name})")
        v = vals[0]
        return FieldMatcher(name, [], False, exists=v if isinstance(v, bool) else _as_text(v).lower() == "true")
    tests = [_compile_value(name, mt, transforms, flags, v, regex_max) for v in vals]
    return FieldMatcher(name, tests, "all" in flags)


def _compile_value(name, mt, transforms, flags, v, regex_max):
    if mt == "re":
        pat = _as_text(v)
        if regex_max is not None and len(pat) > regex_max:
            raise SigmaRuleError("SIG-E010", f"regex dài {len(pat)} > {regex_max} (field {name})")
        fl = (re.IGNORECASE if "i" in flags else 0) | (re.MULTILINE if "m" in flags else 0) | (re.DOTALL if "s" in flags else 0)
        try:
            rx = re.compile(pat, fl)
        except re.error as exc:
            raise SigmaRuleError("SIG-E010", f"regex lỗi ở field {name}: {exc}") from exc
        return lambda x, e: rx.search(_as_text(x)) is not None
    if mt == "cidr":
        try:
            net = ipaddress.ip_network(_as_text(v), strict=False)
        except ValueError as exc:
            raise SigmaRuleError("SIG-E001", f"cidr không hợp lệ ở field {name}: {v}") from exc

        def t_cidr(x, e):
            try:
                return ipaddress.ip_address(_as_text(x).strip()) in net
            except ValueError:
                return False
        return t_cidr
    if mt == "fieldref":
        other = _as_text(v)

        def t_ref(x, e):
            y = e.get(other)
            if y is NA:
                return False
            if y is MISSING:
                return None
            return _as_text(x) == _as_text(y)
        return t_ref
    if mt in ("lt", "lte", "gt", "gte"):
        try:
            ref = float(v)
        except (TypeError, ValueError) as exc:
            raise SigmaRuleError("SIG-E001", f"{mt} cần giá trị số ở field {name}") from exc
        op = {"lt": float.__lt__, "lte": float.__le__, "gt": float.__gt__, "gte": float.__ge__}[mt]

        def t_num(x, e):
            try:
                return op(float(_as_text(x)), ref)
            except ValueError:
                return False
        return t_num
    text = _as_text(v)
    if any(t in transforms for t in ("base64", "base64offset")):
        body = "(?:" + "|".join(re.escape(s) for s in _encode(text, transforms)) + ")"
    else:
        body = _wildcard_regex(text, "windash" in transforms)
    full = {"equals": body, "contains": ".*" + body + ".*", "startswith": body + ".*", "endswith": ".*" + body}[mt]
    rx = re.compile(full, re.DOTALL | (0 if "cased" in flags else re.IGNORECASE))
    return lambda x, e: rx.fullmatch(_as_text(x)) is not None


# -- selection --------------------------------------------------------------------------------------------------------
@dataclass
class Selection:
    name: str
    alternatives: List[List[FieldMatcher]]        # OR của các map, mỗi map là AND các field

    def evaluate(self, e: Event):
        outs, missing, fields = [], set(), {}
        for alt in self.alternatives:
            rs = []
            for fm in alt:
                r, miss = fm.evaluate(e)
                rs.append(r)
                if miss:
                    missing.add(miss)
            res = _and(rs)
            outs.append(res)
            if res is True:
                for fm in alt:
                    v = e.get(fm.name)
                    if v is not NA and v is not MISSING:
                        fields[fm.name] = _as_text(v)
        return _or(outs), missing, fields


def _compile_selection(name, body, allowed, regex_max) -> Selection:
    def one_map(m):
        if not isinstance(m, dict) or not m:
            raise SigmaRuleError("SIG-E006", f"selection '{name}' không phải map field: keyword search chưa hỗ trợ")
        return [_compile_field(k, v, allowed, regex_max) for k, v in m.items()]
    if isinstance(body, dict):
        return Selection(name, [one_map(body)])
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        return Selection(name, [one_map(x) for x in body])
    raise SigmaRuleError("SIG-E006", f"selection '{name}' là danh sách giá trị (keyword search) chưa hỗ trợ")


# -- điều kiện --------------------------------------------------------------------------------------------------------
_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _tokenize(cond: str) -> List[str]:
    if "|" in cond:
        raise SigmaRuleError("SIG-E005", "aggregation ('|') trong condition chưa hỗ trợ")
    toks, pos = [], 0
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            break
        toks.append(m.group(1))
        pos = m.end()
    if any(t.lower() == "near" for t in toks):
        raise SigmaRuleError("SIG-E005", "'near' chưa hỗ trợ")
    return toks


class _Parser:
    """expr := or ; or := and ('or' and)* ; and := not ('and' not)* ; not := 'not' not | atom."""

    def __init__(self, toks, names):
        self.t, self.i, self.names = toks, 0, names

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.p_or()
        if self.peek() is not None:
            raise SigmaRuleError("SIG-E005", f"condition thừa token '{self.t[self.i]}'")
        return node

    def p_or(self):
        node = self.p_and()
        while self.peek() == "or":
            self.take()
            node = ("or", node, self.p_and())
        return node

    def p_and(self):
        node = self.p_not()
        while self.peek() == "and":
            self.take()
            node = ("and", node, self.p_not())
        return node

    def p_not(self):
        if self.peek() == "not":
            self.take()
            return ("not", self.p_not())
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise SigmaRuleError("SIG-E005", "condition kết thúc đột ngột")
        if tok == "(":
            self.take()
            node = self.p_or()
            if self.peek() != ")":
                raise SigmaRuleError("SIG-E005", "thiếu ')' trong condition")
            self.take()
            return node
        if self.i + 1 < len(self.t) and self.t[self.i + 1].lower() == "of":
            q = self.take().lower()
            self.take()
            if q not in ("1", "all", "any"):
                raise SigmaRuleError("SIG-E005", f"'{q} of' chưa hỗ trợ (chỉ '1 of' / 'all of')")
            if self.peek() is None:
                raise SigmaRuleError("SIG-E005", "thiếu đối tượng sau 'of'")
            pat = self.take()
            if pat.lower() == "them":
                sel = [n for n in self.names if not n.startswith("_")]
            else:
                sel = [n for n in self.names if fnmatch.fnmatchcase(n, pat)]
            if not sel:
                raise SigmaRuleError("SIG-E005", f"'{pat}' không khớp selection nào")
            return ("all" if q == "all" else "any", sel)
        name = self.take()
        if name not in self.names:
            raise SigmaRuleError("SIG-E005", f"condition tham chiếu selection không tồn tại '{name}'")
        return ("sel", name)


@dataclass
class EvalResult:
    value: Optional[bool]
    true_selections: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class CompiledSigma:
    selections: Dict[str, Selection]
    tree: tuple
    condition: str
    logsource: dict
    coverage_notes: List[str]

    def evaluate(self, e: Event) -> EvalResult:
        cache: Dict[str, tuple] = {}

        def sel(n):
            if n not in cache:
                cache[n] = self.selections[n].evaluate(e)
            return cache[n][0]

        def ev(node):
            op = node[0]
            if op == "sel":
                return sel(node[1])
            if op == "not":
                v = ev(node[1])
                return None if v is None else not v
            if op == "and":
                return _and([ev(node[1]), ev(node[2])])
            if op == "or":
                return _or([ev(node[1]), ev(node[2])])
            if op == "all":
                return _and([sel(n) for n in node[1]])
            return _or([sel(n) for n in node[1]])         # any / 1 of
        # Đánh giá đủ mọi nhánh (không short-circuit) để giải thích ổn định; số selection nhỏ.
        value = ev(self.tree)
        etf = self.logsource.get("event_type_filter")
        if etf is not None and value is not False:
            et = e.get("EventType")
            if et is NA or et is MISSING or _as_text(et).lower() not in {x.lower() for x in etf}:
                value = False
        true_sel = sorted(n for n, r in cache.items() if r[0] is True)
        missing = sorted({m for r in cache.values() for m in r[1]}) if value is None else []
        fields: Dict[str, str] = {}
        if value is True:
            for n in true_sel:
                fields.update(cache[n][2])
        return EvalResult(value, true_sel, missing, fields)


def _event_ids_in(detection) -> List[int]:
    out = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if str(k).split("|")[0] == "EventID":
                    for y in (v if isinstance(v, list) else [v]):
                        try:
                            out.append(int(y))
                        except (TypeError, ValueError):
                            pass
                else:
                    walk(v)
        elif isinstance(x, list):
            for y in x:
                walk(y)
    walk({k: v for k, v in detection.items() if k != "condition"})
    return out


def compile_rule(rule: dict, regex_max_length: Optional[int] = DEFAULT_REGEX_MAX_LENGTH) -> CompiledSigma:
    if not isinstance(rule, dict):
        raise SigmaRuleError("SIG-E001", "rule phải là mapping")
    if "correlation" in rule or rule.get("action"):
        raise SigmaRuleError("SIG-E005", "correlation rule / rule collection chưa hỗ trợ")
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaRuleError("SIG-E001", "thiếu detection.condition")
    if "timeframe" in det:
        raise SigmaRuleError("SIG-E005", "timeframe chưa hỗ trợ")
    spec = resolve_logsource(rule.get("logsource"))
    if spec is None:
        raise SigmaRuleError("SIG-E002", f"logsource {rule.get('logsource')} không được hỗ trợ")
    notes: List[str] = []
    if spec["kind"] == "defender":
        ids = _event_ids_in(det)
        if ids:
            keep = sorted({i for i in ids if i in spec["event_ids"]})
            drop = sorted({i for i in ids if i not in spec["event_ids"]})
            if not keep:
                raise SigmaRuleError("SIG-E002", f"Event ID Defender {drop} không được thu thập ({spec['event_ids']})")
            spec = {**spec, "event_ids": keep}
            if drop:
                notes.append(f"Event ID {', '.join(map(str, drop))} của rule không được DACN thu thập; chỉ đánh giá {keep}")
    sels = {}
    for name, body in det.items():
        if name == "condition":
            continue
        sels[name] = _compile_selection(name, body, spec["fields"], regex_max_length)
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    if not conds or not all(isinstance(c, str) and c.strip() for c in conds):
        raise SigmaRuleError("SIG-E001", "condition phải là chuỗi")
    trees = [_Parser(_tokenize(c), list(sels)).parse() for c in conds]
    tree = trees[0]
    for t in trees[1:]:
        tree = ("or", tree, t)              # danh sách condition = OR (cú pháp cũ của Sigma)
    return CompiledSigma(sels, tree, " OR ".join(conds), spec, notes)
