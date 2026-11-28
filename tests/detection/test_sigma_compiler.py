"""Bộ biên dịch tập con Sigma (detection.sigma.compiler). Dữ liệu SYNTHETIC; chuỗi "đáng ngờ" ghép lúc chạy
(không để nguyên văn trong tệp tĩnh, cùng lý do tests/detection/test_powershell_rules.py)."""
import base64

import pytest

from detection.sigma.compiler import compile_rule, Event, NA
from detection.sigma.errors import SigmaRuleError

PS = "power" + "shell"


def rule(detection, logsource=None, **kw):
    r = {"title": "t", "id": "11111111-2222-3333-4444-555555555555", "status": "test", "level": "medium",
         "logsource": logsource or {"product": "windows", "category": "process_creation"}, "detection": detection}
    r.update(kw)
    return r


def ev(**fields):
    defined = set(fields) | {"Image", "CommandLine", "ParentImage", "OriginalFileName", "User", "Hashes", "EventID"}
    return Event({k: v for k, v in fields.items() if v is not NA}, defined)


def run(r, e):
    return compile_rule(r).evaluate(e)


# -- modifier và giá trị -------------------------------------------------------------------------------------------
def test_equals_case_insensitive_and_wildcards():
    c = compile_rule(rule({"sel": {"Image": "*\\SCHTASKS.exe"}, "condition": "sel"}))
    assert c.evaluate(ev(Image="C:\\Windows\\System32\\schtasks.exe")).value is True
    assert c.evaluate(ev(Image="C:\\Windows\\System32\\schtasks.exe.bak")).value is False


def test_question_mark_and_escaped_wildcard():
    c = compile_rule(rule({"sel": {"CommandLine": "a?c\\*"}, "condition": "sel"}))
    assert c.evaluate(ev(CommandLine="abc*")).value is True
    assert c.evaluate(ev(CommandLine="abcd")).value is False


def test_contains_startswith_endswith_list_is_or():
    c = compile_rule(rule({"sel": {"CommandLine|contains": ["/create", "/change"]}, "condition": "sel"}))
    assert c.evaluate(ev(CommandLine="schtasks /CREATE /tn x")).value is True
    assert c.evaluate(ev(CommandLine="schtasks /query")).value is False
    s = compile_rule(rule({"sel": {"Image|startswith": "C:\\Users\\"}, "condition": "sel"}))
    assert s.evaluate(ev(Image="c:\\users\\a\\x.exe")).value is True


def test_contains_all_is_and():
    c = compile_rule(rule({"sel": {"CommandLine|contains|all": ["a", "b"]}, "condition": "sel"}))
    assert c.evaluate(ev(CommandLine="xaxb")).value is True
    assert c.evaluate(ev(CommandLine="xax")).value is False


def test_cased_modifier():
    c = compile_rule(rule({"sel": {"CommandLine|contains|cased": "ABC"}, "condition": "sel"}))
    assert c.evaluate(ev(CommandLine="xABCx")).value is True
    assert c.evaluate(ev(CommandLine="xabcx")).value is False


def test_regex_search_case_sensitive_unless_i():
    c = compile_rule(rule({"sel": {"CommandLine|re": "\\s-[Ee]nc\\s"}, "condition": "sel"}))
    assert c.evaluate(ev(CommandLine=PS + " -enc AAA")).value is True
    assert c.evaluate(ev(CommandLine=PS + " -ENC AAA")).value is False
    ci = compile_rule(rule({"sel": {"CommandLine|re|i": "\\s-enc\\s"}, "condition": "sel"}))
    assert ci.evaluate(ev(CommandLine=PS + " -ENC AAA")).value is True


def test_windash_expands_dash_and_slash_at_word_start():
    c = compile_rule(rule({"sel": {"CommandLine|windash|contains": " -urlcache "}, "condition": "sel"}))
    for v in ("certutil -urlcache x", "certutil /urlcache x", "certutil \u2013urlcache x"):
        assert c.evaluate(ev(CommandLine=v)).value is True, v
    assert c.evaluate(ev(CommandLine="certutil urlcache x")).value is False


def test_cidr():
    c = compile_rule(rule({"sel": {"DestinationIp|cidr": ["10.0.0.0/8", "fe80::/10"]}, "condition": "sel"},
                          logsource={"product": "windows", "category": "network_connection"}))
    assert c.evaluate(Event({"DestinationIp": "10.1.2.3"}, {"DestinationIp"})).value is True
    assert c.evaluate(Event({"DestinationIp": "8.8.8.8"}, {"DestinationIp"})).value is False
    assert c.evaluate(Event({"DestinationIp": "not-an-ip"}, {"DestinationIp"})).value is False


def test_base64offset_contains_matches_any_alignment():
    word = "Invoke-" + "Expression"
    c = compile_rule(rule({"sel": {"CommandLine|base64offset|contains": word}, "condition": "sel"}))
    for prefix in ("", "a", "ab"):
        enc = base64.b64encode((prefix + word + " tail").encode()).decode()
        assert c.evaluate(ev(CommandLine="x " + enc)).value is True, prefix
    assert c.evaluate(ev(CommandLine="x " + base64.b64encode(b"hello world").decode())).value is False


def test_utf16le_base64offset():
    word = "Invoke-" + "WebRequest"
    c = compile_rule(rule({"sel": {"CommandLine|utf16le|base64offset|contains": word}, "condition": "sel"}))
    enc = base64.b64encode(("$a=" + word).encode("utf-16-le")).decode()
    assert c.evaluate(ev(CommandLine="-e " + enc)).value is True


def test_base64_plain():
    c = compile_rule(rule({"sel": {"CommandLine|base64|contains": "abc"}, "condition": "sel"}))
    assert c.evaluate(ev(CommandLine="x" + base64.b64encode(b"abc").decode() + "x")).value is True


def test_null_and_exists():
    c = compile_rule(rule({"sel": {"User": None}, "condition": "sel"}))
    assert c.evaluate(ev(User="")).value is True
    assert c.evaluate(ev(User=NA)).value is True          # field vắng
    assert c.evaluate(ev(User="u")).value is False
    e = compile_rule(rule({"sel": {"Hashes|exists": True}, "condition": "sel"}))
    assert e.evaluate(ev(Hashes="SHA256=AA")).value is True
    assert e.evaluate(ev(Hashes=NA)).value is False


def test_numeric_compare_and_int_value_equality():
    c = compile_rule(rule({"sel": {"DestinationPort": 443}, "condition": "sel"},
                          logsource={"product": "windows", "category": "network_connection"}))
    assert c.evaluate(Event({"DestinationPort": "443"}, {"DestinationPort"})).value is True
    g = compile_rule(rule({"sel": {"DestinationPort|gte": 1024}, "condition": "sel"},
                          logsource={"product": "windows", "category": "network_connection"}))
    assert g.evaluate(Event({"DestinationPort": "8080"}, {"DestinationPort"})).value is True
    assert g.evaluate(Event({"DestinationPort": "80"}, {"DestinationPort"})).value is False


def test_fieldref():
    c = compile_rule(rule({"sel": {"Image|fieldref": "ParentImage"}, "condition": "sel"}))
    assert c.evaluate(ev(Image="a.exe", ParentImage="a.exe")).value is True
    assert c.evaluate(ev(Image="a.exe", ParentImage="b.exe")).value is False


# -- điều kiện và logic ba giá trị ------------------------------------------------------------------------------------
DET = {"selection_img": [{"Image|endswith": "\\schtasks.exe"}, {"OriginalFileName": "schtasks.exe"}],
       "selection_cli": {"CommandLine|contains": " /create "},
       "filter_main_system": {"User|contains": ["AUTHORI", "AUTORI"]}}


def test_condition_and_not_with_explanation():
    c = compile_rule(rule({**DET, "condition": "all of selection_* and not 1 of filter_main_*"}))
    r = c.evaluate(ev(Image="C:\\w\\schtasks.exe", OriginalFileName="x", CommandLine="schtasks /create /tn a", User="LAB\\u"))
    assert r.value is True
    assert r.true_selections == ["selection_cli", "selection_img"]
    assert r.fields == {"Image": "C:\\w\\schtasks.exe", "CommandLine": "schtasks /create /tn a"}
    r2 = c.evaluate(ev(Image="C:\\w\\schtasks.exe", OriginalFileName="x", CommandLine="schtasks /create /tn a",
                       User="NT AUTHORITY\\SYSTEM"))
    assert r2.value is False


def test_one_of_them_and_parentheses_and_or():
    c = compile_rule(rule({"a": {"Image": "a.exe"}, "b": {"Image": "b.exe"}, "c": {"User": "x"},
                           "condition": "(a or b) and not c"}))
    assert c.evaluate(ev(Image="b.exe", User="y")).value is True
    assert c.evaluate(ev(Image="b.exe", User="x")).value is False
    t = compile_rule(rule({"a": {"Image": "a.exe"}, "b": {"Image": "b.exe"}, "condition": "1 of them"}))
    assert t.evaluate(ev(Image="a.exe")).value is True


def test_missing_field_gives_unknown_with_missing_list():
    c = compile_rule(rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel"}))
    r = c.evaluate(ev(CommandLine=NA))          # field định nghĩa cho loại sự kiện nhưng vắng trong hàng
    assert r.value is None and r.missing == ["CommandLine"]


def test_unknown_is_absorbed_by_definite_false():
    c = compile_rule(rule({"a": {"Image": "a.exe"}, "b": {"CommandLine|contains": "x"}, "condition": "a and b"}))
    assert c.evaluate(ev(Image="z.exe", CommandLine=NA)).value is False


def test_field_not_defined_for_event_type_is_false_not_unknown():
    c = compile_rule(rule({"sel": {"Details|contains": "x"}, "condition": "sel"},
                          logsource={"product": "windows", "category": "registry_event"}))
    r = c.evaluate(Event({"TargetObject": "HKLM\\k"}, {"TargetObject", "Image", "EventType"}))   # Event 12: không có Details
    assert r.value is False and r.missing == []


# -- từ chối rõ ràng --------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("det,code", [
    ({"sel": {"CommandLine|expand": "%x%"}, "condition": "sel"}, "SIG-E004"),
    ({"sel": {"CommandLine|foo": "x"}, "condition": "sel"}, "SIG-E004"),
    ({"sel": {"CommandLine|base64offset": "x"}, "condition": "sel"}, "SIG-E004"),   # base64offset cần contains
    ({"sel": {"CommandLine": "x"}, "condition": "sel | count() > 5"}, "SIG-E005"),
    ({"sel": {"CommandLine": "x"}, "condition": "sel near other"}, "SIG-E005"),
    ({"sel": {"CommandLine": "x"}, "condition": "2 of sel*"}, "SIG-E005"),
    ({"sel": {"CommandLine": "x"}, "condition": "missing_sel"}, "SIG-E005"),
    ({"sel": {"CommandLine": "x"}, "condition": "sel", "timeframe": "5m"}, "SIG-E005"),
    ({"keywords": ["mimikatz"], "condition": "keywords"}, "SIG-E006"),
    ({"sel": {"TargetFilename": "x"}, "condition": "sel"}, "SIG-E003"),        # không có trong Event 1
    ({"sel": {"CommandLine|re": "(?P<x"}, "condition": "sel"}, "SIG-E010"),
    ({"sel": {"CommandLine|re": "a" * 2000}, "condition": "sel"}, "SIG-E010"),
])
def test_rejections(det, code):
    with pytest.raises(SigmaRuleError) as ei:
        compile_rule(rule(det), regex_max_length=1000)
    assert ei.value.code == code


def test_unsupported_logsource_rejected():
    with pytest.raises(SigmaRuleError) as ei:
        compile_rule(rule({"sel": {"ImageLoaded": "x"}, "condition": "sel"},
                          logsource={"product": "windows", "category": "image_load"}))
    assert ei.value.code == "SIG-E002"


def test_commandline_in_file_event_rejected_not_in_sysmon_event11():
    with pytest.raises(SigmaRuleError) as ei:
        compile_rule(rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel"},
                          logsource={"product": "windows", "category": "file_event"}))
    assert ei.value.code == "SIG-E003"


def test_windefend_eventids_outside_collected_set_noted():
    c = compile_rule(rule({"sel": {"EventID": [1006, 1015, 1116, 1117]}, "condition": "sel"},
                          logsource={"product": "windows", "service": "windefend"}))
    assert c.logsource["event_ids"] == [1116, 1117]
    assert any("1006" in n and "1015" in n for n in c.coverage_notes)
    with pytest.raises(SigmaRuleError) as ei:
        compile_rule(rule({"sel": {"EventID": 1006}, "condition": "sel"}, logsource={"product": "windows", "service": "windefend"}))
    assert ei.value.code == "SIG-E002"
