import hashlib, json
import pytest
from pathlib import Path
import bronze_contract as bc
from pipeline.segment_reader import list_sealed
from agent.bronze_writer import BronzeWriter, verify_segment, recover_dir
from agent.checkpoint import Checkpoint

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def recs(n=4):
    return [bc.build_bronze_record(x, mode="file", seq=i)
            for i, x in enumerate(bc.iter_raw_xml_from_file(SYN))][:n]


def test_seal_writes_manifest_with_correct_hash(tmp_path):
    w = BronzeWriter(tmp_path, max_records=100)
    for r in recs():
        w.append(r)
    seg = w.seal()
    m = json.loads(seg.with_suffix(".manifest.json").read_text())
    assert m["record_count"] == 4 and m["schema_version"] == "bronze-event/1.0"
    assert m["sha256"] == hashlib.sha256(seg.read_bytes()).hexdigest()
    assert verify_segment(seg) == []
    assert b"\r\n" not in seg.read_bytes()
    assert not list(tmp_path.glob("*.part"))


def test_corrupt_byte_is_detected(tmp_path):
    w = BronzeWriter(tmp_path)
    for r in recs():
        w.append(r)
    seg = w.seal()
    data = bytearray(seg.read_bytes()); data[10] ^= 1; seg.write_bytes(bytes(data))
    assert verify_segment(seg)


def test_rotation_by_record_count(tmp_path):
    w = BronzeWriter(tmp_path, max_records=2)
    for r in recs():
        w.append(r)
    w.seal()
    assert len(list(tmp_path.glob("*.jsonl"))) == 2


def test_raw_xml_preserved(tmp_path):
    w = BronzeWriter(tmp_path); r = recs(1)[0]; w.append(r); seg = w.seal()
    assert json.loads(seg.read_text().splitlines()[0])["raw_xml"] == r["raw_xml"]


def test_recover_truncates_partial_line_and_seals(tmp_path):
    w = BronzeWriter(tmp_path)
    for r in recs(2):
        w.append(r)
    w.flush()
    w._fh.close()        # crash thật làm OS đóng handle; trên Windows không đổi tên được tệp còn mở
    part = next(tmp_path.glob("*.part"))
    with part.open("ab") as f:
        f.write(b'{"schema_version": "bronze')   # dòng dở do crash
    report = recover_dir(tmp_path)
    assert report[0]["reason"] == "R-TRUNCATED_TAIL" and report[0]["records"] == 2
    seg = next(tmp_path.glob("*.jsonl"))
    assert verify_segment(seg) == []


def test_recover_empty_part_is_moved_not_deleted(tmp_path):
    (tmp_path / "seg-x.jsonl.part").write_bytes(b"")
    report = recover_dir(tmp_path)
    assert report[0]["reason"] == "R-EMPTY_PART"
    assert list((tmp_path / "quarantine").iterdir())


def test_checkpoint_roundtrip_and_corrupt(tmp_path):
    c = Checkpoint(tmp_path / "cp.json")
    assert c.load() == (None, None)
    c.save("41")
    assert c.load() == ("41", None)
    (tmp_path / "cp.json").write_text("{bad")
    assert c.load() == (None, "C-005")


def test_crash_between_manifest_and_rename_leaves_recoverable_part(tmp_path, monkeypatch):
    import agent.bronze_writer as bw
    w = BronzeWriter(tmp_path)
    for r in recs(3):
        w.append(r)
    real = bw.os.replace

    def crash_on_rename(src, dst):
        if str(dst).endswith(".jsonl"):
            raise OSError("crash giả lập")
        return real(src, dst)
    monkeypatch.setattr(bw.os, "replace", crash_on_rename)
    with pytest.raises(OSError):
        w.seal()
    monkeypatch.undo()
    # reader không thấy segment nửa vời: chưa có .jsonl; .part còn nguyên để phục hồi
    assert list_sealed(tmp_path) == [] and len(list(tmp_path.glob("*.part"))) == 1
    report = recover_dir(tmp_path)
    assert report[0]["reason"] == "R-SEALED_ORPHAN" and report[0]["records"] == 3
    (seg,) = list_sealed(tmp_path)
    assert verify_segment(seg) == []


def test_unreadable_manifest_is_an_error_code_not_an_exception(tmp_path):
    w = BronzeWriter(tmp_path); w.append(recs(1)[0]); seg = w.seal()
    seg.with_suffix(".manifest.json").write_text('{"segment": "x", "sha2')   # ghi dở
    assert verify_segment(seg) == ["V-MANIFEST_UNREADABLE"]
