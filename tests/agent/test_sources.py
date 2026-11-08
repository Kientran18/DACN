import pytest
from pathlib import Path
from agent.sources.base import SourceError
from agent.sources.fake_source import FakeEventSource
from agent.sources.file_source import FileEventSource

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def test_fake_resumes_after_bookmark():
    s = FakeEventSource(["a", "b", "c"])
    assert [i.xml for i in s.iter_events(None)] == ["a", "b", "c"]
    assert [i.xml for i in s.iter_events("0")] == ["b", "c"]


def test_fake_stop_and_fail():
    assert len(list(FakeEventSource(["a", "b", "c"], stop_after=2).iter_events(None))) == 2
    with pytest.raises(SourceError) as e:
        list(FakeEventSource(["a", "b"], fail_after=1).iter_events(None))
    assert e.value.code == "C-006"


def test_file_source_resume():
    all_ = list(FileEventSource(SYN).iter_events(None))
    assert len(all_) == 4
    assert len(list(FileEventSource(SYN).iter_events(all_[1].bookmark))) == 2
