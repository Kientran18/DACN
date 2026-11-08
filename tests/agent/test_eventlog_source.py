import pytest
from agent.sources.eventlog import EventLogSource
from agent.sources.base import SourceError


class FakeApi:
    def __init__(self, evs): self.evs, self.sent = evs, False
    def query(self, ch, bm): return "h", "bm"
    def next(self, h, n):
        if self.sent: return []
        self.sent = True; return self.evs
    def render_xml(self, ev): return f"<Event>{ev}</Event>"
    def update_bookmark(self, bm, ev): self.last = ev
    def render_bookmark(self, bm): return f"bm-{self.last}"


def test_yields_xml_and_bookmark_via_api_layer():
    items = list(EventLogSource(api=FakeApi(["a", "b"])).iter_events(None))
    assert [i.bookmark for i in items] == ["bm-a", "bm-b"]


def test_access_denied_maps_to_c006():
    class Deny:
        def query(self, *a):
            e = OSError("Access is denied"); raise e
    with pytest.raises(SourceError) as e:
        list(EventLogSource(api=Deny()).iter_events(None))
    assert e.value.code == "C-006"


def test_import_on_linux_without_pywin32_gives_c005():
    import sys
    if sys.platform == "win32":
        pytest.skip("Linux only")
    with pytest.raises(SourceError) as e:
        list(EventLogSource().iter_events(None))
    assert e.value.code == "A-001"
