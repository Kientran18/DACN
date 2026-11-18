"""Join lifetime tham chiếu W06: host + GUID + event-time; không PID-only, không giả ancestor."""


def process_context(event, processes):
    guid, host, at = event.get("process_guid"), event["hostname"], event["timestamp"]
    related = [p for p in processes if p["hostname"] == host and p.get("process_guid") == guid]
    starts = [p for p in related if p["sysmon_event_id"] == 1 and p["timestamp"] <= at]
    if not guid or not starts:
        return {"status": "PARTIAL_ANCESTRY", "process": None, "parent": None}
    start = max(starts, key=lambda p: p["timestamp"])
    if any(p["sysmon_event_id"] == 5 and start["timestamp"] <= p["timestamp"] < at for p in related):
        return {"status": "OUTSIDE_LIFETIME", "process": None, "parent": None}
    parents = [p for p in processes if p["hostname"] == host and p["sysmon_event_id"] == 1
               and p.get("process_guid") == start.get("parent_guid") and p["timestamp"] <= start["timestamp"]]
    parent = max(parents, key=lambda p: p["timestamp"]) if parents else None
    if parent and any(p["hostname"] == host and p.get("process_guid") == parent["process_guid"]
                      and p["sysmon_event_id"] == 5 and parent["timestamp"] <= p["timestamp"] < start["timestamp"]
                      for p in processes):
        parent = None
    return {"status": "FULL" if parent else "PARTIAL_ANCESTRY", "process": start, "parent": parent}
