# lab.py

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import ntpath
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
WATCHED_SUFFIX = r"\program files\common files\microsoft shared\ink\hid.dll"
WINDOW = timedelta(minutes=2)
COLLECTION_STATES = {"collected", "unavailable", "unknown"}


@dataclass(frozen=True)
class Event:
    time: datetime
    record_id: int
    event_id: str
    path: str
    image: str | None

    @property
    def sort_key(self):
        return self.time, self.record_id

    def to_dict(self):
        return {
            "time_utc": self.time.isoformat(),
            "record_id": self.record_id,
            "target_path": self.path,
            "process_image": self.image,
        }


def parse_time(value):
    time = datetime.fromisoformat(value)
    if time.utcoffset() is None:
        raise ValueError("timestamps must include a UTC offset")
    return time.astimezone(timezone.utc)


def match_path(path):
    normalized = ntpath.normpath(path).casefold()
    drive, tail = ntpath.splitdrive(normalized)
    if len(drive) != 2 or drive[0] not in "abcdefghijklmnopqrstuvwxyz" or drive[1] != ":":
        return None
    if tail != WATCHED_SUFFIX:
        return None
    return normalized


def read_events(path, host, start, end):
    root = ET.parse(path).getroot()
    if root.tag == EVENT_NS + "Event":
        records = [root]
    elif root.tag in {"Events", EVENT_NS + "Events"}:
        records = root.findall(EVENT_NS + "Event")
        if len(records) != len(root):
            raise ValueError(f"{path}: expected Windows Event XML records")
    else:
        raise ValueError(f"{path}: expected a Windows Event or Events XML document")

    events = []
    for record in records:
        system = record.find(EVENT_NS + "System")
        if system is None:
            raise ValueError(f"{path}: event is missing its System element")
        provider = system.find(EVENT_NS + "Provider")
        event_id = system.findtext(EVENT_NS + "EventID")
        if provider is None or provider.get("Name") != SYSMON_PROVIDER:
            continue
        if event_id not in {"7", "11"}:
            continue

        created = system.find(EVENT_NS + "TimeCreated")
        if created is None or "SystemTime" not in created.attrib:
            raise ValueError(f"{path}: Sysmon event {event_id} is missing SystemTime")
        time = parse_time(created.attrib["SystemTime"])
        if time < start or time > end:
            continue
        computer = system.findtext(EVENT_NS + "Computer", "")
        if computer.casefold() != host.casefold():
            raise ValueError(f"{path}: expected host {host!r}, found {computer!r} in capture interval")

        record_id = int(system.findtext(EVENT_NS + "EventRecordID", ""))
        data = {
            field.get("Name"): field.text
            for field in record.findall(f"{EVENT_NS}EventData/{EVENT_NS}Data")
        }
        path_field = "ImageLoaded" if event_id == "7" else "TargetFilename"
        if not data.get(path_field):
            raise ValueError(f"{path}: event record {record_id} is missing {path_field}")
        events.append(Event(time, record_id, event_id, data[path_field], data.get("Image")))

    return sorted(events, key=lambda event: event.sort_key)


def make_result(matches, gaps):
    status = "no_match"
    if matches:
        status = "matched"
    elif gaps:
        status = "insufficient_data"
    return {
        "status": status,
        "count": len(matches),
        "coverage_gaps": gaps,
        "matches": matches,
    }


def check_capture(capture, directory):
    capture_id = capture["id"]
    host = capture["host"]
    source = capture["source"]
    if source not in {"synthetic", "observed"}:
        raise ValueError(f"{capture_id}: source must be synthetic or observed")
    start = parse_time(capture["start_utc"])
    end = parse_time(capture["end_utc"])
    if end <= start:
        raise ValueError(f"{capture_id}: the capture end must be after its start")

    collection = capture["collection"]
    file_create, image_load = collection["file_create"], collection["image_load"]
    if file_create not in COLLECTION_STATES or image_load not in COLLECTION_STATES:
        raise ValueError(f"{capture_id}: collection must be collected, unavailable, or unknown")
    events = read_events(directory / capture["events"], host, start, end)

    writes = []
    loads_by_path = {}
    for event in events:
        path = match_path(event.path)
        if path is None:
            continue
        if event.event_id == "11":
            writes.append((path, event))
        else:
            loads_by_path.setdefault(path, []).append(event)

    file_gaps = [] if file_create == "collected" else [f"file_create_{file_create}"]
    correlation_gaps = list(file_gaps)
    if image_load != "collected":
        correlation_gaps.append(f"image_load_{image_load}")

    pairs = []
    truncated = []
    next_load_index = {}
    for path, write in writes:
        loads = loads_by_path.get(path, [])
        index = next_load_index.get(path, 0)
        # Writes are sorted, so the load index for each path only moves forward
        while index < len(loads) and loads[index].sort_key <= write.sort_key:
            index += 1
        next_load_index[path] = index

        deadline = write.time + WINDOW
        if index < len(loads) and loads[index].time <= deadline:
            pairs.append({"write": write.to_dict(), "load": loads[index].to_dict()})
        elif deadline > end:
            truncated.append(write.record_id)
    if truncated:
        correlation_gaps.append("capture_ends_before_correlation_window")

    return {
        "id": capture_id,
        "host": host,
        "source": source,
        "windows_build": capture.get("windows_build"),
        "sysmon_version": capture.get("sysmon_version"),
        "sysmon_config_ref": capture.get("sysmon_config_ref"),
        "start_utc": start.isoformat(),
        "end_utc": end.isoformat(),
        "collection": collection,
        "sysmon_event_count": len(events),
        "file_create": make_result([event.to_dict() for _, event in writes], file_gaps),
        "write_then_load": make_result(pairs, correlation_gaps),
        "truncated_write_record_ids": truncated,
    }


def analyze_manifest(path):
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    captures = manifest["captures"]
    if not isinstance(captures, list) or not captures:
        raise ValueError("the manifest must contain a nonempty captures list")
    reports = [check_capture(capture, path.parent) for capture in captures]
    if len({report["id"] for report in reports}) != len(reports):
        raise ValueError("capture IDs must be unique")
    return {"correlation_window_seconds": int(WINDOW.total_seconds()), "captures": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="JSON manifest of exported XML captures")
    args = parser.parse_args()
    try:
        report = analyze_manifest(args.manifest)
    except (ET.ParseError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"Cannot analyze capture: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
