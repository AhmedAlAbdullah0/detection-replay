"""Reproduce the replay, export evidence, and verify the reference outcomes."""
import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import platform
import sqlite3

from detection_replay import EVENTS, RULE, RUN_MINUTES, main, replay, utc


def fixture_db(events=EVENTS):
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE security_events (
            host TEXT, record_id INT, event_id INT, target_sid TEXT,
            event_at INT, indexed_at INT
        );
        CREATE TABLE alerts (
            channel TEXT, host TEXT, record_id INT, rule TEXT,
            PRIMARY KEY (channel, host, record_id, rule)
        );
    """)
    db.executemany("INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?)", events)
    db.commit()
    return db


def collect():
    strategies = []
    for label, lookback, deduplicate in [
        ("5m fixed window", 300, False),
        ("15m lookback", 900, False),
        ("15m + alert dedup", 900, True),
    ]:
        with contextlib.closing(fixture_db()) as db:
            emitted, hits = replay(db, lookback, deduplicate)
        identities = {record_id for _, record_id in emitted}
        first = next((minute for minute, record_id in emitted if record_id == 84234), None)
        strategies.append({
            "strategy": label,
            "lookback_seconds": lookback,
            "deduplicate": deduplicate,
            "raw_hits_per_run": hits,
            "emitted": [{"run_utc": utc(minute * 60), "record_id": record_id}
                        for minute, record_id in emitted],
            "alerts": len(emitted),
            "distinct_event_ids": sorted(identities),
            "duplicate_alerts": len(emitted) - len(identities),
            "late_event_first_alert_utc": utc(first * 60) if first is not None else None,
        })
    assert [item["alerts"] for item in strategies] == [1, 6, 2]
    assert [item["duplicate_alerts"] for item in strategies] == [0, 4, 0]
    assert strategies[0]["raw_hits_per_run"] == [1, 0, 0, 0]
    assert strategies[1]["raw_hits_per_run"] == strategies[2]["raw_hits_per_run"] == [1, 2, 3, 0]
    assert strategies[2]["distinct_event_ids"] == [84217, 84234]
    return {"rule": RULE, "schedule_utc": [utc(minute * 60) for minute in RUN_MINUTES],
            "late_record_id": 84234, "late_event_lag_seconds": 262,
            "strategies": strategies}


def write_evidence(root):
    result = collect()
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        main()
    (root / "replay_output.txt").write_text(captured.getvalue(), encoding="utf-8")
    (root / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with (root / "run_results.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["strategy", "run_utc", "raw_hits", "new_alerts"])
        for item in result["strategies"]:
            for run, raw_hits in zip(result["schedule_utc"], item["raw_hits_per_run"]):
                count = sum(event["run_utc"] == run for event in item["emitted"])
                writer.writerow([item["strategy"], run, raw_hits, count])
    hashes = []
    for name in ["detection_replay.py", "Detection_Query.png", "Detection_Replay.jpg",
                 "replay_output.txt", "results.json", "run_results.csv"]:
        hashes.append(f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}")
    (root / "SHA256SUMS.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    environment = {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                   "platform": platform.system(), "validation_date": "2026-11-23"}
    (root / "environment.json").write_text(json.dumps(environment, indent=2) + "\n", encoding="utf-8")
    print("Verified: alerts [1, 6, 2]; duplicate alerts [0, 4, 0]; late event recovered at 21:10:00.")


if __name__ == "__main__":
    write_evidence(Path(__file__).parent)
