"""Replay scheduled detection using synthetic Windows Security records."""
import sqlite3

RULE = "local-admin-membership"
ADMINISTRATORS = "S-1-5-32-544"
RUN_MINUTES = (5, 10, 15, 20)

# All times are seconds since 21:00:00 UTC.
EVENTS = [
    ("WIN-LAB", 84217, 4732, ADMINISTRATORS, 72, 75),
    ("WIN-LAB", 84234, 4732, ADMINISTRATORS, 200, 462),
    ("WIN-LAB", 84234, 4732, ADMINISTRATORS, 200, 668),
    ("WIN-LAB", 84245, 4732, "S-1-5-32-545", 240, 241),
]


def utc(seconds):
    minutes, seconds = divmod(seconds, 60)
    return f"21:{minutes:02}:{seconds:02}"


def matches(db, run, lookback):
    return db.execute(
        """
        SELECT host, record_id
        FROM security_events
        WHERE event_id = 4732 AND target_sid = ?
          AND indexed_at < ?
          AND event_at >= ? AND event_at < ?
        ORDER BY indexed_at, host, record_id
        """,
        (ADMINISTRATORS, run, run - lookback, run),
    ).fetchall()


def replay(db, lookback, deduplicate):
    emitted = []
    hits_by_run = []
    for minute in RUN_MINUTES:
        raw = matches(db, minute * 60, lookback)
        hits_by_run.append(len(raw))
        with db:
            for host, record_id in raw:
                if deduplicate:
                    write = db.execute(
                        "INSERT OR IGNORE INTO alerts VALUES (?, ?, ?, ?)",
                        ("Security", host, record_id, RULE),
                    )
                    if not write.rowcount:
                        continue
                emitted.append((minute, record_id))
    return emitted, hits_by_run


def main():
    with sqlite3.connect(":memory:") as db:
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
        db.executemany("INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?)", EVENTS)
        fixed, fixed_hits = replay(db, 300, False)
        overlap, overlap_hits = replay(db, 900, False)
        unique, unique_hits = replay(db, 900, True)

    assert fixed == [(5, 84217)] and fixed_hits == [1, 0, 0, 0]
    assert overlap_hits == unique_hits == [1, 2, 3, 0]
    assert unique == [(5, 84217), (10, 84234)]

    _, record_id, _, _, event_at, indexed_at = EVENTS[1]
    print("Scheduled detection replay | Windows Security 4732")
    print("Synthetic events / UTC / 5-minute schedule\n")
    print(f"Late record    {record_id}  event {utc(event_at)}  indexed {utc(indexed_at)}")
    print(f"Index lag      {indexed_at - event_at}s   original window closed at 21:05:00")
    print(f"Replay copy    {record_id}  indexed again at {utc(EVENTS[2][-1])}\n")
    print(f"{'Search strategy':<30} {'Alerts':<8} {'Duplicate':<11} {'Late event'}")
    print("-" * 68)
    for label, alerts in [
        ("5m fixed window", fixed),
        ("15m lookback", overlap),
        ("15m + alert dedup", unique),
    ]:
        first = next((minute for minute, rid in alerts if rid == record_id), None)
        duplicates = len(alerts) - len({rid for _, rid in alerts})
        print(f"{label:<30} {len(alerts):<8} {duplicates:<11} "
              f"{utc(first * 60) if first is not None else 'MISSED'}")
    print("\nDedup key: rule + host + channel + event record ID")


if __name__ == "__main__":
    main()
