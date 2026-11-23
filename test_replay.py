import contextlib
import sqlite3
import unittest

from detection_replay import ADMINISTRATORS, EVENTS, RULE, matches, replay
from verify import collect, fixture_db


class ReplayTests(unittest.TestCase):
    def test_reference_results(self):
        result = collect()["strategies"]
        self.assertEqual([item["alerts"] for item in result], [1, 6, 2])
        self.assertEqual([item["duplicate_alerts"] for item in result], [0, 4, 0])

    def test_late_event_is_unavailable_at_first_run(self):
        with contextlib.closing(fixture_db()) as db:
            self.assertEqual(matches(db, 300, 900), [("WIN-LAB", 84217)])

    def test_index_boundary_is_strict(self):
        with contextlib.closing(fixture_db()) as db:
            self.assertNotIn(("WIN-LAB", 84234), matches(db, 462, 900))
            self.assertIn(("WIN-LAB", 84234), matches(db, 463, 900))

    def test_event_window_lower_boundary_is_inclusive(self):
        with contextlib.closing(fixture_db()) as db:
            self.assertIn(("WIN-LAB", 84217), matches(db, 372, 300))
            self.assertNotIn(("WIN-LAB", 84217), matches(db, 373, 300))

    def test_non_administrator_group_is_excluded(self):
        with contextlib.closing(fixture_db()) as db:
            self.assertNotIn(("WIN-LAB", 84245), matches(db, 300, 900))

    def test_other_event_id_is_excluded(self):
        other = ("WIN-LAB", 90000, 4733, ADMINISTRATORS, 100, 110)
        with contextlib.closing(fixture_db([other])) as db:
            self.assertEqual(replay(db, 900, False)[0], [])

    def test_overlapping_runs_and_reingestion_emit_one_per_identity(self):
        with contextlib.closing(fixture_db()) as db:
            emitted, raw = replay(db, 900, True)
            self.assertEqual(emitted, [(5, 84217), (10, 84234)])
            self.assertEqual(raw, [1, 2, 3, 0])
            self.assertEqual(db.execute("SELECT count(*) FROM alerts").fetchone()[0], 2)

    def test_rerun_on_same_state_emits_no_new_alerts(self):
        with contextlib.closing(fixture_db()) as db:
            replay(db, 900, True)
            emitted, raw = replay(db, 900, True)
            self.assertEqual(emitted, [])
            self.assertEqual(raw, [1, 2, 3, 0])

    def test_same_record_id_on_another_host_is_not_suppressed(self):
        other = ("WIN-SECOND", 84217, 4732, ADMINISTRATORS, 72, 75)
        with contextlib.closing(fixture_db(EVENTS + [other])) as db:
            replay(db, 900, True)
            rows = db.execute("SELECT host FROM alerts WHERE record_id=84217 ORDER BY host").fetchall()
            self.assertEqual(rows, [("WIN-LAB",), ("WIN-SECOND",)])

    def test_dedup_key_includes_rule(self):
        with contextlib.closing(fixture_db()) as db:
            db.execute("INSERT INTO alerts VALUES (?, ?, ?, ?)",
                       ("Security", "WIN-LAB", 84217, "another-rule"))
            self.assertEqual(replay(db, 900, True)[0], [(5, 84217), (10, 84234)])

    def test_delay_beyond_the_search_horizon_still_misses(self):
        late = ("WIN-LAB", 99999, 4732, ADMINISTRATORS, 100, 1300)
        with contextlib.closing(fixture_db([late])) as db:
            self.assertEqual(replay(db, 900, True)[0], [])

    def test_new_process_state_does_not_claim_persistent_dedup(self):
        emitted = []
        for _ in range(2):
            with contextlib.closing(fixture_db()) as db:
                emitted.append(replay(db, 900, True)[0])
        self.assertEqual(emitted[0], emitted[1])
        self.assertEqual(len(emitted[1]), 2)


if __name__ == "__main__":
    unittest.main()
