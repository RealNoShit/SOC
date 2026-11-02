"""Session 10 starter: explore SOC alerts in SQLite.

This is a compatible stand-in, NOT the teacher's original bootstrap file.
Place security_events.json in the same folder to load the event dataset.
"""
import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "soc_alerts.db"
EVENTS_PATH = BASE_DIR / "security_events.json"


def load_events(path):
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if isinstance(data, dict):
        data = data.get("events")
    if not isinstance(data, list):
        raise ValueError("Expected a list of security events.")
    return data


def main():
    if not DB_PATH.is_file():
        print(f"Database not found: {DB_PATH}")
        return

    if EVENTS_PATH.is_file():
        try:
            haendelser = load_events(EVENTS_PATH)
            print(f"Loaded {len(haendelser)} security events.")
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"Could not load events: {error}")
            haendelser = []
    else:
        print("security_events.json not found; database examples still work.")
        haendelser = []

    with sqlite3.connect(DB_PATH) as conn:
        print("\n=== EXISTING SOC ALERTS ===")
        rows = conn.execute(
            "SELECT id, created_at, source_ip, description, severity, status "
            "FROM alerts ORDER BY id"
        ).fetchall()
        for row in rows:
            print(row)

        # TODO (Session 10, Block 3): Investigate events 106-110 and use
        # INSERT INTO alerts (...) VALUES (?, ?, ?, ?, ?) to create one alert.
        # Call conn.commit() after changes.
        # Before inserting on later runs, check for a similar existing alert.

        # TODO (Block 4): UPDATE an alert's status using WHERE id = ?.
        # TODO (Block 5): Integrate Sentinel's suspicious-IP investigations.


if __name__ == "__main__":
    main()
