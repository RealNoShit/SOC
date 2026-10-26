"""Sentinel SOC: first-stage offline event analyzer."""
import json
from pathlib import Path


def load_events(filename):
    """Read a JSON dataset and return its list of security events."""
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)
    events = data["events"]
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        raise ValueError("'events' must be a list of objects")
    return events


def count_event_types(events):
    counts = {}
    for event in events:
        event_type = event.get("event_type") or "unknown"
        counts[event_type] = counts.get(event_type, 0) + 1
    return counts


def high_severity_events(events):
    return [event for event in events if str(event.get("severity", "")).lower() == "high"]


def failed_logins_by_ip(events):
    counts = {}
    for event in events:
        if str(event.get("event_type", "")).replace("-", "_").lower() == "login_failed":
            ip = event.get("source_ip") or "Unknown"
            counts[ip] = counts.get(ip, 0) + 1
    return counts

def usernames_with_failed_logins(events):
    """Return failed login counts keyed by username."""
    counts = {}
    for event in events:
        if str(event.get("event_type", "")).replace("-", "_").lower() == "login_failed":
            username = event.get("username")
            if username:
                counts[username] = counts.get(username, 0) + 1
    return counts


def main():
    filename = Path(__file__).with_name("security_events.json")
    try:
        events = load_events(filename)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as error:
        print(f"Could not load dataset: {error}")
        return

    print("\n=== SENTINEL SOC OVERVIEW ===")
    print(f"Total events: {len(events)}")
    print(f"High severity events: {len(high_severity_events(events))}")
    print("\nEvents by type:")
    for event_type, count in sorted(count_event_types(events).items(), key=lambda item: -item[1]):
        print(f"  {event_type}: {count}")
    print("\nFailed logins by source IP:")
    for ip, count in sorted(failed_logins_by_ip(events).items(), key=lambda item: -item[1]):
        print(f"  {ip}: {count}")
        
    print("\nUsernames with failed login attempts:")
    for username, count in sorted(
        usernames_with_failed_logins(events).items(), key=lambda item: -item[1]
    ):
        print(f"  {username}: {count}")

if __name__ == "__main__":
    main()
