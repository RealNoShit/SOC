"""Sentinel SOC: first-stage offline event analyzer."""
from fileinput import filename
import json
from pathlib import Path
import ipaddress


def load_events(filename):
    with open(filename, "r", encoding="utf-8") as file:
        data = json.load(file)

    # If the JSON contains an "events" dictionary wrapper
    if isinstance(data, dict):
        data = data.get("events")

    # Validate that we now have a list
    if not isinstance(data, list):
        raise ValueError("Dataset must contain a list of events.")

    # Validate each event
    for index, event in enumerate(data):
        if not isinstance(event, dict):
            raise ValueError(f"Event {index} must be a dictionary.")

    return data

def normalize_event_type(event):
    event_type = event.get("event_type") or "unknown"
    return str(event_type).strip().lower().replace("-", "_")

def normalize_severity(event):
    severity = event.get("severity") or "unknown"
    return str(severity).strip().lower()

def normalize_ip(event):
    ip = event.get("source_ip")
    if not ip:
        return "unknown"
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return "invalid_ip"


def count_event_types(events):
    counts = {}
    for event in events:
        event_type = normalize_event_type(event)
        counts[event_type] = counts.get(event_type, 0) + 1
    return counts


def high_severity_events(events):
    return [event for event in events if normalize_severity(event) == "high"]


def failed_logins_by_ip(events):
    counts = {}
    for event in events:
        if normalize_event_type(event) == "login_failed":
            ip = normalize_ip(event)
            counts[ip] = counts.get(ip, 0) + 1
    return counts

def usernames_with_failed_logins(events):
    """Return failed login counts keyed by username."""
    counts = {}
    for event in events:
        if normalize_event_type(event) == "login_failed":
            username = event.get("username")
            if username:
                counts[username] = counts.get(username, 0) + 1
    return counts

def high_severity_by_ip(events):
    """Return high severity event counts keyed by source IP."""
    counts = {}
    for event in events:
        if normalize_severity(event) == "high":
            ip = normalize_ip(event)
            counts[ip] = counts.get(ip, 0) + 1
    return counts

def high_severity_by_host_system(events):
    """Return high severity event counts keyed by host system."""
    counts = {}
    for event in events:
        if normalize_severity(event) == "high":
            host = event.get("host") or "Unknown"
            counts[host] = counts.get(host, 0) + 1
    return counts

def detect_suspicious_ip(events, threshold=5):
    """Detect IPs with failed login attempts exceeding a threshold."""
    failed_ips = failed_logins_by_ip(events)
    suspicious_ips = {ip: count for ip, count in failed_ips.items() if count > threshold and ip not in ["unknown", "invalid_ip"]
                      }
    return suspicious_ips



def test_suspicious_ip_detection():
    events = (
        [{"event_type": "login_failed", "source_ip": "192.168.1.10"}] * 12
        + [{"event_type": "login_failed", "source_ip": "not-an-ip"}] * 15
        + [{"event_type": "login_failed", "source_ip": None}] * 20
    )

    result = detect_suspicious_ip(events, threshold=10)

    assert result == {"192.168.1.10": 12}

    print("Suspicious IP detection test passed!")

def test_normalize_ip():
    assert normalize_ip({"source_ip": "192.168.1.10"}) == "192.168.1.10"
    assert normalize_ip({"source_ip": "not-an-ip"}) == "invalid_ip"
    assert normalize_ip({"source_ip": None}) == "unknown"
    assert normalize_ip({}) == "unknown"

    print("IP normalization tests passed!")

def test_event_analysis():
    events = [
        {"event_type": "login_failed", "severity": "high"},
        {"event_type": "login-failed", "severity": "HIGH"},
        {"event_type": "LOGIN_FAILED", "severity": " low "}
    ]

    event_counts = count_event_types(events)
    high_events = high_severity_events(events)

    assert event_counts["login_failed"] == 3
    assert len(high_events) == 2

    print("Event analysis test passed!")

def main():
    filename = input("Enter JSON filename: ").strip() or "security_events.json"
    try:
        events = load_events(filename)
    except (OSError, json.JSONDecodeError, ValueError) as error:
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

    print("\nHigh severity events by source IP:")
    for ip, count in sorted(high_severity_by_ip(events).items(), key=lambda item: -item[1]):
        print(f"  {ip}: {count}")

    print("\nHigh severity events by host system:")
    for host, count in sorted(high_severity_by_host_system(events).items(), key=lambda item: -item[1]):
        print(f"  {host}: {count}")

    failed_ips = failed_logins_by_ip(events)
    suspicious_ips = detect_suspicious_ip(events)

    if failed_ips:
        top_ip = max(failed_ips, key=failed_ips.get)

        print("\nIP with most failed logins:")
        print(f"  {top_ip}: {failed_ips[top_ip]}")

    if suspicious_ips:
        print("\nSuspicious IPs:")
        for ip, count in sorted(suspicious_ips.items(), key=lambda item: -item[1]):
            print(f"  {ip}: {count}")


    # Run Last
    report = {
    "total_events": len(events),
    "high_severity_count": len(high_severity_events(events)),
    "event_types": count_event_types(events),
    "failed_logins_by_ip": failed_logins_by_ip(events),
    "suspicious_ips": detect_suspicious_ip(events)
    }
    with open("soc_report.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)
    print("\nReport saved to soc_report.json")


if __name__ == "__main__":
    test_normalize_ip()
    test_suspicious_ip_detection()
    test_event_analysis()
    main()
