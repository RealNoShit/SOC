"""Sentinel SOC: first-stage offline event analyzer."""
from fileinput import filename
import json
from pathlib import Path
import ipaddress
import sqlite3
import requests
from datetime import datetime



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


def lookup_ip(ip):
    url = "https://ipwho.is/" + ip
    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as error:
        return {
            "status": "network_error",
            "reason": str(error)
        }

    data = response.json()
    if data.get("success"):
        return {
            "ip": data.get("ip"),
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "organization": data.get("connection", {}).get("org")
        }
    else:
        return { 
            "status": "failed",
            "reason": data.get("message", "Unknown error")
        }

def usernames_targeted_by_ip(events, target_ip):
    usernames = set()

    for event in events:
        if normalize_ip(event) == target_ip:
            if normalize_event_type(event) == "login_failed":
                username = event.get("username")

                if username:
                    usernames.add(username)

    return sorted(usernames)

def hosts_targeted_by_ip(events, target_ip):
    hosts = set()

    for event in events:
        if normalize_ip(event) == target_ip:
            if normalize_event_type(event) == "login_failed":
                host = event.get("host")

                if host:
                    hosts.add(host)

    return sorted(hosts)

def connect_database():
    connection = sqlite3.connect("soc_alerts.db")
    return connection

def alert_exists(connection, ip, description):
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM alerts
        WHERE source_ip = ?
          AND description = ?
          AND status IN ('new', 'investigating')
        LIMIT 1
        """,
        (ip, description)
    )

    return cursor.fetchone() is not None

def create_alert(connection, ip, description, severity):
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO alerts (created_at, source_ip, description, severity, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            datetime.now().isoformat(timespec="seconds"),
            ip,
            description,
            severity,
            "new"
        )
    )

    connection.commit()
    return cursor.lastrowid

def get_active_alerts(connection):
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, source_ip, description, severity, status
        FROM alerts
        WHERE status IN ('new', 'investigating')
        ORDER BY id DESC
    """)

    return cursor.fetchall()

def update_alert_status(connection, alert_id, new_status):
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (new_status, alert_id))

    connection.commit()
    return cursor.rowcount

def delete_alert(connection, alert_id):
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM alerts
        WHERE id = ?
    """, (alert_id,))

    connection.commit()
    return cursor.rowcount

#
#
#
#
#
#
#

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


    investigations = []  
    if suspicious_ips:
        print("\n=== Suspicious IP Investigation ===")
        connection = connect_database()

        for ip, count in sorted(suspicious_ips.items(), key=lambda item: -item[1]):
            usernames = usernames_targeted_by_ip(events, ip)
            hosts = hosts_targeted_by_ip(events, ip)
            ip_info = lookup_ip(ip)

            investigation = {
                "ip": ip,
                "failed_login_attempts": count,
                "usernames_targeted": usernames,
                "hosts_targeted": hosts,
                "ip_intelligence": ip_info
            }
            investigations.append(investigation)

            print(f"IP address: {ip} has {count} failed login attempts.")
            print(f"Usernames targeted by {ip}: {', '.join(usernames) or "unknown"}")
            print(f"Hosts targeted by {ip}: {', '.join(hosts) or "unknown"}")

            description = f"Repeated failed login attempts ({count} attempts)"

            if alert_exists(connection, ip, description):
                print(f"Existing alert found for {ip}. Skipping.")
            else:
                alert_id = create_alert(connection, ip, description, "high")
                print(f"Created alert #{alert_id} for {ip}.")
        connection.close()


    connection = connect_database()
    active_alerts = get_active_alerts(connection)
    connection.close()

    print("\n=== Active SOC Alerts ===")

    for alert in active_alerts:
        alert_id, ip, description, severity, status = alert

        print(f"\nAlert #{alert_id}")
        print(f"Source IP: {ip}")
        print(f"Description: {description}")
        print(f"Severity: {severity.upper()}")
        print(f"Status: {status}")
        print("-" * 40)

    # connection = connect_database()

    # updated_rows = update_alert_status(connection, 5, "investigating")

    # print(f"Updated {updated_rows} alert(s).")

    # connection.close()

    # connection = connect_database()

    # for alert_id in [4, 5]:
    #     deleted_rows = delete_alert(connection, alert_id)
    #     print(f"Alert #{alert_id}: {deleted_rows} row(s) deleted.")

    # connection.close()

    # Run Last
    report = {
    "total_events": len(events),
    "high_severity_count": len(high_severity_events(events)),
    "event_types": count_event_types(events),
    "failed_logins_by_ip": failed_logins_by_ip(events),
    "suspicious_ips": detect_suspicious_ip(events),
    "investigations": investigations
    }
    with open("soc_report.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)
    print("\nReport saved to soc_report.json")


if __name__ == "__main__":
    # test_normalize_ip()
    # test_suspicious_ip_detection()
    # test_event_analysis()
    # lookup_ip("8.8.8.8")
    ip = input("Enter an IP address to look up: ").strip()
    lookup_ip(ip)

    main()
