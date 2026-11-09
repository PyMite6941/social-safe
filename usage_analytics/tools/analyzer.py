#!/usr/bin/env python3
"""
Analyze login/logout events to compute usage statistics and detect anomalies.
Input: JSON file containing an array of login events.
Each event should have:
  - timestamp: ISO 8601 string (e.g., "2025-09-20T08:00:00Z")
  - type: "login" or "logout"
  - device: string (optional)
  - location: object with city, country, ip (all optional)
Output:
  - Average session length
  - Daily usage hours
  - Anomalies: logins outside typical hours (2am-5am).
"""
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

def parse_iso(timestamp_str):
    # Remove trailing Z and parse
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1] + '+00:00'
    return datetime.fromisoformat(timestamp_str)

def load_events(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of events")
    # Sort by timestamp
    data.sort(key=lambda e: parse_iso(e['timestamp']))
    return data

def pair_sessions(events):
    """Pair each login with the next logout."""
    sessions = []  # each as (login_time, logout_time, login_event, logout_event)
    i = 0
    while i < len(events):
        if events[i]['type'] == 'login':
            login_time = parse_iso(events[i]['timestamp'])
            # find next logout
            j = i + 1
            while j < len(events) and events[j]['type'] != 'logout':
                j += 1
            if j < len(events):
                logout_time = parse_iso(events[j]['timestamp'])
                sessions.append((login_time, logout_time, events[i], events[j]))
                i = j + 1
            else:
                # no matching logout; skip
                break
        else:
            # logout without login; skip
            i += 1
    return sessions

def average_session_length(sessions):
    if not sessions:
        return timedelta(0)
    total = timedelta(0)
    for login, logout, _, _ in sessions:
        total += (logout - login)
    return total / len(sessions)

def daily_usage_hours(sessions):
    """Return dict date -> hours spent that day."""
    usage = defaultdict(float)  # date string -> hours
    for login, logout, _, _ in sessions:
        cur = login
        while cur < logout:
            day_key = cur.date().isoformat()
            # compute minutes to next day or logout
            next_day = (cur + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end = min(logout, next_day)
            minutes = (end - cur).seconds / 60.0
            usage[day_key] += minutes
            cur = end
    # convert minutes to hours
    for d in usage:
        usage[d] = usage[d] / 60.0
    return dict(usage)

def detect_anomalies(events):
    anomalies = []
    for ev in events:
        if ev['type'] == 'login':
            dt = parse_iso(ev['timestamp'])
            hour = dt.hour
            if 2 <= hour <= 5:
                anomalies.append({
                    'type': 'unusual_time_login',
                    'timestamp': ev['timestamp'],
                    'details': f"Login at {hour}:00 (unusual hours)"
                })
    return anomalies

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyzer.py <path_to_login_events_json>")
        sys.exit(1)
    path = Path(sys.argv[1])
    if not path.is_file():
        print("File not found")
        sys.exit(1)
    try:
        events = load_events(path)
    except Exception as e:
        print(f"Error loading events: {e}")
        sys.exit(1)
    sessions = pair_sessions(events)
    avg_len = average_session_length(sessions)
    daily_usage = daily_usage_hours(sessions)
    anomalies = detect_anomalies(events)
    print("=== Usage Analytics ===")
    print(f"Total sessions: {len(sessions)}")
    print(f"Average session length: {avg_len}")
    print("\nDaily usage (hours):")
    for day, hours in sorted(daily_usage.items()):
        print(f"  {day}: {hours:.2f} hours")
    print("\n=== Anomalies Detected ===")
    if anomalies:
        for a in anomalies:
            print(f"- {a['type']}: {a.get('details', '')}")
    else:
        print("No anomalies detected.")
    # Also output JSON for further processing
    result = {
        "total_sessions": len(sessions),
        "average_session_length_seconds": avg_len.total_seconds(),
        "daily_usage_hours": daily_usage,
        "anomalies": anomalies
    }
    print("\n=== JSON Output ===")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()