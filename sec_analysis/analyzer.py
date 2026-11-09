#!/usr/bin/env python3
"""
Security analyzer for social media accounts.
- Detects suspicious content using regex patterns.
- Analyzes login/online sessions to compute average usage time.
"""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Optional

PATTERNS_PATH = Path(__file__).parent / "patterns.json"

def load_patterns() -> Dict[str, List[str]]:
    with open(PATTERNS_PATH, 'r') as f:
        return json.load(f)

def compile_patterns(patterns: Dict[str, List[str]]) -> Dict[str, List[re.Pattern]]:
    compiled = {}
    for category, pat_list in patterns.items():
        compiled[category] = [re.compile(p) for p in pat_list]
    return compiled

def detect_suspicious(text: str, compiled: Optional[Dict[str, List[re.Pattern]]] = None) -> Dict[str, List[str]]:
    if compiled is None:
        compiled = compile_patterns(load_patterns())
    findings = {}
    for category, pat_list in compiled.items():
        matches = []
        for pat in pat_list:
            for m in pat.findall(text):
                if isinstance(m, tuple):
                    m = ' '.join(m)
                matches.append(m)
        if matches:
            findings[category] = matches
    return findings

def parse_timestamp(ts: str) -> datetime:
    # Try common formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    raise ValueError(f"Unable to parse timestamp: {ts}")

def average_online_time(sessions: List[Tuple[str, str]]) -> timedelta:
    """
    sessions: list of (login_timestamp, logout_timestamp) strings.
    Returns average duration as timedelta.
    """
    total = timedelta()
    for login_str, logout_str in sessions:
        login = parse_timestamp(login_str)
        logout = parse_timestamp(logout_str)
        if logout < login:
            # Assume overnight?
            logout += timedelta(days=1)
        total += (logout - login)
    if not sessions:
        return timedelta(0)
    return total / len(sessions)

def daily_usage_report(sessions: List[Tuple[str, str]]) -> Dict[str, float]:
    """
    Returns dict with date -> hours spent that day.
    """
    usage = {}
    for login_str, logout_str in sessions:
        login = parse_timestamp(login_str)
        logout = parse_timestamp(logout_str)
        if logout < login:
            logout += timedelta(days=1)
        cur = login
        while cur < logout:
            day_key = cur.date().isoformat()
            # compute minutes to next day or logout
            next_day = (cur + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            end = min(logout, next_day)
            minutes = (end - cur).seconds / 60.0
            usage[day_key] = usage.get(day_key, 0.0) + minutes
            cur = end
    # convert minutes to hours
    for d in usage:
        usage[d] = usage[d] / 60.0
    return usage

if __name__ == "__main__":
    # Example usage
    sample_text = "Check out our $TODAY giveaway! Link in bio. Verify your account at http://fake-login.com"
    print("Detection results:")
    print(json.dumps(detect_suspicious(sample_text), indent=2))
    # Example sessions
    sessions = [
        ("2025-09-20 08:00:00", "2025-09-20 10:30:00"),
        ("2025-09-20 19:00:00", "2025-09-20 22:15:00"),
        ("2025-09-21 09:15:00", "2025-09-21 11:45:00")
    ]
    avg = average_online_time(sessions)
    print(f"\nAverage session length: {avg}")
    print("Daily usage (hours):")
    print(json.dumps(daily_usage_report(sessions), indent=2))