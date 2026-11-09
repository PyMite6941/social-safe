# Security Analysis Module

This directory contains tools for detecting suspicious social media activity and analyzing account usage patterns.

## Files

- `patterns.json` – Regex patterns for common threats:
  - Crypto scam signals (cashtags, giveaway wording, etc.)
  - Phishing indicators
  - Suspicious URL shorteners and risky domains
  - Account takeover indicators (password changes, new devices, etc.)
- `analyzer.py` – Python module with:
  - `detect_suspicious(text)` → returns dict of findings by category.
  - `average_online_time(sessions)` → average session length from login/logout pairs.
  - `daily_usage_report(sessions)` → hours spent per calendar day.

## Usage

```python
from analyzer import detect_suspicious, average_online_time, daily_usage_report

text = "Free $TOKEN airdrop! Click http://bit.ly/xyz to claim."
findings = detect_suspicious(text)
print(findings)

sessions = [("2025-09-20 08:00:00", "2025-09-20 10:30:00")]
avg = average_online_time(sessions)
print(f"Average session: {avg}")

report = daily_usage_report(sessions)
print(report)
```

## Extending

- Add new regex categories to `patterns.json`.
- Implement additional analyzers (e.g., geolocation anomaly detection, posting frequency outliers).
- Integrate with actual social‑media APIs to fetch real‑time activity logs.

## Security Recommendations

1. Enforce MFA on all accounts.
2. Monitor login locations and devices; flag impossible travel.
3. Rate‑limit API requests and monitor for credential‑stuffing patterns.
4. Regularly review authorized applications and revoke unused tokens.
5. Educate users about phishing and social‑engineering tactics.