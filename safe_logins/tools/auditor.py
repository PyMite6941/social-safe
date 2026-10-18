#!/usr/bin/env python3

"""
Audit exported social media account data for login security settings.
Currently supports Facebook and Instagram exported JSON (as of 2024).
Usage: python3 auditor.py <path_to_exported_json> [--platform facebook|instagram]
"""
import json
import sys
from pathlib import Path

def load_export(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading file: {e}")
        sys.exit(1)

def audit_facebook(data):
    findings = []
    # Check if 2FA is enabled (structure may vary)
    # Facebook export: security_and_login_information -> two_factor_authentication
    sec = data.get('security_and_login_information', {})
    tfa = sec.get('two_factor_authentication', {})
    if not tfa.get('enabled', False):
        findings.append("Two-factor authentication is NOT enabled.")
    else:
        findings.append("Two-factor authentication is enabled.")
        # Check method
        method = tfa.get('method', '')
        if 'sms' in method.lower():
            findings.append("WARNING: Using SMS for 2FA (vulnerable to SIM swapping). Consider authenticator app or security key.")
    # Login alerts
    alerts = sec.get('login_alerts', {})
    if not alerts.get('enabled', False):
        findings.append("Login alerts are NOT enabled.")
    else:
        findings.append("Login alerts are enabled.")
    # Active sessions? (might be in a different section)
    # We'll skip for brevity
    return findings

def audit_instagram(data):
    findings = []
    # Instagram export structure may differ; we'll look for security settings
    # This is a placeholder; actual structure requires checking a real export.
    # For now, we'll just check if there's a security section.
    sec = data.get('security_and_login_information', {})
    if not sec:
        findings.append("Could not find security and login information in export. Structure may have changed.")
        return findings
    tfa = sec.get('two_factor_authentication', {})
    if not tfa.get('enabled', False):
        findings.append("Two-factor authentication is NOT enabled.")
    else:
        findings.append("Two-factor authentication is enabled.")
        method = tfa.get('method', '')
        if 'sms' in method.lower():
            findings.append("WARNING: Using SMS for 2FA (vulnerable to SIM swapping). Consider authenticator app or security key.")
    alerts = sec.get('login_alerts', {})
    if not alerts.get('enabled', False):
        findings.append("Login alerts are NOT enabled.")
    else:
        findings.append("Login alerts are enabled.")
    return findings

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = Path(sys.argv[1])
    if not path.is_file():
        print("File not found")
        sys.exit(1)
    platform = "facebook"  # default
    if len(sys.argv) >= 3 and sys.argv[2] == "--platform":
        if len(sys.argv) >= 4:
            platform = sys.argv[3]
        else:
            print("Missing platform argument after --platform")
            sys.exit(1)
    elif len(sys.argv) >= 3:
        # allow shorthand: auditor.py file.json facebook
        platform = sys.argv[2]
    data = load_export(path)
    if platform == "facebook":
        findings = audit_facebook(data)
    elif platform == "instagram":
        findings = audit_instagram(data)
    else:
        print(f"Auditing for platform {"{platform}"} is not implemented yet.")
        sys.exit(1)
    print(f"=== Security Audit for {platform.capitalize()} ===")
    for f in findings:
        print(f"- {f}")

if __name__ == "__main__":
    main()