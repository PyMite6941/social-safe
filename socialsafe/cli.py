"""Cross-platform command-line interface for social-safe.

Works the same on Windows, macOS, and Linux:

    socialsafe scan "message text or link"     # any app: paste a DM, comment, or URL
    socialsafe scan --file message.txt         # or pipe text in on stdin
    socialsafe check-url https://example.com
    socialsafe guide <platform>                # hardening steps (any platform name)
    socialsafe monitor <platform>              # follower/privacy monitor + alerts
    socialsafe platforms                       # list built-in monitors
    socialsafe setup                           # install the browser used by web monitors
    socialsafe threats                         # list the threat signatures checked

`python -m socialsafe ...` is equivalent when the console script isn't on PATH.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Dict, List, Optional

from .monitor.base import (
    MFA_GUIDANCE,
    MFA_SETUP_URLS,
    BaseSocialMonitor,
    ContentScanner,
    PIIDetector,
    user_data_dir,
)
from .monitor.threats import EMERGING_THREATS, analyze_url

PLATFORMS = ["instagram", "twitter", "reddit", "linkedin", "facebook", "tiktok", "youtube", "discord"]
PLATFORM_NOTES = {
    "instagram": "Instaloader (IG_USERNAME / IG_PASSWORD)",
    "twitter": "Official API (TWITTER_* keys)",
    "reddit": "Official API (REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET)",
    "linkedin": "Browser automation (LINKEDIN_USERNAME / LINKEDIN_PASSWORD)",
    "facebook": "Browser automation (FB_USERNAME / FB_PASSWORD)",
    "tiktok": "Browser automation (TIKTOK_USERNAME / TIKTOK_PASSWORD)",
    "youtube": "Browser automation (YOUTUBE_USERNAME / YOUTUBE_PASSWORD)",
    "discord": "Browser automation (DISCORD_USERNAME / DISCORD_PASSWORD)",
}
SEVERITY_RANK = {"none": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


def _configure_console() -> None:
    """Make output safe on consoles that aren't UTF-8 (e.g. older Windows)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def _load_dotenv() -> None:
    """Load a .env from the working directory or the user data dir, if present."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    for candidate in (os.path.join(os.getcwd(), ".env"), str(user_data_dir() / ".env")):
        if os.path.exists(candidate):
            load_dotenv(candidate, override=False)


def scan_text(text: str, pii: bool = True) -> Dict[str, object]:
    """Scan arbitrary text from any platform. Usable as a library function."""
    scanner = ContentScanner(enable_phishing_detection=True)
    result = scanner.scan_post(text)
    result["phishing_classification"] = scanner.classify_phishing(text)
    if pii:
        result["pii"] = {k: v for k, v in PIIDetector().detect_all(text).items() if v}
    return result


def hardening_guide(platform: str) -> Dict[str, object]:
    """Hardening guide for any platform name; unknown names get general steps."""
    # The method only reads `self` when no platform is passed.
    guide = BaseSocialMonitor.get_security_hardening_guide(None, platform)
    guide["mfa_guidance"] = MFA_GUIDANCE.get(
        platform.lower(),
        "Open the app's Settings > Security (or Account) and turn on two-factor "
        "authentication, preferring an authenticator app, passkey, or security key over SMS.",
    )
    guide["mfa_setup_url"] = MFA_SETUP_URLS.get(platform.lower())
    return guide


def _print_scan(result: Dict[str, object]) -> None:
    threats: List[Dict[str, str]] = result["text_threats"]
    sev = result["overall_severity"]
    if not threats and not result.get("pii"):
        print("No known threat patterns found.")
        print("That isn't a guarantee: if a message pressures you, asks for codes, money, or a login, verify it another way.")
        return
    print(f"Overall severity: {sev.upper()}  ({len(threats)} indicator(s))\n")
    for t in sorted(threats, key=lambda t: -SEVERITY_RANK.get(t["severity"], 0)):
        label = t.get("name") or t.get("detail") or f"{t['category'].capitalize()} wording"
        print(f"  [{t['severity'].upper():8}] {label}")
        print(f"             matched: {t['pattern']}")
    cls = result.get("phishing_classification", {})
    if cls.get("is_phishing"):
        print(f"\nPhishing score {cls['score']:.0f} (threshold {cls['threshold']}) - likely phishing.")
    if result.get("pii"):
        print("\nPersonal info found in the text: " + ", ".join(result["pii"].keys()))
    advice = result["text_breakdown"].get("advice") or []
    if advice:
        print("\nWhat to do:")
        for a in advice:
            print(f"  - {a}")


def cmd_scan(args) -> int:
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    elif args.text:
        text = " ".join(args.text)
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print("Give text to scan, use --file, or pipe text in.", file=sys.stderr)
        return 2
    result = scan_text(text, pii=not args.no_pii)
    if args.json:
        print(json.dumps(result, indent=2, default=list))
    else:
        _print_scan(result)
    threshold = SEVERITY_RANK[args.fail_on] if args.fail_on else None
    if threshold is not None and SEVERITY_RANK.get(result["overall_severity"], -1) >= threshold:
        return 1
    return 0


def cmd_check_url(args) -> int:
    worst = -1
    for url in args.urls:
        findings = analyze_url(url)
        if args.json:
            print(json.dumps({"url": url, "findings": findings}, indent=2))
        elif not findings:
            print(f"{url}\n  no red flags in the link itself (the page could still be malicious)")
        else:
            print(url)
            for f in findings:
                print(f"  [{f['severity'].upper():8}] {f['detail']}")
        for f in findings:
            worst = max(worst, SEVERITY_RANK[f["severity"]])
    return 1 if worst >= SEVERITY_RANK["high"] else 0


def cmd_guide(args) -> int:
    guide = hardening_guide(args.platform)
    if args.json:
        print(json.dumps(guide, indent=2))
        return 0
    name = args.platform.capitalize()
    print(f"Securing your {name} account\n")
    print(f"Two-factor authentication: {guide['mfa_guidance']}")
    if guide["mfa_setup_url"]:
        print(f"  {guide['mfa_setup_url']}")
    if guide["steps"]:
        print("\nSteps:")
        for s in guide["steps"]:
            print(f"  {s['step']}. {s['action']} - {s['detail']}")
    else:
        print(f"\nNo {name}-specific steps yet; the general checklist below applies to any platform.")
    print("\nGeneral:")
    for tip in guide["general_tips"]:
        print(f"  - {tip}")
    return 0


def cmd_platforms(args) -> int:
    print("Built-in monitors:")
    for p in PLATFORMS:
        print(f"  {p:10} {PLATFORM_NOTES[p]}")
    print("\n`scan`, `check-url`, and `guide` work for any platform or app, including ones not listed.")
    print("To add a monitor for another platform, see setup_custom_platform.py.")
    return 0


def cmd_threats(args) -> int:
    for sig in EMERGING_THREATS:
        print(f"[{sig.severity.upper():8}] {sig.name}")
        if args.verbose:
            print(f"           {sig.advice}")
    return 0


def cmd_setup(args) -> int:
    """Install Chromium for Playwright using the current interpreter (any OS)."""
    cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
    if args.with_deps:
        cmd.append("--with-deps")
    print("Running: " + " ".join(cmd))
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        print("Playwright isn't installed. Run: pip install playwright", file=sys.stderr)
        return 1


def cmd_monitor(args) -> int:
    from .monitor import get_monitor

    browser_based = args.platform not in ("instagram", "twitter", "reddit")
    kwargs = {"headless": not args.show_browser} if browser_based else {}
    monitor = get_monitor(args.platform, **kwargs)
    password_env = {
        "instagram": "IG_PASSWORD", "facebook": "FB_PASSWORD",
    }.get(args.platform, f"{args.platform.upper()}_PASSWORD")
    if not monitor.login(os.getenv(password_env)):
        print(f"Login to {args.platform} failed.", file=sys.stderr)
        return 1
    changes = monitor.check_changes()
    audit = monitor.audit_account() if monitor.audit_enabled else None
    if args.json:
        print(json.dumps({"changes": changes, "audit": audit}, indent=2, default=list))
    else:
        for key, val in changes.items():
            if val:
                print(f"{key}: {sorted(val) if isinstance(val, (set, list)) else val}")
        if audit and audit.get("risks"):
            print("Risks: " + ", ".join(map(str, audit["risks"])))
    if monitor._should_alert(changes, audit):
        monitor.send_alert(changes, audit_result=audit)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="socialsafe", description="Social media account protection.")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a message, comment, or post from any platform")
    s.add_argument("text", nargs="*", help="text to scan (or use --file / stdin)")
    s.add_argument("--file", help="read text from a file")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-pii", action="store_true", help="skip personal-info detection")
    s.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                   help="exit 1 if overall severity is at least this (for scripts/CI)")
    s.set_defaults(func=cmd_scan)

    u = sub.add_parser("check-url", help="check links for phishing red flags")
    u.add_argument("urls", nargs="+")
    u.add_argument("--json", action="store_true")
    u.set_defaults(func=cmd_check_url)

    g = sub.add_parser("guide", help="account hardening steps for any platform")
    g.add_argument("platform")
    g.add_argument("--json", action="store_true")
    g.set_defaults(func=cmd_guide)

    m = sub.add_parser("monitor", help="run the follower/privacy monitor for a platform")
    m.add_argument("platform", choices=PLATFORMS)
    m.add_argument("--json", action="store_true")
    m.add_argument("--show-browser", action="store_true", help="run browser monitors visibly")
    m.set_defaults(func=cmd_monitor)

    sub.add_parser("platforms", help="list built-in platform monitors").set_defaults(func=cmd_platforms)

    t = sub.add_parser("threats", help="list threat signatures that scan checks")
    t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(func=cmd_threats)

    st = sub.add_parser("setup", help="install the browser used by web-automation monitors")
    st.add_argument("--with-deps", action="store_true", help="also install OS packages (Linux)")
    st.set_defaults(func=cmd_setup)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    _configure_console()
    _load_dotenv()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
