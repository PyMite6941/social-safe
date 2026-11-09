"""Current social-media threat signatures and link analysis for social-safe.

Each signature describes a scam or attack technique actively reported against
social-media users (FBI IC3 / FTC advisories and industry reporting through
2026). Signatures are deliberately phrase-based: they flag messages worth a
second look, they do not prove malice. Every match carries plain-language
advice so the user knows what to do next.

To add a signature, append a ThreatSignature to EMERGING_THREATS. Keep the
regex case-insensitive and anchored on wording the scam actually uses.
"""

from dataclasses import dataclass
from typing import Dict, List
from urllib.parse import urlparse
import ipaddress
import re


@dataclass(frozen=True)
class ThreatSignature:
    id: str
    name: str
    severity: str  # low | medium | high | critical
    pattern: str
    advice: str


EMERGING_THREATS: List[ThreatSignature] = [
    ThreatSignature(
        "gov_impersonation_recovery",
        "Fake FBI / IC3 / FTC agent or fund-recovery scam",
        "critical",
        r"(?i)\b(ic3|fbi|ftc|federal trade commission|internet crime complaint)\b.{0,80}"
        r"\b(recover|refund|case|claim|agent|investigat|fee)"
        r"|\b(recover(y)?|retrieve)\b.{0,40}\b(lost|stolen|scammed)\b.{0,40}\b(funds|money|crypto)",
        "Government agencies, including the FBI's IC3, never contact victims through social media "
        "or charge fees to recover money. File reports only by typing ic3.gov or "
        "reportfraud.ftc.gov into your browser yourself.",
    ),
    ThreatSignature(
        "recovery_fee",
        "Upfront fee to release recovered or prize money",
        "high",
        r"(?i)\b(processing|release|clearance|unlock|withdrawal|tax)\s+fee\b",
        "Being asked to pay before you can receive money is the core of advance-fee and "
        "recovery scams. Do not pay.",
    ),
    ThreatSignature(
        "clickfix",
        "ClickFix: instructions to paste a command into Run / Terminal / PowerShell",
        "critical",
        r"(?i)(win(dows)?\s*(key)?\s*\+\s*r\b|press\s+(win|windows)\s*\+?\s*r"
        r"|paste\s+(it|this|the\s+(code|command))\s+(in|into)\s+(the\s+)?(run|terminal|powershell|cmd)"
        r"|powershell\s+-(e|enc|encodedcommand|w\s+hidden)\b|mshta\s+https?://|curl\s+[^|]+\|\s*(sh|bash))",
        "No legitimate site, captcha or support agent asks you to paste commands into Run, "
        "Terminal or PowerShell. This installs malware that steals saved passwords and session cookies.",
    ),
    ThreatSignature(
        "mfa_code_theft",
        "Request for a login, 2FA or verification code",
        "critical",
        r"(?i)(send|give|share|forward|read)\s+(me\s+)?(the|that|your)\s+"
        r"(\d-digit\s+)?(code|otp|verification code|login code|2fa code|security code)"
        r"|(sent|texted)\s+(you\s+)?(a|my)\s+code\s+by\s+(mistake|accident)",
        "Never share a login or 2FA code with anyone, even a friend. A code sent to you is the "
        "key to your account, and \"I sent it by mistake\" is a takeover trick.",
    ),
    ThreatSignature(
        "account_appeal_phish",
        "Fake copyright / policy violation or verified-badge notice",
        "high",
        r"(?i)(copyright\s+(infringement|violation|complaint)|violat\w*\s+(our\s+)?(community\s+)?(guidelines|standards|terms))"
        r".{0,120}(appeal|disabled|deleted|suspended|restricted|24\s*hours|48\s*hours)"
        r"|(meta|blue|verified)\s+(badge|verification|verified).{0,60}(apply|claim|form|eligible)",
        "Platforms deliver policy notices inside the app's own notification or support inbox, "
        "not through DMs or comments. Check your account status from the app itself.",
    ),
    ThreatSignature(
        "seed_phrase_wallet_drain",
        "Wallet connect / seed phrase / airdrop drainer",
        "critical",
        r"(?i)(seed|recovery|secret)\s+phrase|private\s+key|connect\s+(your\s+)?wallet"
        r"|claim\s+(your\s+)?(airdrop|tokens?)|wallet\s+(validation|sync|verification)",
        "No real project needs your seed phrase or private key, and \"connect wallet to claim\" "
        "sites are drainers. Never type a seed phrase into a site or message.",
    ),
    ThreatSignature(
        "pig_butchering",
        "Relationship-led investment scam (\"pig butchering\")",
        "high",
        r"(?i)(my\s+(uncle|aunt|mentor|cousin)|insider|trading\s+(platform|signals?|group))"
        r".{0,80}(profit|returns?|invest|usdt|crypto|forex|gold)"
        r"|(guaranteed|daily)\s+(profit|returns?)",
        "A stranger or new online friend steering you toward an investment platform is the "
        "classic pig-butchering pattern. Withdrawals stop working once you deposit more.",
    ),
    ThreatSignature(
        "task_scam",
        "Task / \"like-for-pay\" job scam",
        "high",
        r"(?i)(like|rate|review|follow)\s+(videos?|products?|hotels?|apps?|posts?)\s+.{0,30}(earn|paid|commission|\$)"
        r"|(complete|finish)\s+(daily\s+)?tasks?.{0,40}(commission|earn|deposit|recharge|vip)"
        r"|(recharge|top\s*up|deposit)\s+to\s+(unlock|continue|withdraw)",
        "Jobs that pay you to like or rate things and then ask you to deposit money to "
        "\"unlock\" earnings are task scams. Real employers never ask you to pay.",
    ),
    ThreatSignature(
        "deepfake_emergency",
        "Voice / video clone emergency or \"new number\" request",
        "high",
        r"(?i)(this\s+is\s+my\s+new\s+number|it'?s\s+me.{0,20}new\s+(number|account|phone)"
        r"|lost\s+my\s+phone.{0,60}(send|wire|transfer|money|gift\s*card)"
        r"|(bail|accident|arrested|hospital).{0,60}(send|wire|transfer)\s+(money|funds|\$))",
        "Voices and faces can be cloned from a few seconds of public video. Hang up and call "
        "the person back on a number you already have, or ask a question only they would know.",
    ),
    ThreatSignature(
        "sextortion",
        "Sextortion / intimate-image threat",
        "critical",
        r"(?i)(i\s+have|we\s+have|i\s+recorded|got)\s+(your\s+)?(nudes?|intimate|private\s+(video|photos?|pics?))"
        r"|(send|share|post|leak)\s+(it|them|these|your\s+(pics|photos|video))\s+to\s+(all\s+)?(your\s+)?(followers|friends|family|contacts)",
        "Do not pay or send anything more. Stop replying, keep screenshots, block the account, "
        "and report it. Minors can use NCMEC's Take It Down (takeitdown.ncmec.org).",
    ),
    ThreatSignature(
        "gift_card_payment",
        "Payment demanded in gift cards or crypto ATM",
        "high",
        r"(?i)(gift\s*cards?|steam\s*cards?|apple\s*cards?|google\s*play\s*cards?|bitcoin\s+atm|crypto\s+atm)"
        r".{0,60}(pay|send|buy|purchase|code|scratch)"
        r"|(pay|send|buy|purchase)\b.{0,40}(gift\s*cards?|steam\s*cards?|apple\s*cards?|google\s*play\s*cards?|bitcoin\s+atm|crypto\s+atm)",
        "Legitimate businesses and agencies never demand payment in gift cards or through crypto ATMs.",
    ),
    ThreatSignature(
        "discord_nitro_game",
        "Free Nitro / \"try my game\" malware lure",
        "high",
        r"(?i)free\s+(discord\s+)?nitro|nitro\s+(gift|giveaway|for\s+free)"
        r"|(try|test)\s+(out\s+)?my\s+(new\s+)?(game|app|beta).{0,60}(download|\.exe|\.zip|\.rar|link)",
        "\"Test my game\" downloads and free-Nitro links are token stealers that take over your "
        "Discord and spam your friends. Don't run files from DMs.",
    ),
    ThreatSignature(
        "quishing",
        "QR code sent to sign in, pay or verify",
        "medium",
        r"(?i)scan\s+(the|this)\s+qr.{0,60}(log\s*in|sign\s*in|verify|pay|claim|unlock)",
        "QR codes hide the real link. Navigate to the site yourself instead of scanning codes "
        "sent in messages.",
    ),
    ThreatSignature(
        "fake_brand_deal",
        "Fake brand collaboration with download or login step",
        "medium",
        r"(?i)(brand\s+(deal|collab\w*|partnership)|sponsorship|ambassador)"
        r".{0,120}(download|\.exe|\.zip|log\s*in|sign\s*in|contract\s+(file|link))",
        "Fake sponsorships often ship malware as a \"contract\" or ask you to sign in on a "
        "lookalike page. Verify the brand through its official website first.",
    ),
    ThreatSignature(
        "is_this_you",
        "\"Is this you in this video?\" credential lure",
        "medium",
        r"(?i)(is\s+(this|that)\s+you|you\s+in\s+(this|that)\s+(video|pic|photo)|look\s+what\s+(they|someone)\s+posted)",
        "This classic lure leads to a fake login page. Don't sign in from a link sent in a DM.",
    ),
]


# Brands commonly spoofed in social-media phishing and their legitimate domains.
BRAND_DOMAINS: Dict[str, List[str]] = {
    "instagram": ["instagram.com", "cdninstagram.com"],
    "facebook": ["facebook.com", "fb.com", "fb.me", "fbcdn.net"],
    "meta": ["meta.com", "facebook.com", "metastatus.com"],
    "whatsapp": ["whatsapp.com", "wa.me"],
    "tiktok": ["tiktok.com", "tiktokv.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discord.media"],
    "youtube": ["youtube.com", "youtu.be", "google.com"],
    "google": ["google.com", "googleusercontent.com", "goo.gl"],
    "twitter": ["twitter.com", "x.com", "t.co"],
    "linkedin": ["linkedin.com", "lnkd.in"],
    "reddit": ["reddit.com", "redd.it"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
    "shorturl.at", "ow.ly", "s.id", "tiny.cc", "buff.ly",
}

# TLDs heavily over-represented in phishing relative to legitimate use.
HIGH_RISK_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "rest", "cfd", "sbs", "icu",
    "buzz", "monster", "lol", "quest", "beauty", "hair", "support", "live",
}

_URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"')\]]+|[a-z0-9-]+(?:\.[a-z0-9-]+)+/[^\s<>\"')\]]*)")


def extract_urls(text: str) -> List[str]:
    """Pull URL-looking strings out of free text."""
    return [m.rstrip(".,;:!?") for m in _URL_RE.findall(text or "")]


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(url: str) -> List[Dict[str, str]]:
    """Return a list of risk findings for a single URL (empty if none)."""
    findings: List[Dict[str, str]] = []
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return findings

    def add(kind: str, severity: str, detail: str):
        findings.append({"url": url, "type": kind, "severity": severity, "detail": detail})

    try:
        ipaddress.ip_address(host)
        add("ip_address_host", "high", "Link points to a raw IP address instead of a domain.")
    except ValueError:
        pass

    if "xn--" in host:
        add("punycode_domain", "high",
            "Domain uses punycode, which can disguise lookalike letters (e.g. a Cyrillic letter that looks like 'a').")

    if "@" in (parsed.netloc or ""):
        add("credentials_in_url", "high",
            "Text before '@' in a link is ignored by the browser; the real site is after it.")

    if host in URL_SHORTENERS:
        add("url_shortener", "medium", "Shortened link hides the real destination.")

    tld = host.rsplit(".", 1)[-1]
    if tld in HIGH_RISK_TLDS:
        add("high_risk_tld", "medium", f".{tld} domains are frequently used for phishing.")

    registrable = _registrable(host)
    for brand, legit in BRAND_DOMAINS.items():
        if brand in host and registrable not in legit and not any(host.endswith("." + d) for d in legit):
            add("brand_lookalike", "critical",
                f"Mentions '{brand}' but is not an official {brand} domain ({registrable}).")
            break

    if parsed.scheme == "http" and "://" in url:
        add("no_https", "low", "Link is not encrypted (http://).")

    return findings


def match_emerging_threats(text: str) -> List[Dict[str, str]]:
    """Match text against EMERGING_THREATS signatures."""
    results = []
    for sig in EMERGING_THREATS:
        m = _COMPILED[sig.id].search(text or "")
        if m:
            results.append({
                "id": sig.id,
                "name": sig.name,
                "pattern": m.group(0)[:120],
                "severity": sig.severity,
                "advice": sig.advice,
            })
    return results


_COMPILED = {sig.id: re.compile(sig.pattern) for sig in EMERGING_THREATS}
