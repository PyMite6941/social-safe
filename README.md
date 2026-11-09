# social-safe

Social media account protection for any platform: scan any message or link for current scams, get hardening steps for any account, and monitor followers/privacy on Instagram, X, Reddit, LinkedIn, Facebook, TikTok, YouTube, and Discord.

Runs on **Windows, macOS, and Linux** (Python 3.10+). CI tests all three.

## Features

- **Scan anything from any app**: paste a DM, comment, email, or link into `socialsafe scan` and get a severity rating plus what to do
- **Current threat signatures**: fake FBI/IC3 recovery agents, ClickFix "paste this command" lures, 2FA-code theft, wallet drainers, pig-butchering, task scams, voice-clone emergencies, sextortion, fake copyright/appeal notices, Discord Nitro / "test my game" malware, quishing
- **Link analysis**: brand-lookalike domains, punycode, raw IPs, shorteners, high-risk TLDs
- **Account hardening guides** for 8 platforms, plus a general checklist for any other
- Monitor follower/following changes (8 built-in platforms)
- Get alerts for suspicious activity (via thresholds)
- Check and alert on unexpected privacy setting changes
- **Privacy audit of new followers/following for risky characteristics** (zero posts, zero followers, high following/follower ratio)
- **Phishing detection** in posts and DMs (suspicious URLs, language patterns)
- **AI social engineering risk evaluation** (via configurable AI model)
- Highly customizable via environment variables or parameters
- Easy-to-use Python package
- Easy extension to other platforms
## Installation

```bash
pip install socialsafe
# or the latest from GitHub
pip install git+https://github.com/PyMite6941/social-safe.git

# Only needed for the browser-based monitors (LinkedIn, Facebook, TikTok, YouTube, Discord)
socialsafe setup            # add --with-deps on Linux to install system libraries
```

The same commands work in PowerShell, Command Prompt, macOS Terminal, and Linux shells. If `socialsafe` isn't on your PATH, use `python -m socialsafe` (or `py -m socialsafe` on Windows).

Node.js users can install the launcher, which finds your Python install and forwards to it:

```bash
npm install -g @pymite6941/socialsafe
```

Follower state is stored per user: `%LOCALAPPDATA%\socialsafe` on Windows, `~/Library/Application Support/socialsafe` on macOS, and `~/.local/state/socialsafe` on Linux. Set `SOCIALSAFE_HOME` to change it. A `.env` placed there is loaded automatically, as is one in the current directory.

## Quick start (any platform)

```bash
socialsafe scan "Hi, Agent Miller with the FBI IC3. We can recover your lost funds for a processing fee."
socialsafe scan --file message.txt          # or pipe text in on stdin
socialsafe check-url http://instagram-security-check.xyz/login
socialsafe guide tiktok                     # any name works, e.g. `guide mastodon`
socialsafe threats -v                       # every signature and its advice
socialsafe monitor discord                  # follower/privacy monitor for a built-in platform
```

`scan` exits with status 1 when used with `--fail-on high` (or another level) and the message reaches that severity, so it can be used in scripts. `--json` gives machine-readable output.

## Usage

### Monitoring

```python
from socialsafe.monitor import monitor_instagram

# Monitor your account and get email alerts
changes, audit = monitor_instagram(
    username="your_instagram_handle",
    password="your_app_specific_password",  # Use app-specific password for security
    alert_email="your_alert_email@example.com"
)
```

### Advanced Usage (with custom thresholds and settings)

```python
from socialsafe.monitor import monitor_instagram

changes, audit = monitor_instagram(
    username="your_instagram_handle",
    password="your_app_specific_password",
    alert_email="your_alert_email@example.com",
    # Expect account to be private, alert if it becomes public
    expected_privacy="private",
    # Monitor only followers (not following)
    monitor_followers=True,
    monitor_following=False,
    # Alert if more than 5 new followers in a check
    alert_threshold_new_followers=5,
    # Alert if more than 2 lost followers
    alert_threshold_lost_followers=2,
    # Check state file in a specific location
    state_file="/path/to/your/ig_state.json"
)
```

### Via Command Line

After installation, you can use the `socialsafe-monitor` command:

```bash
socialsafe-monitor
```

This reads all configuration from environment variables (see below). For other platforms use `socialsafe monitor <platform>`.

## Configuration via Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your values
```

### Required Credentials
- `IG_USERNAME`: Your Instagram username (handle)
- `IG_PASSWORD`: Your Instagram password - **USE AN APP-SPECIFIC PASSWORD FOR SECURITY**
  (Go to Instagram Settings → Security → Two-Factor Authentication → App Passwords)

### Alert Configuration
- `ALERT_EMAIL`: Email address to send alerts to
- `ALERT_APP_PASSWORD`: SMTP password for sending alerts (App Password for Gmail/other SMTP)
- `SMTP_SERVER`: SMTP server (default: smtp.gmail.com)
- `SMTP_PORT`: SMTP port (default: 465)

### Monitoring Behavior
- `EXPECTED_PRIVACY`: Expected account privacy ('private' or 'public', default: 'private')
  - Alerts if actual privacy doesn't match
- `MONITOR_FOLLOWERS`: Monitor followers? ('true' or 'false', default: 'true')
- `MONITOR_FOLLOWING`: Monitor following? ('true' or 'false', default: 'true')
- `ALERT_THRESHOLD_NEW_FOLLOWERS`: Alert if new followers exceed this number in a check (default: 10)
- `ALERT_THRESHOLD_LOST_FOLLOWERS`: Alert if lost followers exceed this number (default: 10)
- `ALERT_THRESHOLD_NEW_FOLLOWING`: Alert if new follows exceed this number (default: 10)
- `ALERT_THRESHOLD_LOST_FOLLOWING`: Alert if lost follows exceed this number (default: 10)
- `STATE_FILE`: File to store previous state (default: 'ig_state.json')

### Audit Configuration
- `AUDIT_ENABLED`: Enable privacy audit (true/false, default: true)
- `AUDIT_RISK_ZERO_POSTS`: Flag new followers with zero posts (true/false, default: true)
- `AUDIT_RISK_ZERO_FOLLOWERS`: Flag new followers with zero followers (true/false, default: true)
- `AUDIT_RISK_HIGH_FOLLOWING_RATIO`: Flag new followers with high following/follower ratio (true/false, default: true)
- `AUDIT_FOLLOWING_RATIO_THRESHOLD`: Following/Follower ratio above this is risky (default: 100)
- `AUDIT_MIN_FOLLOWERS_FOR_RATIO`: Minimum followers to apply ratio check (default: 10)
- `AUDIT_ALERT_THRESHOLD_RISKY`: Number of risky new followers that triggers an alert (default: 5)

### Advanced
- `ALERT_METHODS`: Comma-separated alert methods (email,telegram) - placeholder for future (default: email)
- `CHECK_INTERVAL`: Check interval in seconds if running in daemon mode (not used in one-shot mode)

## Privacy Features

While this package focuses on monitoring, remember to:
1. Set your Instagram account to private (or public as desired)
2. Hide your activity status
3. Hide likes and view counts
4. Remove unwanted followers
5. Enable two-factor authentication

## Security Notes

- Never hard-code passwords in scripts
- Use app-specific passwords for Instagram and SMTP when possible
- Store sensitive credentials in environment variables (or a protected .env file)
- The tool only reads your follower/following lists (which you already expose to your approved followers)
- It does not post, message, or modify your account in any way

## How It Works

1. Authenticates to Instagram using your credentials (via Instaloader)
2. Fetches your current follower and following lists
3. Compares against the previous run (stored in STATE_FILE)
4. Checks if your account privacy setting matches EXPECTED_PRIVACY
5. **Optionally audits new followers for risky characteristics** (zero posts, zero followers, high following/follower ratio)
6. Sends an email alert if:
   - Privacy setting changed unexpectedly
   - New/lost followers or following exceed configured thresholds
   - Number of risky new followers exceeds audit threshold
7. Updates the state file for the next run

## Privacy Audit Details

When audit is enabled, the tool examines each new follower (since last check) and flags them as risky if they meet any of the enabled criteria:
- **Zero posts** (`mediacount == 0`) - likely a new or inactive account
- **Zero followers** - may indicate a bot or spam account
- **High following/follower ratio** (`follows / followers > threshold` and followers ≥ minimum) - indicative of follow-for-spam or bot behavior

Audit results are included in the alert email when the number of risky followers exceeds `AUDIT_ALERT_THRESHOLD_RISKY`.

## Threat Detection & Severity Rating

social-safe scans posts, comments, and DMs across platforms for social media attacks. Every detected threat is rated by severity so you can prioritize your response.

### What we detect

| Threat type | Examples | Typical severity |
|-------------|----------|------------------|
| **Phishing** | Fake login pages, "account suspended" links, credential harvesters, short URLs (bit.ly, t.co) | high |
| **Scams** | Investment/crypto giveaways, romance scams, fake job offers, impersonation, marketplace fraud | high |
| **Spam** | Engagement bait ("vote for me"), brand collaboration DMs, follow-for-follow, bot-like behavior | medium |
| **Suspicious content** | Urgency language, "click here", "free NFT", "your account will be deleted" | medium |
| **Current campaigns** | See the table below | medium to critical |
| **Risky links** | Lookalike brand domains, punycode, raw IP addresses, shorteners, `.zip`/`.top`/`.xyz` and similar TLDs | low to critical |

#### Current campaign signatures

Defined in `socialsafe/monitor/threats.py`. Each match comes with plain-language advice.

| Signature | Severity |
|-----------|----------|
| Fake FBI / IC3 / FTC agents and "fund recovery" offers | critical |
| ClickFix: "press Win+R and paste this" / PowerShell lures | critical |
| Requests for login or 2FA codes ("I sent you a code by mistake") | critical |
| Wallet connect / seed phrase / airdrop drainers | critical |
| Sextortion threats | critical |
| Upfront "processing / release fee" demands | high |
| Fake copyright-violation, appeal, or verified-badge notices | high |
| Pig-butchering investment pitches | high |
| Task scams ("like videos for commission, recharge to unlock") | high |
| Voice/video-clone emergencies and "this is my new number" | high |
| Gift-card or crypto-ATM payment demands | high |
| Free Discord Nitro / "try my game" malware | high |
| QR codes sent to sign in or pay (quishing) | medium |
| Fake brand deals with a download or login step | medium |
| "Is this you in this video?" lures | medium |

To add one, append a `ThreatSignature` to `EMERGING_THREATS`.

### Severity levels

- **critical** — credential theft, account takeover, malware (act immediately)
- **high** — phishing links, investment/romance/job scams, impersonation (act promptly)
- **medium** — spam, engagement bait, suspicious links (review)
- **low** — generic suspicious content (monitor)

Detection is pattern-based and best-effort; it can produce false positives or miss novel formats, and is not a substitute for platform security controls.

### Configuration

Content scanning and phishing detection are disabled by default. Enable them in `.env`:

```
ENABLE_CONTENT_SCANNING="true"
ENABLE_PHISHING_DETECTION="true"
ENABLE_PII_DETECTION="true"
CONTENT_SCAN_KEYWORDS="free nft,click here for,urgent action required,mr beast,crypto giveaway,verify your account"
```

Detected threats are included in alert emails and counted toward alert thresholds.

### Phishing Classification Algorithm

social-safe includes a scoring-based phishing classifier (`ContentScanner.classify_phishing`) that separates phishing attempts from legitimate / non-phishing content.

**How it works**
1. Each piece of text is scanned against weighted phishing keyword categories:
   - **Urgency** — "urgent", "account suspended", "verify immediately", "security alert", "expires"
   - **Credential** — "login", "password", "verify your account", "confirm your identity"
   - **Money / reward** — "you won", "free money", "prize", "wire transfer", "double your money"
   - **Threat** — "account will be deleted", "suspended", "unauthorized access", "legal action"
   - **Impersonation** — "from support", "from security", "instagram support", "official notification"
   - **Suspicious link** — "bit.ly", "tinyurl", "t.co", "click here", "verify now"
2. Each matched keyword adds its weight to a total phishing score.
3. If the score meets or exceeds the threshold (default `20`), the content is classified as **phishing**; otherwise it is treated as **non-phishing**.
4. A confidence level (`none` / `low` / `medium` / `high`) is reported based on the score.

**Example output**
```json
{
  "is_phishing": true,
  "score": 43.0,
  "threshold": 20,
  "confidence": "high",
  "categories": {
    "urgency": ["account suspended", "verify immediately"],
    "suspicious_link": ["bit.ly"]
  },
  "reason": "Phishing attempt detected (score 43.0 >= threshold 20). Matched 3 phishing indicator(s) across 2 category(ies)."
}
```

Detection is pattern-based and best-effort; it can produce false positives or miss novel formats, and is not a substitute for platform security controls.

### MFA / Account Security

social-safe can check your account's security posture and help you harden it against takeover.

**Check MFA (two-factor / multi-factor authentication)**
Most social platforms do not expose 2FA status through their public APIs, so `monitor._check_2fa_status()` returns `mfa_enabled: null` (unknown) together with platform-specific guidance on how to verify and enable MFA manually:

- **Instagram** — Accounts Center > Password and security > Two-factor authentication (use an authenticator app, save backup codes)
- **X / Twitter** — Settings and privacy > Security and account access > Security > Two-factor authentication
- **LinkedIn** — Me > Settings & Privacy > Sign in & security > Two-step verification
- **Reddit** — User Settings > Safety > Use two factor authentication
- **Facebook** — Settings & Privacy > Settings > Accounts Center > Password and security > Two-factor authentication
- **TikTok** — Profile > Menu > Settings and privacy > Security > 2-step verification
- **YouTube** — Google Account > Security > 2-Step Verification (YouTube uses your Google account)
- **Discord** — User Settings > My Account > Two-Factor Authentication (use an authenticator app, save backup codes)

**Run a full security audit**
`monitor.audit_account_security()` combines 2FA/MFA, login alerts, active sessions, security checkup, HTTPS/TLS, and account verification into a single report with an overall risk rating (`low` / `medium` / `high`) and prioritized remediation recommendations.

**Get a hardening guide**
`monitor.get_security_hardening_guide("instagram")` returns step-by-step instructions to secure an account (enable 2FA, set to private, review active sessions, revoke third-party app access, enable login alerts), plus general tips such as using unique passwords and preferring authenticator apps over SMS.

## Supported Platforms

social-safe monitors and audits the following platforms:

| Platform | Method | Best For |
|----------|--------|----------|
| **Instagram** | API (Instaloader) | Follower/following monitoring, privacy alerts, post/DM scanning |
| **Twitter / X** | API (tweepy) | Follower/following monitoring, tweet/DM scanning, phishing detection |
| **Reddit** | API (praw) | Subreddit monitoring, post/comment scanning, PII detection |
| **LinkedIn** | Playwright | Connection monitoring, privacy alerts, post/article scanning |
| **Facebook** | Playwright | Friend monitoring, privacy alerts, post scanning **(#1 platform for scam losses per FTC)** |
| **TikTok** | Playwright | Follower/following monitoring, post/caption scanning |
| **YouTube** | Playwright | Subscriber monitoring, video/comment scanning |
| **Discord** | Playwright | Friend monitoring, DM scanning for scams and PII |

Platforms marked with Playwright use web automation (a controlled browser) since they do not expose a public API suitable for follower monitoring. Enable them with the corresponding environment variables below.

### Configuration via Environment Variables

Copy `.env.example` to `.env` and fill in your values for the platforms you want to monitor.

**Required Credentials** (set at least the platforms you use):
- `IG_USERNAME` / `IG_PASSWORD` — Instagram
- `TWITTER_USERNAME` / `TWITTER_PASSWORD` — Twitter / X
- `REDDIT_USERNAME` / `REDDIT_PASSWORD` — Reddit
- `LINKEDIN_USERNAME` / `LINKEDIN_PASSWORD` — LinkedIn
- `FB_USERNAME` / `FB_PASSWORD` — Facebook
- `TIKTOK_USERNAME` / `TIKTOK_PASSWORD` — TikTok
- `YOUTUBE_USERNAME` / `YOUTUBE_PASSWORD` — YouTube
- `DISCORD_USERNAME` / `DISCORD_PASSWORD` — Discord

**Alert Configuration** (required):
- `ALERT_EMAIL` — Email address to send alerts to
- `ALERT_APP_PASSWORD` — SMTP password for sending alerts (App Password for Gmail/other SMTP)
- `SMTP_SERVER` — SMTP server (default: smtp.gmail.com)
- `SMTP_PORT` — SMTP port (default: 465)

**Monitoring Behavior**:
- `EXPECTED_PRIVACY` — Expected account privacy ('private' or 'public', default: 'private')
- `MONITOR_FOLLOWERS` — Monitor followers? ('true' or 'false', default: 'true')
- `MONITOR_FOLLOWING` — Monitor following? ('true' or 'false', default: 'true')
- `ALERT_THRESHOLD_NEW_FOLLOWERS` — Alert if new followers exceed this number (default: 10)
- `ALERT_THRESHOLD_LOST_FOLLOWERS` — Alert if lost followers exceed this number (default: 10)
- `STATE_FILE` — File to store previous state (default: 'ig_state.json')

**Audit Configuration**:
- `AUDIT_ENABLED` — Enable privacy/security audit (true/false, default: true)
- `AUDIT_RISK_ZERO_POSTS` — Flag new followers with zero posts (true/false, default: true)
- `AUDIT_RISK_ZERO_FOLLOWERS` — Flag new followers with zero followers (true/false, default: true)
- `AUDIT_RISK_HIGH_FOLLOWING_RATIO` — Flag new followers with high following/follower ratio (true/false, default: true)
- `AUDIT_FOLLOWING_RATIO_THRESHOLD` — Following/Follower ratio above this is risky (default: 100)
- `AUDIT_MIN_FOLLOWERS_FOR_RATIO` — Minimum followers to apply ratio check (default: 10)
- `AUDIT_ALERT_THRESHOLD_RISKY` — Number of risky new followers that triggers an alert (default: 5)

**OSINT & Threat Scanning** (optional, disabled by default):
- `ENABLE_CONTENT_SCANNING` — Scan posts/DMs for threats (true/false, default: false)
- `ENABLE_PHISHING_DETECTION` — Detect phishing links/pages (true/false, default: false)
- `ENABLE_PII_DETECTION` — Detect PII in posts/DMs (true/false, default: false)
- `CONTENT_SCAN_KEYWORDS` — Custom scan keywords (comma-separated)

## Example Alert Email

```
🔒 Instagram Alert for @your_handle

🚨 PRIVACY SETTING CHANGED: Expected private, but account is currently public
🚨 NEW FOLLOWERS THRESHOLD EXCEEDED: 15 new followers (threshold: 10)
📥 New followers (15): user1, user2, user3, user4, user5, ...and 10 more
🚨 RISKY NEW FOLLOWERS THRESHOLD EXCEEDED: 8 risky new followers (threshold: 5)
   • @suspicious1 (risk: zero_posts, zero_followers)
   • @suspicious2 (risk: high_following_ratio_150.0)
   • @suspicious3 (risk: zero_posts)
   ...and 5 more
```

## Contributing

Feel free to submit issues or pull requests!