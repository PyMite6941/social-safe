# social-safe

Instagram privacy protection and monitoring tools.

## Features

- Monitor follower/following changes (Instagram and Twitter/X)
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
```

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

This reads all configuration from environment variables (see below).

Additionally, if you install the npm wrapper globally (`npm install -g .`), you can use the `socialsafe` command, which wraps the Python command for Node.js users.

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

## Supported Platforms

- Primary: Instagram (via Instaloader)
- The core logic can be extended to other platforms in the future

## Contributing

Feel free to submit issues or pull requests!