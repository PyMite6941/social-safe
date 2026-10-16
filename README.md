# social-safe

Instagram privacy protection and monitoring tools.

## Features

- Monitor follower/following changes
- Get alerts for suspicious activity
- Tools to enhance Instagram privacy
- Easy-to-use Python package

## Installation

```bash
pip install socialsafe
```

## Usage

### Monitoring

```python
from socialsafe.monitor import monitor_instagram

# Monitor your account and get email alerts
changes = monitor_instagram(
    username="your_instagram_handle",
    password="your_app_specific_password",  # Use app-specific password for security
    alert_email="your_alert_email@example.com"
)
```

Or via command line:

```bash
socialsafe-monitor
```
(Requires setting environment variables: IG_USERNAME, IG_PASSWORD, ALERT_EMAIL, ALERT_APP_PASSWORD)

## Privacy Features

While this package focuses on monitoring, remember to:
1. Set your Instagram account to private
2. Hide your activity status
3. Hide likes and view counts
4. Remove unwanted followers
5. Enable two-factor authentication

## Security Notes

- Never hard-code passwords in scripts
- Use app-specific passwords for Instagram when possible
- Store sensitive credentials in environment variables