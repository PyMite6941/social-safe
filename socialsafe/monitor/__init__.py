"""Instagram monitoring module for social-safe"""

import instaloader
import smtplib
import os
import json
from email.message import EmailMessage
from typing import Set, Dict, Optional, List, Tuple
from pathlib import Path


class InstagramMonitor:
    def __init__(
        self,
        username: Optional[str] = None,
        state_file: Optional[str] = None,
        expected_privacy: Optional[str] = None,
        monitor_followers: Optional[bool] = None,
        monitor_following: Optional[bool] = None,
        alert_threshold_new_followers: Optional[int] = None,
        alert_threshold_lost_followers: Optional[int] = None,
        alert_threshold_new_following: Optional[int] = None,
        alert_threshold_lost_following: Optional[int] = None,
        audit_enabled: Optional[bool] = None,
        audit_risk_zero_posts: Optional[bool] = None,
        audit_risk_zero_followers: Optional[bool] = None,
        audit_risk_high_following_ratio: Optional[bool] = None,
        audit_following_ratio_threshold: Optional[int] = None,
        audit_min_followers_for_ratio: Optional[int] = None,
        audit_alert_threshold_risky: Optional[int] = None,
    ):
        """
        Initialize Instagram monitor with configuration from parameters or environment.

        Args:
            username: Instagram username (overrides IG_USERNAME env)
            state_file: Path to state file (overrides STATE_FILE env or default 'ig_state.json')
            expected_privacy: Expected privacy ('private' or 'public') 
                             (overrides EXPECTED_PRIVACY env or default 'private')
            monitor_followers: Whether to monitor followers (overrides MONITOR_FOLLOWERS env)
            monitor_following: Whether to monitor following (overrides MONITOR_FOLLOWING env)
            alert_threshold_*: Thresholds for alerting on changes (overrides respective env vars)
            audit_enabled: Whether to run privacy audit (overrides AUDIT_ENABLED env)
            audit_risk_zero_posts: Flag risky new followers with zero posts (overrides AUDIT_RISK_ZERO_POSTS env)
            audit_risk_zero_followers: Flag risky new followers with zero followers (overrides AUDIT_RISK_ZERO_FOLLOWERS env)
            audit_risk_high_following_ratio: Flag risky new followers with high following/follower ratio (overrides AUDIT_RISK_HIGH_FOLLOWING_RATIO env)
            audit_following_ratio_threshold: Threshold for following/follower ratio to consider risky (overrides AUDIT_FOLLOWING_RATIO_THRESHOLD env)
            audit_min_followers_for_ratio: Minimum followers to apply ratio check (overrides AUDIT_MIN_FOLLOWERS_FOR_RATIO env)
            audit_alert_threshold_risky: Number of risky followers that triggers an alert (overrides AUDIT_ALERT_THRESHOLD_RISKY env)
        """
        # Read from environment with fallbacks
        self.username = username or os.getenv('IG_USERNAME')
        if not self.username:
            raise ValueError("IG_USERNAME must be set in environment or passed to constructor")
        
        self.state_file = Path(state_file or os.getenv('STATE_FILE', 'ig_state.json'))
        
        # Privacy expectation
        self.expected_privacy = expected_privacy or os.getenv('EXPECTED_PRIVACY', 'private')
        if self.expected_privacy not in ['private', 'public']:
            raise ValueError("EXPECTED_PRIVACY must be either 'private' or 'public'")
        
        # Monitoring flags
        self.monitor_followers = monitor_followers
        if self.monitor_followers is None:
            self.monitor_followers = os.getenv('MONITOR_FOLLOWERS', 'true').lower() == 'true'
        
        self.monitor_following = monitor_following
        if self.monitor_following is None:
            self.monitor_following = os.getenv('MONITOR_FOLLOWING', 'true').lower() == 'true'
        
        # Alert thresholds
        self.alert_threshold_new_followers = alert_threshold_new_followers
        if self.alert_threshold_new_followers is None:
            self.alert_threshold_new_followers = int(os.getenv('ALERT_THRESHOLD_NEW_FOLLOWERS', '10'))
        
        self.alert_threshold_lost_followers = alert_threshold_lost_followers
        if self.alert_threshold_lost_followers is None:
            self.alert_threshold_lost_followers = int(os.getenv('ALERT_THRESHOLD_LOST_FOLLOWERS', '10'))
        
        self.alert_threshold_new_following = alert_threshold_new_following
        if self.alert_threshold_new_following is None:
            self.alert_threshold_new_following = int(os.getenv('ALERT_THRESHOLD_NEW_FOLLOWING', '10'))
        
        self.alert_threshold_lost_following = alert_threshold_lost_following
        if self.alert_threshold_lost_following is None:
            self.alert_threshold_lost_following = int(os.getenv('ALERT_THRESHOLD_LOST_FOLLOWING', '10'))
        
        # Audit settings
        self.audit_enabled = audit_enabled
        if self.audit_enabled is None:
            self.audit_enabled = os.getenv('AUDIT_ENABLED', 'true').lower() == 'true'
        
        self.audit_risk_zero_posts = audit_risk_zero_posts
        if self.audit_risk_zero_posts is None:
            self.audit_risk_zero_posts = os.getenv('AUDIT_RISK_ZERO_POSTS', 'true').lower() == 'true'
        
        self.audit_risk_zero_followers = audit_risk_zero_followers
        if self.audit_risk_zero_followers is None:
            self.audit_risk_zero_followers = os.getenv('AUDIT_RISK_ZERO_FOLLOWERS', 'true').lower() == 'true'
        
        self.audit_risk_high_following_ratio = audit_risk_high_following_ratio
        if self.audit_risk_high_following_ratio is None:
            self.audit_risk_high_following_ratio = os.getenv('AUDIT_RISK_HIGH_FOLLOWING_RATIO', 'true').lower() == 'true'
        
        self.audit_following_ratio_threshold = audit_following_ratio_threshold
        if self.audit_following_ratio_threshold is None:
            self.audit_following_ratio_threshold = int(os.getenv('AUDIT_FOLLOWING_RATIO_THRESHOLD', '100'))
        
        self.audit_min_followers_for_ratio = audit_min_followers_for_ratio
        if self.audit_min_followers_for_ratio is None:
            self.audit_min_followers_for_ratio = int(os.getenv('AUDIT_MIN_FOLLOWERS_FOR_RATIO', '10'))
        
        self.audit_alert_threshold_risky = audit_alert_threshold_risky
        if self.audit_alert_threshold_risky is None:
            self.audit_alert_threshold_risky = int(os.getenv('AUDIT_ALERT_THRESHOLD_RISKY', '5'))
        
        # Initialize loader and state
        self.loader = instaloader.Instaloader()
        self.state = self._load_state()
    
    def _load_state(self) -> Dict[str, Set[str]]:
        """Load previous follower/following state from file"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    return {
                        "followers": set(data.get("followers", [])),
                        "following": set(data.get("following", []))
                    }
            except (json.JSONDecodeError, IOError):
                # If file is corrupted, start fresh
                pass
        return {"followers": set(), "following": set()}
    
    def _save_state(self):
        """Save current follower/following state to file"""
        data = {
            "followers": list(self.state["followers"]),
            "following": list(self.state["following"])
        }
        # Ensure directory exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def login(self, password: Optional[str] = None):
        """Login to Instagram"""
        password = password or os.getenv('IG_PASSWORD')
        if not password:
            raise ValueError("IG_PASSWORD must be set in environment or passed to login()")
        
        try:
            self.loader.login(self.username, password)
        except Exception as e:
            raise ConnectionError(f"Failed to login to Instagram: {e}")
    
    def check_changes(self) -> Dict[str, Set[str] | bool]:
        """Check for follower/following changes and privacy setting"""
        if not self.loader.context.is_logged_in:
            raise RuntimeError("Not logged in. Call login() first.")
        
        profile = instaloader.Profile.from_username(self.loader.context, self.username)
        
        # Get current sets
        current_followers = set()
        current_following = set()
        
        if self.monitor_followers:
            current_followers = {f.username for f in profile.get_followers()}
        if self.monitor_following:
            current_following = {f.username for f in profile.get_followings()}
        
        # Compute changes
        changes = {}
        
        if self.monitor_followers:
            changes["new_followers"] = current_followers - self.state["followers"]
            changes["lost_followers"] = self.state["followers"] - current_followers
        else:
            changes["new_followers"] = set()
            changes["lost_followers"] = set()
        
        if self.monitor_following:
            changes["new_following"] = current_following - self.state["following"]
            changes["lost_following"] = self.state["following"] - current_following
        else:
            changes["new_following"] = set()
            changes["lost_following"] = set()
        
        # Check privacy setting
        current_privacy = 'private' if profile.is_private else 'public'
        privacy_changed = (self.expected_privacy != current_privacy)
        changes["privacy_changed"] = privacy_changed
        
        # Update state for next time (only what we monitor)
        if self.monitor_followers:
            self.state["followers"] = current_followers
        if self.monitor_following:
            self.state["following"] = current_following
        self._save_state()
        
        return changes
    
    def audit_account(self) -> Dict[str, object]:
        """
        Perform a privacy risk audit on the account.
        Returns a dictionary with audit results.
        """
        if not self.loader.context.is_logged_in:
            raise RuntimeError("Not logged in. Call login() first.")
        
        if not self.audit_enabled:
            return {"audit_enabled": False, "risks": []}
        
        profile = instaloader.Profile.from_username(self.loader.context, self.username)
        risks = []
        details = {}
        
        # 1. Check if account is public when expected private (or vice versa)
        current_privacy = 'private' if profile.is_private else 'public'
        if self.expected_privacy != current_privacy:
            risks.append("unexpected_privacy")
            details["unexpected_privacy"] = {
                "expected": self.expected_privacy,
                "actual": current_privacy
            }
        
        # 2. Check new followers for risky characteristics (if monitoring followers)
        risky_new_followers = []
        if self.monitor_followers:
            # Compute current followers and new followers since last check
            current_followers_set = {f.username for f in profile.get_followers()}
            new_followers_set = current_followers_set - self.state["followers"]
            
            for username in new_followers_set:
                try:
                    follower_profile = instaloader.Profile.from_username(self.loader.context, username)
                    is_risky = False
                    risk_factors = []
                    
                    if self.audit_risk_zero_posts and follower_profile.mediacount == 0:
                        is_risky = True
                        risk_factors.append("zero_posts")
                    
                    if self.audit_risk_zero_followers and follower_profile.followers == 0:
                        is_risky = True
                        risk_factors.append("zero_followers")
                    
                    if self.audit_risk_high_following_ratio:
                        if follower_profile.followers >= self.audit_min_followers_for_ratio:
                            # Avoid division by zero
                            if follower_profile.followers > 0:
                                ratio = follower_profile.follows / follower_profile.followers
                                if ratio > self.audit_following_ratio_threshold:
                                    is_risky = True
                                    risk_factors.append(f"high_following_ratio_{ratio:.1f}")
                            else:
                                # followers == 0 already caught by zero_followers above
                                pass
                    
                    if is_risky:
                        risky_new_followers.append({
                            "username": username,
                            "risk_factors": risk_factors,
                            "mediacount": follower_profile.mediacount,
                            "followers": follower_profile.followers,
                            "following": follower_profile.follows
                        })
                except Exception:
                    # If we can't fetch the profile, skip or mark as unknown?
                    continue
        
        if risky_new_followers:
            risks.append("risky_new_followers")
            details["risky_new_followers"] = risky_new_followers
        
        # Compile result
        result = {
            "audit_enabled": True,
            "risks": risks,
            "details": details,
            "timestamp": str(Path(__file__).stat().st_mtime)  # simple timestamp
        }
        return result
    
    def _should_alert(self, changes: Dict[str, Set[str] | bool], audit_result: Optional[Dict] = None) -> bool:
        """Determine if changes exceed thresholds, privacy changed, or audit finds risks"""
        # Always alert on privacy change
        if changes.get("privacy_changed", False):
            return True
        
        # Check thresholds for each change type
        if self.monitor_followers:
            if len(changes["new_followers"]) > self.alert_threshold_new_followers:
                return True
            if len(changes["lost_followers"]) > self.alert_threshold_lost_followers:
                return True
        
        if self.monitor_following:
            if len(changes["new_following"]) > self.alert_threshold_new_following:
                return True
            if len(changes["lost_following"]) > self.alert_threshold_lost_following:
                return True
        
        # Check audit results for risks that exceed threshold
        if audit_result and audit_result.get("audit_enabled", False):
            risks = audit_result.get("risks", [])
            # For risky_new_followers, check count
            if "risky_new_followers" in risks:
                details = audit_result.get("details", {})
                risky_list = details.get("risky_new_followers", [])
                if len(risky_list) > self.audit_alert_threshold_risky:
                    return True
        
        return False
    
    def send_alert(self, changes: Dict[str, Set[str] | bool], 
                   email_to: Optional[str] = None,
                   email_from: Optional[str] = None,
                   smtp_server: Optional[str] = None,
                   smtp_port: Optional[int] = None,
                   smtp_user: Optional[str] = None,
                   smtp_password: Optional[str] = None,
                   audit_result: Optional[Dict] = None):
        """Send email alert about changes if thresholds exceeded, privacy changed, or audit finds risks"""
        # Only send if we should alert
        if not self._should_alert(changes, audit_result):
            return
        
        # Use parameters or environment
        email_to = email_to or os.getenv('ALERT_EMAIL')
        email_from = email_from or os.getenv('ALERT_EMAIL', email_to)
        smtp_server = smtp_server or os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = smtp_port or int(os.getenv('SMTP_PORT', '465'))
        smtp_user = smtp_user or os.getenv('ALERT_APP_PASSWORD', email_from)  # Often same as email_from for app passwords
        smtp_password = smtp_password or os.getenv('ALERT_APP_PASSWORD')
        
        if not email_to:
            raise ValueError("ALERT_EMAIL must be set in environment or passed to send_alert()")
        if not smtp_password:
            raise ValueError("ALERT_APP_PASSWORD must be set in environment or passed to send_alert()")
        
        # Build alert message
        body_lines = []
        
        if changes.get("privacy_changed", False):
            # Re-fetch profile to get current privacy status for the message
            profile = instaloader.Profile.from_username(self.loader.context, self.username)
            current_privacy = 'private' if profile.is_private else 'public'
            body_lines.append(
                f"🚨 PRIVACY SETTING CHANGED: Expected {self.expected_privacy}, "
                f"but account is currently {current_privacy}"
            )
        
        if self.monitor_followers:
            if changes["new_followers"]:
                count = len(changes["new_followers"])
                if count > self.alert_threshold_new_followers:
                    body_lines.append(
                        f"🚨 NEW FOLLOWERS THRESHOLD EXCEEDED: {count} new followers "
                        f"(threshold: {self.alert_threshold_new_followers})"
                    )
                else:
                    # Show first 5 if many
                    followers_list = list(changes["new_followers"])
                    display_list = followers_list[:5]
                    if len(followers_list) > 5:
                        display_list.append(f"...and {len(followers_list) - 5} more")
                    body_lines.append(f"📥 New followers ({count}): {', '.join(display_list)}")
            
            if changes["lost_followers"]:
                count = len(changes["lost_followers"])
                if count > self.alert_threshold_lost_followers:
                    body_lines.append(
                        f"🚨 LOST FOLLOWERS THRESHOLD EXCEEDED: {count} lost followers "
                        f"(threshold: {self.alert_threshold_lost_followers})"
                    )
                else:
                    # Show first 5 if many
                    followers_list = list(changes["lost_followers"])
                    display_list = followers_list[:5]
                    if len(followers_list) > 5:
                        display_list.append(f"...and {len(followers_list) - 5} more")
                    body_lines.append(f"📤 Lost followers ({count}): {', '.join(display_list)}")
        
        if self.monitor_following:
            if changes["new_following"]:
                count = len(changes["new_following"])
                if count > self.alert_threshold_new_following:
                    body_lines.append(
                        f"🚨 NEW FOLLOWING THRESHOLD EXCEEDED: {count} new follows "
                        f"(threshold: {self.alert_threshold_new_following})"
                    )
                else:
                    # Show first 5 if many
                    following_list = list(changes["new_following"])
                    display_list = following_list[:5]
                    if len(following_list) > 5:
                        display_list.append(f"...and {len(following_list) - 5} more")
                    body_lines.append(f"➡️ New following ({count}): {', '.join(display_list)}")
            
            if changes["lost_following"]:
                count = len(changes["lost_following"])
                if count > self.alert_threshold_lost_following:
                    body_lines.append(
                        f"🚨 LOST FOLLOWING THRESHOLD EXCEEDED: {count} lost follows "
                        f"(threshold: {self.alert_threshold_lost_following})"
                    )
                else:
                    # Show first 5 if many
                    following_list = list(changes["lost_following"])
                    display_list = following_list[:5]
                    if len(following_list) > 5:
                        display_list.append(f"...and {len(following_list) - 5} more")
                    body_lines.append(f"⬅️ Lost following ({count}): {', '.join(display_list)}")
        
        # Add audit risks if any and above threshold
        if audit_result and audit_result.get("audit_enabled", False):
            risks = audit_result.get("risks", [])
            details = audit_result.get("details", {})
            if "risky_new_followers" in risks:
                risky_list = details.get("risky_new_followers", [])
                if len(risky_list) > self.audit_alert_threshold_risky:
                    body_lines.append(
                        f"🚨 RISKY NEW FOLLOWERS THRESHOLD EXCEEDED: {len(risky_list)} risky new followers "
                        f"(threshold: {self.audit_alert_threshold_risky})"
                    )
                    # Show first few risky followers
                    for i, risky in enumerate(risky_list[:3]):
                        body_lines.append(
                            f"   • @{risky['username']} (risk: {', '.join(risky['risk_factors'])})"
                        )
                    if len(risky_list) > 3:
                        body_lines.append(f"   ...and {len(risky_list) - 3} more")
            if "unexpected_privacy" in risks:
                exp = details.get("unexpected_privacy", {}).get("expected", "unknown")
                act = details.get("unexpected_privacy", {}).get("actual", "unknown")
                body_lines.append(
                    f"🚨 UNEXPECTED PRIVACY: Expected {exp}, found {act}"
                )
        
        if not body_lines:
            # This shouldn't happen if _should_alert returned True, but just in case
            body_lines.append("Changes detected but no specific details to show.")
        
        body = "\n".join(body_lines)
        
        msg = EmailMessage()
        msg["Subject"] = f"🔒 Instagram Alert for @{self.username}"
        msg["From"] = email_from
        msg["To"] = email_to
        msg.set_content(body)
        
        try:
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
        except Exception as e:
            raise RuntimeError(f"Failed to send alert email: {e}")


def monitor_instagram(
    username: Optional[str] = None,
    password: Optional[str] = None,
    alert_email: Optional[str] = None,
    state_file: Optional[str] = None,
    expected_privacy: Optional[str] = None,
    monitor_followers: Optional[bool] = None,
    monitor_following: Optional[bool] = None,
    alert_threshold_new_followers: Optional[int] = None,
    alert_threshold_lost_followers: Optional[int] = None,
    alert_threshold_new_following: Optional[int] = None,
    alert_threshold_lost_following: Optional[int] = None,
    audit_enabled: Optional[bool] = None,
    audit_risk_zero_posts: Optional[bool] = None,
    audit_risk_zero_followers: Optional[bool] = None,
    audit_risk_high_following_ratio: Optional[bool] = None,
    audit_following_ratio_threshold: Optional[int] = None,
    audit_min_followers_for_ratio: Optional[int] = None,
    audit_alert_threshold_risky: Optional[int] = None,
) -> Tuple[Dict[str, Set[str] | bool], Optional[Dict]]:
    """
    Convenience function to monitor Instagram and alert on changes.
    
    All parameters can be overridden via environment variables (see .env.example).
    
    Returns:
        Tuple of (changes_dict, audit_result_dict)
        changes_dict: Dictionary of changes (new_followers, lost_followers, new_following, 
        lost_following, privacy_changed) - empty sets/no change if no significant changes.
        audit_result_dict: Dictionary from audit_account() if audit enabled, else None.
    """
    monitor = InstagramMonitor(
        username=username,
        state_file=state_file,
        expected_privacy=expected_privacy,
        monitor_followers=monitor_followers,
        monitor_following=monitor_following,
        alert_threshold_new_followers=alert_threshold_new_followers,
        alert_threshold_lost_followers=alert_threshold_lost_followers,
        alert_threshold_new_following=alert_threshold_new_following,
        alert_threshold_lost_following=alert_threshold_lost_following,
        audit_enabled=audit_enabled,
        audit_risk_zero_posts=audit_risk_zero_posts,
        audit_risk_zero_followers=audit_risk_zero_followers,
        audit_risk_high_following_ratio=audit_risk_high_following_ratio,
        audit_following_ratio_threshold=audit_following_ratio_threshold,
        audit_min_followers_for_ratio=audit_min_followers_for_ratio,
        audit_alert_threshold_risky=audit_alert_threshold_risky,
    )
    monitor.login(password)
    changes = monitor.check_changes()
    audit_result = None
    if monitor.audit_enabled:
        audit_result = monitor.audit_account()
    
    if monitor._should_alert(changes, audit_result):
        monitor.send_alert(
            changes,
            email_to=alert_email,
            email_from=alert_email,  # Default to using alert email as from address
            smtp_user=alert_email,   # Often the same for app passwords
            smtp_password=os.getenv("ALERT_APP_PASSWORD"),  # Explicitly get from env
            audit_result=audit_result
        )
    
    return changes, audit_result