"""Reddit monitor adapter for social-safe"""

import praw
import os
from typing import Set, Dict, Optional, List
from pathlib import Path
from .base import BaseSocialMonitor


class RedditMonitor(BaseSocialMonitor):
    """Reddit platform monitor."""

    @property
    def platform_name(self) -> str:
        return "reddit"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('REDDIT_USERNAME')
        if not username:
            raise ValueError("REDDIT_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        # Reddit doesn't have private/public accounts in the same way
        # We can consider if the user has chosen to hide their activity?
        # For simplicity, we'll treat as always 'public' for monitoring purposes
        # but allow override via environment
        expected_privacy = expected_privacy or os.getenv('REDDIT_EXPECTED_PRIVACY', 'public')
        if expected_privacy not in ['public', 'private']:
            raise ValueError("REDDIT_EXPECTED_PRIVACY must be either 'public' or 'private'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize Reddit client."""
        # Reddit API credentials
        client_id = os.getenv('REDDIT_CLIENT_ID')
        client_secret = os.getenv('REDDIT_CLIENT_SECRET')
        user_agent = os.getenv('REDDIT_USER_AGENT', f'socialsafe-monitor-by-/u/{self.username}')
        
        if not all([client_id, client_secret]):
            raise ValueError("Reddit API credentials (REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET) must be set in environment")
        
        # Initialize Reddit instance
        self.reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent=user_agent,
            # For read-only access to public data, we don't need username/password
            # but for actions like checking inbox, we need auth
            username=os.getenv('REDDIT_USERNAME'),
            password=os.getenv('REDDIT_PASSWORD'),
        )
        
        # Get the redditor object for the user
        self.redditor = self.reddit.redditor(self.username)

    def login(self, password: Optional[str] = None) -> bool:
        """Login to Reddit (verify credentials)"""
        # For Reddit, login is handled during initialization if username/password provided
        # We'll verify by trying to access the user's profile
        try:
            # Trigger a request to verify credentials
            _ = self.redditor.id  # This will make an API call
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to login to Reddit: {e}")

    def check_changes(self) -> Dict[str, Set[str] | bool]:
        """Check for follower/following changes and privacy setting"""
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        # On Reddit, we can monitor:
        # - Followers (users who follow you)
        # - Following (subreddits you're subscribed to)
        # Privacy: whether your activity is hidden (Reddit has option to hide activity from public)
        
        # Get current sets
        try:
            redditor_obj = self.reddit.redditor(self.username)
            # Force fetch
            _ = redditor_obj.id
        except Exception:
            # If we can't get the user, raise
            raise ValueError(f"Reddit user {self.username} not found")
        
        current_followers = set()
        current_following = set()  # will store subreddit display names
        
        if self.monitor_followers:
            try:
                # Get followers (note: this may be limited to 1000 by default)
                for follower in redditor_obj.followers(limit=None):
                    current_followers.add(follower.name)
            except Exception:
                # If we can't get followers (might require auth or be empty), continue with empty set
                pass
        
        if self.monitor_following:
            try:
                # Get subscribed subreddits
                for subreddit in redditor_obj.subreddits(limit=None):
                    current_following.add(subreddit.display_name)
            except Exception:
                pass
        
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
        
        # Check privacy setting: Reddit has "hide my activity" option
        # We'll try to see if the account is flagged as hidden? Not directly available.
        # Instead, we'll check if the user has chosen to hide their activity via the "is_mod"? No.
        # For now, we'll skip privacy change detection for Reddit or set a placeholder.
        # We'll implement a simple check: if the user has no public posts/comments? Not reliable.
        # We'll set privacy_changed to False for now and note in documentation.
        changes["privacy_changed"] = False
        
        # Update state for next time
        if self.monitor_followers:
            self.state["followers"] = current_followers
        if self.monitor_following:
            self.state["following"] = current_following
        self._save_state()
        
        return changes

    def audit_account(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the Reddit account."""
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        if not self.audit_enabled:
            return {"audit_enabled": False, "risks": []}
        
        risks = []
        details = {}
        
        # 1. Check if account activity is hidden when expected public (or vice versa)
        # We'll attempt to see if the user has any public posts/comments as a proxy
        # For simplicity, we'll skip this check and note limitation
        
        # 2. Check new followers for risky characteristics (if monitoring followers)
        risky_new_followers = []
        if self.monitor_followers:
            try:
                redditor_obj = self.reddit.redditor(self.username)
                # Get current followers again
                current_followers_set = set()
                for follower in redditor_obj.followers(limit=None):
                    current_followers_set.add(follower.name)
                new_followers_set = current_followers_set - self.state["followers"]
                
                for username in new_followers_set:
                    try:
                        follower_redditor = self.reddit.redditor(username)
                        # Force fetch
                        _ = follower_redditor.id
                        is_risky = False
                        risk_factors = []
                        
                        # Check for zero posts/comments
                        if self.audit_risk_zero_posts:
                            # Reddit: we can check comment karma and link karma?
                            # Actually we can check if the user has any submissions or comments
                            # We'll try to see if they have any recent activity
                            # For simplicity, we'll check if comment karma and link karma are both zero
                            # Note: new accounts may have zero karma but that's not necessarily risky
                            if follower_redditor.comment_karma == 0 and follower_redditor.link_karma == 0:
                                is_risky = True
                                risk_factors.append("zero_karma")
                        
                        # Check for zero followers (of the follower)
                        if self.audit_risk_zero_followers:
                            # Get follower's followers count? Not directly available without another API call
                            # We'll skip for now to avoid excessive API calls
                            pass
                        
                        # Check for high following ratio? Reddit doesn't have a direct equivalent
                        # We'll skip
                        
                        if is_risky:
                            risky_new_followers.append({
                                "username": username,
                                "risk_factors": risk_factors,
                                "comment_karma": getattr(follower_redditor, 'comment_karma', 0),
                                "link_karma": getattr(follower_redditor, 'link_karma', 0),
                            })
                    except Exception:
                        # If we can't fetch the follower's profile, skip
                        continue
            except Exception:
                # If we can't get followers, skip risky follower check
                pass
        
        if risky_new_followers:
            risks.append("risky_new_followers")
            details["risky_new_followers"] = risky_new_followers
        
        # 3. Check for encryption/security settings
        if self.audit_check_https:
            https_result = self._check_https_connection()
            if https_result["risk_detected"]:
                risks.append("https_not_enforced")
                details["https_not_enforced"] = https_result["details"]
        
        if self.audit_check_2fa:
            fa_result = self._check_2fa_status()
            if fa_result["risk_detected"]:
                risks.append("2fa_not_enabled")
                details["2fa_not_enabled"] = fa_result["details"]
        
        if self.audit_check_login_alerts:
            alerts_result = self._check_login_alerts()
            if alerts_result["risk_detected"]:
                risks.append("login_alerts_not_enabled")
                details["login_alerts_not_enabled"] = alerts_result["details"]
        
        if self.audit_check_active_sessions:
            sessions_result = self._check_active_sessions()
            if sessions_result["risk_detected"]:
                risks.append("suspicious_active_sessions")
                details["suspicious_active_sessions"] = sessions_result["details"]
        
        if self.audit_check_recent_security_checkup:
            checkup_result = self._check_recent_security_checkup()
            if checkup_result["risk_detected"]:
                risks.append("no_recent_security_checkup")
                details["no_recent_security_checkup"] = checkup_result["details"]
        
        if self.audit_check_account_verification:
            verification_result = self._check_account_verification()
            if verification_result["risk_detected"]:
                risks.append("account_not_verified")
                details["account_not_verified"] = verification_result["details"]
        # 4. Scan recent posts/comments for PII and suspicious content if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                # Get recent posts and comments
                redditor_obj = self.reddit.redditor(self.username)
                # We'll get combined recent activity
                # For simplicity, we'll check submissions and comments separately
                suspicious_posts = []
                pii_posts = []
                
                # Check submissions (posts)
                for submission in redditor_obj.submissions.new(limit=10):
                    # submission is a Submission object
                    text = submission.title + " " + (submission.selftext or "")
                    # For media, we can check if it's a link post? We'll skip image scanning for now
                    # but we can still scan text
                    if self.enable_content_scanning:
                        content_threats = self.scan_content(text, [])
                        if content_threats["text_threats"] or content_threats["image_threats"]:
                            suspicious_posts.append({
                                "post_id": submission.id,
                                "title": submission.title[:100] + "..." if len(submission.title) > 100 else submission.title,
                                "threats": content_threats
                            })
                    if self.enable_pii_detection:
                        pii_matches = self.scan_for_pii(text)
                        if any(pii_matches.values()):
                            pii_posts.append({
                                "post_id": submission.id,
                                "title": submission.title[:100] + "..." if len(submission.title) > 100 else submission.title,
                                "pii_matches": pii_matches
                            })
                
                # Check comments
                for comment in redditor_obj.comments.new(limit=10):
                    text = comment.body
                    if self.enable_content_scanning:
                        content_threats = self.scan_content(text, [])
                        if content_threats["text_threats"] or content_threats["image_threats"]:
                            suspicious_posts.append({
                                "comment_id": comment.id,
                                "body": comment.body[:100] + "..." if len(comment.body) > 100 else comment.body,
                                "threats": content_threats
                            })
                    if self.enable_pii_detection:
                        pii_matches = self.scan_for_pii(text)
                        if any(pii_matches.values()):
                            pii_posts.append({
                                "comment_id": comment.id,
                                "body": comment.body[:100] + "..." if len(comment.body) > 100 else comment.body,
                                "pii_matches": pii_matches
                            })
                
                if suspicious_posts:
                    risks.append("suspicious_content_in_activity")
                    details["suspicious_content_in_activity"] = suspicious_posts
                
                if pii_posts:
                    risks.append("pii_detected_in_activity")
                    details["pii_detected_in_activity"] = pii_posts
                    
            except Exception as e:
                # If we can't scan activity, continue without it
                pass
        
        # Compile result
        result = {
            "audit_enabled": True,
            "risks": risks,
            "details": details,
            "timestamp": str(Path(__file__).stat().st_mtime)  # simple timestamp
        }
        return result

    def _is_logged_in(self) -> bool:
        """Check if currently logged in to Reddit"""
        try:
            # Try to access the user's profile to verify auth
            _ = self.redditor.id
            return True
        except Exception:
            return False

    def get_recent_activity(self, count: int = 10) -> List:
        """Get recent posts and comments from the user (for content scanning).
        
        Returns:
            List of submission and comment objects
        """
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        activity = []
        redditor_obj = self.reddit.redditor(self.username)
        
        # Get recent submissions
        for submission in redditor_obj.submissions.new(limit=count):
            activity.append(submission)
            if len(activity) >= count:
                break
        
        # If we need more, get comments
        if len(activity) < count:
            for comment in redditor_obj.comments.new(limit=count - len(activity)):
                activity.append(comment)
        
        return activity[:count]

    def scan_content_from_activity(self) -> Dict[str, List[str]]:
        """Convenience method to scan recent activity for threats."""
        if not self.enable_content_scanning and not self.enable_pii_detection:
            return {"text_threats": [], "image_threats": []}
        
        activity = self.get_recent_activity(count=10)
        all_text_threats = []
        all_image_threats = []  # We're not scanning images for Reddit posts in this implementation
        
        for item in activity:
            if hasattr(item, 'title'):
                text = item.title + " " + (getattr(item, 'selftext', '') or "")
            elif hasattr(item, 'body'):
                text = item.body
            else:
                text = str(item)
            
            if self.enable_content_scanning:
                content_threats = self.scan_content(text, [])
                all_text_threats.extend(content_threats["text_threats"])
                all_image_threats.extend(content_threats["image_threats"])
            
            if self.enable_pii_detection:
                pii_matches = self.scan_for_pii(text)
                # For simplicity, we'll just note that PII was found; we could aggregate by type
                if any(pii_matches.values()):
                    all_text_threats.append("pii_detected")
        
        return {
            "text_threats": list(set(all_text_threats)),  # deduplicate
            "image_threats": list(set(all_image_threats))
        }
