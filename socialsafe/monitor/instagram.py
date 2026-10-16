"""Instagram monitoring module for social-safe"""

import instaloader
import os
from typing import Set, Dict, Optional, List
from pathlib import Path
from .base import BaseSocialMonitor


class InstagramMonitor(BaseSocialMonitor):
    """Instagram platform monitor."""

    @property
    def platform_name(self) -> str:
        return "instagram"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('IG_USERNAME')
        if not username:
            raise ValueError("IG_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        expected_privacy = expected_privacy or os.getenv('EXPECTED_PRIVACY', 'private')
        if expected_privacy not in ['private', 'public']:
            raise ValueError("EXPECTED_PRIVACY must be either 'private' or 'public'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize Instagram client."""
        self.loader = instaloader.Instaloader()

    def login(self, password: Optional[str] = None) -> bool:
        """Login to Instagram"""
        password = password or os.getenv('IG_PASSWORD')
        if not password:
            raise ValueError("IG_PASSWORD must be set in environment or passed to login()")
        
        try:
            self.loader.login(self.username, password)
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to login to Instagram: {e}")

    def check_changes(self) -> Dict[str, Set[str] | bool]:
        """Check for follower/following changes and privacy setting"""
        if not self._is_logged_in():
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
        """Perform a privacy/risk audit on the Instagram account."""
        if not self._is_logged_in():
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
        # 4. Scan recent posts for PII and suspicious content if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                # Get recent posts
                posts = []
                for post in profile.get_posts():
                    posts.append(post)
                    if len(posts) >= 10:  # Limit to 10 most recent posts
                        break
                
                # Scan each post
                suspicious_posts = []
                pii_posts = []
                
                for post in posts:
                    caption = post.caption or ""
                    image_urls = [post.url] if post.url else []
                    
                    # Content scanning
                    if self.enable_content_scanning:
                        content_threats = self.scan_content(caption, image_urls)
                        if content_threats["text_threats"] or content_threats["image_threats"]:
                            suspicious_posts.append({
                                "post_id": post.mediaid,
                                "caption": caption[:100] + "..." if len(caption) > 100 else caption,
                                "threats": content_threats
                            })
                    
                    # PII detection
                    if self.enable_pii_detection:
                        pii_matches = self.scan_for_pii(caption)
                        if any(pii_matches.values()):
                            pii_posts.append({
                                "post_id": post.mediaid,
                                "caption": caption[:100] + "..." if len(caption) > 100 else caption,
                                "pii_matches": pii_matches
                            })
                
                if suspicious_posts:
                    risks.append("suspicious_content_in_posts")
                    details["suspicious_content_in_posts"] = suspicious_posts
                
                if pii_posts:
                    risks.append("pii_detected_in_posts")
                    details["pii_detected_in_posts"] = pii_posts
                    
            except Exception as e:
                # If we can't scan posts, continue without it
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
        """Check if currently logged in to Instagram"""
        return self.loader.context.is_logged_in

    def get_recent_posts(self, count: int = 10) -> List:
        """Get recent posts from the user (for content scanning).
        
        Returns:
            List of post objects
        """
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        profile = instaloader.Profile.from_username(self.loader.context, self.username)
        posts = []
        for post in profile.get_posts():
            posts.append(post)
            if len(posts) >= count:
                break
        return posts