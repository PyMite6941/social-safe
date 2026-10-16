"""LinkedIn monitor adapter for social-safe using Playwright."""

import asyncio
import os
from typing import Set, Dict, Optional, List
from pathlib import Path
from .base import BaseSocialMonitor
from .playwright_base import BasePlaywrightMonitor


class LinkedInMonitor(BasePlaywrightMonitor):
    """LinkedIn platform monitor using Playwright for web automation."""

    @property
    def platform_name(self) -> str:
        return "linkedin"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('LINKEDIN_USERNAME')
        if not username:
            raise ValueError("LINKEDIN_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        # LinkedIn doesn't have traditional private/public profiles in the same way
        # We'll consider if the profile is visible to search engines or not
        # For simplicity, we'll treat as always 'public' for monitoring purposes
        # but allow override via environment
        expected_privacy = expected_privacy or os.getenv('LINKEDIN_EXPECTED_PRIVACY', 'public')
        if expected_privacy not in ['public', 'private']:
            raise ValueError("LINKEDIN_EXPECTED_PRIVACY must be either 'public' or 'private'")
        return expected_privacy

    async def _login_async(self, password: Optional[str] = None) -> bool:
        """Login to LinkedIn using Playwright."""
        await self._init_browser()
        
        password = password or os.getenv('LINKEDIN_PASSWORD')
        if not password:
            raise ValueError("LINKEDIN_PASSWORD must be set in environment or passed to login()")
        
        try:
            # Navigate to LinkedIn login page
            await self._page.goto("https://www.linkedin.com/login")
            
            # Fill in username/email
            await self._page.fill("#username", self.username)
            
            # Fill in password
            await self._page.fill("#password", password)
            
            # Click login button
            await self._page.click("button[type='submit']")
            
            # Wait for navigation to feed or profile page
            # LinkedIn redirects to feed after login
            await self._page.wait_for_url("https://www.linkedin.com/feed/**", timeout=10000)
            
            # Additional check: look for an element that indicates we're logged in
            await self._page.wait_for_selector(".global-nav__me-photo", timeout=5000)
            
            return True
        except Exception as e:
            await self._close_browser()
            raise ConnectionError(f"Failed to login to LinkedIn: {e}")

    async def _is_logged_in_async(self) -> bool:
        """Check if currently logged in to LinkedIn."""
        if not self._page:
            return False
            
        try:
            # Check if we're on a LinkedIn domain and see if we're logged in
            current_url = self._page.url
            if "linkedin.com" not in current_url:
                # Navigate to LinkedIn to check
                await self._page.goto("https://www.linkedin.com", timeout=5000)
                await self._page.wait_for_timeout(2000)  # Let it redirect if needed
            
            # Look for elements that indicate logged-in state
            # These are selectors that appear when logged in
            logged_in_selectors = [
                ".global-nav__me-photo",
                ".nav-item__profile-member-photo",
                "#global-nav-typeahead",  # Search bar
                ".feed-shared-update-v2"  # Feed content
            ]
            
            for selector in logged_in_selectors:
                try:
                    await self._page.wait_for_selector(selector, timeout=3000)
                    return True
                except:
                    continue
                    
            return False
        except Exception:
            return False

    async def _check_changes_async(self) -> Dict[str, Set[str] | bool]:
        """Check for follower/following changes and privacy setting on LinkedIn."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")
        
        # On LinkedIn, we can monitor:
        # - Followers (people who follow you)
        # - Following (people you follow/connections)
        # Note: LinkedIn uses "connections" more than following/followers like other platforms
        # For simplicity, we'll monitor connections as "following" and followers as "followers"
        
        # Get current sets
        try:
            # Go to profile page
            await self._page.goto(f"https://www.linkedin.com/in/{self.username}/", timeout=10000)
            await self._page.wait_for_timeout(3000)
        except Exception:
            # If we can't get to the profile, try search
            await self._page.goto(f"https://www.linkedin.com/search/results/people/?keywords={self.username}", timeout=10000)
            await self._page.wait_for_timeout(3000)
        
        current_followers = set()
        current_following = set()  # Will store connection names
        
        if self.monitor_followers:
            try:
                # Navigate to followers page
                await self._page.goto(f"https://www.linkedin.com/in/{self.username}/detail/recent-activity/followers/", timeout=10000)
                await self._page.wait_for_timeout(3000)
                
                # Scroll to load more followers (simplified - in reality would need pagination handling)
                for _ in range(3):
                    await self._page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await self._page.wait_for_timeout(2000)
                
                # Extract follower names
                follower_elements = await self._page.query_selector_all(".org-people-profile-card__profile-title, .search-result__title")
                for element in follower_elements:
                    try:
                        text = await element.inner_text()
                        # Clean up the text (might have extra whitespace/newlines)
                        name = text.strip().split('\n')[0] if '\n' in text else text.strip()
                        if name and len(name) > 1:  # Basic validation
                            current_followers.add(name)
                    except:
                        continue
            except Exception:
                # If we can't get followers, continue with empty set
                pass
        
        if self.monitor_following:
            try:
                # Navigate to connections page
                await self._page.goto(f"https://www.linkedin.com/mynetwork/invite-connect/connections/", timeout=10000)
                await self._page.wait_for_timeout(3000)
                
                # Scroll to load more connections
                for _ in range(3):
                    await self._page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await self._page.wait_for_timeout(2000)
                
                # Extract connection names
                connection_elements = await self._page.query_selector_all(".mn-connection-card__details, .search-result__title")
                for element in connection_elements:
                    try:
                        text = await element.inner_text()
                        name = text.strip().split('\n')[0] if '\n' in text else text.strip()
                        if name and len(name) > 1:
                            current_following.add(name)
                    except:
                        continue
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
        
        # Check privacy setting: LinkedIn has profile visibility options
        # We'll check if profile is visible to search engines/public
        privacy_changed = False
        try:
            await self._page.goto(f"https://www.linkedin.com/in/{self.username}/edit/public-profile/", timeout=10000)
            await self._page.wait_for_timeout(2000)
            
            # Check if public profile is toggled on
            # This is a simplified check - in reality would need to check the actual toggle state
            public_profile_toggle = await self._page.query_selector("#public-profile-toggle")
            if public_profile_toggle:
                is_public = await public_profile_toggle.is_checked()
                expected_is_public = (self.expected_privacy == 'public')
                privacy_changed = (is_public != expected_is_public)
        except Exception:
            # If we can't check privacy, assume no change
            privacy_changed = False
        
        changes["privacy_changed"] = privacy_changed
        
        # Update state for next time
        if self.monitor_followers:
            self.state["followers"] = current_followers
        if self.monitor_following:
            self.state["following"] = current_following
        self._save_state()
        
        return changes

    async def _audit_account_async(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the LinkedIn account."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")
        
        if not self.audit_enabled:
            return {"audit_enabled": False, "risks": []}
        
        risks = []
        details = {}
        
        # 1. Check if profile visibility matches expected
        try:
            await self._page.goto(f"https://www.linkedin.com/in/{self.username}/edit/public-profile/", timeout=10000)
            await self._page.wait_for_timeout(2000)
            
            public_profile_toggle = await self._page.query_selector("#public-profile-toggle")
            if public_profile_toggle:
                is_public = await public_profile_toggle.is_checked()
                current_privacy = 'public' if is_public else 'private'
                
                if self.expected_privacy != current_privacy:
                    risks.append("unexpected_privacy")
                    details["unexpected_privacy"] = {
                        "expected": self.expected_privacy,
                        "actual": current_privacy
                    }
        except Exception:
            pass  # Skip this check if we can't access privacy settings
        
        # 2. Check new connections/followers for risky characteristics
        # Note: This would require visiting each profile which is rate-limited
        # We'll skip detailed analysis for now to avoid LinkedIn restrictions
        
        # 3. Check for encryption/security settings
        # LinkedIn doesn't expose much about encryption via public interface
        
        # 4. Scan recent posts/articles for PII and suspicious content if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                # Go to recent activity page
                await self._page.goto(f"https://www.linkedin.com/in/{self.username}/detail/recent-activity/posts/", timeout=10000)
                await self._page.wait_for_timeout(3000)
                
                # Scroll to load more posts
                for _ in range(2):
                    await self._page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await self._page.wait_for_timeout(2000)
                
                # Extract post texts
                post_elements = await self._page.query_selector_all(".feed-shared-update-v2__description, .update-components-text")
                suspicious_posts = []
                pii_posts = []
                
                for element in post_elements[:10]:  # Limit to 10 most recent
                    try:
                        text = await element.inner_text()
                        text = text.strip()
                        
                        if self.enable_content_scanning:
                            content_threats = self.scan_content(text, [])
                            if content_threats["text_threats"] or content_threats["image_threats"]:
                                suspicious_posts.append({
                                    "post_id": f"linkedin_post_{len(suspicious_posts)}",
                                    "content": text[:100] + "..." if len(text) > 100 else text,
                                    "threats": content_threats
                                })
                        
                        if self.enable_pii_detection:
                            pii_matches = self.scan_for_pii(text)
                            if any(pii_matches.values()):
                                pii_posts.append({
                                    "post_id": f"linkedin_post_{len(pii_posts)}",
                                    "content": text[:100] + "..." if len(text) > 100 else text,
                                    "pii_matches": pii_matches
                                })
                    except:
                        continue
                
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
            "timestamp": str(Path(__file__).stat().st_mtime)
        }
        return result

    def scan_content_from_feed(self) -> Dict[str, List[str]]:
        """Convenience method to scan recent feed/posts for threats."""
        if not self.enable_content_scanning and not self.enable_pii_detection:
            return {"text_threats": [], "image_threats": []}
        
        # This would require async handling, but for simplicity we'll note
        # that actual implementation would need to be async
        return {"text_threats": [], "image_threats": []}