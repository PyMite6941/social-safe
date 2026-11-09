"""Facebook monitoring module for social-safe.

Uses Playwright web automation since Facebook does not expose a public API
suitable for follower/following monitoring and security auditing.

NOTE: Facebook's DOM selectors change frequently. The selectors below are
representative and should be verified against the live site. Update them as
needed when Facebook updates its markup.
"""

import os
from typing import Set, Dict, Optional
from .playwright_base import BasePlaywrightMonitor


class FacebookMonitor(BasePlaywrightMonitor):
    """Facebook platform monitor using Playwright web automation."""

    @property
    def platform_name(self) -> str:
        return "facebook"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('FB_USERNAME')
        if not username:
            raise ValueError("FB_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        expected_privacy = expected_privacy or os.getenv('EXPECTED_PRIVACY', 'private')
        if expected_privacy not in ['private', 'public']:
            raise ValueError("EXPECTED_PRIVACY must be either 'private' or 'public'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize Facebook-specific state."""
        self.login_url = "https://www.facebook.com/login"
        self.profile_url = f"https://www.facebook.com/{self.username}"
        self.friends_url = f"https://www.facebook.com/{self.username}/friends"

    async def _login_async(self, password: Optional[str] = None) -> bool:
        """Log in to Facebook using Playwright."""
        password = password or os.getenv('FB_PASSWORD')
        if not password:
            raise ValueError("FB_PASSWORD must be set in environment or passed to login()")

        await self._init_browser()
        page = self._page
        await page.goto(self.login_url, wait_until="networkidle")

        # Facebook login form selectors (verify against live site)
        await page.fill('input[name="email"]', self.username)
        await page.fill('input[name="pass"]', password)
        await page.click('button[name="login"]')
        await page.wait_for_timeout(4000)

        return await self._is_logged_in_async()

    async def _is_logged_in_async(self) -> bool:
        """Check if currently logged in to Facebook."""
        if self._page is None:
            return False
        try:
            url = self._page.url
            return "login" not in url and "facebook.com" in url
        except Exception:
            return False

    async def _check_changes_async(self) -> Dict[str, object]:
        """Check for friend/follower changes and privacy setting on Facebook."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")

        page = self._page
        await page.goto(self.profile_url, wait_until="networkidle")
        await page.wait_for_timeout(3000)

        # NOTE: Facebook heavily obfuscates class names and structures.
        # These selectors are representative and must be verified against
        # the live site. Update them when Facebook changes its markup.
        current_friends: Set[str] = set()
        current_following: Set[str] = set()

        try:
            await page.goto(self.friends_url, wait_until="networkidle")
            await page.wait_for_timeout(3000)
            # Extract friend usernames/profile links from the friends page
            friend_links = await page.query_selector_all('a[href*="/profile.php?id="], a[href*="/"]')
            for link in friend_links:
                try:
                    href = await link.get_attribute("href")
                    text = await link.inner_text()
                    if href and text and text.strip():
                        current_friends.add(text.strip())
                except Exception:
                    continue
        except Exception:
            pass

        changes: Dict[str, object] = {}
        if self.monitor_followers:
            changes["new_followers"] = current_friends - self.state["followers"]
            changes["lost_followers"] = self.state["followers"] - current_friends
        else:
            changes["new_followers"] = set()
            changes["lost_followers"] = set()

        if self.monitor_following:
            changes["new_following"] = current_following - self.state["following"]
            changes["lost_following"] = self.state["following"] - current_following
        else:
            changes["new_following"] = set()
            changes["lost_following"] = set()

        changes["privacy_changed"] = False
        self.state["followers"] = current_friends
        self.state["following"] = current_following
        self._save_state()
        return changes

    async def _audit_account_async(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the Facebook account."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")

        if not self.audit_enabled:
            return {"audit_enabled": False, "risks": []}

        risks = []
        details = {}

        # Run the shared base security checks (2FA, login alerts, sessions, etc.)
        security = self.audit_account_security()
        risks.extend(security.get("findings", []))
        details["security_checks"] = security.get("checks", [])

        # Check content scanning on recent posts if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                page = self._page
                await page.goto(self.profile_url, wait_until="networkidle")
                await page.wait_for_timeout(3000)
                post_elements = await page.query_selector_all('[data-testid="post_message"]')
                for elem in post_elements[:10]:
                    text = await elem.inner_text()
                    if self.enable_content_scanning:
                        threats = self.scan_content(text)
                        if threats["text_threats"] or threats["image_threats"]:
                            risks.append("suspicious_content_in_posts")
                            details.setdefault("suspicious_content_in_posts", []).append({
                                "text": text[:100],
                                "threats": threats,
                            })
                    if self.enable_pii_detection:
                        pii = self.scan_for_pii(text)
                        if any(pii.values()):
                            risks.append("pii_detected_in_posts")
                            details.setdefault("pii_detected_in_posts", []).append({
                                "text": text[:100],
                                "pii_matches": pii,
                            })
            except Exception:
                pass

        return {
            "audit_enabled": True,
            "risks": risks,
            "details": details,
        }

    async def _is_logged_in_async_public(self) -> bool:
        """Public wrapper so external code can check login status."""
        return await self._is_logged_in_async()
