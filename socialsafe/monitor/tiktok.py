"""TikTok monitoring module for social-safe.

Uses Playwright web automation since TikTok does not expose a public API
suitable for follower/following monitoring and security auditing.

NOTE: TikTok's DOM selectors change frequently and the site uses aggressive
bot detection. The selectors below are representative and must be verified
against the live site. Update them as needed when TikTok changes its markup.
"""

import os
from typing import Set, Dict, Optional
from .playwright_base import BasePlaywrightMonitor


class TikTokMonitor(BasePlaywrightMonitor):
    """TikTok platform monitor using Playwright web automation."""

    @property
    def platform_name(self) -> str:
        return "tiktok"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('TIKTOK_USERNAME')
        if not username:
            raise ValueError("TIKTOK_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        expected_privacy = expected_privacy or os.getenv('EXPECTED_PRIVACY', 'private')
        if expected_privacy not in ['private', 'public']:
            raise ValueError("EXPECTED_PRIVACY must be either 'private' or 'public'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize TikTok-specific state."""
        self.login_url = "https://www.tiktok.com/login"
        self.profile_url = f"https://www.tiktok.com/@{self.username}"
        self.following_url = f"https://www.tiktok.com/@{self.username}/following"
        self.followers_url = f"https://www.tiktok.com/@{self.username}/followers"

    async def _login_async(self, password: Optional[str] = None) -> bool:
        """Log in to TikTok using Playwright."""
        password = password or os.getenv('TIKTOK_PASSWORD')
        if not password:
            raise ValueError("TIKTOK_PASSWORD must be set in environment or passed to login()")

        await self._init_browser()
        page = self._page
        await page.goto(self.login_url, wait_until="networkidle")

        # TikTok login selectors (verify against live site)
        await page.fill('input[name="username"], input[placeholder*="username" i], input[placeholder*="email" i]', self.username)
        await page.fill('input[type="password"]', password)
        await page.click('button[type="submit"], text="Log in"')
        await page.wait_for_timeout(5000)

        return await self._is_logged_in_async()

    async def _is_logged_in_async(self) -> bool:
        """Check if currently logged in to TikTok."""
        if self._page is None:
            return False
        try:
            url = self._page.url
            return "login" not in url and "tiktok.com" in url
        except Exception:
            return False

    async def _check_changes_async(self) -> Dict[str, object]:
        """Check for follower/following changes on TikTok."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")

        page = self._page
        current_followers: Set[str] = set()
        current_following: Set[str] = set()

        # NOTE: TikTok uses aggressive bot detection and obfuscated selectors.
        # These selectors are representative and must be verified against the
        # live site. Update them when TikTok changes its markup.
        try:
            await page.goto(self.followers_url, wait_until="networkidle")
            await page.wait_for_timeout(4000)
            user_links = await page.query_selector_all('a[href*="/@"]')
            for link in user_links:
                try:
                    text = await link.inner_text()
                    href = await link.get_attribute("href")
                    if text and href and "@" in href:
                        current_followers.add(text.strip().lstrip("@"))
                except Exception:
                    continue
        except Exception:
            pass

        try:
            await page.goto(self.following_url, wait_until="networkidle")
            await page.wait_for_timeout(4000)
            user_links = await page.query_selector_all('a[href*="/@"]')
            for link in user_links:
                try:
                    text = await link.inner_text()
                    href = await link.get_attribute("href")
                    if text and href and "@" in href:
                        current_following.add(text.strip().lstrip("@"))
                except Exception:
                    continue
        except Exception:
            pass

        changes: Dict[str, object] = {}
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

        changes["privacy_changed"] = False
        self.state["followers"] = current_followers
        self.state["following"] = current_following
        self._save_state()
        return changes

    async def _audit_account_async(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the TikTok account."""
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

        # Scan recent posts/captions for threats and PII if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                page = self._page
                await page.goto(self.profile_url, wait_until="networkidle")
                await page.wait_for_timeout(4000)
                post_captions = await page.query_selector_all('[data-e2e="user-post-item"], .video-text')
                for elem in post_captions[:10]:
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
