"""YouTube monitoring module for social-safe.

Uses Playwright web automation since YouTube does not expose a public API
suitable for subscriber/following monitoring and security auditing without
OAuth credentials.

NOTE: YouTube's DOM selectors change frequently. The selectors below are
representative and must be verified against the live site. Update them as
needed when YouTube changes its markup.
"""

import os
from typing import Set, Dict, Optional
from .playwright_base import BasePlaywrightMonitor


class YouTubeMonitor(BasePlaywrightMonitor):
    """YouTube platform monitor using Playwright web automation."""

    @property
    def platform_name(self) -> str:
        return "youtube"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('YOUTUBE_USERNAME')
        if not username:
            raise ValueError("YOUTUBE_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        expected_privacy = expected_privacy or os.getenv('EXPECTED_PRIVACY', 'private')
        if expected_privacy not in ['private', 'public']:
            raise ValueError("EXPECTED_PRIVACY must be either 'private' or 'public'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize YouTube-specific state."""
        self.login_url = "https://www.youtube.com/signin"
        self.channel_url = f"https://www.youtube.com/@{self.username}"
        self.subscribers_url = f"https://www.youtube.com/@{self.username}/subscribers"

    async def _login_async(self, password: Optional[str] = None) -> bool:
        """Log in to YouTube (Google account) using Playwright."""
        password = password or os.getenv('YOUTUBE_PASSWORD')
        if not password:
            raise ValueError("YOUTUBE_PASSWORD must be set in environment or passed to login()")

        await self._init_browser()
        page = self._page
        await page.goto(self.login_url, wait_until="networkidle")

        # YouTube/Google login flow (verify against live site)
        await page.fill('input[type="email"], input[name="identifier"]', self.username)
        await page.click('button:has-text("Next")')
        await page.wait_for_timeout(3000)
        await page.fill('input[type="password"]', password)
        await page.click('button:has-text("Next")')
        await page.wait_for_timeout(5000)

        return await self._is_logged_in_async()

    async def _is_logged_in_async(self) -> bool:
        """Check if currently logged in to YouTube."""
        if self._page is None:
            return False
        try:
            url = self._page.url
            return "signin" not in url and "accounts.google.com" not in url and "youtube.com" in url
        except Exception:
            return False

    async def _check_changes_async(self) -> Dict[str, object]:
        """Check for subscriber changes on YouTube."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")

        page = self._page
        current_subscribers: Set[str] = set()
        current_subscriptions: Set[str] = set()

        # NOTE: YouTube subscriber lists are not publicly accessible for most
        # channels due to privacy. This monitors what is observable.
        # Selectors are representative and must be verified against the live site.
        try:
            await page.goto(self.channel_url, wait_until="networkidle")
            await page.wait_for_timeout(4000)
            # Extract channel links from videos/comments sections
            channel_links = await page.query_selector_all('a[href*="/channel/"], a[href*="/@"]')
            for link in channel_links:
                try:
                    text = await link.inner_text()
                    href = await link.get_attribute("href")
                    if text and text.strip():
                        current_subscriptions.add(text.strip())
                except Exception:
                    continue
        except Exception:
            pass

        changes: Dict[str, object] = {}
        if self.monitor_followers:
            changes["new_followers"] = current_subscribers - self.state["followers"]
            changes["lost_followers"] = self.state["followers"] - current_subscribers
        else:
            changes["new_followers"] = set()
            changes["lost_followers"] = set()

        if self.monitor_following:
            changes["new_following"] = current_subscriptions - self.state["following"]
            changes["lost_following"] = self.state["following"] - current_subscriptions
        else:
            changes["new_following"] = set()
            changes["lost_following"] = set()

        changes["privacy_changed"] = False
        self.state["followers"] = current_subscribers
        self.state["following"] = current_subscriptions
        self._save_state()
        return changes

    async def _audit_account_async(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the YouTube account."""
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

        # Scan video titles/descriptions/comments for threats and PII if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                page = self._page
                await page.goto(self.channel_url, wait_until="networkidle")
                await page.wait_for_timeout(4000)
                text_elements = await page.query_selector_all('#video-title, #description-text, ytd-comment-renderer #content-text')
                for elem in text_elements[:10]:
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
