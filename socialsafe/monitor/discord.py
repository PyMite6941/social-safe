"""Discord monitoring module for social-safe.

Uses Playwright web automation since Discord does not expose a public API
suitable for friend/server monitoring and security auditing without a bot token.

NOTE: Discord's DOM selectors change frequently and the site uses aggressive
bot detection. The selectors below are representative and must be verified
against the live site. Update them as needed when Discord changes its markup.
"""

import os
from typing import Set, Dict, Optional
from .playwright_base import BasePlaywrightMonitor


class DiscordMonitor(BasePlaywrightMonitor):
    """Discord platform monitor using Playwright web automation."""

    @property
    def platform_name(self) -> str:
        return "discord"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('DISCORD_USERNAME')
        if not username:
            raise ValueError("DISCORD_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        expected_privacy = expected_privacy or os.getenv('EXPECTED_PRIVACY', 'private')
        if expected_privacy not in ['private', 'public']:
            raise ValueError("EXPECTED_PRIVACY must be either 'private' or 'public'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize Discord-specific state."""
        self.login_url = "https://discord.com/login"
        self.profile_url = "https://discord.com/users/@me"
        self.friends_url = "https://discord.com/users/@me/friends"

    async def _login_async(self, password: Optional[str] = None) -> bool:
        """Log in to Discord using Playwright."""
        password = password or os.getenv('DISCORD_PASSWORD')
        if not password:
            raise ValueError("DISCORD_PASSWORD must be set in environment or passed to login()")

        await self._init_browser()
        page = self._page
        await page.goto(self.login_url, wait_until="networkidle")

        # Discord login selectors (verify against live site)
        await page.fill('input[name="email"], input[placeholder*="email" i]', self.username)
        await page.fill('input[name="password"], input[placeholder*="password" i]', password)
        await page.click('button:has-text("Login"), button[type="submit"]')
        await page.wait_for_timeout(5000)

        return await self._is_logged_in_async()

    async def _is_logged_in_async(self) -> bool:
        """Check if currently logged in to Discord."""
        if self._page is None:
            return False
        try:
            url = self._page.url
            return "login" not in url and "discord.com" in url
        except Exception:
            return False

    async def _check_changes_async(self) -> Dict[str, object]:
        """Check for friend changes on Discord."""
        if not await self._is_logged_in_async():
            raise RuntimeError("Not logged in. Call login() first.")

        page = self._page
        current_friends: Set[str] = set()
        current_guilds: Set[str] = set()

        # NOTE: Discord's friend list is rendered client-side and may require
        # interaction to load. These selectors are representative and must be
        # verified against the live site. Update them when Discord changes.
        try:
            await page.goto(self.friends_url, wait_until="networkidle")
            await page.wait_for_timeout(4000)
            friend_elements = await page.query_selector_all('[class*="user-"], [class*="friend-"]')
            for elem in friend_elements:
                try:
                    text = await elem.inner_text()
                    if text and text.strip():
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
            changes["new_following"] = current_guilds - self.state["following"]
            changes["lost_following"] = self.state["following"] - current_guilds
        else:
            changes["new_following"] = set()
            changes["lost_following"] = set()

        changes["privacy_changed"] = False
        self.state["followers"] = current_friends
        self.state["following"] = current_guilds
        self._save_state()
        return changes

    async def _audit_account_async(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the Discord account."""
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

        # Scan DMs/messages for threats and PII if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                page = self._page
                await page.goto("https://discord.com/channels/@me", wait_until="networkidle")
                await page.wait_for_timeout(4000)
                message_elements = await page.query_selector_all('[class*="message-"], [class*="markup-"]')
                for elem in message_elements[:10]:
                    text = await elem.inner_text()
                    if self.enable_content_scanning:
                        threats = self.scan_content(text)
                        if threats["text_threats"] or threats["image_threats"]:
                            risks.append("suspicious_content_in_dms")
                            details.setdefault("suspicious_content_in_dms", []).append({
                                "text": text[:100],
                                "threats": threats,
                            })
                    if self.enable_pii_detection:
                        pii = self.scan_for_pii(text)
                        if any(pii.values()):
                            risks.append("pii_detected_in_dms")
                            details.setdefault("pii_detected_in_dms", []).append({
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
