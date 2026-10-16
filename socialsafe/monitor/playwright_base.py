"""Base class for Playwright-based social media monitors."""

import asyncio
import os
from abc import ABC, abstractmethod
from typing import Set, Dict, Optional, List
from pathlib import Path
from playwright.async_api import async_playwright, Browser, Page
from .base import BaseSocialMonitor


class BasePlaywrightMonitor(BaseSocialMonitor, ABC):
    """Base class for social media monitors using Playwright for web automation."""

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
        enable_content_scanning: Optional[bool] = None,
        content_scan_keywords: Optional[List[str]] = None,
        content_scan_image_hashes: Optional[List[str]] = None,
        enable_pii_detection: Optional[bool] = None,
        pii_patterns: Optional[List[str]] = None,
        enable_phishing_detection: Optional[bool] = None,
        enable_ai_social_engineering_eval: Optional[bool] = None,
        ai_model_provider: Optional[str] = None,
        ai_model_name: Optional[str] = None,
        ai_api_key_env_var: Optional[str] = None,
        ai_api_base_url: Optional[str] = None,
        ai_social_engineering_threshold: Optional[int] = None,
        headless: bool = True,
        slow_mo: int = 0,
    ):
        """Initialize Playwright-based monitor.
        
        Args:
            headless: Whether to run browser in headless mode
            slow_mo: Slow down operations by specified milliseconds
        """
        super().__init__(
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
            enable_content_scanning=enable_content_scanning,
            content_scan_keywords=content_scan_keywords,
            content_scan_image_hashes=content_scan_image_hashes,
            enable_pii_detection=enable_pii_detection,
            pii_patterns=pii_patterns,
            enable_phishing_detection=enable_phishing_detection,
            enable_ai_social_engineering_eval=enable_ai_social_engineering_eval,
            ai_model_provider=ai_model_provider,
            ai_model_name=ai_model_name,
            ai_api_key_env_var=ai_api_key_env_var,
            ai_api_base_url=ai_api_base_url,
            ai_social_engineering_threshold=ai_social_engineering_threshold,
        )
        self.headless = headless
        self.slow_mo = slow_mo
        self._browser: Optional[Browser] = None
        self._page: Optional[Page] = None
        self._playwright = None

    async def _init_browser(self):
        """Initialize Playwright browser."""
        if self._playwright is None:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless,
                slow_mo=self.slow_mo
            )
            self._page = await self._browser.new_page()
            # Set viewport for consistency
            await self._page.set_viewport_size({"width": 1280, "height": 720})

    async def _close_browser(self):
        """Close Playwright browser."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._page = None
        self._playwright = None

    def login(self, password: Optional[str] = None) -> bool:
        """Login to the platform using Playwright.
        
        This is a synchronous wrapper for the async login method.
        """
        try:
            # Run the async login in a new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._login_async(password))
            loop.close()
            return result
        except Exception as e:
            raise ConnectionError(f"Failed to login: {e}")

    @abstractmethod
    async def _login_async(self, password: Optional[str] = None) -> bool:
        """Async login implementation using Playwright."""
        pass

    def _is_logged_in(self) -> bool:
        """Check if currently logged in to the platform.
        
        This is a synchronous wrapper for the async method.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._is_logged_in_async())
            loop.close()
            return result
        except Exception:
            return False

    @abstractmethod
    async def _is_logged_in_async(self) -> bool:
        """Async check if logged in."""
        pass

    def check_changes(self) -> Dict[str, Set[str] | bool]:
        """Check for follower/following changes and privacy setting.
        
        This is a synchronous wrapper for the async method.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._check_changes_async())
            loop.close()
            return result
        except Exception as e:
            raise RuntimeError(f"Failed to check changes: {e}")

    @abstractmethod
    async def _check_changes_async(self) -> Dict[str, Set[str] | bool]:
        """Async check for changes."""
        pass

    def audit_account(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the account.
        
        This is a synchronous wrapper for the async method.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self._audit_account_async())
            loop.close()
            return result
        except Exception as e:
            raise RuntimeError(f"Failed to audit account: {e}")

    @abstractmethod
    async def _audit_account_async(self) -> Dict[str, object]:
        """Async audit account."""
        pass

    def __del__(self):
        """Cleanup browser resources."""
        if self._browser or self._playwright:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self._close_browser())
                loop.close()
            except Exception:
                pass  # Ignore cleanup errors during destruction