"""Base classes for social media monitoring adapters."""

from abc import ABC, abstractmethod
from typing import Set, Dict, Optional, List, Tuple, Union
from pathlib import Path
import json
import os
import re
import sys

from .threats import analyze_url, extract_urls, match_emerging_threats


def user_data_dir() -> Path:
    """Per-user data directory for social-safe on Windows, macOS, and Linux.

    Override with the SOCIALSAFE_HOME environment variable.
    """
    override = os.getenv("SOCIALSAFE_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "socialsafe"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "socialsafe"
    return Path(os.getenv("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "socialsafe"


def default_state_path(platform: str) -> Path:
    """Where a platform's follower state is stored.

    A ``<platform>_state.json`` already in the working directory (the layout
    used before 0.2.0) keeps being used so existing installs don't lose state.
    """
    legacy = Path(f"{platform}_state.json")
    if legacy.exists():
        return legacy
    return user_data_dir() / f"{platform}_state.json"


# Where each platform's 2FA / MFA settings live.
MFA_SETUP_URLS: Dict[str, str] = {
    "instagram": "https://www.instagram.com/accounts/security/",
    "twitter": "https://x.com/settings/security",
    "linkedin": "https://www.linkedin.com/mypreferences/d/two-step-verification",
    "reddit": "https://www.reddit.com/settings/safety",
    "facebook": "https://accountscenter.facebook.com/password_and_security",
    "tiktok": "https://www.tiktok.com/setting/security",
    "youtube": "https://myaccount.google.com/signinoptions/two-step-verification",
    "discord": "https://discord.com/channels/@me",
}

# Human-readable path to each platform's 2FA / MFA settings.
MFA_GUIDANCE: Dict[str, str] = {
    "instagram": (
        "Open Instagram > Accounts Center > Password and security > "
        "Two-factor authentication. Choose Authentication app, SMS, or WhatsApp. "
        "Save backup codes."
    ),
    "twitter": (
        "Open X > Settings and privacy > Security and account access > "
        "Security > Two-factor authentication. Choose Authentication app "
        "or Security key."
    ),
    "linkedin": (
        "Open LinkedIn > Me > Settings & Privacy > Sign in & security > "
        "Two-step verification. Choose Authenticator app or Phone number."
    ),
    "reddit": (
        "Open Reddit > User Settings > Safety > Use two factor "
        "authentication. Toggle on and follow setup."
    ),
    "facebook": (
        "Open Facebook > Settings & privacy > Settings > Accounts Center > "
        "Password and security > Two-factor authentication. Choose "
        "Authentication app or Security key and save recovery codes."
    ),
    "tiktok": (
        "Open TikTok > Profile > Menu > Settings and privacy > Security & "
        "permissions > 2-step verification. Pick at least two methods."
    ),
    "youtube": (
        "YouTube uses your Google Account: open myaccount.google.com > "
        "Security > 2-Step Verification. Prefer passkeys, a security key, "
        "or Google prompts over SMS."
    ),
    "discord": (
        "Open Discord > User Settings (gear icon) > My Account > Password and "
        "Authentication > Enable Authenticator App. Save your backup codes."
    ),
}


class BaseSocialMonitor(ABC):
    """Abstract base class for social media platform monitors."""

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
        audit_check_https: Optional[bool] = None,
        audit_check_2fa: Optional[bool] = None,
        audit_check_login_alerts: Optional[bool] = None,
        audit_check_active_sessions: Optional[bool] = None,
        audit_check_recent_security_checkup: Optional[bool] = None,
        audit_check_account_verification: Optional[bool] = None,
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
    ):
        """Initialize base monitor with configuration."""
        self.username = self._get_username(username)
        self.state_file = Path(state_file or os.getenv('STATE_FILE') or default_state_path(self.platform_name))
        self.expected_privacy = self._get_expected_privacy(expected_privacy)
        self.monitor_followers = self._get_bool_env('MONITOR_FOLLOWERS', monitor_followers, True)
        self.monitor_following = self._get_bool_env('MONITOR_FOLLOWING', monitor_following, True)
        self.alert_threshold_new_followers = self._get_int_env('ALERT_THRESHOLD_NEW_FOLLOWERS', alert_threshold_new_followers, 10)
        self.alert_threshold_lost_followers = self._get_int_env('ALERT_THRESHOLD_LOST_FOLLOWERS', alert_threshold_lost_followers, 10)
        self.alert_threshold_new_following = self._get_int_env('ALERT_THRESHOLD_NEW_FOLLOWING', alert_threshold_new_following, 10)
        self.alert_threshold_lost_following = self._get_int_env('ALERT_THRESHOLD_LOST_FOLLOWING', alert_threshold_lost_following, 10)
        self.audit_enabled = self._get_bool_env('AUDIT_ENABLED', audit_enabled, True)
        self.audit_risk_zero_posts = self._get_bool_env('AUDIT_RISK_ZERO_POSTS', audit_risk_zero_posts, True)
        self.audit_risk_zero_followers = self._get_bool_env('AUDIT_RISK_ZERO_FOLLOWERS', audit_risk_zero_followers, True)
        self.audit_risk_high_following_ratio = self._get_bool_env('AUDIT_RISK_HIGH_FOLLOWING_RATIO', audit_risk_high_following_ratio, True)
        self.audit_following_ratio_threshold = self._get_int_env('AUDIT_FOLLOWING_RATIO_THRESHOLD', audit_following_ratio_threshold, 100)
        self.audit_min_followers_for_ratio = self._get_int_env('AUDIT_MIN_FOLLOWERS_FOR_RATIO', audit_min_followers_for_ratio, 10)
        self.audit_alert_threshold_risky = self._get_int_env('AUDIT_ALERT_THRESHOLD_RISKY', audit_alert_threshold_risky, 5)
        self.audit_check_https = self._get_bool_env('AUDIT_CHECK_HTTPS', audit_check_https, True)
        self.audit_check_2fa = self._get_bool_env('AUDIT_CHECK_2FA', audit_check_2fa, True)
        self.audit_check_login_alerts = self._get_bool_env('AUDIT_CHECK_LOGIN_ALERTS', audit_check_login_alerts, True)
        self.audit_check_active_sessions = self._get_bool_env('AUDIT_CHECK_ACTIVE_SESSIONS', audit_check_active_sessions, True)
        self.audit_check_recent_security_checkup = self._get_bool_env('AUDIT_CHECK_RECENT_SECURITY_CHECKUP', audit_check_recent_security_checkup, True)
        self.audit_check_account_verification = self._get_bool_env('AUDIT_CHECK_ACCOUNT_VERIFICATION', audit_check_account_verification, True)
        self.enable_content_scanning = self._get_bool_env('ENABLE_CONTENT_SCANNING', enable_content_scanning, False)
        self.content_scan_keywords = content_scan_keywords or []
        self.content_scan_image_hashes = content_scan_image_hashes or []
        self.enable_pii_detection = self._get_bool_env('ENABLE_PII_DETECTION', enable_pii_detection, False)
        self.pii_patterns = pii_patterns or []
        self.enable_phishing_detection = self._get_bool_env('ENABLE_PHISHING_DETECTION', enable_phishing_detection, False)
        self.enable_ai_social_engineering_eval = self._get_bool_env('ENABLE_AI_SOCIAL_ENGINEERING_EVAL', enable_ai_social_engineering_eval, False)
        self.ai_model_provider = ai_model_provider or os.getenv('AI_MODEL_PROVIDER')
        self.ai_model_name = ai_model_name or os.getenv('AI_MODEL_NAME')
        self.ai_api_key_env_var = ai_api_key_env_var or os.getenv('AI_API_KEY_ENV_VAR', 'AI_API_KEY')
        self.ai_api_base_url = ai_api_base_url or os.getenv('AI_API_BASE_URL')
        self.ai_social_engineering_threshold = self._get_int_env('AI_SOCIAL_ENGINEERING_THRESHOLD', ai_social_engineering_threshold, 70)
        
        # Initialize state
        self.state = self._load_state()
        self._initialize_platform_specific()
        
        # Initialize content scanner if enabled
        if self.enable_content_scanning:
            self.content_scanner = ContentScanner(
                keywords=self.content_scan_keywords,
                known_bad_hashes=self.content_scan_image_hashes,
                enable_phishing_detection=self.enable_phishing_detection
            )
        else:
            self.content_scanner = None
            
        # Initialize PII detector if enabled
        if self.enable_pii_detection:
            self.pii_detector = PIIDetector(
                patterns=self.pii_patterns
            )
        else:
            self.pii_detector = None
            
        # Initialize AI evaluator if enabled
        if self.enable_ai_social_engineering_eval:
            self.ai_evaluator = AIEvaluator(
                provider=self.ai_model_provider,
                model_name=self.ai_model_name,
                api_key_env_var=self.ai_api_key_env_var,
                api_base_url=self.ai_api_base_url
            )
        else:
            self.ai_evaluator = None

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Return the platform name (e.g., 'instagram', 'twitter')."""
        pass

    @abstractmethod
    def _get_username(self, username: Optional[str]) -> str:
        """Get username from parameter or environment."""
        pass

    @abstractmethod
    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        """Get expected privacy setting from parameter or environment."""
        pass

    @abstractmethod
    def _initialize_platform_specific(self):
        """Initialize platform-specific clients/connections."""
        pass

    @abstractmethod
    def login(self, password: Optional[str] = None) -> bool:
        """Login to the platform. Return True if successful."""
        pass

    @abstractmethod
    def check_changes(self) -> Dict[str, Union[Set[str], bool]]:
        """Check for follower/following changes and privacy setting.
        
        Returns:
            Dict with keys: new_followers (Set[str]), lost_followers (Set[str]), 
                          new_following (Set[str]), lost_following (Set[str]), 
                          privacy_changed (bool)
        """
        pass

    def _check_https_connection(self) -> Dict[str, object]:
        """Check if the platform connection uses HTTPS/TLS.
        
        Returns:
            Dict with risk status and details
        """
        # This is a basic check - in practice, all legitimate platforms should use HTTPS
        # We can verify by checking if our API calls are made over HTTPS
        # For now, we'll assume HTTPS is used if we successfully connected
        # A more thorough implementation would verify certificates and protocol versions
        
        return {
            "risk_detected": False,
            "details": {
                "https_enforced": True,
                "note": "Connection security assumed based on successful API connection"
            }
        }

    def _check_2fa_status(self) -> Dict[str, object]:
        """Check if two-factor authentication / MFA is enabled.

        Most social platforms do not expose 2FA status through their public
        APIs, so this returns a structured result with ``mfa_enabled`` set to
        ``None`` (unknown) when the platform cannot confirm it, together with
        platform-specific guidance on how the user can verify and enable MFA
        manually.

        Returns:
            Dict with keys:
              - risk_detected (bool): True if MFA status is unknown or disabled
              - details (dict): mfa_enabled (bool|None), method (str|None),
                platform (str), guidance (str), setup_url (str|None)
        """
        platform = getattr(self, "platform_name", "unknown")
        guidance = MFA_GUIDANCE.get(
            platform,
            "Go to your account security settings and enable two-factor / "
            "multi-factor authentication (preferably an authenticator app or "
            "security key).",
        )
        setup_url = MFA_SETUP_URLS.get(platform)
        return {
            "risk_detected": True,
            "details": {
                "mfa_enabled": None,
                "method": None,
                "platform": platform,
                "note": (
                    "2FA status is not exposed by this platform's public API. "
                    "Verify and enable MFA manually using the guidance below."
                ),
                "guidance": guidance,
                "setup_url": setup_url,
            },
        }

    def _check_login_alerts(self) -> Dict[str, object]:
        """Check if login alerts/notifications are enabled.
        
        Returns:
            Dict with risk status and details (platform-specific implementation needed)
        """
        # Placeholder - platform-specific implementation needed
        return {
            "risk_detected": False,
            "details": {
                "login_alerts_enabled": None,
                "note": "Login alerts status check not implemented for this platform"
            }
        }

    def _check_active_sessions(self) -> Dict[str, object]:
        """Check for suspicious or excessive active sessions.
        
        Returns:
            Dict with risk status and details (platform-specific implementation needed)
        """
        # Placeholder - platform-specific implementation needed
        return {
            "risk_detected": False,
            "details": {
                "suspicious_sessions": [],
                "note": "Active sessions check not implemented for this platform"
            }
        }

    def _check_recent_security_checkup(self) -> Dict[str, object]:
        """Check if the account has had a recent security checkup.
        
        Returns:
            Dict with risk status and details (platform-specific implementation needed)
        """
        # Placeholder - platform-specific implementation needed
        return {
            "risk_detected": False,
            "details": {
                "recent_security_checkup": None,
                "note": "Recent security checkup status not implemented for this platform"
            }
        }

    def _check_account_verification(self) -> Dict[str, object]:
        """Check if the account is verified (where applicable).
        
        Returns:
            Dict with risk status and details
        """
        # Many platforms don't expose verification status via basic APIs
        # Platform-specific implementations should override this method
        return {
            "risk_detected": False,
            "details": {
                "is_verified": None,
                "note": "Account verification status not available via this platform's API"
            }
        }

    def audit_account_security(self) -> Dict[str, object]:
        """Run a comprehensive account security audit.

        Combines 2FA/MFA status, login alerts, active sessions, recent security
        checkup, HTTPS enforcement, and account verification into a single
        security report with an overall risk rating and remediation guidance.

        Returns:
            Dict with keys:
              - overall_risk (str): 'low' / 'medium' / 'high' / 'critical'
              - checks (list): one dict per security check
              - mfa (dict): 2FA/MFA status and setup guidance
              - recommendations (list): actionable hardening steps
        """
        mfa_result = self._check_2fa_status()
        checks = []
        checks.append(("2FA / MFA", mfa_result))
        checks.append(("Login alerts", self._check_login_alerts()))
        checks.append(("Active sessions", self._check_active_sessions()))
        checks.append(("Security checkup", self._check_recent_security_checkup()))
        checks.append(("HTTPS / TLS", self._check_https_connection()))
        checks.append(("Account verification", self._check_account_verification()))

        formatted_checks = []
        risk_score = 0
        findings = []
        for name, result in checks:
            details = result.get("details", {}) or {}
            if result.get("risk_detected"):
                risk_score += 1
                findings.append(name)
            formatted_checks.append({
                "check": name,
                "risk_detected": result.get("risk_detected", False),
                "details": details,
            })

        if risk_score >= 5:
            overall_risk = "critical"
        elif risk_score >= 3:
            overall_risk = "high"
        elif risk_score >= 2:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        recommendations = []
        if mfa_result.get("details", {}).get("mfa_enabled") is not True:
            recommendations.append(
                "Enable two-factor / multi-factor authentication (preferably "
                "an authenticator app or security key, not SMS)."
            )
        recommendations.append(
            "Review and remove any unrecognized active sessions or logged-in devices."
        )
        recommendations.append(
            "Turn on login alerts so you are notified of new sign-ins."
        )
        recommendations.append(
            "Run a security checkup on the platform and update your recovery email/phone."
        )
        recommendations.append(
            "Use a strong, unique password and a password manager."
        )

        return {
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "checks": formatted_checks,
            "findings": findings,
            "mfa": mfa_result,
            "recommendations": recommendations,
        }

    def get_security_hardening_guide(self, platform: str = None) -> Dict[str, object]:
        """Return platform-specific steps to secure/harden a social media account.

        Covers MFA setup, privacy settings, login alerts, active-session review,
        and third-party app access revocation. Based on official platform help
        documentation (Facebook/Meta, X, LinkedIn, Reddit, Instagram).

        Args:
            platform: Platform name (instagram, twitter, linkedin, reddit,
                      facebook, tiktok, youtube, discord).
                      Defaults to this monitor's platform.

        Returns:
            Dict with keys: platform, steps (list of dicts), mfa_setup_url,
            general_tips (list).
        """
        platform = (platform or getattr(self, "platform_name", "")).lower()
        step_map = {
            "instagram": [
                {"step": 1, "action": "Enable two-factor authentication",
                 "detail": "Accounts Center > Password and security > Two-factor authentication. Use an authenticator app and save backup codes."},
                {"step": 2, "action": "Set account to private",
                 "detail": "Settings > Privacy > Account privacy > Private account."},
                {"step": 3, "action": "Review active sessions",
                 "detail": "Accounts Center > Password and security > Where you're logged in. Log out unknown devices."},
                {"step": 4, "action": "Remove third-party app access",
                 "detail": "Settings > Apps and websites > Active. Remove apps you no longer use."},
                {"step": 5, "action": "Enable login alerts",
                 "detail": "Accounts Center > Password and security > Login alerts."},
            ],
            "twitter": [
                {"step": 1, "action": "Enable two-factor authentication",
                 "detail": "Settings and privacy > Security and account access > Security > Two-factor authentication. Use an authenticator app or security key."},
                {"step": 2, "action": "Protect your posts",
                 "detail": "Settings and privacy > Privacy and safety > Audience and tagging > Protect your posts."},
                {"step": 3, "action": "Review active sessions",
                 "detail": "Settings and privacy > Security and account access > Apps and sessions > Sessions. Log out unknown devices."},
                {"step": 4, "action": "Revoke third-party app access",
                 "detail": "Settings and privacy > Security and account access > Apps and sessions > Connected apps."},
            ],
            "linkedin": [
                {"step": 1, "action": "Enable two-step verification",
                 "detail": "Me > Settings & Privacy > Sign in & security > Two-step verification. Use an authenticator app."},
                {"step": 2, "action": "Adjust profile visibility",
                 "detail": "Settings & Privacy > Visibility. Control who can see your connections, profile, and activity."},
                {"step": 3, "action": "Review active sessions",
                 "detail": "Settings & Privacy > Sign in & security > Where you're signed in."},
                {"step": 4, "action": "Manage third-party apps",
                 "detail": "Settings & Privacy > Account > Permitted services."},
            ],
            "reddit": [
                {"step": 1, "action": "Enable two-factor authentication",
                 "detail": "User Settings > Safety > Use two factor authentication."},
                {"step": 2, "action": "Review active sessions",
                 "detail": "User Settings > Safety > Active sessions."},
                {"step": 3, "action": "Adjust privacy",
                 "detail": "User Settings > Privacy. Limit who can message you and view your profile."},
            ],
            "facebook": [
                {"step": 1, "action": "Enable two-factor authentication",
                 "detail": "Accounts Center > Password and security > Two-factor authentication. Use an authenticator app or security key."},
                {"step": 2, "action": "Run Privacy Checkup",
                 "detail": "Settings & privacy > Privacy Checkup. Limit who can see your posts, friends list, and contact info."},
                {"step": 3, "action": "Review where you're logged in",
                 "detail": "Accounts Center > Password and security > Where you're logged in. Log out unknown devices."},
                {"step": 4, "action": "Remove third-party apps",
                 "detail": "Settings > Apps and websites. Remove apps you no longer use."},
                {"step": 5, "action": "Turn on login alerts",
                 "detail": "Accounts Center > Password and security > Login alerts."},
            ],
            "tiktok": [
                {"step": 1, "action": "Enable 2-step verification",
                 "detail": "Settings and privacy > Security & permissions > 2-step verification."},
                {"step": 2, "action": "Set account to private",
                 "detail": "Settings and privacy > Privacy > Private account."},
                {"step": 3, "action": "Review devices",
                 "detail": "Settings and privacy > Security & permissions > Manage devices. Remove unknown devices."},
                {"step": 4, "action": "Restrict direct messages",
                 "detail": "Settings and privacy > Privacy > Direct messages. Limit who can message you."},
            ],
            "youtube": [
                {"step": 1, "action": "Enable Google 2-Step Verification",
                 "detail": "myaccount.google.com > Security > 2-Step Verification. Prefer passkeys or a security key."},
                {"step": 2, "action": "Run Google Security Checkup",
                 "detail": "myaccount.google.com/security-checkup. Review devices, third-party access, and recovery info."},
                {"step": 3, "action": "Review channel permissions",
                 "detail": "YouTube Studio > Settings > Permissions. Remove managers you don't recognize."},
                {"step": 4, "action": "Hide subscriptions and saved playlists",
                 "detail": "YouTube Settings > Privacy. Keep subscriptions and playlists private."},
            ],
            "discord": [
                {"step": 1, "action": "Enable authenticator-app 2FA",
                 "detail": "User Settings > My Account > Password and Authentication > Enable Authenticator App."},
                {"step": 2, "action": "Lock down DMs and friend requests",
                 "detail": "User Settings > Content & Social. Limit DMs from server members and who can add you as a friend."},
                {"step": 3, "action": "Review authorized apps",
                 "detail": "User Settings > Authorized Apps. Deauthorize apps you don't use."},
                {"step": 4, "action": "Review logged-in devices",
                 "detail": "User Settings > Devices. Log out unknown sessions."},
            ],
        }
        steps = step_map.get(platform, [])
        general_tips = [
            "Use a unique, strong password for each social account (password manager recommended).",
            "Prefer an authenticator app or hardware security key over SMS for 2FA.",
            "Save 2FA backup codes in a secure, offline location.",
            "Regularly review logged-in devices and revoke unknown sessions.",
            "Limit who can see your posts, contacts, and personal details via privacy settings.",
            "Be cautious of urgent DMs, short URLs, and credential requests — verify through another channel.",
        ]
        return {
            "platform": platform,
            "steps": steps,
            "mfa_setup_url": MFA_SETUP_URLS.get(platform),
            "general_tips": general_tips,
        }

    @abstractmethod
    def audit_account(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the account.
        
        Returns:
            Dict with audit results including risks and details.
        """
        pass

    def _load_state(self) -> Dict[str, Set[str]]:
        """Load previous follower/following state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
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
        """Save current follower/following state to file."""
        data = {
            "followers": list(self.state["followers"]),
            "following": list(self.state["following"])
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def _get_bool_env(self, env_var: str, param_val: Optional[bool], default: bool) -> bool:
        """Get boolean value from parameter or environment."""
        if param_val is not None:
            return param_val
        val = os.getenv(env_var, str(default)).lower()
        return val in ('true', '1', 'yes', 'on')

    def _get_int_env(self, env_var: str, param_val: Optional[int], default: int) -> int:
        """Get integer value from parameter or environment."""
        if param_val is not None:
            return param_val
        try:
            return int(os.getenv(env_var, str(default)))
        except ValueError:
            return default

    def _should_alert(self, changes: Dict[str, Union[Set[str], bool]], audit_result: Optional[Dict] = None) -> bool:
        """Determine if changes exceed thresholds, privacy changed, or audit finds risks."""
        # Always alert on privacy change
        if changes.get("privacy_changed", False):
            return True
        
        # Check thresholds for each change type - only check if the value is a set
        new_followers = changes.get("new_followers")
        if isinstance(new_followers, set) and self.monitor_followers:
            if len(new_followers) > self.alert_threshold_new_followers:
                return True
        
        lost_followers = changes.get("lost_followers")
        if isinstance(lost_followers, set) and self.monitor_followers:
            if len(lost_followers) > self.alert_threshold_lost_followers:
                return True
        
        new_following = changes.get("new_following")
        if isinstance(new_following, set) and self.monitor_following:
            if len(new_following) > self.alert_threshold_new_following:
                return True
        
        lost_following = changes.get("lost_following")
        if isinstance(lost_following, set) and self.monitor_following:
            if len(lost_following) > self.alert_threshold_lost_following:
                return True
        
        # Check audit results for risks that exceed threshold
        if audit_result and audit_result.get("audit_enabled", False):
            risks = audit_result.get("risks", [])
            if "risky_new_followers" in risks:
                details = audit_result.get("details", {})
                risky_list = details.get("risky_new_followers", [])
                if len(risky_list) > self.audit_alert_threshold_risky:
                    return True
            
            # Check for phishing threats
            if "phishing_detected" in risks:
                details = audit_result.get("details", {})
                phishing_list = details.get("phishing_detected", [])
                if len(phishing_list) > 0:  # Alert on any phishing detection
                    return True
            
            # Check for PII detection
            if any(risk.startswith("pii_detected_in_") for risk in risks):
                details = audit_result.get("details", {})
                # Check if any PII detection risk has findings
                for risk_key in risks:
                    if risk_key.startswith("pii_detected_in_") and risk_key in details:
                        pii_list = details[risk_key]
                        if len(pii_list) > 0:  # Alert on any PII detection
                            return True

            # Check for high social engineering risk
            if "high_social_engineering_risk" in risks:
                details = audit_result.get("details", {})
                se_score = details.get("social_engineering_score", 0)
                if se_score >= self.ai_social_engineering_threshold:
                    return True
        
        return False

    def send_alert(self, changes: Dict[str, Union[Set[str], bool]], 
                   email_to: Optional[str] = None,
                   audit_result: Optional[Dict] = None,
                   content_threats: Optional[Dict] = None,
                   pii_threats: Optional[Dict] = None):
        """Send email alert if thresholds exceeded, privacy changed, audit finds risks, or content/PII threats detected."""
        # To be implemented by subclasses or provided as common implementation
        # For now, this is a placeholder that subclasses should override
        pass

    def monitor(self) -> Tuple[Dict[str, Union[Set[str], bool]], Optional[Dict]]:
        """Convenience method to monitor and return changes and audit results.
        
        Note: Actual login and alert sending would be handled by the caller
        or a convenience function.
        """
        if not self._is_logged_in():
            raise RuntimeError(f"Not logged in to {self.platform_name}. Call login() first.")
        
        changes = self.check_changes()
        audit_result = None
        if self.audit_enabled:
            audit_result = self.audit_account()
        
        return changes, audit_result

    @abstractmethod
    def _is_logged_in(self) -> bool:
        """Check if currently logged in to the platform."""
        pass

    def scan_content(self, text: str, image_urls: Optional[List[str]] = None) -> Dict[str, object]:
        """Scan content for threats using the content scanner.
        
        Returns:
            Dict with keys 'text_threats' and 'image_threats'
        """
        if not self.enable_content_scanning or not self.content_scanner:
            return {"text_threats": [], "image_threats": []}
        
        if image_urls is None:
            image_urls = []
            
        return self.content_scanner.scan_post(text, image_urls)

    def scan_for_pii(self, text: str) -> Dict[str, List[str]]:
        """Scan text for PII using the PII detector.
        
        Returns:
            Dict with keys for each PII type found and lists of matches
        """
        if not self.enable_pii_detection or not self.pii_detector:
            return {}
        
        return self.pii_detector.detect_all(text)

    def scan_for_phishing(self, text: str, image_urls: Optional[List[str]] = None) -> Dict[str, object]:
        """Scan content for phishing threats using the content scanner.
        
        Returns:
            Dict with keys 'text_threats' and 'image_threats'
        """
        if not self.enable_content_scanning or not self.content_scanner:
            return {"text_threats": [], "image_threats": []}
        
        if image_urls is None:
            image_urls = []
            
        # Use the content scanner which now includes phishing detection
        return self.content_scanner.scan_post(text, image_urls)

    def evaluate_social_engineering_risk(self, text: str) -> Dict[str, object]:
        """Evaluate text for social engineering risk using AI.
        
        Returns:
            Dict with keys: risk_level (str), score (int), explanation (str)
        """
        if not self.enable_ai_social_engineering_eval or not self.ai_evaluator:
            return {"risk_level": "disabled", "score": 0, "explanation": "AI social engineering evaluation is disabled"}
        
        return self.ai_evaluator.evaluate(text)


class ContentScanner:
    """Handles OSINT content scanning for threats including phishing detection."""
    
    def __init__(self, keywords: List[str] = None, known_bad_hashes: List[str] = None, enable_phishing_detection: bool = False):
        # Known bad image hashes (perceptual hashes of malicious images)
        # In practice, these would be loaded from a database or feed
        self.known_bad_image_hashes = set(known_bad_hashes or [])
        
        # Suspicious text patterns (regex or keyword lists)
        # Default keywords plus any provided
        default_keywords = [
            # Example patterns - would be expanded based on threat intelligence
            "free nft",
            "click here for",
            "urgent action required",
            "your account will be deleted",
            "mr beast",  # Specifically mentioned by user
            "crypto giveaway",
            "verify your account"
        ]
        all_keywords = default_keywords + (keywords or [])
        # Filter out empty strings and create regex patterns
        filtered_keywords = [kw.strip() for kw in all_keywords if kw.strip()]
        self.suspicious_text_patterns = [rf"(?i){re.escape(kw)}" for kw in filtered_keywords]
        
        # Threat severity levels used when rating detected threats.
        # critical: credential theft / account takeover / malware
        # high: phishing links, investment/romance/job scams, impersonation
        # medium: spam / engagement bait / suspicious links
        # low: generic suspicious content
        self.severity_map = {
            "suspicious": "medium",
            "phishing": "high",
            "scam": "high",
            "spam": "medium",
        }

        # Weighted phishing keyword categories for scoring-based classification.
        # Each keyword maps to a weight; the sum of matched weights produces a
        # phishing score that is compared against phishing_threshold to separate
        # phishing attempts from legitimate (non-phishing) content.
        # Weights reflect research into social media attack vectors:
        # urgency, credential harvesting, money/reward lures, threats, and
        # impersonation are strongest phishing indicators.
        self.phishing_keyword_weights = {
            "urgency": [
                ("urgent", 12), ("immediate action", 14), ("account suspended", 16),
                ("verify immediately", 16), ("security alert", 12), ("expires", 10),
                ("act now", 11), ("limited time", 10), ("within 24 hours", 14),
            ],
            "credential": [
                ("verify your account", 15), ("login", 8), ("password", 10),
                ("confirm your identity", 14), ("update your password", 14),
                ("secure login", 13), ("sign in", 6), ("credentials", 12),
            ],
            "money_reward": [
                ("free money", 14), ("you won", 13), ("congratulations", 10),
                ("prize", 10), ("reward", 9), ("cash app", 12), ("wire transfer", 13),
                ("inheritance", 12), ("lottery winner", 14), ("double your money", 15),
            ],
            "threat": [
                ("account will be deleted", 16), ("suspended", 13), ("blocked", 12),
                ("unauthorized access", 14), ("security breach", 14), ("legal action", 12),
                ("penalty", 10), ("arrest", 14),
            ],
            "impersonation": [
                ("from support", 13), ("from security", 13), ("from admin", 12),
                ("official notification", 12), ("instagram support", 14),
                ("facebook support", 14), ("twitter support", 14),
            ],
            "suspicious_link": [
                ("bit.ly", 11), ("tinyurl", 11), ("t.co", 10), ("shortlink", 10),
                ("click here", 9), ("verify now", 13),
            ],
        }
        # Score >= phishing_threshold => classified as phishing attempt.
        # Below threshold => legitimate / non-phishing content.
        self.phishing_threshold = 20

        # Phishing-specific patterns (credential theft, fake logins, urgent lures)
        self.phishing_patterns = [
            # Urgent/threatening language
            r"(?i)(urgent|immediate action|account suspended|verify immediately|security alert)",
            # Suspicious URLs/link shorteners
            r"(?i)(bit\.ly|tinyurl|t\.co|shortlink|url\.shorten)",
            # Fake login pages
            r"(?i)(login.*secure|secure.*login|account.*verify|verify.*account)",
            # Financial scams
            r"(?i)(wire transfer|funds transfer|inheritance|lottery winner|prize money)",
            # Impersonation (support/security/admin)
            r"(?i)(from.*support|from.*security|from.*admin|official.*notification)",
            # Too good to be true
            r"(?i)(you.*won|congratulations.*you|free.*gift|claim.*prize)",
        ]

        # Scam patterns (investment, crypto giveaway, romance, job, impersonation, marketplace)
        # Each entry: (regex, severity)
        self.scam_patterns = [
            (r"(?i)(crypto.*giveaway|bitcoin.*giveaway|free.*crypto|send.*crypto)", "high"),
            (r"(?i)(investment.*opportunity|double.*money|guaranteed.*return|passive.*income)", "high"),
            (r"(?i)(romance|soulmate|true love|marry me|i love you)", "high"),
            (r"(?i)(work from home|easy money|no experience required|onboarding fee)", "high"),
            (r"(?i)(impersonat|pretending to be|posing as|fake account)", "high"),
            (r"(?i)(marketplace|buy now|cheap.*iphone|counterfeit|replica)", "medium"),
            (r"(?i)(money mule|cash app|venmo|paypal.*send|wire transfer)", "high"),
        ]

        # Spam patterns (engagement bait, brand collaboration, bot-like behavior)
        self.spam_patterns = [
            (r"(?i)(vote for me|can you vote|help me win)", "medium"),
            (r"(?i)(is this you|i can.t believe|look at this|check this out)", "medium"),
            (r"(?i)(brand collaboration|brand deal|sponsored post|ambassador|influencer)", "medium"),
            (r"(?i)(follow for follow|sub for sub|like for like|team followback)", "medium"),
            (r"(?i)(comment below|dm me|whatsapp|telegram.*me|text me)", "low"),
        ]

        # Compile regex patterns, pairing each with its severity level
        self.compiled_suspicious_patterns = [
            (re.compile(pattern), self.severity_map["suspicious"])
            for pattern in self.suspicious_text_patterns
        ]
        self.compiled_phishing_patterns = [
            (re.compile(pattern), self.severity_map["phishing"])
            for pattern in self.phishing_patterns
        ] if enable_phishing_detection else []
        self.compiled_scam_patterns = [
            (re.compile(pattern), severity) for pattern, severity in self.scam_patterns
        ]
        self.compiled_spam_patterns = [
            (re.compile(pattern), severity) for pattern, severity in self.spam_patterns
        ]
    
    def scan_image(self, image_path_or_url: str) -> List[str]:
        """Scan an image for known threats.
        
        Returns:
            List of threat identifiers found (empty if none)
        """
        # In a real implementation, this would:
        # 1. Download the image if URL
        # 2. Compute perceptual hash (using something like imagehash)
        # 3. Compare against known bad hashes
        # 4. Optionally run ML model for content classification
        # For now, return empty list as placeholder
        # TODO: Implement actual perceptual hashing
        return []
    
    def scan_text(self, text: str) -> Dict[str, object]:
        """Scan text for suspicious, phishing, scam, and spam patterns.

        Each detected threat is rated with a severity level:
        critical, high, medium, or low (based on research into social media
        attack vectors: phishing, malvertising, investment/romance/job scams,
        impersonation, and spam/engagement bait).

        Returns:
            Dict with keys 'suspicious_threats', 'phishing_threats',
            'scam_threats', 'spam_threats' (each a list of
            {"pattern": str, "severity": str}), plus 'overall_severity'
            and 'threat_count'.
        """
        def _matches(compiled):
            found = []
            for regex, severity in compiled:
                m = regex.search(text)
                if m:
                    found.append({"pattern": m.group(0), "severity": severity})
            return found

        suspicious_threats = _matches(self.compiled_suspicious_patterns)
        phishing_threats = _matches(self.compiled_phishing_patterns)
        scam_threats = _matches(self.compiled_scam_patterns)
        spam_threats = _matches(self.compiled_spam_patterns)
        emerging_threats = match_emerging_threats(text)
        link_threats = [f for url in extract_urls(text) for f in analyze_url(url)]
        for f in link_threats:
            f.setdefault("pattern", f["url"])

        all_threats = (suspicious_threats + phishing_threats + scam_threats
                       + spam_threats + emerging_threats + link_threats)
        overall_severity = self._rate_overall(all_threats)

        return {
            "suspicious_threats": suspicious_threats,
            "phishing_threats": phishing_threats,
            "scam_threats": scam_threats,
            "spam_threats": spam_threats,
            "emerging_threats": emerging_threats,
            "link_threats": link_threats,
            "advice": sorted({t["advice"] for t in emerging_threats}),
            "overall_severity": overall_severity,
            "threat_count": len(all_threats),
        }

    def _rate_overall(self, threats: List[Dict[str, object]]) -> str:
        """Return the highest severity among detected threats ('none' if none)."""
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        best = "low"
        for threat in threats:
            sev = str(threat.get("severity", "low"))
            if rank.get(sev, 0) > rank.get(best, 0):
                best = sev
        return best if threats else "none"

    def classify_phishing(self, text: str) -> Dict[str, object]:
        """Classify text as phishing or non-phishing using a weighted keyword
        scoring algorithm.

        The algorithm sums weights of matched phishing keywords across categories
        (urgency, credential harvesting, money/reward lures, threats,
        impersonation, suspicious links). If the total score meets or exceeds
        ``self.phishing_threshold`` the content is classified as a phishing
        attempt; otherwise it is treated as legitimate / non-phishing.

        Returns:
            Dict with keys:
              - is_phishing (bool): True if score >= threshold
              - score (float): total weighted score
              - threshold (float): the classification threshold
              - confidence (str): 'low' / 'medium' / 'high' based on score
              - categories (dict): category -> list of matched keywords
              - matched_keywords (list): all matched (keyword, weight, category)
              - reason (str): human-readable explanation
        """
        lowered = text.lower()
        matched_keywords = []
        categories = {cat: [] for cat in self.phishing_keyword_weights}
        total_score = 0.0

        for category, entries in self.phishing_keyword_weights.items():
            for keyword, weight in entries:
                # Word-boundary match so "t.co" doesn't fire inside "at.com"
                if re.search(rf"(?<!\w){re.escape(keyword)}(?!\w)", lowered):
                    matched_keywords.append({
                        "keyword": keyword,
                        "weight": weight,
                        "category": category,
                    })
                    categories[category].append(keyword)
                    total_score += weight

        is_phishing = total_score >= self.phishing_threshold
        if total_score >= 40:
            confidence = "high"
        elif total_score >= self.phishing_threshold:
            confidence = "medium"
        elif total_score > 0:
            confidence = "low"
        else:
            confidence = "none"

        if is_phishing:
            reason = (
                f"Phishing attempt detected (score {total_score} >= "
                f"threshold {self.phishing_threshold}). Matched {len(matched_keywords)} "
                f"phishing indicator(s) across {sum(1 for v in categories.values() if v)} category(ies)."
            )
        else:
            reason = (
                f"Not classified as phishing (score {total_score} < "
                f"threshold {self.phishing_threshold}). No sufficient phishing indicators."
            )

        return {
            "is_phishing": is_phishing,
            "score": total_score,
            "threshold": self.phishing_threshold,
            "confidence": confidence,
            "categories": categories,
            "matched_keywords": matched_keywords,
            "reason": reason,
        }

    def scan_post(self, post_text: str, image_urls: Optional[List[str]] = None) -> Dict[str, object]:
        """Scan a complete post (text and images) for threats.
        
        Returns:
            Dict with keys:
              - text_threats (list): flat list of {"category", "pattern",
                "severity"} dicts; empty when nothing matched, so callers
                can test it for truthiness
              - image_threats (list): matched image threat identifiers
              - text_breakdown (dict): full per-category result of scan_text
              - overall_severity (str): highest severity, or 'none'
        """
        if image_urls is None:
            image_urls = []

        text_results = self.scan_text(post_text)
        text_threats = [
            {"category": category.replace("_threats", ""), **threat}
            for category in ("suspicious_threats", "phishing_threats",
                             "scam_threats", "spam_threats",
                             "emerging_threats", "link_threats")
            for threat in text_results[category]
        ]
        image_threats = []
        for url in image_urls:
            image_threats.extend(self.scan_image(url))

        return {
            "text_threats": text_threats,
            "image_threats": image_threats,
            "text_breakdown": text_results,
            "overall_severity": text_results["overall_severity"],
        }


class PIIDetector:
    """Detects Personally Identifiable Information (PII) in text."""
    
    def __init__(self, patterns: List[str] = None):
        # Default PII patterns (regex)
        default_patterns = [
            # Email addresses
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            
            # Phone numbers (various formats)
            r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            
            # Social Security Numbers (US)
            r'\b\d{3}-?\d{2}-?\d{4}\b',
            
            # Credit card numbers (basic pattern - should be enhanced with validation)
            r'\b(?:\d[ -]*?){13,16}\b',
            
            # IP addresses
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            
            # Dates of birth (MM/DD/YYYY or DD/MM/YYYY)
            r'\b(0[1-9]|1[0-2])[-/](0[1-9]|[12][0-9]|3[01])[-/](\d{4})\b',
            r'\b(0[1-9]|[12][0-9]|3[01])[-/](0[1-9]|1[0-2])[-/](\d{4})\b',
            
            # Passport numbers (US format)
            r'\b[0-9]{9}\b',
            
            # Driver's license numbers (varies by state - example pattern)
            r'\b[A-Z]{1,2}[0-9]{6,8}\b',
        ]
        
        all_patterns = default_patterns + (patterns or [])
        # Filter out empty strings
        filtered_patterns = [p.strip() for p in all_patterns if p.strip()]
        self.pii_patterns = [re.compile(pattern) for pattern in filtered_patterns]
        
        # Map pattern indices to PII types for better reporting
        self.pii_types = [
            "email",
            "phone_number", 
            "ssn",
            "credit_card",
            "ip_address",
            "dob_mm_dd_yyyy",
            "dob_dd_mm_yyyy",
            "passport_number",
            "drivers_license"
        ]
        # Extend if we have more patterns than types
        while len(self.pii_types) < len(self.pii_patterns):
            self.pii_types.append(f"pii_pattern_{len(self.pii_types)}")
    
    def detect_pii(self, text: str, pii_type: str) -> List[str]:
        """Detect specific type of PII in text.
        
        Args:
            text: Text to scan
            pii_type: Type of PII to detect (must match self.pii_types)
            
        Returns:
            List of matches found
        """
        try:
            idx = self.pii_types.index(pii_type)
            if idx < len(self.pii_patterns):
                pattern = self.pii_patterns[idx]
                return pattern.findall(text)
        except (ValueError, IndexError):
            pass
        return []
    
    def detect_all(self, text: str) -> Dict[str, List[str]]:
        """Detect all types of PII in text.
        
        Returns:
            Dict with keys as PII types and lists of matches
        """
        results = {}
        for i, (pii_type, pattern) in enumerate(zip(self.pii_types, self.pii_patterns)):
            matches = pattern.findall(text)
            if matches:
                # Flatten list if matches contains tuples (from capture groups)
                flattened = []
                for match in matches:
                    if isinstance(match, tuple):
                        # For patterns with capture groups, join or take first non-empty
                        non_empty = [m for m in match if m]
                        if non_empty:
                            flattened.append(non_empty[0] if len(non_empty) == 1 else "_".join(non_empty))
                        else:
                            flattened.append(match[0] if match else "")
                    else:
                        flattened.append(match)
                results[pii_type] = flattened
        return results


class AIEvaluator:
    """Evaluates content for social engineering risk using AI models."""
    
    def __init__(self, provider: Optional[str] = None, model_name: Optional[str] = None,
                 api_key_env_var: str = None, api_base_url: Optional[str] = None):
        self.provider = provider
        self.model_name = model_name
        self.api_key_env_var = api_key_env_var or 'AI_API_KEY'
        self.api_base_url = api_base_url
        self.api_key = None
        self._load_api_key()
    
    def _load_api_key(self):
        """Load API key from environment variable."""
        if self.api_key_env_var:
            self.api_key = os.getenv(self.api_key_env_var)
    
    def evaluate(self, text: str) -> Dict[str, object]:
        """Evaluate text for social engineering risk.
        
        Returns:
            Dict with keys: risk_level (str), score (int), explanation (str)
        """
        # If not configured, return disabled
        if not self.api_key:
            return {
                "risk_level": "disabled", 
                "score": 0, 
                "explanation": "AI evaluation is not configured. Set API key via environment variable."
            }
        
        # For now, return a placeholder implementation
        # In a real implementation, this would call an AI API
        # We'll implement a simple rule-based approach for demonstration
        # that can be replaced with actual API calls
        
        # Simple heuristic for demonstration (would be replaced with actual AI call)
        social_engineering_indicators = [
            r'(?i)(urgent|emergency|immediate action required)',
            r'(?i)(your account.*(?:locked|suspended|compromised))',
            r'(?i)(verify.*identity|confirm.*details)',
            r'(?i)(click.*here|download.*attachment)',
            r'(?i)(limited time|offer expires|act now)',
            r'(?i)(congratulations|you.*won|prize|reward)',
            r'(?i)(help.*me|financial trouble|wire transfer)',
            r'(?i)(secret.*deal|confidential|private.*offer)',
            r'(?i)(authorities|police|court|legal.*action)',
            r'(?i)(family.*emergency|friend.*in.*need)'
        ]
        
        score = 0
        detected_indicators = []
        
        for pattern in social_engineering_indicators:
            if re.search(pattern, text):
                score += 10  # Each indicator adds 10 points
                detected_indicators.append(pattern)
        
        # Cap score at 100
        score = min(score, 100)
        
        # Determine risk level
        if score >= 70:
            risk_level = "high"
        elif score >= 40:
            risk_level = "medium"
        elif score > 0:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        explanation = f"Detected {len(detected_indicators)} social engineering indicators: {', '.join(detected_indicators[:3])}{'...' if len(detected_indicators) > 3 else ''}"
        
        return {
            "risk_level": risk_level,
            "score": score,
            "explanation": explanation
        }
        
        # TODO: Replace the above with actual AI API call like:
        # return self._call_ai_api(text)
    
    def _call_ai_api(self, text: str) -> Dict[str, object]:
        """Make actual API call to AI service for social engineering evaluation.
        
        This is a placeholder for the actual implementation which would
        depend on the specific AI provider (OpenAI, Anthropic, etc.).
        """
        # This would be implemented based on the provider:
        # - OpenAI: Use openai library to call ChatCompletion
        # - Anthropic: Use anthropic library to call Messages API
        # - Custom: Use requests to call custom endpoint
        #
        # For now, we'll return a placeholder that indicates this needs
        # to be implemented with actual API credentials
        
        # In a production implementation, this would:
        # 1. Format the request according to the provider's API
        # 2. Send the request with proper authentication
        # 3. Parse the response to extract risk score and explanation
        # 4. Handle errors and rate limiting
        #
        # Example structure for OpenAI:
        # import openai
        # openai.api_key = self.api_key
        # response = openai.ChatCompletion.create(
        #     model=self.model_name or "gpt-3.5-turbo",
        #     messages=[
        #         {"role": "system", "content": "You are a security expert analyzing text for social engineering risk. Provide a score from 0-100 where 0 is no risk and 100 is high risk, along with a brief explanation."},
        #         {"role": "user", "content": f"Analyze this text for social engineering risk: {text}"}
        #     ],
        #     max_tokens=150
        # )
        # 
        # Then parse response.choices[0].message.content to extract score and explanation
        
        # For now, return indication that this needs implementation
        return {
            "risk_level": "not_implemented",
            "score": 0,
            "explanation": "AI API call not implemented. This is a placeholder for actual AI service integration."
        }


# Example usage would be in platform-specific implementations
# For instance, in TwitterMonitor:
#   scanner = ContentScanner(enable_phishing_detection=True)
#   pii_detector = PIIDetector()
#   ai_evaluator = AIEvaluator(provider="openai", model_name="gpt-3.5-turbo")
#   for tweet in self.get_user_timeline():
#       threats = scanner.scan_post(tweet.text, tweet.media_urls)
#       pii_matches = pii_detector.detect_all(tweet.text)
#       se_risk = ai_evaluator.evaluate(tweet.text)
#       if threats["text_threats"] or threats["image_threats"] or any(pii_matches.values()) or se_risk["score"] > 50:
#           # Handle threat detection