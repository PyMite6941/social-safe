"""Base classes for social media monitoring adapters."""

from abc import ABC, abstractmethod
from typing import Set, Dict, Optional, List, Tuple, Union
from pathlib import Path
import json
import os
import re


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
        enable_content_scanning: Optional[bool] = None,
        content_scan_keywords: Optional[List[str]] = None,
        content_scan_image_hashes: Optional[List[str]] = None,
        enable_pii_detection: Optional[bool] = None,
        pii_patterns: Optional[List[str]] = None,
    ):
        """Initialize base monitor with configuration."""
        self.username = self._get_username(username)
        self.state_file = Path(state_file or os.getenv('STATE_FILE', f'{self.platform_name}_state.json'))
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
        self.enable_content_scanning = self._get_bool_env('ENABLE_CONTENT_SCANNING', enable_content_scanning, False)
        self.content_scan_keywords = content_scan_keywords or []
        self.content_scan_image_hashes = content_scan_image_hashes or []
        self.enable_pii_detection = self._get_bool_env('ENABLE_PII_DETECTION', enable_pii_detection, False)
        self.pii_patterns = pii_patterns or []
        
        # Initialize state
        self.state = self._load_state()
        self._initialize_platform_specific()
        
        # Initialize content scanner if enabled
        if self.enable_content_scanning:
            self.content_scanner = ContentScanner(
                keywords=self.content_scan_keywords,
                known_bad_hashes=self.content_scan_image_hashes
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
        """Save current follower/following state to file."""
        data = {
            "followers": list(self.state["followers"]),
            "following": list(self.state["following"])
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, 'w') as f:
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

    def scan_content(self, text: str, image_urls: List[str] = None) -> Dict[str, List[str]]:
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


class ContentScanner:
    """Handles OSINT content scanning for threats."""
    
    def __init__(self, keywords: List[str] = None, known_bad_hashes: List[str] = None):
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
        
        # Compile regex patterns
        self.compiled_patterns = [re.compile(pattern) for pattern in self.suspicious_text_patterns]
    
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
    
    def scan_text(self, text: str) -> List[str]:
        """Scan text for suspicious patterns.
        
        Returns:
            List of threat identifiers found (empty if none)
        """
        threats = []
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(text):
                threats.append(f"suspicious_text_pattern_{i}")
        return threats
    
    def scan_post(self, post_text: str, image_urls: List[str] = None) -> Dict[str, List[str]]:
        """Scan a complete post (text and images) for threats.
        
        Returns:
            Dict with keys 'text_threats' and 'image_threats'
        """
        if image_urls is None:
            image_urls = []
            
        text_threats = self.scan_text(post_text)
        image_threats = []
        
        for url in image_urls:
            image_threats.extend(self.scan_image(url))
        
        return {
            "text_threats": text_threats,
            "image_threats": image_threats
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


# Example usage would be in platform-specific implementations
# For instance, in TwitterMonitor:
#   scanner = ContentScanner()
#   pii_detector = PIIDetector()
#   for tweet in self.get_user_timeline():
#       threats = scanner.scan_post(tweet.text, tweet.media_urls)
#       pii_matches = pii_detector.detect_all(tweet.text)
#       if threats["text_threats"] or threats["image_threats"] or any(pii_matches.values()):
#           # Handle threat detection