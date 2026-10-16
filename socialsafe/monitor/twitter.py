"""Twitter/X monitor adapter for social-safe"""

import tweepy
import os
from typing import Set, Dict, Optional, List
from pathlib import Path
from .base import BaseSocialMonitor


class TwitterMonitor(BaseSocialMonitor):
    """Twitter/X platform monitor."""

    @property
    def platform_name(self) -> str:
        return "twitter"

    def _get_username(self, username: Optional[str]) -> str:
        username = username or os.getenv('TWITTER_USERNAME')
        if not username:
            raise ValueError("TWITTER_USERNAME must be set in environment or passed to constructor")
        return username

    def _get_expected_privacy(self, expected_privacy: Optional[str]) -> str:
        # Twitter doesn't have private/public in the same way as Instagram
        # Protected vs unprotected is the closest equivalent
        expected_privacy = expected_privacy or os.getenv('TWITTER_EXPECTED_PRIVACY', 'unprotected')
        if expected_privacy not in ['protected', 'unprotected']:
            raise ValueError("TWITTER_EXPECTED_PRIVACY must be either 'protected' or 'unprotected'")
        return expected_privacy

    def _initialize_platform_specific(self):
        """Initialize Twitter client."""
        # Try to use Bearer Token first (for v2 API), fallback to OAuth 1.0a
        bearer_token = os.getenv('TWITTER_BEARER_TOKEN')
        if bearer_token:
            self.client = tweepy.Client(bearer_token=bearer_token)
            self.api = None  # v2 API only
        else:
            # Fallback to OAuth 1.0a for v1.1 API
            api_key = os.getenv('TWITTER_API_KEY')
            api_secret = os.getenv('TWITTER_API_SECRET')
            access_token = os.getenv('TWITTER_ACCESS_TOKEN')
            access_token_secret = os.getenv('TWITTER_ACCESS_TOKEN_SECRET')
            
            if not all([api_key, api_secret, access_token, access_token_secret]):
                raise ValueError("Twitter API credentials not found in environment")
            
            auth = tweepy.OAuth1UserHandler(
                api_key, api_secret, access_token, access_token_secret
            )
            self.api = tweepy.API(auth)
            self.client = None  # Will use v1.1 API

    def login(self, password: Optional[str] = None) -> bool:
        """Login to Twitter (verify credentials)"""
        try:
            if self.client:
                # Test v2 API
                me = self.client.get_me()
                if not me or not hasattr(me, 'data') or not me.data:
                    raise ConnectionError("Failed to verify credentials")
            elif self.api:
                # Test v1.1 API
                self.api.verify_credentials()
            else:
                raise RuntimeError("No Twitter client initialized")
            return True
        except Exception as e:
            raise ConnectionError(f"Failed to login to Twitter: {e}")

    def check_changes(self) -> Dict[str, Set[str] | bool]:
        """Check for follower/following changes and privacy setting"""
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        # Get current user info
        if self.client:
            # v2 API
            user_response = self.client.get_user(username=self.username, user_fields=['public_metrics', 'protected'])
            if not user_response or not hasattr(user_response, 'data') or not user_response.data:
                raise ValueError(f"User {self.username} not found")
            user = user_response.data
            current_followers_count = user.public_metrics['followers_count']
            current_following_count = user.public_metrics['following_count']
            is_protected = user.protected
            
            # Note: v2 API doesn't easily give us lists of followers/following without elevated access
            # For now, we'll only monitor counts, not specific user lists
            # To get actual lists, we'd need to use pagination endpoints which require more complex handling
            current_followers = set()  # Placeholder - would need to fetch via API
            current_following = set()  # Placeholder - would need to fetch via API
        elif self.api:
            # v1.1 API
            user = self.api.get_user(screen_name=self.username)
            current_followers_count = user.followers_count
            current_following_count = user.friends_count
            is_protected = user.protected
            
            # Get followers and following lists (limited by API rate limits)
            if self.monitor_followers:
                current_followers = {f.screen_name for f in self.api.get_followers(screen_name=self.username)}
            else:
                current_followers = set()
                
            if self.monitor_following:
                current_following = {f.screen_name for f in self.api.get_friends(screen_name=self.username)}
            else:
                current_following = set()
        else:
            raise RuntimeError("No Twitter client initialized")
        
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
        
        # Check privacy setting (protected vs unprotected)
        current_privacy = 'protected' if is_protected else 'unprotected'
        privacy_changed = (self.expected_privacy != current_privacy)
        changes["privacy_changed"] = privacy_changed
        
        # Update state for next time
        if self.monitor_followers:
            self.state["followers"] = current_followers
        if self.monitor_following:
            self.state["following"] = current_following
        self._save_state()
        
        return changes

    def audit_account(self) -> Dict[str, object]:
        """Perform a privacy/risk audit on the Twitter account."""
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        if not self.audit_enabled:
            return {"audit_enabled": False, "risks": []}
        
        # Get user info
        if self.client:
            user_response = self.client.get_user(username=self.username, user_fields=['public_metrics', 'protected', 'verified'])
            if not user_response or not hasattr(user_response, 'data') or not user_response.data:
                raise ValueError(f"User {self.username} not found")
            user = user_response.data
            followers_count = user.public_metrics['followers_count']
            following_count = user.public_metrics['following_count']
            is_protected = user.protected
            is_verified = user.verified
        elif self.api:
            user = self.api.get_user(screen_name=self.username)
            followers_count = user.followers_count
            following_count = user.friends_count
            is_protected = user.protected
            is_verified = user.verified
        else:
            raise RuntimeError("No Twitter client initialized")
        
        risks = []
        details = {}
        
        # 1. Check if account protection status matches expected
        current_privacy = 'protected' if is_protected else 'unprotected'
        if self.expected_privacy != current_privacy:
            risks.append("unexpected_privacy")
            details["unexpected_privacy"] = {
                "expected": self.expected_privacy,
                "actual": current_privacy
            }
        
        # 2. Check new followers for risky characteristics (if monitoring followers)
        risky_new_followers = []
        if self.monitor_followers:
            # Note: Getting detailed follower info requires additional API calls
            # For simplicity, we'll skip detailed follower analysis for now
            # In a full implementation, we would fetch each new follower's profile
            pass
        
        if risky_new_followers:
            risks.append("risky_new_followers")
            details["risky_new_followers"] = risky_new_followers
        
        # 3. Check for encryption/security settings
        # Twitter doesn't expose much about encryption via API
        # We can note if the account is verified (which might indicate authenticity)
        if not is_verified:
            # Not necessarily a risk, but worth noting for public figures
            pass
        
        # 4. Scan recent tweets for PII and suspicious content if enabled
        if self.enable_content_scanning or self.enable_pii_detection:
            try:
                # Get recent tweets
                if self.client:
                    # v2 API
                    user_response = self.client.get_user(username=self.username)
                    user_id = None
                    if user_response and hasattr(user_response, 'data') and user_response.data:
                        user_id = user_response.data.id
                    if user_id:
                        tweets_response = self.client.get_users_tweets(
                            id=user_id,
                            max_results=10,
                            tweet_fields=['text', 'attachments']
                        )
                        tweets = tweets_response.data if tweets_response and hasattr(tweets_response, 'data') else []
                    else:
                        tweets = []
                elif self.api:
                    # v1.1 API
                    tweets = self.api.user_timeline(screen_name=self.username, count=10, tweet_mode='extended')
                else:
                    tweets = []
                
                # Scan each tweet
                suspicious_tweets = []
                pii_tweets = []
                
                for tweet in tweets:
                    # Get tweet text
                    if hasattr(tweet, 'text'):
                        text = tweet.text
                    elif hasattr(tweet, 'full_text'):
                        text = tweet.full_text
                    else:
                        text = str(tweet)
                    
                    # Get media URLs if available
                    media_urls = []
                    if hasattr(tweet, 'entities') and tweet.entities and 'media' in tweet.entities:
                        media_urls = [media['media_url'] for media in tweet.entities['media']]
                    elif hasattr(tweet, 'attachments') and tweet.attachments:
                        # v2 API media handling - simplified
                        pass
                    
                    # Content scanning
                    if self.enable_content_scanning:
                        content_threats = self.scan_content(text, media_urls)
                        if content_threats["text_threats"] or content_threats["image_threats"]:
                            suspicious_tweets.append({
                                "tweet_id": getattr(tweet, 'id', str(tweet)),
                                "text": text[:100] + "..." if len(text) > 100 else text,
                                "threats": content_threats
                            })
                    
                    # PII detection
                    if self.enable_pii_detection:
                        pii_matches = self.scan_for_pii(text)
                        if any(pii_matches.values()):
                            pii_tweets.append({
                                "tweet_id": getattr(tweet, 'id', str(tweet)),
                                "text": text[:100] + "..." if len(text) > 100 else text,
                                "pii_matches": pii_matches
                            })
                
                if suspicious_tweets:
                    risks.append("suspicious_content_in_tweets")
                    details["suspicious_content_in_tweets"] = suspicious_tweets
                
                if pii_tweets:
                    risks.append("pii_detected_in_tweets")
                    details["pii_detected_in_tweets"] = pii_tweets
                    
            except Exception as e:
                # If we can't scan tweets, continue without it
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
        """Check if currently logged in to Twitter"""
        try:
            if self.client:
                me = self.client.get_me()
                if not me or not hasattr(me, 'data') or not me.data:
                    return False
            elif self.api:
                self.api.verify_credentials()
            else:
                return False
            return True
        except Exception:
            return False

    def get_recent_tweets(self, count: int = 10) -> List:
        """Get recent tweets from the user (for content scanning).
        
        Returns:
            List of tweet objects
        """
        if not self._is_logged_in():
            raise RuntimeError("Not logged in. Call login() first.")
        
        if self.client:
            # v2 API
            user_response = self.client.get_user(username=self.username)
            user_id = None
            if user_response and hasattr(user_response, 'data') and user_response.data:
                user_id = user_response.data.id
            if user_id:
                tweets_response = self.client.get_users_tweets(
                    id=user_id,
                    max_results=count,
                    tweet_fields=['text']
                )
                return tweets_response.data if tweets_response and hasattr(tweets_response, 'data') else []
            else:
                return []
        elif self.api:
            # v1.1 API
            return self.api.user_timeline(screen_name=self.username, count=count, tweet_mode='extended')
        else:
            return []