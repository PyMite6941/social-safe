#!/usr/bin/env python3
"""
Demo script showing how social-safe connects to Instagram (via Instaloader)
Illustrates the authentication and data access mechanism for monitoring
"""

import os
import instaloader
from instaloader.exceptions import BadCredentialsException, ConnectionException

def demo_instagram_connection():
    """Demonstrate Instagram connection and basic data access"""
    # Get credentials from environment (never hard-coded)
    username = os.getenv("IG_USERNAME")
    password = os.getenv("IG_PASSWORD")
    
    if not username or not password:
        print("❌ Error: Set IG_USERNAME and IG_PASSWORD environment variables")
        print("   Example: export IG_USERNAME='your_handle'")
        print("            export IG_PASSWORD='your_app_specific_password'")
        return False
    
    print(f"🔌 Connecting to Instagram as @{username}...")
    L = instaloader.Instaloader()
    
    try:
        # Attempt login (this is the actual platform connection)
        L.login(username, password)
        print("✅ Successfully connected to Instagram!")
        
        # Prove connection by accessing public profile data
        profile = instaloader.Profile.from_username(L.context, username)
        print(f"\n📊 Profile Info (verified via API):")
        print(f"   Full Name: {profile.full_name}")
        print(f"   Followers: {profile.followers:,}")
        print(f"   Following: {profile.follows:,}")
        print(f"   Posts: {profile.mediacount:,}")
        print(f"   Private Account: {profile.is_private}")
        
        # Show what we can monitor (the core privacy protection feature)
        print(f"\n🔍 Monitoring Capabilities Enabled:")
        print(f"   • Track follower/following changes")
        print(f"   • Detect new/unexpected followers")
        print(f"   • Monitor for mass unfollows (possible targeting)")
        print(f"   • Alert via email/Telegram on anomalies")
        
        # Note: We cannot hide followers/following lists from approved followers
        # (platform limitation), but we can alert when those lists change
        print(f"\n⚠️  Important Platform Limitation:")
        print(f"   Even with a private account, your approved followers")
        print(f"   can still see your full followers/following lists.")
        print(f"   This tool helps by alerting you to *changes* in those lists.")
        
        return True
        
    except BadCredentialsException:
        print("❌ Login failed: Invalid username or password")
        print("   💡 Tip: Use an app-specific password (Instagram Settings → Security)")
        return False
    except ConnectionException:
        print("❌ Network error: Check internet connection")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = demo_instagram_connection()
    exit(0 if success else 1)