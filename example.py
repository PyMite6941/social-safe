#!/usr/bin/env python3
"""
Example usage of the social-safe package for Instagram monitoring
"""

import os
from socialsafe.monitor import monitor_instagram

def main():
    # Example - in practice, get these from environment variables or secure storage
    username = os.getenv("IG_USERNAME", "your_instagram_handle")
    password = os.getenv("IG_PASSWORD")  # App-specific password recommended
    alert_email = os.getenv("ALERT_EMAIL", "your_alert@example.com")
    
    if not password:
        print("Error: IG_PASSWORD environment variable not set")
        print("Set it to your Instagram app-specific password")
        return 1
    
    print(f"Monitoring Instagram account: {username}")
    print(f"Alerts will be sent to: {alert_email}")
    
    try:
        changes = monitor_instagram(
            username=username,
            password=password,
            alert_email=alert_email
        )
        
        # Check if there are any changes worth reporting
        has_changes = False
        for change_type, value in changes.items():
            if change_type == "privacy_changed":
                if value:  # True means privacy changed
                    has_changes = True
                    print(f"  {change_type}: {value} (expected privacy setting changed)")
            else:  # It's a set of strings
                if value:  # non-empty set
                    has_changes = True
                    print(f"  {change_type}: {len(value)} accounts")
        
        if has_changes:
            print("Changes detected and alert sent!")
        else:
            print("No changes detected since last check")
            
    except Exception as e:
        print(f"Error during monitoring: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())