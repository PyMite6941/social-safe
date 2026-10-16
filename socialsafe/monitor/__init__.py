"""Instagram monitoring module for social-safe"""

import instaloader
import smtplib
import os
import json
from email.message import EmailMessage
from typing import Set, Dict
from pathlib import Path


class InstagramMonitor:
    def __init__(self, username: str, state_file: str = "ig_state.json"):
        self.username = username
        self.state_file = Path(state_file)
        self.loader = instaloader.Instaloader()
        self.state = self._load_state()
    
    def _load_state(self) -> Dict[str, Set[str]]:
        """Load previous follower/following state from file"""
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                data = json.load(f)
                return {
                    "followers": set(data.get("followers", [])),
                    "following": set(data.get("following", []))
                }
        return {"followers": set(), "following": set()}
    
    def _save_state(self):
        """Save current follower/following state to file"""
        data = {
            "followers": list(self.state["followers"]),
            "following": list(self.state["following"])
        }
        with open(self.state_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def login(self, password: str):
        """Login to Instagram"""
        self.loader.login(self.username, password)
    
    def check_changes(self) -> Dict[str, Set[str]]:
        """Check for follower/following changes"""
        profile = instaloader.Profile.from_username(
            self.loader.context, self.username
        )
        
        current_followers = {f.username for f in profile.get_followers()}
        current_following = {f.username for f in profile.get_followings()}
        
        changes = {
            "new_followers": current_followers - self.state["followers"],
            "lost_followers": self.state["followers"] - current_followers,
            "new_following": current_following - self.state["following"],
            "lost_following": self.state["following"] - current_following
        }
        
        # Update state
        self.state["followers"] = current_followers
        self.state["following"] = current_following
        self._save_state()
        
        return changes
    
    def send_alert(self, changes: Dict[str, Set[str]], email_to: str, 
                   email_from: str, smtp_server: str = "smtp.gmail.com",
                   smtp_port: int = 465, smtp_user: str = None, 
                   smtp_password: str = None):
        """Send email alert about changes"""
        # Only send if there are changes
        if not any(changes.values()):
            return
        
        body_lines = []
        if changes["new_followers"]:
            body_lines.append(f"New followers: {', '.join(changes['new_followers'])}")
        if changes["lost_followers"]:
            body_lines.append(f"Lost followers: {', '.join(changes['lost_followers'])}")
        if changes["new_following"]:
            body_lines.append(f"Now following: {', '.join(changes['new_following'])}")
        if changes["lost_following"]:
            body_lines.append(f"Unfollowed: {', '.join(changes['lost_following'])}")
        
        body = "\n".join(body_lines)
        
        msg = EmailMessage()
        msg["Subject"] = "Instagram Activity Alert"
        msg["From"] = email_from
        msg["To"] = email_to
        msg.set_content(body)
        
        smtp_user = smtp_user or email_from
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(smtp_user, smtp_password)
            server.send_message(msg)


def monitor_instagram(username: str, password: str, 
                     alert_email: str, state_file: str = "ig_state.json"):
    """Simple function to monitor Instagram and alert on changes"""
    monitor = InstagramMonitor(username, state_file)
    monitor.login(password)
    changes = monitor.check_changes()
    
    if any(changes.values()):
        monitor.send_alert(
            changes, 
            email_to=alert_email,
            email_from=alert_email,  # Using same for simplicity
            smtp_user=alert_email,
            smtp_password=os.getenv("ALERT_APP_PASSWORD")  # App-specific password
        )
    return changes