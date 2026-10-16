"""Social media monitoring modules for social-safe"""

import os
from .base import BaseSocialMonitor, ContentScanner, PIIDetector
from .instagram import InstagramMonitor
from .twitter import TwitterMonitor

# Factory function to get monitor instance by platform name
def get_monitor(platform: str, **kwargs) -> BaseSocialMonitor:
    """Get a monitor instance for the specified platform.
    
    Args:
        platform: Platform name ('instagram', 'twitter', etc.)
        **kwargs: Arguments to pass to the monitor constructor
        
    Returns:
        BaseSocialMonitor instance for the specified platform
        
    Raises:
        ValueError: If platform is not supported
    """
    monitors = {
        'instagram': InstagramMonitor,
        'twitter': TwitterMonitor,
        # Add more platforms here as they are implemented
    }
    
    monitor_class = monitors.get(platform.lower())
    if monitor_class is None:
        raise ValueError(f"Unsupported platform: {platform}. Supported platforms: {list(monitors.keys())}")
    
    return monitor_class(**kwargs)


# Convenience function for Instagram (backward compatibility)
def monitor_instagram(*args, **kwargs):
    """Convenience function for Instagram monitoring (backward compatibility).
    
    This function maintains backward compatibility with the original interface.
    """
    monitor = InstagramMonitor(*args, **kwargs)
    password = kwargs.get('password') or os.getenv('IG_PASSWORD')
    monitor.login(password)
    changes = monitor.check_changes()
    audit_result = None
    if monitor.audit_enabled:
        audit_result = monitor.audit_account()
    
    if monitor._should_alert(changes, audit_result):
        monitor.send_alert(changes, audit_result=audit_result)
    
    return changes, audit_result


# Export all public classes and functions
__all__ = [
    'BaseSocialMonitor',
    'ContentScanner',
    'PIIDetector',
    'InstagramMonitor',
    'TwitterMonitor',
    'get_monitor',
    'monitor_instagram'
]