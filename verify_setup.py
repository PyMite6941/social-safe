#!/usr/bin/env python3
"""
Verification script for social-safe custom platform setup.
"""

import os
import sys

def main():
    print("Verifying social-safe setup for custom platforms...")
    print("=" * 60)
    
    # Check that we can import the base classes
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'socialsafe'))
        from socialsafe.monitor.base import BaseSocialMonitor
        from socialsafe.monitor.playwright_base import BasePlaywrightMonitor
        print("✓ Base classes imported successfully")
    except Exception as e:
        print(f"✗ Failed to import base classes: {e}")
        return False
    
    # Check that we can import existing platform monitors
    try:
        from socialsafe.monitor import (
            InstagramMonitor, 
            TwitterMonitor, 
            RedditMonitor, 
            LinkedInMonitor,
            get_monitor
        )
        print("✓ Existing platform monitors imported successfully")
        
        # Test the factory function
        try:
            monitor = get_monitor('instagram')
            print(f"✓ Factory function works: {type(monitor).__name__}")
        except Exception as e:
            # Expected to fail without credentials, but should not be an import error
            if "must be set" in str(e):
                print("✓ Factory function works (credential error expected)")
            else:
                print(f"✗ Unexpected error from factory: {e}")
                return False
                
    except Exception as e:
        print(f"✗ Failed to import platform monitors: {e}")
        return False
    
    # Check that the setup script exists and is readable
    setup_script = os.path.join(os.path.dirname(__file__), 'setup_custom_platform.py')
    if os.path.exists(setup_script):
        print("✓ Custom platform setup script exists")
    else:
        print("✗ Custom platform setup script missing")
        return False
    
    # Show what files were created/modified
    print("\nFiles created or modified for custom platform support:")
    print("- socialsafe/monitor/linkedin.py (LinkedIn monitor using Playwright)")
    print("- socialsafe/monitor/playwright_base.py (Base class for web automation monitors)")
    print("- socialsafe/monitor/__init__.py (Updated to include LinkedIn and export base classes)")
    print("- setup.py (Updated to include playwright dependency)")
    print("- index.html (Updated documentation showing LinkedIn as supported)")
    print("- setup_custom_platform.py (This verification script and tutorial)")
    
    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print("social-safe now supports:")
    print("  ✓ Instagram (official API)")
    print("  ✓ Twitter/X (official API)")
    print("  ✓ Reddit (official API)")
    print("  ✓ LinkedIn (Playwright web automation)")
    print("  ✓ Easy extensibility for custom platforms")
    print()
    print("To add a custom platform:")
    print("  1. Inherit from BaseSocialMonitor (for API-based platforms)")
    print("  2. Inherit from BasePlaywrightMonitor (for web automation)")
    print("  3. Add your monitor to the monitors dict in socialsafe/monitor/__init__.py")
    print("  4. Set up appropriate environment variables for credentials")
    print()
    print("See setup_custom_platform.py for detailed examples.")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)