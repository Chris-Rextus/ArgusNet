# src/argusnet/services/media_downloader/instagram/utils.py

"""
Instagram-specific utilities
"""

import re
from typing import Optional, Tuple


def extract_instagram_shortcode(url: str) -> Optional[str]:
    """
    Extract shortcode from Instagram URL
    
    Handles:
    - https://www.instagram.com/p/ABC123/
    - https://www.instagram.com/reel/ABC123/
    - https://www.instagram.com/stories/username/ABC123/
    """
    patterns = [
        r'instagram\.com/p/([^/?]+)',      # Posts
        r'instagram\.com/reel/([^/?]+)',    # Reels
        r'instagram\.com/stories/[^/]+/([^/?]+)',  # Stories
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    
    return None


def is_instagram_story(url: str) -> bool:
    """Check if URL is an Instagram story"""
    return '/stories/' in url


def is_instagram_reel(url: str) -> bool:
    """Check if URL is an Instagram reel"""
    return '/reel/' in url