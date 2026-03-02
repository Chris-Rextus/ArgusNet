# src/services/media_downloader/common/utils.py

"""
Common utilities for media downloader
"""

import os
import re
from pathlib import Path
from typing import Optional
from datetime import datetime


def sanitize_filename(filename: str) -> str:
    """Remove invalid characters from filename"""
    # Replace invalid characters with underscore
    invalid_chars = r'[<>:"/\\|?*]'
    return re.sub(invalid_chars, '_', filename)


def create_download_directory(base_dir: Optional[Path] = None) -> Path:
    """Create and return download directory"""
    if base_dir is None:
        base_dir = Path.home() / "Downloads" / "ArgusNet_Media"
    
    # Create timestamped subdirectory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    download_dir = base_dir / f"download_{timestamp}"
    
    # Create directory if it doesn't exist
    download_dir.mkdir(parents=True, exist_ok=True)
    
    return download_dir


def get_file_extension(url: str, content_type: Optional[str] = None) -> str:
    """Determine file extension from URL or content type"""
    # Try to get extension from URL
    url_path = url.split('?')[0]  # Remove query parameters
    if '.' in url_path:
        ext = url_path.split('.')[-1].lower()
        if ext in ['jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov', 'avi']:
            return ext
    
    # Fallback based on content type
    if content_type:
        content_map = {
            'image/jpeg': 'jpg',
            'image/jpg': 'jpg',
            'image/png': 'png',
            'image/gif': 'gif',
            'video/mp4': 'mp4',
            'video/quicktime': 'mov',
        }
        return content_map.get(content_type, 'bin')
    
    return 'bin'