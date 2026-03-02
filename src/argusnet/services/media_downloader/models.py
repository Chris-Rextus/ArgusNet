"""
Base models for media downloader
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any


class BasePlatformDownloader(ABC):
    """Base class for platform-specific downloaders"""
    
    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Name of the platform (e.g., 'Instagram', 'YouTube')"""
        pass
    
    @abstractmethod
    def download(self, url: str, download_dir: Path, **kwargs) -> Dict[str, Any]:
        """
        Download media from the given URL
        
        Returns:
            Dict with keys: 'success', 'file_paths', 'error_message'
        """
        pass
    
    @abstractmethod
    def validate_url(self, url: str) -> bool:
        """Check if URL is valid for this platform"""
        pass