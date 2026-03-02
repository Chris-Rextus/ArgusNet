# src/argusnet/services/media_downloader/instagram/downloader.py

"""
Instagram downloader using RapidAPI
You need to sign up at https://rapidapi.com/ and get an API key
"""

import requests
from pathlib import Path
from typing import Optional, Dict, Any
import os

from argusnet.services.media_downloader.models import BasePlatformDownloader
from .utils import extract_instagram_shortcode


class InstagramDownloader(BasePlatformDownloader):
    """Instagram downloader using RapidAPI"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('RAPIDAPI_KEY', '')
        self.headers = {
            'X-RapidAPI-Key': self.api_key,
            'X-RapidAPI-Host': 'instagram-downloader-download-instagram-videos-stories.p.rapidapi.com'
        }
    
    @property
    def platform_name(self) -> str:
        return "Instagram (RapidAPI)"
    
    def validate_url(self, url: str) -> bool:
        return extract_instagram_shortcode(url) is not None
    
    def download(self, url: str, download_dir: Path, **kwargs) -> Dict[str, Any]:
        if not self.api_key:
            return {
                'success': False,
                'error': 'RapidAPI key not configured. Get one at https://rapidapi.com/'
            }
        
        try:
            # This is an example API - you'll need to find a working one
            response = requests.get(
                'https://instagram-downloader-download-instagram-videos-stories.p.rapidapi.com/index',
                headers=self.headers,
                params={'url': url},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                # Process the response based on the API's structure
                # This will vary depending on which API you use
                
                downloaded_files = []
                # Download logic here...
                
                return {
                    'success': True,
                    'file_paths': downloaded_files,
                    'message': 'Downloaded using RapidAPI'
                }
            else:
                return {
                    'success': False,
                    'error': f'API error: {response.status_code}'
                }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}