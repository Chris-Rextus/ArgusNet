"""
Media Downloader Service for ArgusNet
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

from argusnet.core.interfaces import BaseService
from .models import BasePlatformDownloader
from .platforms.instagram import InstagramDownloader


class MediaDownloaderService(BaseService):
    """Main service for downloading media from various platforms"""
    
    @property
    def key(self) -> str:
        return "dl"
    
    @property
    def name(self) -> str:
        return "Media Downloader"
    
    def __init__(self):
        self.platforms: Dict[str, BasePlatformDownloader] = {
            'instagram': InstagramDownloader(),
        }
    
    def _create_download_directory(self) -> Path:
        """Create a timestamped download directory"""
        base_dir = Path.home() / "ArgusNet_Downloads"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        download_dir = base_dir / f"download_{timestamp}"
        download_dir.mkdir(parents=True, exist_ok=True)
        return download_dir
    
    def _detect_platform(self, url: str) -> Optional[BasePlatformDownloader]:
        """Detect which platform downloader to use"""
        for downloader in self.platforms.values():
            if downloader.validate_url(url):
                return downloader
        return None
    
    def _print_menu(self) -> None:
        """Display the service menu"""
        print("\n" + "=" * 50)
        print("MEDIA DOWNLOADER")
        print("=" * 50)
        print("\nAvailable Platforms:")
        for name in self.platforms.keys():
            print(f"  • {name.capitalize()}")
        print("\nCommands:")
        print("  • Enter URL to download")
        print("  • 'back' - Return to main menu")
        print()
    
    def run(self) -> None:
        """Main service execution loop"""
        while True:
            self._print_menu()
            
            url = input("URL to download: ").strip()
            
            if url.lower() in ['back', 'exit', 'quit']:
                break
            
            if not url:
                print("❌ Please enter a URL")
                continue
            
            # Detect platform
            downloader = self._detect_platform(url)
            
            if not downloader:
                print("\n❌ Unsupported platform or invalid URL")
                print("Currently supported: Instagram")
                continue
            
            # Create download directory
            download_dir = self._create_download_directory()
            print(f"\n📁 Download directory: {download_dir}")
            print(f"📥 Downloading from {downloader.platform_name}...")
            
            try:
                # Perform download
                result = downloader.download(url, download_dir)
                
                if result['success']:
                    print(f"\n✅ Download successful!")
                    
                    if result.get('file_paths'):
                        print("\nFiles downloaded:")
                        for path in result['file_paths']:
                            filename = Path(path).name
                            print(f"  • {filename}")
                    
                    if result.get('message'):
                        print(f"\n{result['message']}")
                else:
                    print(f"\n❌ Download failed: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"\n❌ Error during download: {str(e)}")
            
            input("\nPress Enter to continue...")


# Service instance for automatic registration
service = MediaDownloaderService()