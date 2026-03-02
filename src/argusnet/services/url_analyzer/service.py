"""
ArgusNet - Advanced URL Analyzer Service

Comprehensive diagnostics including:
- DNS resolution
- Connectivity tests
- HTTP/HTTPS analysis
- TLS inspection
- WHOIS intelligence
- Security header scoring
- Reliability & performance scoring
- Risk classification
"""

import asyncio
from pprint import pprint

from argusnet.core.interfaces import BaseService
from argusnet.services.url_analyzer.layers.dns_layer.dns import DNSLayer
from argusnet.services.url_analyzer.layers.connectivity_layer.connectivity import ConnectivityLayer
from argusnet.services.url_analyzer.layers.http_layer.http import HTTPLayer
from argusnet.services.url_analyzer.layers.tls_layer.tls import TLSLayer  
from argusnet.services.url_analyzer.models import URLAnalysisReport
from argusnet.services.url_analyzer.display import URLAnalyzerInterface


class URLAnalyzerService(BaseService):

    @property
    def key(self) -> str:
        return "url"
    
    @property
    def name(key) -> str:
        return "URL Analyzer - Network Intelligence"
        
    def run(self) -> None:
        """
        CLI entrypoint for this service.
        """
        url = input("\nEnter a URL to analyze: ").strip()

        if not url:
            print("No URL provided.")
            return

        try:
            report = asyncio.run(self._analyze(url))
            URLAnalyzerInterface.render_dns(report.dns)
            URLAnalyzerInterface.render_connectivity(report.connectivity)
            URLAnalyzerInterface.render_http(report.http)
            #URLAnalyzerInterface.render_tls(report.tls)  

        except Exception as e:
            print(f"[ERROR] Analysis failed: {e}")

    async def _analyze(self, url: str) -> URLAnalysisReport:
        # 1️⃣ Initialize empty report
        report = URLAnalysisReport(url=url)

        # 2️⃣ Define pipeline
        self.pipeline = [
            DNSLayer(),
            ConnectivityLayer(),
            HTTPLayer(),
            #TLSLayer(),  
            # DomainLayer(),
            # IPIntelLayer(),
            # ScoringLayer(),
        ]

        # 3️⃣ Execute pipeline sequentially
        for layer in self.pipeline:
            report = await layer.run(report)

        # 4️⃣ Return fully enriched report
        return report


service = URLAnalyzerService()