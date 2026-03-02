# src/argusnet/services/url_analyzer/layers/http_layer/http.py

"""
HTTP Intelligence Layer
Comprehensive HTTP analysis including protocol detection, security headers,
technology fingerprinting, endpoint discovery, and vulnerability assessment.
"""

import time
import asyncio
import aiohttp
import re
import hashlib
from urllib.parse import urlparse, urljoin
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from bs4 import BeautifulSoup

from argusnet.services.url_analyzer.layers.baselayer import BaseLayer
from .models import (
    HTTPIntelligence,
    ProtocolSupport,
    VirtualHost,
    HTTPMethodTest,
    MethodAnalysis,
    RedirectHop,
    RedirectChain,
    DiscoveredPath,
    ParameterTest,
    ParameterAnalysis,
    EndpointDiscovery,
    WebServerInfo,
    FrameworkInfo,
    CMSInfo,
    JSLibrary,
    TechnologyStack,
    HSTSAnalysis,
    CSPAnalysis,
    CookieAnalysis,
    CORSAnalysis,
    SecurityHeaders,
    MetaTag,
    FormField,
    FormAnalysis,
    LinkAnalysis,
    RobotsTxt,
    SitemapXml,
    ContentAnalysis,
    InformationDisclosure,
    ConfigurationIssue,
    TLSIssues,
    WAFDetection,
    VulnerabilityIndicators,
    RESTEndpoint,
    GraphQLInfo,
    WebSocketInfo,
    SPAInfo,
    ModernWebFeatures,
    RateLimitingInfo,
    LoadBalancerStickiness,
    ABTestingInfo,
    BotDetectionInfo,
    BehavioralPatterns,
    ResponseTimeMetrics,
    CachingAnalysis,
    CompressionAnalysis,
    KeepAliveAnalysis,
    PerformanceMetrics,
    RiskScores,
    Recommendation,
)


# ===============================
# CONFIGURATION
# ===============================

COMMON_PATHS = [
    # Admin interfaces
    "admin", "administrator", "admin.php", "admin/", "wp-admin", "wp-admin/",
    "cpanel", "webmail", "phpmyadmin", "phpPgAdmin", "adminer",
    
    # API endpoints
    "api", "api/", "api/v1", "api/v2", "api/v3", "rest", "rest/",
    "graphql", "graphiql", "swagger", "swagger-ui", "docs", "api-docs",
    
    # Sensitive files
    ".env", ".git/config", ".git/HEAD", ".svn/entries", ".svn/wc.db",
    "backup.sql", "database.sql", "dump.sql", "db.sql", "backup.tar.gz",
    "phpinfo.php", "info.php", "test.php", "phpinfo", "info",
    
    # Configuration files
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "sitemap",
    "web.config", ".htaccess", "nginx.conf", "httpd.conf",
    "config.php", "configuration.php", "settings.php", "wp-config.php",
    
    # Common directories
    "backup", "backups", "temp", "tmp", "log", "logs", "debug",
    "uploads", "downloads", "files", "media", "assets", "static",
    
    # Cloud metadata
    "latest/meta-data/", "metadata/v1/", "v1/", "metadata/",
    "meta-data/", "user-data", "meta-data/iam/security-credentials/",
]

PARAMETERS_TO_TEST = [
    "id", "page", "user", "admin", "debug", "test", "error",
    "redirect", "url", "next", "return", "return_to", "returnUrl",
    "file", "document", "folder", "root", "path", "document",
    "cmd", "command", "exec", "execute", "run",
    "sql", "query", "db", "database",
    "search", "q", "query", "s",
]

COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "PATCH", "CONNECT"]


class HTTPLayer(BaseLayer):
    """
    Comprehensive HTTP Intelligence Layer
    Aggressive but safe HTTP analysis including protocol detection,
    security headers, technology fingerprinting, and endpoint discovery.
    """

    name = "HTTP Intelligence Layer"

    def __init__(self):
        super().__init__()
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_read=5)
        self.connector = aiohttp.TCPConnector(
            limit=50,
            ttl_dns_cache=300,
            ssl=False,
            force_close=True,
            enable_cleanup_closed=True
        )

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=self.timeout,
                headers={"User-Agent": COMMON_USER_AGENTS[0]}
            )
        return self.session

    async def run(self, report):
        """Main execution entry point"""
        
        # Extract hostname from URL
        parsed = urlparse(report.url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        protocol = parsed.scheme

        if not hostname:
            report.http = None
            return report

        start = time.perf_counter()

        # Initialize HTTP intelligence object
        intel = HTTPIntelligence(
            url=report.url,
            hostname=hostname,
            port=port,
            protocol=protocol,
            analyzed_at=datetime.utcnow()
        )

        self.logger.info(f"[*] Starting HTTP intelligence gathering for {hostname}")

        try:
            # =========================
            # PHASE 1: PROTOCOL & TRANSPORT DETECTION
            # =========================
            await self._phase1_protocol_detection(intel, hostname, port)
            
            # =========================
            # PHASE 2: REDIRECT CHAIN ANALYSIS
            # =========================
            await self._phase2_redirect_analysis(intel, hostname, port)
            
            # =========================
            # PHASE 3: VIRTUAL HOST DISCOVERY
            # =========================
            await self._phase3_virtual_host_discovery(intel, hostname, port)
            
            # =========================
            # PHASE 4: HTTP METHOD TESTING
            # =========================
            await self._phase4_method_testing(intel, hostname, port)
            
            # =========================
            # PHASE 5: ENDPOINT DISCOVERY
            # =========================
            await self._phase5_endpoint_discovery(intel, hostname, port)
            
            # =========================
            # PHASE 6: TECHNOLOGY STACK FINGERPRINTING
            # =========================
            await self._phase6_technology_fingerprinting(intel, hostname, port)
            
            # =========================
            # PHASE 7: SECURITY HEADER ANALYSIS
            # =========================
            await self._phase7_security_header_analysis(intel, hostname, port)
            
            # =========================
            # PHASE 8: CONTENT ANALYSIS
            # =========================
            await self._phase8_content_analysis(intel, hostname, port)
            
            # =========================
            # PHASE 9: VULNERABILITY INDICATORS
            # =========================
            await self._phase9_vulnerability_indicators(intel, hostname, port)
            
            # =========================
            # PHASE 10: MODERN WEB DETECTION
            # =========================
            await self._phase10_modern_web_detection(intel, hostname, port)
            
            # =========================
            # PHASE 11: BEHAVIORAL PATTERNS
            # =========================
            await self._phase11_behavioral_patterns(intel, hostname, port)
            
            # =========================
            # PHASE 12: PERFORMANCE METRICS
            # =========================
            await self._phase12_performance_metrics(intel, hostname, port)
            
            # =========================
            # FINALIZE: RISK SCORING & RECOMMENDATIONS
            # =========================
            intel.calculate_risk_scores()
            intel.generate_recommendations()

        except Exception as e:
            self.logger.error(f"[-] HTTP analysis failed: {str(e)}")
            intel.errors.append(f"Analysis error: {str(e)}")

        finally:
            if self.session:
                await self.session.close()
                self.session = None

        end = time.perf_counter()
        intel.analysis_duration_ms = round((end - start) * 1000, 2)
        report.http = intel

        self.logger.info(f"[+] HTTP analysis complete - Duration: {intel.analysis_duration_ms}ms")
        return report

    # ===============================
    # PHASE 1: PROTOCOL & TRANSPORT DETECTION
    # ===============================

    async def _phase1_protocol_detection(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Detect supported HTTP protocols and features"""
        
        self.logger.debug("[Phase 1] Detecting protocol support")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        try:
            # Test HTTP/1.1
            async with session.get(base_url, allow_redirects=False) as response:
                intel.protocol_support.http_1_1 = True
                
                # Check for upgrade headers
                if response.headers.get('upgrade', '').lower() == 'websocket':
                    intel.protocol_support.websocket_supported = True
                
                if response.headers.get('connection', '').lower() == 'upgrade':
                    intel.protocol_support.upgrade_required = True
            
            # Test HTTP/2 via ALPN (requires specialized client)
            # Simplified check - look for HTTP/2 indicators
            try:
                async with session.get(base_url, headers={"Accept": "*/*"}) as response:
                    if response.version == (2, 0):
                        intel.protocol_support.http_2 = True
                    if 'cf-http2' in response.headers.get('via', '').lower():
                        intel.protocol_support.http_2 = True
            except:
                pass
            
            # Check for HTTP/2 push
            if intel.protocol_support.http_2:
                # Simplified check - look for push headers
                try:
                    async with session.get(base_url, headers={"Accept": "*/*"}) as response:
                        if response.headers.get('x-http2-push'):
                            intel.protocol_support.http_2_push_supported = True
                except:
                    pass
            
            # ALPN protocols (would need SSL context inspection)
            # This is a placeholder - actual ALPN detection requires SSL socket
            if intel.protocol == "https":
                intel.protocol_support.alpn_protocols = ["http/1.1"]
                if intel.protocol_support.http_2:
                    intel.protocol_support.alpn_protocols.append("h2")
                    
        except Exception as e:
            self.logger.debug(f"Protocol detection failed: {str(e)}")

    # ===============================
    # PHASE 2: REDIRECT CHAIN ANALYSIS
    # ===============================

    async def _phase2_redirect_analysis(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Follow and analyze redirect chain"""
        
        self.logger.debug("[Phase 2] Analyzing redirect chain")
        
        session = await self._ensure_session()
        current_url = f"{intel.protocol}://{hostname}:{port}/"
        hops = []
        visited = set()
        redirect_count = 0
        max_redirects = 20
        
        while redirect_count < max_redirects and current_url not in visited:
            visited.add(current_url)
            
            try:
                async with session.get(current_url, allow_redirects=False) as response:
                    status = response.status
                    
                    # Check if this is a redirect
                    if status in [301, 302, 303, 307, 308]:
                        location = response.headers.get('location')
                        if location:
                            # Construct absolute URL
                            next_url = urljoin(current_url, location)
                            
                            hop = RedirectHop(
                                url=current_url,
                                status_code=status,
                                headers=dict(response.headers)
                            )
                            
                            # Check for meta redirect in HTML
                            if response.headers.get('content-type', '').startswith('text/html'):
                                try:
                                    html = await response.text()
                                    soup = BeautifulSoup(html, 'html.parser')
                                    meta = soup.find('meta', attrs={'http-equiv': 'refresh'})
                                    if meta and meta.get('content'):
                                        hop.is_meta_redirect = True
                                except:
                                    pass
                            
                            hops.append(hop)
                            current_url = next_url
                            redirect_count += 1
                            continue
                    
                    # Not a redirect - final response
                    intel.redirect_chain.hops = hops
                    intel.redirect_chain.final_url = current_url
                    intel.redirect_chain.final_status_code = status
                    intel.redirect_chain.redirect_count = redirect_count
                    
                    # Check HTTPS enforcement
                    if current_url.startswith('https') and intel.protocol == 'http':
                        intel.redirect_chain.enforces_https = True
                    
                    # Check HSTS
                    if response.headers.get('strict-transport-security'):
                        intel.redirect_chain.hsts_enforced = True
                    
                    break
                    
            except Exception as e:
                self.logger.debug(f"Redirect chain error: {str(e)}")
                break
        
        if redirect_count >= max_redirects:
            intel.redirect_chain.redirect_loop_detected = True

    # ===============================
    # PHASE 3: VIRTUAL HOST DISCOVERY
    # ===============================

    async def _phase3_virtual_host_discovery(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Test different Host headers to discover virtual hosts"""
        
        self.logger.debug("[Phase 3] Discovering virtual hosts")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        # Get baseline response
        try:
            async with session.get(base_url) as baseline:
                baseline_status = baseline.status
                baseline_content = await baseline.text()
                baseline_length = len(baseline_content)
                baseline_title = self._extract_title(baseline_content)
        except:
            return
        
        # Test variations
        test_hosts = [
            f"www.{hostname}",
            f"admin.{hostname}",
            f"mail.{hostname}",
            hostname.replace('.', '-'),
            hostname.split('.')[0],
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
        ]
        
        for test_host in test_hosts[:5]:  # Limit to 5 to avoid excessive requests
            try:
                headers = {"Host": test_host}
                async with session.get(base_url, headers=headers) as response:
                    content = await response.text()
                    content_length = len(content)
                    title = self._extract_title(content)
                    
                    vhost = VirtualHost(
                        host_header=test_host,
                        status_code=response.status,
                        content_length=content_length,
                        title=title,
                        different_content=(
                            response.status != baseline_status or
                            abs(content_length - baseline_length) > 100 or
                            title != baseline_title
                        )
                    )
                    
                    if vhost.different_content:
                        vhost.vhost_detected = True
                    
                    intel.virtual_hosts.append(vhost)
                    
            except Exception:
                continue

    # ===============================
    # PHASE 4: HTTP METHOD TESTING
    # ===============================

    async def _phase4_method_testing(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Test supported HTTP methods and check for vulnerabilities"""
        
        self.logger.debug("[Phase 4] Testing HTTP methods")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}/"
        
        # First get allowed methods via OPTIONS
        try:
            async with session.options(base_url) as response:
                allow_header = response.headers.get('allow', '')
                if allow_header:
                    intel.method_analysis.options = [m.strip() for m in allow_header.split(',')]
        except:
            pass
        
        # Test each method
        for method in HTTP_METHODS:
            try:
                async with session.request(method, base_url, allow_redirects=False) as response:
                    method_test = HTTPMethodTest(
                        method=method,
                        allowed=response.status not in [405, 501],
                        status_code=response.status
                    )
                    
                    # Check for TRACE vulnerability
                    if method == "TRACE" and method_test.allowed:
                        if response.headers.get('content-type', '').startswith('message/http'):
                            method_test.trace_vulnerable = True
                            intel.method_analysis.trace_vulnerable = True
                    
                    intel.method_analysis.method_tests.append(method_test)
                    
                    # Track unsafe methods
                    if method in ["PUT", "DELETE", "TRACE"] and method_test.allowed:
                        intel.method_analysis.unsafe_methods_allowed.append(method)
                        
            except Exception:
                continue
        
        # Set individual flags for convenience
        for test in intel.method_analysis.method_tests:
            if test.method == "TRACE" and test.allowed:
                intel.method_analysis.trace_enabled = True
            elif test.method == "PUT" and test.allowed:
                intel.method_analysis.put_enabled = True
            elif test.method == "DELETE" and test.allowed:
                intel.method_analysis.delete_enabled = True
            elif test.method == "PATCH" and test.allowed:
                intel.method_analysis.patch_enabled = True

    # ===============================
    # PHASE 5: ENDPOINT DISCOVERY
    # ===============================

    async def _phase5_endpoint_discovery(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Discover endpoints via brute force and parsing"""
        
        self.logger.debug("[Phase 5] Discovering endpoints")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        # First check robots.txt and sitemap.xml
        await self._check_robots_and_sitemap(intel, base_url)
        
        # Path brute force
        await self._bruteforce_paths(intel, base_url)
        
        # Parameter fuzzing
        await self._fuzz_parameters(intel, base_url)

    async def _check_robots_and_sitemap(self, intel: HTTPIntelligence, base_url: str):
        """Check robots.txt and sitemap.xml for endpoints"""
        
        session = await self._ensure_session()
        
        # robots.txt
        try:
            async with session.get(f"{base_url}/robots.txt") as response:
                if response.status == 200:
                    content = await response.text()
                    robots = RobotsTxt(present=True, content=content)
                    
                    # Parse robots.txt
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.lower().startswith('disallow:'):
                            path = line[9:].strip()
                            if path:
                                robots.disallowed_paths.append(path)
                        elif line.lower().startswith('allow:'):
                            path = line[6:].strip()
                            if path:
                                robots.allowed_paths.append(path)
                        elif line.lower().startswith('sitemap:'):
                            sitemap = line[8:].strip()
                            robots.sitemaps.append(sitemap)
                        elif line.lower().startswith('crawl-delay:'):
                            try:
                                robots.crawl_delay = float(line[12:].strip())
                            except:
                                pass
                    
                    intel.content_analysis.robots_txt = robots
        except:
            pass
        
        # sitemap.xml
        try:
            async with session.get(f"{base_url}/sitemap.xml") as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'xml')
                    
                    sitemap = SitemapXml(present=True)
                    
                    # Check if it's a sitemap index
                    if soup.find('sitemapindex'):
                        sitemap.is_sitemap_index = True
                        for loc in soup.find_all('loc'):
                            sitemap.urls.append(loc.text)
                    else:
                        for loc in soup.find_all('loc'):
                            sitemap.urls.append(loc.text)
                    
                    sitemap.url_count = len(sitemap.urls)
                    
                    # Add discovered URLs to paths
                    for url in sitemap.urls:
                        parsed = urlparse(url)
                        if parsed.path:
                            path = DiscoveredPath(
                                path=parsed.path,
                                discovery_method="sitemap"
                            )
                            intel.endpoint_discovery.paths_discovered.append(path)
                    
                    intel.content_analysis.sitemap_xml = sitemap
        except:
            pass

    async def _bruteforce_paths(self, intel: HTTPIntelligence, base_url: str):
        """Brute force common paths"""
        
        session = await self._ensure_session()
        
        for path in COMMON_PATHS:
            try:
                url = f"{base_url}/{path}"
                async with session.get(url, allow_redirects=False) as response:
                    if response.status < 400 or response.status in [401, 403]:
                        discovered = DiscoveredPath(
                            path=f"/{path}",
                            status_code=response.status,
                            content_type=response.headers.get('content-type'),
                            content_length=int(response.headers.get('content-length', 0)),
                            discovery_method="bruteforce",
                            requires_auth=response.status in [401, 403]
                        )
                        
                        # Try to get title
                        if response.headers.get('content-type', '').startswith('text/html'):
                            try:
                                html = await response.text()
                                title = self._extract_title(html)
                                if title:
                                    discovered.title = title
                            except:
                                pass
                        
                        # Categorize
                        if '/api/' in path or path.startswith('api'):
                            discovered.is_api_endpoint = True
                            intel.endpoint_discovery.api_endpoints.append(f"/{path}")
                        
                        if any(x in path for x in ['.git', '.svn', '.env', 'backup', 'sql']):
                            intel.endpoint_discovery.sensitive_files.append(discovered)
                        
                        if any(x in path for x in ['config', '.htaccess', 'web.config']):
                            intel.endpoint_discovery.config_files.append(discovered)
                        
                        if any(x in path for x in ['admin', 'administrator', 'cpanel']):
                            intel.endpoint_discovery.admin_interfaces.append(discovered)
                        
                        if 'metadata' in path or 'latest/meta-data' in path:
                            intel.endpoint_discovery.cloud_metadata_endpoints.append(discovered)
                        
                        intel.endpoint_discovery.paths_discovered.append(discovered)
                        
            except Exception:
                continue

    async def _fuzz_parameters(self, intel: HTTPIntelligence, base_url: str):
        """Fuzz common parameters to detect reflections"""
        
        session = await self._ensure_session()
        
        for param in PARAMETERS_TO_TEST[:10]:  # Limit to first 10 to avoid excessive requests
            test_value = f"test_{param}_123"
            url = f"{base_url}/?{param}={test_value}"
            
            try:
                async with session.get(url) as response:
                    content = await response.text()
                    
                    param_test = ParameterTest(
                        parameter=param,
                        value=test_value
                    )
                    
                    # Check for reflection
                    if test_value in content:
                        param_test.reflected = True
                        param_test.reflected_in_body = True
                        intel.endpoint_discovery.parameter_analysis.xss_reflection_points += 1
                    
                    # Check for open redirect
                    if response.status in [301, 302] and test_value in response.headers.get('location', ''):
                        param_test.reflected = True
                        param_test.reflected_in_headers = True
                        intel.endpoint_discovery.parameter_analysis.open_redirect_candidates.append(param)
                    
                    # Check for SQL errors
                    sql_patterns = ['sql', 'mysql', 'postgresql', 'sqlite', 'ora-', 'mysql_fetch']
                    content_lower = content.lower()
                    if any(pattern in content_lower for pattern in sql_patterns):
                        intel.endpoint_discovery.parameter_analysis.sql_error_patterns.append(param)
                        param_test.caused_error = True
                    
                    intel.endpoint_discovery.parameter_analysis.parameters_tested.append(param)
                    intel.endpoint_discovery.parameter_analysis.reflections_found.append(param_test)
                    
            except Exception:
                continue

    # ===============================
    # PHASE 6: TECHNOLOGY STACK FINGERPRINTING
    # ===============================

    async def _phase6_technology_fingerprinting(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Fingerprint web server, frameworks, CMS, and libraries"""
        
        self.logger.debug("[Phase 6] Fingerprinting technology stack")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        try:
            async with session.get(base_url) as response:
                headers = response.headers
                content = await response.text()
                
                # Web Server
                server = headers.get('server', '')
                powered_by = headers.get('x-powered-by', '')
                via = headers.get('via', '')
                
                web_server = WebServerInfo(
                    server_header=server,
                    software=self._extract_server_software(server),
                    version=self._extract_version(server),
                    via_header=via,
                    powered_by=powered_by
                )
                
                # Check case sensitivity
                web_server.case_sensitive = await self._test_case_sensitivity(base_url)
                
                # Check 404 page
                web_server.default_404_page, web_server.custom_404_detected = await self._test_404_page(base_url)
                
                intel.technology_stack.web_server = web_server
                
                # Framework Detection
                frameworks = await self._detect_frameworks(headers, content)
                intel.technology_stack.frameworks = frameworks
                
                # CMS Detection
                cms = await self._detect_cms(headers, content, base_url, intel)
                intel.technology_stack.cms = cms
                
                # JavaScript Libraries
                js_libraries = await self._detect_js_libraries(content, base_url)
                intel.technology_stack.js_libraries = js_libraries
                
                # Programming Language
                intel.technology_stack.programming_language = self._detect_programming_language(headers, content)
                
                # OS Hint
                intel.technology_stack.os_detected = self._detect_os(headers, server)
                
        except Exception as e:
            self.logger.debug(f"Technology fingerprinting failed: {str(e)}")

    def _extract_server_software(self, server: str) -> Optional[str]:
        """Extract server software from Server header"""
        server_lower = server.lower()
        if 'nginx' in server_lower:
            return 'nginx'
        elif 'apache' in server_lower:
            return 'apache'
        elif 'iis' in server_lower or 'microsoft-iis' in server_lower:
            return 'iis'
        elif 'cloudflare' in server_lower:
            return 'cloudflare'
        elif 'openresty' in server_lower:
            return 'openresty'
        elif 'caddy' in server_lower:
            return 'caddy'
        return server.split('/')[0] if server else None

    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from string"""
        version_pattern = r'(\d+\.\d+(?:\.\d+)?)'
        match = re.search(version_pattern, text)
        return match.group(1) if match else None

    async def _test_case_sensitivity(self, base_url: str) -> bool:
        """Test if server is case sensitive"""
        session = await self._ensure_session()
        try:
            # Request same path with different case
            async with session.get(f"{base_url}/index.html") as resp1:
                async with session.get(f"{base_url}/INDEX.HTML") as resp2:
                    return resp1.status != resp2.status
        except:
            return False

    async def _test_404_page(self, base_url: str) -> tuple:
        """Test if 404 page is custom or default"""
        session = await self._ensure_session()
        random_path = f"/nonexistent_{hashlib.md5(b'test').hexdigest()[:8]}.html"
        
        try:
            async with session.get(f"{base_url}{random_path}") as response:
                if response.status == 404:
                    content = await response.text()
                    # Check for common default 404 indicators
                    default_indicators = ['404 Not Found', '404 - Not Found', '404 error']
                    content_lower = content.lower()
                    
                    is_default = any(indicator.lower() in content_lower for indicator in default_indicators)
                    return is_default, not is_default
        except:
            pass
        
        return True, False

    async def _detect_frameworks(self, headers: Dict, content: str) -> List[FrameworkInfo]:
        """Detect web frameworks"""
        frameworks = []
        content_lower = content.lower()
        
        # Framework signatures
        signatures = [
            # Django
            (r'django', ['csrftoken', 'django_language'], 'Django'),
            # Flask
            (r'flask', ['flask'], 'Flask'),
            # Ruby on Rails
            (r'rails', ['csrf-param', 'csrf-token', 'rails'], 'Ruby on Rails'),
            # Laravel
            (r'laravel', ['laravel_session'], 'Laravel'),
            # Symfony
            (r'symfony', ['symfony'], 'Symfony'),
            # ASP.NET
            (r'asp\.net', ['x-aspnet-version', '__viewstate', '__eventvalidation'], 'ASP.NET'),
            # Spring
            (r'spring', ['spring'], 'Spring'),
            # Express
            (r'express', ['x-powered-by: express'], 'Express'),
            # Next.js
            (r'next\.js', ['__next', 'next-route-announcer'], 'Next.js'),
        ]
        
        for pattern, indicators, name in signatures:
            confidence = 0.0
            
            # Check headers
            for header, value in headers.items():
                header_lower = header.lower()
                value_lower = value.lower()
                
                if any(indicator.lower() in value_lower for indicator in indicators):
                    confidence += 0.4
                if re.search(pattern, header_lower) or re.search(pattern, value_lower):
                    confidence += 0.3
            
            # Check content
            for indicator in indicators:
                if indicator.lower() in content_lower:
                    confidence += 0.2
            
            if confidence > 0.3:
                framework = FrameworkInfo(
                    name=name,
                    confidence=min(confidence, 1.0),
                    evidence=[f"Matched: {indicator}" for indicator in indicators[:3]]
                )
                frameworks.append(framework)
        
        return frameworks

    async def _detect_cms(self, headers: Dict, content: str, base_url: str, intel: HTTPIntelligence) -> Optional[CMSInfo]:
        """Detect Content Management System"""
        content_lower = content.lower()
        
        # CMS signatures
        cms_signatures = {
            'WordPress': {
                'indicators': ['wp-content', 'wp-includes', 'wp-json', 'wordpress'],
                'plugins': ['wp-content/plugins/', 'wp-content/themes/'],
                'confidence': 0.0
            },
            'Drupal': {
                'indicators': ['sites/default', 'drupal', 'jquery.update'],
                'plugins': ['sites/all/modules', 'sites/all/themes'],
                'confidence': 0.0
            },
            'Joomla': {
                'indicators': ['joomla', 'com_content', 'com_contact'],
                'plugins': ['components/', 'modules/', 'templates/'],
                'confidence': 0.0
            },
            'Magento': {
                'indicators': ['magento', 'skin/frontend', 'js/mage'],
                'plugins': ['app/code/', 'app/design/'],
                'confidence': 0.0
            },
            'Shopify': {
                'indicators': ['shopify', 'cdn.shopify', 'myshopify.com'],
                'plugins': ['/products/', '/collections/'],
                'confidence': 0.0
            },
        }
        
        best_cms = None
        best_confidence = 0.0
        plugins_found = []
        
        for cms_name, signatures in cms_signatures.items():
            confidence = 0.0
            
            # Check content indicators
            for indicator in signatures['indicators']:
                if indicator in content_lower:
                    confidence += 0.3
            
            # Check headers
            if cms_name == 'WordPress' and 'x-powered-by' in headers:
                if 'wordpress' in headers['x-powered-by'].lower():
                    confidence += 0.4
            
            # Check for plugins/themes
            for plugin in signatures['plugins']:
                if plugin in content_lower:
                    confidence += 0.2
                    plugins_found.append(plugin)
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_cms = cms_name
        
        if best_cms and best_confidence > 0.3:
            cms_info = CMSInfo(
                name=best_cms,
                confidence=best_confidence,
                evidence=[f"Matched {best_cms} patterns"],
                plugins=plugins_found
            )
            return cms_info
        
        return None

    async def _detect_js_libraries(self, content: str, base_url: str) -> List[JSLibrary]:
        """Detect JavaScript libraries"""
        libraries = []
        
        # Library signatures
        js_signatures = {
            'jQuery': [r'jquery[.-](\d+\.\d+\.\d+)', r'jQuery v\d+\.\d+\.\d+'],
            'React': [r'react(?:\.min)?\.js', r'React\.createElement'],
            'Vue': [r'vue(?:\.min)?\.js', r'Vue\.js', r'new Vue\({'],
            'Angular': [r'angular(?:\.min)?\.js', r'ng-app', r'ng-controller'],
            'Bootstrap': [r'bootstrap(?:\.min)?\.js', r'bootstrap(?:\.min)?\.css'],
            'Lodash': [r'lodash(?:\.min)?\.js', r'_.\w+'],
            'Moment.js': [r'moment(?:\.min)?\.js', r'moment\(\)'],
            'D3.js': [r'd3(?:\.min)?\.js', r'd3\.\w+'],
        }
        
        for lib_name, patterns in js_signatures.items():
            confidence = 0.0
            version = None
            
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    confidence += 0.4
                    if len(match.groups()) > 0:
                        version = match.group(1)
            
            if confidence > 0.3:
                library = JSLibrary(
                    name=lib_name,
                    version=version,
                    confidence=min(confidence, 1.0)
                )
                libraries.append(library)
        
        return libraries

    def _detect_programming_language(self, headers: Dict, content: str) -> Optional[str]:
        """Detect programming language from headers and content"""
        content_lower = content.lower()
        
        language_signatures = {
            'PHP': ['php', 'x-powered-by: php'],
            'Python': ['python', 'django', 'flask', 'wsgi'],
            'Ruby': ['ruby', 'rails', 'rack'],
            'Java': ['java', 'jsp', 'servlet', 'spring'],
            'Node.js': ['node', 'express', 'javascript'],
            'Go': ['golang', 'go '],
            'C#': ['asp.net', 'iis', '.net'],
        }
        
        # Check headers
        for header, value in headers.items():
            header_lower = header.lower()
            value_lower = value.lower()
            
            for lang, sigs in language_signatures.items():
                if any(sig in header_lower or sig in value_lower for sig in sigs):
                    return lang
        
        # Check content
        for lang, sigs in language_signatures.items():
            if any(sig in content_lower for sig in sigs):
                return lang
        
        return None

    def _detect_os(self, headers: Dict, server: str) -> Optional[str]:
        """Detect operating system from headers"""
        server_lower = server.lower()
        
        os_signatures = {
            'Linux': ['ubuntu', 'debian', 'centos', 'red hat', 'linux'],
            'Windows': ['windows', 'win32', 'win64', 'iis'],
            'FreeBSD': ['freebsd', 'openbsd'],
            'macOS': ['darwin', 'macos'],
        }
        
        for os_name, sigs in os_signatures.items():
            if any(sig in server_lower for sig in sigs):
                return os_name
        
        return None

    # ===============================
    # PHASE 7: SECURITY HEADER ANALYSIS
    # ===============================

    async def _phase7_security_header_analysis(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Analyze security headers and cookie security"""
        
        self.logger.debug("[Phase 7] Analyzing security headers")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        try:
            async with session.get(base_url) as response:
                headers = response.headers
                
                # HSTS
                hsts = headers.get('strict-transport-security', '')
                if hsts:
                    hsts_analysis = HSTSAnalysis(present=True, raw_header=hsts)
                    
                    # Parse HSTS
                    for directive in hsts.split(';'):
                        directive = directive.strip()
                        if 'max-age=' in directive:
                            try:
                                hsts_analysis.max_age = int(directive.split('=')[1])
                            except:
                                pass
                        elif 'includeSubDomains' in directive:
                            hsts_analysis.include_subdomains = True
                        elif 'preload' in directive:
                            hsts_analysis.preload = True
                    
                    intel.security_headers.hsts = hsts_analysis
                
                # CSP
                csp = headers.get('content-security-policy', '')
                if csp:
                    csp_analysis = CSPAnalysis(present=True, raw_policy=csp)
                    
                    # Parse CSP directives
                    for directive in csp.split(';'):
                        directive = directive.strip()
                        if ' ' in directive:
                            name, values = directive.split(' ', 1)
                            csp_analysis.directives[name] = [v.strip() for v in values.split(' ') if v.strip()]
                            
                            # Check for unsafe configurations
                            if name == 'default-src' and not values:
                                csp_analysis.missing_default_src = True
                            if name == 'script-src':
                                if "'unsafe-inline'" in values:
                                    csp_analysis.unsafe_inline = True
                                if "'unsafe-eval'" in values:
                                    csp_analysis.unsafe_eval = True
                            if name == 'frame-ancestors':
                                csp_analysis.frame_ancestors = [v.strip() for v in values.split(' ') if v.strip()]
                    
                    intel.security_headers.csp = csp_analysis
                
                # Other security headers
                intel.security_headers.x_frame_options = headers.get('x-frame-options')
                intel.security_headers.x_content_type_options = headers.get('x-content-type-options')
                intel.security_headers.referrer_policy = headers.get('referrer-policy')
                intel.security_headers.permissions_policy = headers.get('permissions-policy')
                intel.security_headers.x_xss_protection = headers.get('x-xss-protection')
                intel.security_headers.expect_ct = headers.get('expect-ct')
                intel.security_headers.feature_policy = headers.get('feature-policy')
                
                # CORS
                cors = CORSAnalysis(
                    present='access-control-allow-origin' in headers,
                    allow_origin=headers.get('access-control-allow-origin'),
                    allow_credentials='access-control-allow-credentials' in headers,
                    allow_methods=headers.get('access-control-allow-methods', '').split(', ') if headers.get('access-control-allow-methods') else [],
                    allow_headers=headers.get('access-control-allow-headers', '').split(', ') if headers.get('access-control-allow-headers') else [],
                    expose_headers=headers.get('access-control-expose-headers', '').split(', ') if headers.get('access-control-expose-headers') else [],
                    max_age=int(headers.get('access-control-max-age', 0)) if headers.get('access-control-max-age') else None
                )
                
                # Check for misconfigurations
                if cors.allow_origin == '*':
                    cors.wildcard_origin = True
                if cors.wildcard_origin and cors.allow_credentials:
                    cors.wildcard_with_credentials = True
                    cors.misconfigured = True
                
                intel.security_headers.cors = cors
                
                # Cookies
                for cookie in response.cookies.values():
                    cookie_analysis = CookieAnalysis(
                        name=cookie.key,
                        value=cookie.value,
                        domain=cookie.get('domain', ''),
                        path=cookie.get('path', ''),
                        secure=cookie.get('secure', False),
                        http_only=cookie.get('httponly', False),
                        same_site=cookie.get('samesite', None),
                        session_cookie='expires' not in cookie,
                        persistent='expires' in cookie
                    )
                    
                    if 'expires' in cookie:
                        try:
                            cookie_analysis.expires = datetime.strptime(cookie['expires'], '%a, %d %b %Y %H:%M:%S %Z')
                        except:
                            pass
                    
                    if 'max-age' in cookie:
                        try:
                            cookie_analysis.max_age = int(cookie['max-age'])
                        except:
                            pass
                    
                    intel.security_headers.cookies.append(cookie_analysis)
                    
        except Exception as e:
            self.logger.debug(f"Security header analysis failed: {str(e)}")

    # ===============================
    # PHASE 8: CONTENT ANALYSIS
    # ===============================

    async def _phase8_content_analysis(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Analyze HTML content, forms, links, and metadata"""
        
        self.logger.debug("[Phase 8] Analyzing content")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        try:
            async with session.get(base_url) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Title
                title_tag = soup.find('title')
                if title_tag:
                    intel.content_analysis.title = title_tag.string
                
                # Meta tags
                for meta in soup.find_all('meta'):
                    meta_tag = MetaTag(
                        name=meta.get('name'),
                        property=meta.get('property'),
                        content=meta.get('content')
                    )
                    intel.content_analysis.meta_tags.append(meta_tag)
                    
                    # Language detection from meta
                    if meta.get('http-equiv') == 'content-language':
                        intel.content_analysis.language = meta.get('content')
                
                # Canonical URL
                canonical = soup.find('link', rel='canonical')
                if canonical and canonical.get('href'):
                    intel.content_analysis.canonical_url = canonical.get('href')
                
                # Favicon
                favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
                if favicon and favicon.get('href'):
                    favicon_url = urljoin(base_url, favicon.get('href'))
                    intel.content_analysis.favicon = favicon_url
                    
                    # Try to fetch favicon for hash
                    try:
                        async with session.get(favicon_url) as fav_response:
                            if fav_response.status == 200:
                                fav_data = await fav_response.read()
                                intel.content_analysis.favicon_hash = hashlib.md5(fav_data).hexdigest()
                    except:
                        pass
                
                # Forms
                for form in soup.find_all('form'):
                    form_fields = []
                    
                    for input_field in form.find_all('input'):
                        field = FormField(
                            name=input_field.get('name', ''),
                            type=input_field.get('type', 'text'),
                            value=input_field.get('value'),
                            required='required' in input_field.attrs,
                            maxlength=int(input_field.get('maxlength', 0)) if input_field.get('maxlength') else None,
                            placeholder=input_field.get('placeholder')
                        )
                        form_fields.append(field)
                    
                    form_analysis = FormAnalysis(
                        action=form.get('action', ''),
                        method=form.get('method', 'get').upper(),
                        fields=form_fields,
                        has_file_upload=any(f.type == 'file' for f in form_fields),
                        is_login_form=any(f.type == 'password' for f in form_fields),
                        is_search_form=form.get('method', '').upper() == 'GET' and any(f.name == 'q' for f in form_fields)
                    )
                    
                    # Check for CSRF token
                    csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token']
                    for field in form_fields:
                        if any(indicator in field.name.lower() for indicator in csrf_indicators):
                            form_analysis.has_csrf_token = True
                            form_analysis.csrf_token_name = field.name
                            break
                    
                    intel.content_analysis.forms.append(form_analysis)
                
                # Links
                internal_links = []
                external_links = []
                js_files = []
                css_files = []
                images = []
                iframes = []
                
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href.startswith('http'):
                        if hostname in href:
                            internal_links.append(href)
                        else:
                            external_links.append(href)
                    elif href.startswith('/') or href.startswith('.'):
                        internal_links.append(urljoin(base_url, href))
                
                for script in soup.find_all('script', src=True):
                    src = script.get('src')
                    if src:
                        js_files.append(urljoin(base_url, src))
                
                for css in soup.find_all('link', rel='stylesheet', href=True):
                    href = css.get('href')
                    if href:
                        css_files.append(urljoin(base_url, href))
                
                for img in soup.find_all('img', src=True):
                    src = img.get('src')
                    if src:
                        images.append(urljoin(base_url, src))
                
                for iframe in soup.find_all('iframe', src=True):
                    src = iframe.get('src')
                    if src:
                        iframes.append(urljoin(base_url, src))
                
                intel.content_analysis.links = LinkAnalysis(
                    internal_links=internal_links,
                    external_links=external_links,
                    javascript_files=js_files,
                    css_files=css_files,
                    image_sources=images,
                    iframe_sources=iframes,
                    total_links=len(internal_links) + len(external_links)
                )
                
        except Exception as e:
            self.logger.debug(f"Content analysis failed: {str(e)}")

    # ===============================
    # PHASE 9: VULNERABILITY INDICATORS
    # ===============================

    async def _phase9_vulnerability_indicators(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Detect passive vulnerability indicators"""
        
        self.logger.debug("[Phase 9] Detecting vulnerability indicators")
        
        # Information Disclosure
        info_disclosure = InformationDisclosure()
        
        # Check server version leak
        if intel.technology_stack.web_server.version:
            info_disclosure.server_version_leak = True
        
        # Check framework version leak
        for framework in intel.technology_stack.frameworks:
            if framework.version:
                info_disclosure.framework_version_leak = True
        
        # Check discovered sensitive files
        if intel.endpoint_discovery.sensitive_files:
            info_disclosure.backup_files_found = [p.path for p in intel.endpoint_discovery.sensitive_files]
        
        # Check for directory listing
        for path in intel.endpoint_discovery.paths_discovered:
            if path.status_code == 200 and 'Index of /' in (path.title or ''):
                info_disclosure.directory_listing_enabled.append(path.path)
        
        # Check for debug mode
        debug_indicators = ['debug', 'dev', 'test', 'staging']
        for path in intel.endpoint_discovery.paths_discovered:
            if any(indicator in path.path for indicator in debug_indicators):
                info_disclosure.debug_mode_detected = True
        
        # Check for .git exposure
        if any(p.path == '/.git/config' for p in intel.endpoint_discovery.sensitive_files):
            info_disclosure.git_folder_exposed = True
        
        # Check for .env exposure
        if any(p.path == '/.env' for p in intel.endpoint_discovery.sensitive_files):
            info_disclosure.env_file_exposed = True
        
        intel.vulnerability_indicators.information_disclosure = info_disclosure
        
        # Configuration Issues
        config_issues = ConfigurationIssue()
        
        # Check for admin interfaces
        if intel.endpoint_discovery.admin_interfaces:
            config_issues.admin_interfaces_exposed = [p.path for p in intel.endpoint_discovery.admin_interfaces]
        
        # Check for PHP info
        for path in intel.endpoint_discovery.sensitive_files:
            if 'phpinfo' in path.path or 'info.php' in path.path:
                config_issues.php_info_pages.append(path.path)
        
        # Check for stack traces
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        try:
            # Try to trigger error
            async with session.get(f"{base_url}/?error=1") as response:
                content = await response.text()
                trace_indicators = ['stack trace', 'traceback', 'exception', 'error in']
                if any(indicator in content.lower() for indicator in trace_indicators):
                    config_issues.debug_endpoints.append('/?error=1')
        except:
            pass
        
        intel.vulnerability_indicators.configuration_issues = config_issues
        
        # TLS Issues (simplified - connectivity layer should provide more)
        tls_issues = TLSIssues()
        
        # Check mixed content
        if intel.protocol == 'https':
            for link in intel.content_analysis.links.internal_links:
                if link.startswith('http://'):
                    tls_issues.mixed_content.append(link)
        
        intel.vulnerability_indicators.tls_issues = tls_issues
        
        # WAF Detection
        waf = await self._detect_waf(intel, hostname, port)
        intel.vulnerability_indicators.waf = waf

    async def _detect_waf(self, intel: HTTPIntelligence, hostname: str, port: int) -> WAFDetection:
        """Detect Web Application Firewall"""
        
        waf = WAFDetection()
        
        # Check headers
        if hasattr(intel, 'security_headers') and intel.security_headers:
            headers = {}
            
            # Cloudflare
            if hasattr(intel, 'raw_responses'):
                for resp in intel.raw_responses.values():
                    if 'cf-ray' in resp.get('headers', {}):
                        waf.present = True
                        waf.provider = 'Cloudflare'
                        waf.confidence = 0.9
                        waf.evidence.append('CF-Ray header detected')
                        waf.headers['cf-ray'] = resp['headers']['cf-ray']
                    
                    if 'cf-cache-status' in resp.get('headers', {}):
                        waf.present = True
                        waf.provider = 'Cloudflare'
                        waf.evidence.append('CF-Cache-Status header detected')
            
            # AWS WAF
            for header in ['x-amz-cf-id', 'x-amz-cf-pop']:
                if hasattr(intel, 'raw_responses'):
                    for resp in intel.raw_responses.values():
                        if header in resp.get('headers', {}):
                            waf.present = True
                            waf.provider = 'AWS WAF/CloudFront'
                            waf.confidence = 0.85
                            waf.evidence.append(f'{header} detected')
            
            # Akamai
            for header in ['x-akamai-', 'x-akamai-request-id']:
                if hasattr(intel, 'raw_responses'):
                    for resp in intel.raw_responses.values():
                        if any(header.startswith(h) for h in resp.get('headers', {})):
                            waf.present = True
                            waf.provider = 'Akamai'
                            waf.confidence = 0.85
                            waf.evidence.append('Akamai headers detected')
        
        return waf

    # ===============================
    # PHASE 10: MODERN WEB DETECTION
    # ===============================

    async def _phase10_modern_web_detection(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Detect modern web features: REST APIs, GraphQL, WebSockets, SPAs"""
        
        self.logger.debug("[Phase 10] Detecting modern web features")
        
        # REST API Detection
        rest_apis = []
        for path in intel.endpoint_discovery.paths_discovered:
            if path.is_api_endpoint:
                # Try to determine methods
                methods = ['GET']
                
                rest_endpoint = RESTEndpoint(
                    path=path.path,
                    methods=methods,
                    content_type=path.content_type
                )
                rest_apis.append(rest_endpoint)
        
        intel.modern_web.rest_apis = rest_apis
        
        # GraphQL Detection
        graphql = GraphQLInfo()
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        # Check common GraphQL endpoints
        graphql_endpoints = ['/graphql', '/graphiql', '/graph', '/gql', '/query']
        
        for endpoint in graphql_endpoints:
            try:
                url = f"{base_url}{endpoint}"
                async with session.post(url, json={"query": "{__typename}"}) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'data' in data or 'errors' in data:
                            graphql.present = True
                            graphql.endpoint = endpoint
                            
                            # Check introspection
                            try:
                                intro_query = """
                                {
                                    __schema {
                                        types {
                                            name
                                        }
                                    }
                                }
                                """
                                async with session.post(url, json={"query": intro_query}) as intro_response:
                                    if intro_response.status == 200:
                                        intro_data = await intro_response.json()
                                        if 'data' in intro_data and '__schema' in intro_data['data']:
                                            graphql.introspection_enabled = True
                                            graphql.schema_available = True
                            except:
                                pass
                            
                            break
            except:
                continue
        
        intel.modern_web.graphql = graphql if graphql.present else None
        
        # WebSocket Detection
        websocket = WebSocketInfo()
        
        # Check for Upgrade header
        if intel.protocol_support.websocket_supported:
            websocket.present = True
            websocket.endpoints = ['/ws', '/websocket', '/socket']
            websocket.secure = intel.protocol == 'https'
        
        intel.modern_web.websocket = websocket if websocket.present else None
        
        # SPA Detection
        spa = SPAInfo()
        
        # Check for client-side routing indicators
        if intel.content_analysis.links:
            # Check for pushState URLs
            for link in intel.content_analysis.links.internal_links:
                if '#' in link and '!' not in link:
                    spa.client_side_routing = True
                    spa.is_spa = True
        
        # Check for initial JSON payload
        session = await self._ensure_session()
        try:
            async with session.get(base_url) as response:
                content = await response.text()
                json_pattern = r'<script[^>]*>window\.__INITIAL_STATE__\s*=\s*({.*?})</script>'
                match = re.search(json_pattern, content, re.DOTALL)
                if match:
                    spa.initial_json_payload = match.group(1)[:200] + '...'
                    spa.api_driven = True
                    spa.is_spa = True
        except:
            pass
        
        # Detect SPA framework
        for lib in intel.technology_stack.js_libraries:
            if lib.name in ['React', 'Vue', 'Angular']:
                spa.framework = lib.name
                spa.is_spa = True
        
        intel.modern_web.spa = spa

    # ===============================
    # PHASE 11: BEHAVIORAL PATTERNS
    # ===============================

    async def _phase11_behavioral_patterns(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Detect behavioral patterns: rate limiting, load balancing, A/B testing, bot detection"""
        
        self.logger.debug("[Phase 11] Analyzing behavioral patterns")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        # Rate Limiting Detection
        rate_limiting = RateLimitingInfo()
        
        # Make rapid requests to trigger rate limiting
        statuses = []
        for i in range(5):
            try:
                async with session.get(base_url) as response:
                    statuses.append(response.status)
                    
                    if response.status == 429:
                        rate_limiting.detected = True
                        rate_limiting.status_code = 429
                        
                        retry_after = response.headers.get('retry-after')
                        if retry_after:
                            try:
                                rate_limiting.retry_after = int(retry_after)
                            except:
                                pass
            except:
                pass
        
        intel.behavioral_patterns.rate_limiting = rate_limiting
        
        # Load Balancer Stickiness
        stickiness = LoadBalancerStickiness()
        
        # Check for stickiness cookies
        for cookie in intel.security_headers.cookies:
            if 'lb' in cookie.name.lower() or 'balance' in cookie.name.lower() or 'server' in cookie.name.lower():
                stickiness.detected = True
                stickiness.cookie_based = True
                stickiness.cookie_name = cookie.name
                stickiness.method = 'Cookie-based'
        
        intel.behavioral_patterns.load_balancer_stickiness = stickiness
        
        # A/B Testing Detection
        ab_testing = ABTestingInfo()
        
        # Check for A/B testing cookies
        ab_cookies = ['ab', '_ab', 'optimizely', 'variation', 'exp', 'experiment']
        for cookie in intel.security_headers.cookies:
            if any(ab_cookie in cookie.name.lower() for ab_cookie in ab_cookies):
                ab_testing.detected = True
                ab_testing.cookies.append(cookie.name)
        
        # Check for A/B testing headers
        for response in intel.raw_responses.values():
            headers = response.get('headers', {})
            for header in headers:
                if 'x-ab' in header.lower() or 'x-variant' in header.lower():
                    ab_testing.detected = True
                    ab_testing.headers.append(header)
        
        intel.behavioral_patterns.ab_testing = ab_testing
        
        # Bot Detection
        bot_detection = BotDetectionInfo()
        
        # Try to access with suspicious user agent
        try:
            headers = {"User-Agent": "curl/7.68.0"}
            async with session.get(base_url, headers=headers) as response:
                if response.status in [403, 429, 503]:
                    bot_detection.detected = True
                    bot_detection.headers.append('User-Agent filtering')
                    
                    # Check for challenge page
                    content = await response.text()
                    if 'captcha' in content.lower():
                        bot_detection.captcha_present = True
                    if 'challenge' in content.lower() or 'cf-browser-verification' in content:
                        bot_detection.javascript_challenge = True
        except:
            pass
        
        intel.behavioral_patterns.bot_detection = bot_detection

    # ===============================
    # PHASE 12: PERFORMANCE METRICS
    # ===============================

    async def _phase12_performance_metrics(self, intel: HTTPIntelligence, hostname: str, port: int):
        """Measure performance metrics: response times, caching, compression"""
        
        self.logger.debug("[Phase 12] Measuring performance metrics")
        
        session = await self._ensure_session()
        base_url = f"{intel.protocol}://{hostname}:{port}"
        
        # Response Time Metrics
        response_times = []
        ttfb_times = []
        
        for i in range(3):
            try:
                start = time.perf_counter()
                async with session.get(base_url) as response:
                    first_byte = time.perf_counter()
                    content = await response.read()
                    end = time.perf_counter()
                    
                    ttfb = (first_byte - start) * 1000
                    total = (end - start) * 1000
                    
                    ttfb_times.append(ttfb)
                    response_times.append(total)
                    
                    # Store raw response for later analysis
                    intel.raw_responses[f"main_{i}"] = {
                        "headers": dict(response.headers),
                        "status": response.status,
                    }
            except:
                continue
        
        if response_times:
            metrics = ResponseTimeMetrics(
                ttfb_ms=sum(ttfb_times) / len(ttfb_times) if ttfb_times else 0,
                total_time_ms=sum(response_times) / len(response_times),
                samples=response_times
            )
            intel.performance.response_times['main_page'] = metrics
            
            # Error rate (placeholder - would need more requests)
            intel.performance.error_rate = 0.0
            intel.performance.timeout_rate = 0.0
        
        # Caching Analysis
        if 'main_0' in intel.raw_responses:
            headers = intel.raw_responses['main_0']['headers']
            
            caching = CachingAnalysis(
                cache_control=headers.get('cache-control'),
                pragma=headers.get('pragma'),
                etag=headers.get('etag'),
                age=int(headers.get('age', 0)) if headers.get('age') else None,
                vary_headers=headers.get('vary', '').split(', ') if headers.get('vary') else []
            )
            
            if headers.get('expires'):
                try:
                    caching.expires = datetime.strptime(headers['expires'], '%a, %d %b %Y %H:%M:%S %Z')
                except:
                    pass
            
            if headers.get('last-modified'):
                try:
                    caching.last_modified = datetime.strptime(headers['last-modified'], '%a, %d %b %Y %H:%M:%S %Z')
                except:
                    pass
            
            # Check cache hit
            if headers.get('cf-cache-status') in ['HIT', 'REVALIDATED']:
                caching.cdn_cache_hit = True
            if headers.get('x-cache') in ['HIT', 'HIT from cloudfront']:
                caching.cdn_cache_hit = True
            
            intel.performance.caching = caching
        
        # Compression Analysis
        compression = CompressionAnalysis()
        
        # Test with and without compression
        try:
            # With compression
            headers = {"Accept-Encoding": "gzip, deflate, br"}
            async with session.get(base_url, headers=headers) as response:
                compression.content_encoding = response.headers.get('content-encoding')
                compressed_size = len(await response.read())
                compression.compressed_size = compressed_size
                
                if 'gzip' in (compression.content_encoding or ''):
                    compression.gzip_supported = True
                elif 'br' in (compression.content_encoding or ''):
                    compression.brotli_supported = True
                elif 'deflate' in (compression.content_encoding or ''):
                    compression.deflate_supported = True
            
            # Without compression
            headers = {"Accept-Encoding": "identity"}
            async with session.get(base_url, headers=headers) as response:
                original_size = len(await response.read())
                compression.original_size = original_size
                
                if compression.compressed_size and original_size:
                    compression.compression_ratio = original_size / compression.compressed_size
            
        except:
            pass
        
        intel.performance.compression = compression
        
        # Keep-Alive Analysis
        if 'main_0' in intel.raw_responses:
            headers = intel.raw_responses['main_0']['headers']
            
            keep_alive = KeepAliveAnalysis(
                keep_alive_supported='keep-alive' in headers.get('connection', '').lower(),
                connection_header=headers.get('connection')
            )
            
            # Parse Keep-Alive header
            if headers.get('keep-alive'):
                keep_alive_str = headers['keep-alive']
                if 'timeout=' in keep_alive_str:
                    try:
                        keep_alive.timeout_seconds = int(keep_alive_str.split('timeout=')[1].split(',')[0])
                    except:
                        pass
                if 'max=' in keep_alive_str:
                    try:
                        keep_alive.max_requests = int(keep_alive_str.split('max=')[1].split(',')[0])
                    except:
                        pass
            
            intel.performance.keep_alive = keep_alive

    # ===============================
    # UTILITY METHODS
    # ===============================

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.find('title')
            return title.string if title else None
        except:
            return None

    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None