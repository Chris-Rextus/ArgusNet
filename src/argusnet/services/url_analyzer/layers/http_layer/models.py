# src/argusnet/services/url_analyzer/layers/http_layer/models.py

"""
HTTP Intelligence Models
Comprehensive data structures for HTTP analysis, security headers,
technology fingerprinting, and vulnerability indicators.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


# ===============================
# PROTOCOL & TRANSPORT
# ===============================

@dataclass
class ProtocolSupport:
    """HTTP protocol variants supported"""
    http_1_0: bool = False
    http_1_1: bool = False
    http_2: bool = False
    http_3: bool = False
    alpn_protocols: List[str] = field(default_factory=list)
    http_2_push_supported: bool = False
    websocket_supported: bool = False
    upgrade_required: bool = False


@dataclass
class VirtualHost:
    """Virtual host detection results"""
    host_header: str
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    title: Optional[str] = None
    different_content: bool = False
    vhost_detected: bool = False


@dataclass
class HTTPMethodTest:
    """HTTP method testing results"""
    method: str
    allowed: bool = False
    status_code: Optional[int] = None
    supports_cors: bool = False
    response_body: Optional[str] = None


@dataclass
class MethodAnalysis:
    """HTTP method support analysis"""
    options: List[str] = field(default_factory=list)
    trace_enabled: bool = False
    put_enabled: bool = False
    delete_enabled: bool = False
    patch_enabled: bool = False
    trace_vulnerable: bool = False
    unsafe_methods_allowed: List[str] = field(default_factory=list)
    method_tests: List[HTTPMethodTest] = field(default_factory=list)


# ===============================
# REDIRECT & NAVIGATION
# ===============================

@dataclass
class RedirectHop:
    """Single redirect hop in chain"""
    url: str
    status_code: int
    headers: Dict[str, str]
    is_meta_redirect: bool = False
    is_javascript_redirect: bool = False


@dataclass
class RedirectChain:
    """Complete redirect chain analysis"""
    hops: List[RedirectHop] = field(default_factory=list)
    final_url: Optional[str] = None
    final_status_code: Optional[int] = None
    redirect_count: int = 0
    enforces_https: bool = False
    hsts_enforced: bool = False
    mixed_content_detected: bool = False
    redirect_loop_detected: bool = False


# ===============================
# ENDPOINT DISCOVERY
# ===============================

@dataclass
class DiscoveredPath:
    """Discovered endpoint or path"""
    path: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    title: Optional[str] = None
    discovery_method: str = "bruteforce"  # bruteforce, sitemap, robots, etc
    requires_auth: bool = False
    is_api_endpoint: bool = False
    response_time_ms: Optional[float] = None


@dataclass
class ParameterTest:
    """Parameter fuzzing result"""
    parameter: str
    value: str
    reflected: bool = False
    reflected_in_body: bool = False
    reflected_in_headers: bool = False
    reflected_in_cookies: bool = False
    caused_error: bool = False
    error_message: Optional[str] = None
    status_code: Optional[int] = None


@dataclass
class ParameterAnalysis:
    """Parameter fuzzing analysis"""
    parameters_tested: List[str] = field(default_factory=list)
    reflections_found: List[ParameterTest] = field(default_factory=list)
    xss_reflection_points: int = 0
    open_redirect_candidates: List[str] = field(default_factory=list)
    sql_error_patterns: List[str] = field(default_factory=list)
    debug_parameters_active: List[str] = field(default_factory=list)


@dataclass
class EndpointDiscovery:
    """Comprehensive endpoint discovery results"""
    paths_discovered: List[DiscoveredPath] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    sensitive_files: List[DiscoveredPath] = field(default_factory=list)
    config_files: List[DiscoveredPath] = field(default_factory=list)
    admin_interfaces: List[DiscoveredPath] = field(default_factory=list)
    cloud_metadata_endpoints: List[DiscoveredPath] = field(default_factory=list)
    parameter_analysis: ParameterAnalysis = field(default_factory=ParameterAnalysis)
    
    @property
    def total_discovered(self) -> int:
        return len(self.paths_discovered)


# ===============================
# TECHNOLOGY STACK
# ===============================

@dataclass
class WebServerInfo:
    """Web server fingerprint"""
    server_header: Optional[str] = None
    software: Optional[str] = None  # nginx, apache, iis, etc
    version: Optional[str] = None
    via_header: Optional[str] = None
    powered_by: Optional[str] = None
    case_sensitive: bool = False
    default_404_page: bool = False
    custom_404_detected: bool = False
    os_hint: Optional[str] = None


@dataclass
class FrameworkInfo:
    """Web framework detection"""
    name: Optional[str] = None  # django, rails, laravel, etc
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    cookies: List[str] = field(default_factory=list)


@dataclass
class CMSInfo:
    """Content Management System detection"""
    name: Optional[str] = None  # wordpress, drupal, joomla, etc
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    themes: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)


@dataclass
class JSLibrary:
    """JavaScript library detection"""
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    source_url: Optional[str] = None
    cdn_provider: Optional[str] = None


@dataclass
class TechnologyStack:
    """Complete technology stack fingerprinting"""
    web_server: WebServerInfo = field(default_factory=WebServerInfo)
    frameworks: List[FrameworkInfo] = field(default_factory=list)
    cms: Optional[CMSInfo] = None
    js_libraries: List[JSLibrary] = field(default_factory=list)
    programming_language: Optional[str] = None
    database_hint: Optional[str] = None
    os_detected: Optional[str] = None
    container_detected: Optional[str] = None  # docker, k8s, etc


# ===============================
# SECURITY HEADERS
# ===============================

@dataclass
class HSTSAnalysis:
    """HTTP Strict Transport Security analysis"""
    present: bool = False
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    preload_ready: bool = False
    raw_header: Optional[str] = None


@dataclass
class CSPAnalysis:
    """Content Security Policy analysis"""
    present: bool = False
    raw_policy: Optional[str] = None
    directives: Dict[str, List[str]] = field(default_factory=dict)
    unsafe_inline: bool = False
    unsafe_eval: bool = False
    wildcard_sources: List[str] = field(default_factory=list)
    missing_default_src: bool = False
    report_uri: Optional[str] = None
    report_to: Optional[str] = None
    frame_ancestors: List[str] = field(default_factory=list)
    
    @property
    def security_score(self) -> int:
        """Score CSP configuration (0-100)"""
        score = 100
        if self.unsafe_inline:
            score -= 40
        if self.unsafe_eval:
            score -= 30
        if self.wildcard_sources:
            score -= len(self.wildcard_sources) * 10
        if self.missing_default_src:
            score -= 20
        return max(0, score)


@dataclass
class CookieAnalysis:
    """Individual cookie security analysis"""
    name: str
    value: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None  # Strict, Lax, None
    expires: Optional[datetime] = None
    max_age: Optional[int] = None
    session_cookie: bool = False
    persistent: bool = False
    
    @property
    def security_score(self) -> int:
        """Score individual cookie security"""
        score = 100
        if not self.secure:
            score -= 40
        if not self.http_only:
            score -= 30
        if self.same_site == "None":
            score -= 20
        elif not self.same_site:
            score -= 10
        return max(0, score)


@dataclass
class CORSAnalysis:
    """Cross-Origin Resource Sharing analysis"""
    present: bool = False
    allow_origin: Optional[str] = None
    allow_credentials: bool = False
    allow_methods: List[str] = field(default_factory=list)
    allow_headers: List[str] = field(default_factory=list)
    expose_headers: List[str] = field(default_factory=list)
    max_age: Optional[int] = None
    wildcard_origin: bool = False
    wildcard_with_credentials: bool = False
    misconfigured: bool = False


@dataclass
class SecurityHeaders:
    """Comprehensive security header analysis"""
    hsts: HSTSAnalysis = field(default_factory=HSTSAnalysis)
    csp: CSPAnalysis = field(default_factory=CSPAnalysis)
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    x_xss_protection: Optional[str] = None
    expect_ct: Optional[str] = None
    feature_policy: Optional[str] = None
    
    cookies: List[CookieAnalysis] = field(default_factory=list)
    cors: CORSAnalysis = field(default_factory=CORSAnalysis)
    
    @property
    def security_score(self) -> int:
        """Calculate overall security header score (0-100)"""
        score = 0
        
        # HSTS (20 points)
        if self.hsts.present:
            score += 10
            if self.hsts.max_age and self.hsts.max_age >= 31536000:
                score += 5
            if self.hsts.include_subdomains:
                score += 5
        
        # CSP (25 points)
        if self.csp.present:
            score += 10
            score += self.csp.security_score // 4  # Up to 15 points
        
        # X-Frame-Options (10 points)
        if self.x_frame_options in ['DENY', 'SAMEORIGIN']:
            score += 10
        
        # X-Content-Type-Options (10 points)
        if self.x_content_type_options == 'nosniff':
            score += 10
        
        # Referrer-Policy (10 points)
        if self.referrer_policy in ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']:
            score += 10
        elif self.referrer_policy:
            score += 5
        
        # Permissions-Policy (5 points)
        if self.permissions_policy:
            score += 5
        
        # Cookies (20 points)
        if self.cookies:
            cookie_score = sum(c.security_score for c in self.cookies) / len(self.cookies)
            score += int(cookie_score * 0.2)
        
        return min(100, score)


# ===============================
# CONTENT ANALYSIS
# ===============================

@dataclass
class MetaTag:
    """HTML meta tag"""
    name: Optional[str] = None
    property: Optional[str] = None
    content: Optional[str] = None


@dataclass
class FormField:
    """HTML form field"""
    name: str
    type: str  # text, password, hidden, etc
    value: Optional[str] = None
    required: bool = False
    maxlength: Optional[int] = None
    placeholder: Optional[str] = None


@dataclass
class FormAnalysis:
    """HTML form analysis"""
    action: str
    method: str  # GET, POST
    fields: List[FormField] = field(default_factory=list)
    has_csrf_token: bool = False
    csrf_token_name: Optional[str] = None
    has_file_upload: bool = False
    is_login_form: bool = False
    is_search_form: bool = False
    is_contact_form: bool = False


@dataclass
class LinkAnalysis:
    """Link extraction and analysis"""
    internal_links: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    javascript_files: List[str] = field(default_factory=list)
    css_files: List[str] = field(default_factory=list)
    image_sources: List[str] = field(default_factory=list)
    iframe_sources: List[str] = field(default_factory=list)
    total_links: int = 0


@dataclass
class RobotsTxt:
    """robots.txt analysis"""
    present: bool = False
    content: Optional[str] = None
    disallowed_paths: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    crawl_delay: Optional[float] = None
    user_agents: List[str] = field(default_factory=list)


@dataclass
class SitemapXml:
    """sitemap.xml analysis"""
    present: bool = False
    urls: List[str] = field(default_factory=list)
    url_count: int = 0
    last_modified: Optional[datetime] = None
    is_sitemap_index: bool = False


@dataclass
class ContentAnalysis:
    """Comprehensive content analysis"""
    title: Optional[str] = None
    meta_tags: List[MetaTag] = field(default_factory=list)
    canonical_url: Optional[str] = None
    language: Optional[str] = None
    favicon: Optional[str] = None
    favicon_hash: Optional[str] = None
    forms: List[FormAnalysis] = field(default_factory=list)
    links: LinkAnalysis = field(default_factory=LinkAnalysis)
    robots_txt: RobotsTxt = field(default_factory=RobotsTxt)
    sitemap_xml: SitemapXml = field(default_factory=SitemapXml)
    
    @property
    def wordpress_detected(self) -> bool:
        """Quick WordPress detection"""
        return any('wp-content' in link for link in self.links.internal_links)


# ===============================
# VULNERABILITY INDICATORS
# ===============================

@dataclass
class InformationDisclosure:
    """Information disclosure findings"""
    server_version_leak: bool = False
    framework_version_leak: bool = False
    directory_listing_enabled: List[str] = field(default_factory=list)
    backup_files_found: List[str] = field(default_factory=list)
    debug_mode_detected: bool = False
    stack_trace_detected: bool = False
    database_error_detected: bool = False
    php_info_detected: bool = False
    git_folder_exposed: bool = False
    svn_folder_exposed: bool = False
    env_file_exposed: bool = False


@dataclass
class ConfigurationIssue:
    """Configuration issues found"""
    default_credentials_pages: List[str] = field(default_factory=list)
    admin_interfaces_exposed: List[str] = field(default_factory=list)
    php_info_pages: List[str] = field(default_factory=list)
    database_error_pages: List[str] = field(default_factory=list)
    debug_endpoints: List[str] = field(default_factory=list)
    sensitive_folders_exposed: List[str] = field(default_factory=list)


@dataclass
class TLSIssues:
    """TLS/SSL issues (complements connectivity layer)"""
    mixed_content: List[str] = field(default_factory=list)
    weak_cipher_suites: List[str] = field(default_factory=list)
    protocol_downgrade_possible: bool = False
    ssl_issues_found: List[str] = field(default_factory=list)


@dataclass
class WAFDetection:
    """Web Application Firewall detection"""
    present: bool = False
    provider: Optional[str] = None  # cloudflare, akamai, aws, modsecurity, etc
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    block_page_detected: bool = False


@dataclass
class VulnerabilityIndicators:
    """Passive vulnerability indicators"""
    information_disclosure: InformationDisclosure = field(default_factory=InformationDisclosure)
    configuration_issues: ConfigurationIssue = field(default_factory=ConfigurationIssue)
    tls_issues: TLSIssues = field(default_factory=TLSIssues)
    waf: WAFDetection = field(default_factory=WAFDetection)
    
    @property
    def risk_score(self) -> int:
        """Calculate risk score based on findings (0-100)"""
        score = 0
        if self.information_disclosure.server_version_leak:
            score += 10
        if self.information_disclosure.directory_listing_enabled:
            score += 20
        if self.information_disclosure.backup_files_found:
            score += 25
        if self.information_disclosure.debug_mode_detected:
            score += 30
        if self.information_disclosure.git_folder_exposed:
            score += 40
        if self.configuration_issues.admin_interfaces_exposed:
            score += 35
        if self.tls_issues.mixed_content:
            score += 15
        return min(100, score)


# ===============================
# API & MODERN WEB
# ===============================

@dataclass
class RESTEndpoint:
    """REST API endpoint detection"""
    path: str
    methods: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    authentication_required: bool = False
    rate_limited: bool = False
    response_example: Optional[str] = None


@dataclass
class GraphQLInfo:
    """GraphQL detection"""
    present: bool = False
    endpoint: Optional[str] = None
    introspection_enabled: bool = False
    schema_available: bool = False
    queries_detected: List[str] = field(default_factory=list)
    mutations_detected: List[str] = field(default_factory=list)


@dataclass
class WebSocketInfo:
    """WebSocket detection"""
    present: bool = False
    endpoints: List[str] = field(default_factory=list)
    secure: bool = False  # wss:// vs ws://
    protocols: List[str] = field(default_factory=list)


@dataclass
class SPAInfo:
    """Single Page Application detection"""
    is_spa: bool = False
    framework: Optional[str] = None  # react, vue, angular, etc
    client_side_routing: bool = False
    initial_json_payload: Optional[str] = None
    api_driven: bool = False


@dataclass
class ModernWebFeatures:
    """Modern web technology detection"""
    rest_apis: List[RESTEndpoint] = field(default_factory=list)
    graphql: Optional[GraphQLInfo] = None
    websocket: Optional[WebSocketInfo] = None
    spa: SPAInfo = field(default_factory=SPAInfo)
    server_sent_events: bool = False
    web_workers: bool = False


# ===============================
# BEHAVIORAL PATTERNS
# ===============================

@dataclass
class RateLimitingInfo:
    """Rate limiting detection"""
    detected: bool = False
    status_code: Optional[int] = None
    retry_after: Optional[int] = None
    ip_based: bool = False
    user_based: bool = False
    backoff_required: bool = False
    requests_per_minute: Optional[int] = None


@dataclass
class LoadBalancerStickiness:
    """Load balancer session stickiness"""
    detected: bool = False
    cookie_name: Optional[str] = None
    cookie_based: bool = False
    ip_based: bool = False
    url_based: bool = False


@dataclass
class ABTestingInfo:
    """A/B testing detection"""
    detected: bool = False
    cookies: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    variants_detected: int = 0
    experiment_names: List[str] = field(default_factory=list)


@dataclass
class BotDetectionInfo:
    """Bot detection mechanisms"""
    detected: bool = False
    challenge_page: bool = False
    captcha_present: bool = False
    javascript_challenge: bool = False
    headers: List[str] = field(default_factory=list)


@dataclass
class BehavioralPatterns:
    """Behavioral fingerprinting results"""
    rate_limiting: RateLimitingInfo = field(default_factory=RateLimitingInfo)
    load_balancer_stickiness: LoadBalancerStickiness = field(default_factory=LoadBalancerStickiness)
    ab_testing: ABTestingInfo = field(default_factory=ABTestingInfo)
    bot_detection: BotDetectionInfo = field(default_factory=BotDetectionInfo)


# ===============================
# PERFORMANCE & RELIABILITY
# ===============================

@dataclass
class ResponseTimeMetrics:
    """Response time analysis"""
    ttfb_ms: float = 0.0
    total_time_ms: float = 0.0
    dns_time_ms: Optional[float] = None
    connect_time_ms: Optional[float] = None
    ssl_time_ms: Optional[float] = None
    transfer_time_ms: Optional[float] = None
    samples: List[float] = field(default_factory=list)
    
    @property
    def avg_time_ms(self) -> float:
        if not self.samples:
            return self.ttfb_ms
        return sum(self.samples) / len(self.samples)


@dataclass
class CachingAnalysis:
    """Caching headers analysis"""
    cache_control: Optional[str] = None
    pragma: Optional[str] = None
    expires: Optional[datetime] = None
    etag: Optional[str] = None
    last_modified: Optional[datetime] = None
    age: Optional[int] = None
    cache_hit: bool = False
    cdn_cache_hit: bool = False
    vary_headers: List[str] = field(default_factory=list)
    
    @property
    def cacheable(self) -> bool:
        return self.cache_control not in ['no-cache', 'no-store', 'private']


@dataclass
class CompressionAnalysis:
    """Compression support analysis"""
    gzip_supported: bool = False
    brotli_supported: bool = False
    deflate_supported: bool = False
    content_encoding: Optional[str] = None
    compression_ratio: Optional[float] = None
    original_size: Optional[int] = None
    compressed_size: Optional[int] = None


@dataclass
class KeepAliveAnalysis:
    """Keep-Alive connection analysis"""
    keep_alive_supported: bool = False
    timeout_seconds: Optional[int] = None
    max_requests: Optional[int] = None
    connection_header: Optional[str] = None


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics"""
    response_times: Dict[str, ResponseTimeMetrics] = field(default_factory=dict)
    caching: CachingAnalysis = field(default_factory=CachingAnalysis)
    compression: CompressionAnalysis = field(default_factory=CompressionAnalysis)
    keep_alive: KeepAliveAnalysis = field(default_factory=KeepAliveAnalysis)
    error_rate: float = 0.0
    timeout_rate: float = 0.0
    uptime_estimate: float = 100.0
    
    @property
    def performance_score(self) -> int:
        """Calculate performance score (0-100)"""
        score = 100
        
        # Response time deductions
        avg_ttfb = self.response_times.get('main_page', ResponseTimeMetrics()).avg_time_ms
        if avg_ttfb > 1000:
            score -= 40
        elif avg_ttfb > 500:
            score -= 20
        elif avg_ttfb > 200:
            score -= 10
        
        # Caching deductions
        if not self.caching.cacheable:
            score -= 20
        
        # Compression bonus
        if self.compression.compression_ratio and self.compression.compression_ratio > 2:
            score += 10
        elif self.compression.compression_ratio and self.compression.compression_ratio > 1.5:
            score += 5
        
        # Error rate deductions
        score -= int(self.error_rate * 100)
        
        return max(0, min(100, score))
    
    @property
    def reliability_score(self) -> int:
        """Calculate reliability score (0-100)"""
        return max(0, 100 - int(self.error_rate * 100) - int(self.timeout_rate * 100))


# ===============================
# RISK SCORING & RECOMMENDATIONS
# ===============================

@dataclass
class RiskScores:
    """Comprehensive risk scoring"""
    security_score: int = 0
    performance_score: int = 0
    reliability_score: int = 0
    overall_score: int = 0
    risk_level: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    security_headers_score: int = 0
    tls_score: int = 0
    information_disclosure_score: int = 0
    vulnerability_score: int = 0
    configuration_score: int = 0


@dataclass
class Recommendation:
    """Actionable recommendation"""
    category: str  # security, performance, reliability, architecture
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    issue: str
    recommendation: str
    evidence: Optional[str] = None


# ===============================
# ROOT HTTP INTELLIGENCE MODEL
# ===============================

@dataclass
class HTTPIntelligence:
    """
    Complete HTTP intelligence container.
    Aggregates all web analysis results.
    """
    
    # ===============================
    # BASIC INFO
    # ===============================
    url: str
    hostname: str
    port: int
    protocol: str  # http, https
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    
    # ===============================
    # CORE INTELLIGENCE OBJECTS
    # ===============================
    protocol_support: ProtocolSupport = field(default_factory=ProtocolSupport)
    redirect_chain: RedirectChain = field(default_factory=RedirectChain)
    virtual_hosts: List[VirtualHost] = field(default_factory=list)
    method_analysis: MethodAnalysis = field(default_factory=MethodAnalysis)
    
    endpoint_discovery: EndpointDiscovery = field(default_factory=EndpointDiscovery)
    technology_stack: TechnologyStack = field(default_factory=TechnologyStack)
    security_headers: SecurityHeaders = field(default_factory=SecurityHeaders)
    content_analysis: ContentAnalysis = field(default_factory=ContentAnalysis)
    
    vulnerability_indicators: VulnerabilityIndicators = field(default_factory=VulnerabilityIndicators)
    modern_web: ModernWebFeatures = field(default_factory=ModernWebFeatures)
    behavioral_patterns: BehavioralPatterns = field(default_factory=BehavioralPatterns)
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    
    # ===============================
    # RISK ASSESSMENT
    # ===============================
    risk_scores: RiskScores = field(default_factory=RiskScores)
    recommendations: List[Recommendation] = field(default_factory=list)
    
    # ===============================
    # METADATA
    # ===============================
    analysis_duration_ms: Optional[float] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    debug_info: Dict[str, Any] = field(default_factory=dict)
    
    # ===============================
    # RAW DATA
    # ===============================
    raw_responses: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_risk_scores(self) -> None:
        """Calculate all risk scores"""
        
        # Security score
        security_score = 0
        security_score += self.security_headers.security_score * 0.3  # 30%
        
        # TLS score (from connectivity layer or TLS layer)
        if hasattr(self, 'tls_score'):
            security_score += self.tls_score * 0.2  # 20%
        
        # Information disclosure (20%)
        disclosure_score = 100 - self.vulnerability_indicators.risk_score
        security_score += disclosure_score * 0.2
        
        # Vulnerability indicators (20%)
        security_score += (100 - self.vulnerability_indicators.risk_score) * 0.2
        
        # Configuration (10%)
        config_score = 100
        if self.vulnerability_indicators.configuration_issues.admin_interfaces_exposed:
            config_score -= 30
        if self.vulnerability_indicators.configuration_issues.php_info_pages:
            config_score -= 20
        security_score += config_score * 0.1
        
        self.risk_scores.security_score = int(security_score)
        self.risk_scores.security_headers_score = self.security_headers.security_score
        self.risk_scores.vulnerability_score = self.vulnerability_indicators.risk_score
        
        # Performance score
        self.risk_scores.performance_score = self.performance.performance_score
        
        # Reliability score
        self.risk_scores.reliability_score = self.performance.reliability_score
        
        # Overall score (weighted average)
        self.risk_scores.overall_score = int(
            (self.risk_scores.security_score * 0.5) +
            (self.risk_scores.performance_score * 0.3) +
            (self.risk_scores.reliability_score * 0.2)
        )
        
        # Risk level
        if self.risk_scores.overall_score >= 90:
            self.risk_scores.risk_level = "INFO"
        elif self.risk_scores.overall_score >= 70:
            self.risk_scores.risk_level = "LOW"
        elif self.risk_scores.overall_score >= 50:
            self.risk_scores.risk_level = "MEDIUM"
        elif self.risk_scores.overall_score >= 30:
            self.risk_scores.risk_level = "HIGH"
        else:
            self.risk_scores.risk_level = "CRITICAL"
    
    def generate_recommendations(self) -> None:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Security headers
        if not self.security_headers.hsts.present:
            recommendations.append(Recommendation(
                category="security",
                severity="HIGH",
                issue="Missing HSTS header",
                recommendation="Implement Strict-Transport-Security header with max-age=31536000 and includeSubDomains"
            ))
        
        if not self.security_headers.csp.present:
            recommendations.append(Recommendation(
                category="security",
                severity="MEDIUM",
                issue="Missing Content-Security-Policy header",
                recommendation="Implement CSP to mitigate XSS and data injection attacks"
            ))
        
        if self.security_headers.csp.unsafe_inline:
            recommendations.append(Recommendation(
                category="security",
                severity="HIGH",
                issue="CSP allows unsafe-inline",
                recommendation="Remove 'unsafe-inline' from CSP and use nonces or hashes instead"
            ))
        
        # Information disclosure
        if self.vulnerability_indicators.information_disclosure.server_version_leak:
            recommendations.append(Recommendation(
                category="security",
                severity="MEDIUM",
                issue="Server version information disclosed",
                recommendation="Remove or obfuscate Server header to prevent version enumeration"
            ))
        
        if self.vulnerability_indicators.information_disclosure.directory_listing_enabled:
            recommendations.append(Recommendation(
                category="security",
                severity="HIGH",
                issue="Directory listing enabled",
                recommendation=f"Disable directory listing for: {self.vulnerability_indicators.information_disclosure.directory_listing_enabled}"
            ))
        
        if self.vulnerability_indicators.information_disclosure.git_folder_exposed:
            recommendations.append(Recommendation(
                category="security",
                severity="CRITICAL",
                issue=".git folder exposed",
                recommendation="Restrict access to .git folder immediately - contains source code and history"
            ))
        
        # Performance
        if self.performance.compression.content_encoding != 'gzip' and self.performance.compression.content_encoding != 'br':
            recommendations.append(Recommendation(
                category="performance",
                severity="MEDIUM",
                issue="Compression not enabled",
                recommendation="Enable gzip or brotli compression to reduce bandwidth and improve load times"
            ))
        
        if not self.performance.caching.cacheable:
            recommendations.append(Recommendation(
                category="performance",
                severity="LOW",
                issue="Caching not configured",
                recommendation="Implement proper caching headers for static assets"
            ))
        
        self.recommendations = recommendations
    
    @property
    def summary(self) -> Dict[str, Any]:
        """Quick summary of HTTP analysis"""
        return {
            'url': self.url,
            'protocols': {
                'http1.1': self.protocol_support.http_1_1,
                'http2': self.protocol_support.http_2,
                'http3': self.protocol_support.http_3,
                'websocket': self.protocol_support.websocket_supported
            },
            'redirect_chain_length': self.redirect_chain.redirect_count,
            'final_url': self.redirect_chain.final_url,
            'endpoints_discovered': self.endpoint_discovery.total_discovered,
            'web_server': self.technology_stack.web_server.software,
            'framework': [f.name for f in self.technology_stack.frameworks if f.confidence > 0.5],
            'cms': self.technology_stack.cms.name if self.technology_stack.cms else None,
            'security_score': self.risk_scores.security_score,
            'performance_score': self.risk_scores.performance_score,
            'reliability_score': self.risk_scores.reliability_score,
            'risk_level': self.risk_scores.risk_level,
            'recommendations_count': len(self.recommendations)
        }