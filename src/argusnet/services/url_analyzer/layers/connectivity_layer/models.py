# src/argusnet/services/url_analyzer/layers/connectivity_layer/models.py

"""
Connectivity Intelligence Models
Data structures for port scanning, service fingerprinting, TLS analysis,
and architecture inference.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

# ==========================================================
# 1. PORT INTELLIGENCE
# ==========================================================

@dataclass
class PortService:
    """Individual open port with service information"""
    port: int
    protocol: str                 # "tcp" | "udp"
    state: str                    # "open" | "closed" | "filtered"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    banner_raw: Optional[bytes] = None
    response_time_ms: Optional[float] = None
    is_standard: bool = True


@dataclass
class PortScanResult:
    """Complete result of scanning a single port"""
    port: int
    protocol: str = "tcp"
    state: str = "filtered"  # open, closed, filtered, unfiltered
    service: Optional[str] = None
    banner: Optional[str] = None
    banner_raw: Optional[bytes] = None
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


@dataclass
class ServiceFingerprint:
    """Detailed fingerprint of a service"""
    port: int
    service: str
    banner: Optional[str]
    protocol: Optional[str]
    version: Optional[str]
    os_hint: Optional[str]
    confidence: float
    fingerprint_hash: Optional[str] = None
    cpe: Optional[str] = None  # Common Platform Enumeration


@dataclass
class PortIntelligence:
    """Collection of port-related intelligence"""
    open_ports: List[PortService] = field(default_factory=list)
    filtered_ports: List[int] = field(default_factory=list)
    closed_ports: List[int] = field(default_factory=list)
    
    port_categories: Dict[str, List[int]] = field(default_factory=dict)
    sensitive_ports: List[int] = field(default_factory=list)
    database_ports: List[int] = field(default_factory=list)
    non_standard_ports: List[int] = field(default_factory=list)
    
    service_fingerprints: List[ServiceFingerprint] = field(default_factory=list)
    
    unusual_port_usage: bool = False
    exposed_sensitive_service: bool = False
    
    @property
    def open_port_count(self) -> int:
        return len(self.open_ports)
    
    @property
    def filtered_port_count(self) -> int:
        return len(self.filtered_ports)
    
    @property
    def closed_port_count(self) -> int:
        return len(self.closed_ports)


# ==========================================================
# 2. PERFORMANCE & RTT
# ==========================================================

@dataclass
class RTTMetrics:
    """Round-trip time and performance metrics"""
    baseline_rtt_ms: Optional[float] = None
    min_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_percent: Optional[float] = None
    rtt_samples: List[float] = field(default_factory=list)
    
    @property
    def rtt_stability(self) -> Optional[str]:
        """Classify RTT stability"""
        if self.jitter_ms is None:
            return None
        if self.jitter_ms < 5:
            return "Very Stable"
        elif self.jitter_ms < 20:
            return "Stable"
        elif self.jitter_ms < 50:
            return "Moderate"
        else:
            return "Unstable"


# ==========================================================
# 3. IPv6 INTELLIGENCE
# ==========================================================

@dataclass
class IPv6Info:
    """IPv6 capability and configuration information"""
    ipv6_enabled: bool = False
    dual_stack: bool = False
    ipv6_addresses: List[str] = field(default_factory=list)
    ipv6_only: bool = False
    ipv6_reachability: Optional[bool] = None
    ipv6_rtt_ms: Optional[float] = None
    
    @property
    def stack_type(self) -> str:
        """Describe the IP stack configuration"""
        if self.ipv6_only:
            return "IPv6 Only"
        elif self.dual_stack:
            return "Dual Stack"
        elif self.ipv6_enabled:
            return "IPv6 Enabled"
        else:
            return "IPv4 Only"


# ==========================================================
# 4. TLS INTELLIGENCE
# ==========================================================

@dataclass
class CertificateInfo:
    """SSL/TLS certificate details"""
    subject: str
    issuer: str
    san_list: List[str]
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    key_algorithm: str
    key_size: int
    signature_algorithm: str
    serial_number: str
    fingerprint: str
    is_self_signed: bool
    is_expired: bool
    is_valid_hostname: bool
    revocation_status: Optional[str] = None
    chain_length: int = 1
    
    @property
    def is_trusted(self) -> bool:
        """Check if certificate is trusted (not expired, not self-signed)"""
        return not self.is_expired and not self.is_self_signed
    
    @property
    def days_until_renewal(self) -> int:
        """Days until certificate renewal recommended (30 days before expiry)"""
        return max(0, self.days_until_expiry - 30)


@dataclass
class TLSIntelligence:
    """TLS/SSL configuration and certificate intelligence"""
    certificates: List[CertificateInfo] = field(default_factory=list)
    tls_versions: List[str] = field(default_factory=list)
    weak_protocols: List[str] = field(default_factory=list)
    weak_protocols_detected: bool = False
    cipher_suites: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    compression_enabled: bool = False
    secure_renegotiation: Optional[bool] = None
    ocsp_stapling: bool = False
    hsts_enabled: bool = False
    
    @property
    def tls_score(self) -> int:
        """Calculate TLS security score (0-100)"""
        score = 100
        
        # Deductions for weak protocols
        if 'SSLv3' in self.weak_protocols:
            score -= 30
        if 'TLSv1.0' in self.weak_protocols:
            score -= 20
        if 'TLSv1.1' in self.weak_protocols:
            score -= 10
        
        # Deductions for certificate issues
        for cert in self.certificates:
            if cert.is_expired:
                score -= 40
            if cert.is_self_signed:
                score -= 20
            if cert.days_until_expiry < 30:
                score -= 15
            if cert.key_size < 2048:
                score -= 25
        
        # Deductions for weak ciphers
        score -= len(self.weak_ciphers) * 5
        
        # Additions for good practices
        if 'TLSv1.3' in self.tls_versions:
            score += 15
        if self.hsts_enabled:
            score += 10
        if self.ocsp_stapling:
            score += 10
        
        return max(0, min(100, score))


# ==========================================================
# 5. TCP STACK FINGERPRINT
# ==========================================================

@dataclass
class TCPStackFingerprint:
    """TCP/IP stack fingerprint for OS detection"""
    window_size: Optional[int] = None
    ttl: Optional[int] = None
    mss: Optional[int] = None
    window_scaling: Optional[int] = None
    sack_ok: Optional[bool] = None
    nop: Optional[bool] = None
    wscale: Optional[int] = None
    timestamp: Optional[bool] = None
    guessed_os: Optional[str] = None
    os_confidence: Optional[float] = None
    os_family: Optional[str] = None  # Windows, Linux, BSD, etc
    
    @property
    def ttl_category(self) -> Optional[str]:
        """Categorize TTL value"""
        if self.ttl is None:
            return None
        if self.ttl <= 64:
            return "Unix/Linux"
        elif self.ttl <= 128:
            return "Windows"
        elif self.ttl <= 255:
            return "Network Device"
        else:
            return "Unknown"


# ==========================================================
# 6. BANNER & RESPONSE ANALYSIS
# ==========================================================

@dataclass
class BannerInfo:
    """Captured banner information"""
    banner: str
    banner_raw: bytes
    port: int
    protocol: str
    encoding: str = "utf-8"
    is_truncated: bool = False


@dataclass
class ResponseAnalysis:
    """HTTP/HTTPS response analysis"""
    status_code: int
    status_text: str
    headers: Dict[str, str]
    server_header: Optional[str]
    content_type: Optional[str]
    content_length: Optional[str]
    location: Optional[str]
    cookies: List[Dict[str, str]]
    response_time_ms: Optional[str]
    url: str
    technologies: List[str] = field(default_factory=list)
    body_preview: Optional[str] = None
    title: Optional[str] = None
    
    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect"""
        return self.status_code in [301, 302, 303, 307, 308]
    
    @property
    def is_error(self) -> bool:
        """Check if response is an error"""
        return self.status_code >= 400
    
    @property
    def server_signature(self) -> Optional[str]:
        """Extract server signature"""
        if self.server_header:
            return self.server_header.split('/')[0].lower()
        return None


# ==========================================================
# 7. CDN & LOAD BALANCER DETECTION
# ==========================================================

@dataclass
class CDNDetection:
    """CDN provider detection results"""
    provider: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    detection_methods: List[str] = field(default_factory=list)
    
    @property
    def is_detected(self) -> bool:
        return self.provider is not None and self.confidence >= 0.5


@dataclass
class LoadBalancerInfo:
    """Load balancer detection results"""
    detected: bool = False
    method: Optional[str] = None
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    provider: Optional[str] = None  # F5, Netscaler, HAProxy, etc
    
    @property
    def is_likely(self) -> bool:
        return self.detected and self.confidence >= 0.6


# ==========================================================
# 8. ARCHITECTURE PATTERN
# ==========================================================

@dataclass
class ArchitecturePattern:
    """Inferred infrastructure architecture patterns"""
    cdn_detected: bool = False
    load_balancer_detected: bool = False
    high_availability: bool = False
    ha_score: int = 0
    cloud_provider: Optional[str] = None
    waf_detected: bool = False  # Web Application Firewall
    reverse_proxy_detected: bool = False
    caching_detected: bool = False
    
    @property
    def complexity_level(self) -> str:
        """Classify infrastructure complexity"""
        score = 0
        if self.cdn_detected:
            score += 1
        if self.load_balancer_detected:
            score += 1
        if self.high_availability:
            score += 1
        if self.waf_detected:
            score += 1
        if self.reverse_proxy_detected:
            score += 1
        if self.caching_detected:
            score += 1
        if self.cloud_provider:
            score += 1
            
        if score >= 5:
            return "Complex Enterprise"
        elif score >= 3:
            return "Medium"
        elif score >= 1:
            return "Simple"
        else:
            return "Basic"


# ==========================================================
# 9. SCAN SUMMARY
# ==========================================================

@dataclass
class ConnectivityScanSummary:
    """Summary of connectivity scan results"""
    target_ip: str
    target_hostname: Optional[str]
    scan_duration_ms: float
    open_ports_count: int
    total_ports_scanned: int
    services_identified: List[str]
    tls_certificates_count: int
    cdn_provider: Optional[str]
    load_balancer_detected: bool
    cloud_provider: Optional[str]
    risk_level: str
    risk_score: int
    
    @property
    def scan_speed_pps(self) -> float:
        """Ports per second scan rate"""
        if self.scan_duration_ms > 0:
            return (self.total_ports_scanned / self.scan_duration_ms) * 1000
        return 0


# ==========================================================
# 10. ROOT CONNECTIVITY INTELLIGENCE
# ==========================================================

@dataclass
class ConnectivityIntelligence:
    """
    Complete connectivity intelligence container.
    Aggregates all port scanning, service fingerprinting, TLS analysis,
    and architecture inference results.
    """
    
    # ====================================================
    # TARGET IDENTIFICATION
    # ====================================================
    target_ip: Optional[str] = None
    target_hostname: Optional[str] = None
    
    # ====================================================
    # TIMING
    # ====================================================
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    scan_duration_ms: Optional[float] = None
    
    # ====================================================
    # CORE INTELLIGENCE OBJECTS
    # ====================================================
    port_intel: PortIntelligence = field(default_factory=PortIntelligence)
    performance: RTTMetrics = field(default_factory=RTTMetrics)
    ipv6: IPv6Info = field(default_factory=IPv6Info)
    tls_intelligence: Optional[TLSIntelligence] = None
    tcp_stack_fingerprint: Optional[TCPStackFingerprint] = None
    architecture: ArchitecturePattern = field(default_factory=ArchitecturePattern)
    cdn_detection: CDNDetection = field(default_factory=CDNDetection)
    load_balancer_info: LoadBalancerInfo = field(default_factory=LoadBalancerInfo)
    
    # ====================================================
    # HTTP INTELLIGENCE
    # ====================================================
    http_responses: Dict[int, ResponseAnalysis] = field(default_factory=dict)
    
    # ====================================================
    # RISK SCORING
    # ====================================================
    risk_score: int = 0
    risk_level: str = "INFO"
    risk_factors: List[str] = field(default_factory=list)
    
    # ====================================================
    # GENERAL STATUS
    # ====================================================
    reachable: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # ====================================================
    # METADATA
    # ====================================================
    debug_info: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def scan_summary(self) -> ConnectivityScanSummary:
        """Generate scan summary"""
        return ConnectivityScanSummary(
            target_ip=self.target_ip or "Unknown",
            target_hostname=self.target_hostname,
            scan_duration_ms=self.scan_duration_ms or 0,
            open_ports_count=len(self.port_intel.open_ports),
            total_ports_scanned=(len(self.port_intel.open_ports) + 
                               len(self.port_intel.filtered_ports) + 
                               len(self.port_intel.closed_ports)),
            services_identified=list(set(
                p.service for p in self.port_intel.open_ports if p.service
            )),
            tls_certificates_count=len(self.tls_intelligence.certificates) if self.tls_intelligence else 0,
            cdn_provider=self.cdn_detection.provider,
            load_balancer_detected=self.load_balancer_info.detected,
            cloud_provider=self.architecture.cloud_provider,
            risk_level=self.risk_level,
            risk_score=self.risk_score
        )
    
    @property
    def has_web_server(self) -> bool:
        """Check if web server is detected"""
        web_ports = [80, 443, 8080, 8443, 8000, 8888]
        return any(p.port in web_ports for p in self.port_intel.open_ports)
    
    @property
    def has_database(self) -> bool:
        """Check if database is exposed"""
        return len(self.port_intel.database_ports) > 0
    
    @property
    def has_sensitive_services(self) -> bool:
        """Check if sensitive services are exposed"""
        return self.port_intel.exposed_sensitive_service