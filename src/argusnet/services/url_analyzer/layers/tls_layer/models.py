# src/argusnet/services/url_analyzer/layers/tls_layer/models.py

"""
TLS Intelligence Models
Comprehensive data structures for TLS/SSL analysis, certificate inspection,
cryptographic assessment, and vulnerability detection.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from datetime import datetime
from enum import Enum


# ===============================
# TLS-SPECIFIC ENUMS
# ===============================

class TLSVersion(Enum):
    """TLS protocol versions"""
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"
    UNKNOWN = "Unknown"


class CipherSuite(Enum):
    """Cipher suite categories"""
    AEAD = "AEAD"
    PFS = "Perfect Forward Secrecy"
    WEAK = "Weak"
    STRONG = "Strong"
    EXPORT = "Export-grade"
    NULL = "Null encryption"
    ANON = "Anonymous"
    DEPRECATED = "Deprecated"


class KeyAlgorithm(Enum):
    """Public key algorithms"""
    RSA = "RSA"
    ECDSA = "ECDSA"
    DSA = "DSA"
    Ed25519 = "Ed25519"
    Ed448 = "Ed448"
    DH = "Diffie-Hellman"
    EC = "Elliptic Curve"
    GOST = "GOST"
    UNKNOWN = "Unknown"


class HashAlgorithm(Enum):
    """Hash algorithms used in signatures"""
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    SHA224 = "SHA224"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"
    UNKNOWN = "Unknown"


class CertificateStatus(Enum):
    """Certificate validity status"""
    VALID = "Valid"
    EXPIRED = "Expired"
    NOT_YET_VALID = "Not yet valid"
    REVOKED = "Revoked"
    SELF_SIGNED = "Self-signed"
    UNTRUSTED = "Untrusted"
    UNKNOWN = "Unknown"


class RevocationStatus(Enum):
    """Revocation check status"""
    GOOD = "Good"
    REVOKED = "Revoked"
    UNKNOWN = "Unknown"
    FAILED = "Check failed"
    NOT_CHECKED = "Not checked"
    OCSP_REQUIRED = "OCSP required"


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TLSGrade(Enum):
    """SSL Labs-style grading"""
    A_PLUS = "A+"
    A = "A"
    A_MINUS = "A-"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"
    T = "T"  # No TLS


# ===============================
# CERTIFICATE MODELS
# ===============================

@dataclass
class SubjectInfo:
    """Certificate subject information"""
    common_name: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    locality: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    email: Optional[str] = None
    serial_number: Optional[str] = None
    street_address: Optional[str] = None
    postal_code: Optional[str] = None
    business_category: Optional[str] = None
    jurisdiction: Optional[str] = None
    
    @property
    def full_string(self) -> str:
        """Return full subject string in RFC 4514 format"""
        parts = []
        if self.common_name:
            parts.append(f"CN={self.common_name}")
        if self.organization:
            parts.append(f"O={self.organization}")
        if self.organizational_unit:
            parts.append(f"OU={self.organizational_unit}")
        if self.locality:
            parts.append(f"L={self.locality}")
        if self.state:
            parts.append(f"ST={self.state}")
        if self.country:
            parts.append(f"C={self.country}")
        if self.email:
            parts.append(f"E={self.email}")
        return ", ".join(parts)


@dataclass
class IssuerInfo:
    """Certificate issuer information"""
    common_name: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    locality: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    email: Optional[str] = None
    ca_name: Optional[str] = None  # Friendly CA name (Let's Encrypt, DigiCert, etc.)
    is_trusted: bool = True
    trust_store: List[str] = field(default_factory=list)  # Which trust stores include this CA
    
    @property
    def full_string(self) -> str:
        """Return full issuer string in RFC 4514 format"""
        parts = []
        if self.common_name:
            parts.append(f"CN={self.common_name}")
        if self.organization:
            parts.append(f"O={self.organization}")
        if self.organizational_unit:
            parts.append(f"OU={self.organizational_unit}")
        if self.locality:
            parts.append(f"L={self.locality}")
        if self.state:
            parts.append(f"ST={self.state}")
        if self.country:
            parts.append(f"C={self.country}")
        return ", ".join(parts)


@dataclass
class PublicKeyInfo:
    """Public key details"""
    algorithm: KeyAlgorithm
    bits: int  # Key size in bits
    curve: Optional[str] = None  # For EC keys (secp256r1, etc.)
    fingerprint: Optional[str] = None  # Public key fingerprint
    modulus: Optional[str] = None  # RSA modulus (hex)
    exponent: int = 65537  # RSA public exponent
    valid_for_signing: bool = True
    valid_for_encryption: bool = True
    debian_weak_key: bool = False  # CVE-2008-0166
    roca_vulnerable: bool = False  # CVE-2017-15361
    reuse_count: int = 1  # Number of certificates sharing this key


@dataclass
class ExtensionInfo:
    """X.509 certificate extension"""
    oid: str
    name: str
    critical: bool
    value: Any
    description: Optional[str] = None


@dataclass
class SANEntry:
    """Subject Alternative Name entry"""
    type: str  # DNS, IP, email, URI
    value: str
    is_wildcard: bool = False
    
    @property
    def domain(self) -> Optional[str]:
        """Extract domain from DNS entry"""
        if self.type == 'DNS':
            return self.value.replace('*.', '')
        return None


@dataclass
class CTLogEntry:
    """Certificate Transparency log entry"""
    log_name: str
    log_id: str
    timestamp: datetime
    sct_version: int
    signature: str
    verified: bool = False
    embedded: bool = True  # Embedded in certificate vs. delivered separately


@dataclass
class CertificateInfo:
    """
    Comprehensive X.509 certificate information
    """
    # Basic Info
    serial_number: str
    fingerprint_sha1: str
    fingerprint_sha256: str
    version: int
    
    # Subject & Issuer
    subject: SubjectInfo
    issuer: IssuerInfo
    
    # Validity
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    days_since_issued: int
    status: CertificateStatus
    
    # Public Key
    public_key: PublicKeyInfo
    
    # Signature
    signature_algorithm: str
    hash_algorithm: HashAlgorithm
    signature_value: str
    
    # Extensions
    extensions: List[ExtensionInfo] = field(default_factory=list)
    san_entries: List[SANEntry] = field(default_factory=list)
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    basic_constraints: Optional[Dict[str, Any]] = None
    name_constraints: Optional[Dict[str, Any]] = None
    policy_oids: List[str] = field(default_factory=list)
    authority_info: Dict[str, str] = field(default_factory=dict)  # CA Issuers, OCSP
    crl_distribution_points: List[str] = field(default_factory=list)
    
    # Certificate Transparency
    ct_logs: List[CTLogEntry] = field(default_factory=list)
    sct_count: int = 0
    ct_compliant: bool = False
    
    # Chain Info
    chain_depth: int = 0
    is_ca: bool = False
    is_self_signed: bool = False
    is_leaf: bool = True
    is_intermediate: bool = False
    is_root: bool = False
    
    # Revocation
    revocation_status: RevocationStatus = RevocationStatus.NOT_CHECKED
    revocation_check_time: Optional[datetime] = None
    ocsp_uri: Optional[str] = None
    ocsp_response: Optional[Dict[str, Any]] = None
    crl_uris: List[str] = field(default_factory=list)
    crl_check_results: Dict[str, bool] = field(default_factory=dict)
    
    # Metadata
    source: str = "direct"  # direct, ct_log, archive
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    queried_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def common_names(self) -> List[str]:
        """Extract all common names (CN and SANs)"""
        names = []
        if self.subject.common_name:
            names.append(self.subject.common_name)
        for san in self.san_entries:
            if san.type == 'DNS' and san.value not in names:
                names.append(san.value)
        return names
    
    @property
    def domains(self) -> List[str]:
        """Extract all domains (excluding wildcards)"""
        domains = set()
        for name in self.common_names:
            if name.startswith('*.'):
                domains.add(name[2:])
            else:
                domains.add(name)
        return sorted(list(domains))
    
    @property
    def wildcard_domains(self) -> List[str]:
        """Extract wildcard domains"""
        wildcards = []
        for san in self.san_entries:
            if san.type == 'DNS' and san.is_wildcard:
                wildcards.append(san.value)
        return wildcards
    
    @property
    def expired(self) -> bool:
        return self.status == CertificateStatus.EXPIRED
    
    @property
    def trusted(self) -> bool:
        return self.status == CertificateStatus.VALID and not self.is_self_signed
    
    @property
    def weak_crypto(self) -> bool:
        """Check for weak cryptographic parameters"""
        if self.public_key.bits < 2048 and self.public_key.algorithm == KeyAlgorithm.RSA:
            return True
        if self.hash_algorithm in [HashAlgorithm.MD5, HashAlgorithm.SHA1]:
            return True
        if self.public_key.roca_vulnerable:
            return True
        return False


@dataclass
class CertificateChain:
    """Complete certificate chain"""
    leaf: CertificateInfo
    intermediates: List[CertificateInfo] = field(default_factory=list)
    root: Optional[CertificateInfo] = None
    
    @property
    def complete(self) -> bool:
        """Is the chain complete to a trusted root?"""
        return self.root is not None and self.root.issuer.is_trusted
    
    @property
    def length(self) -> int:
        """Total chain length"""
        return 1 + len(self.intermediates) + (1 if self.root else 0)
    
    @property
    def issues(self) -> List[str]:
        """Identify chain issues"""
        issues = []
        if not self.complete:
            issues.append("Incomplete chain - missing certificates")
        if self.leaf.expired:
            issues.append("Leaf certificate expired")
        for i, cert in enumerate(self.intermediates):
            if cert.expired:
                issues.append(f"Intermediate {i+1} expired")
        if self.root and self.root.issuer.is_trusted is False:
            issues.append("Root certificate not trusted")
        return issues


# ===============================
# CIPHER & PROTOCOL MODELS
# ===============================

@dataclass
class CipherInfo:
    """Detailed cipher suite information"""
    name: str  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    hex_code: str  # 0xC0,0x2F
    iana_name: str  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    openssl_name: str  # ECDHE-RSA-AES256-GCM-SHA384
    
    # Protocol
    protocol: TLSVersion
    kx_algorithm: str  # ECDHE, RSA, DHE, etc.
    auth_algorithm: str  # RSA, ECDSA, PSK, etc.
    enc_algorithm: str  # AES, CHACHA20, CAMELLIA, etc.
    enc_mode: str  # GCM, CCM, CBC, etc.
    enc_key_size: int  # 128, 256, etc.
    mac_algorithm: str  # SHA256, SHA384, POLY1305, etc.
    prf_algorithm: str  # SHA256, SHA384, etc.
    
    # Security
    category: CipherSuite
    provides_pfs: bool  # Perfect Forward Secrecy
    provides_aead: bool  # Authenticated Encryption with Associated Data
    is_export: bool  # Export-grade cipher
    is_null: bool  # Null encryption
    is_anon: bool  # Anonymous authentication
    is_deprecated: bool  # Deprecated by RFC
    is_weak: bool  # Cryptographically weak
    
    # Performance
    relative_speed: str  # Fast, Medium, Slow
    hardware_accelerated: bool
    
    # Standards
    rfc: Optional[str] = None
    recommended: bool = False
    
    @property
    def security_level(self) -> str:
        """Return security level classification"""
        if self.is_null or self.is_anon:
            return "INSECURE"
        if self.is_export:
            return "WEAK (Export)"
        if self.is_deprecated:
            return "DEPRECATED"
        if self.category == CipherSuite.WEAK:
            return "WEAK"
        if self.category == CipherSuite.STRONG:
            return "STRONG"
        if self.category == CipherSuite.AEAD:
            return "AEAD (Strong)"
        return "UNKNOWN"


@dataclass
class ProtocolSupport:
    """TLS protocol version support"""
    sslv2: bool = False
    sslv3: bool = False
    tlsv1_0: bool = False
    tlsv1_1: bool = False
    tlsv1_2: bool = False
    tlsv1_3: bool = False
    
    # Version details
    tlsv1_3_early_data: bool = False  # 0-RTT support
    tlsv1_3_psk: bool = False  # Pre-shared keys support
    
    # Fallback
    downgrade_prevention: bool = False  # TLS_FALLBACK_SCSV
    min_version: Optional[TLSVersion] = None
    max_version: Optional[TLSVersion] = None
    preferred_version: Optional[TLSVersion] = None
    
    @property
    def supported_versions(self) -> List[TLSVersion]:
        """List of supported TLS versions"""
        versions = []
        if self.sslv2:
            versions.append(TLSVersion.SSLv2)
        if self.sslv3:
            versions.append(TLSVersion.SSLv3)
        if self.tlsv1_0:
            versions.append(TLSVersion.TLSv1_0)
        if self.tlsv1_1:
            versions.append(TLSVersion.TLSv1_1)
        if self.tlsv1_2:
            versions.append(TLSVersion.TLSv1_2)
        if self.tlsv1_3:
            versions.append(TLSVersion.TLSv1_3)
        return versions
    
    @property
    def weak_versions(self) -> List[TLSVersion]:
        """List of weak/deprecated versions"""
        weak = []
        if self.sslv2:
            weak.append(TLSVersion.SSLv2)
        if self.sslv3:
            weak.append(TLSVersion.SSLv3)
        if self.tlsv1_0:
            weak.append(TLSVersion.TLSv1_0)
        if self.tlsv1_1:
            weak.append(TLSVersion.TLSv1_1)
        return weak


@dataclass
class CipherPreference:
    """Server cipher preference information"""
    server_preferred: bool  # Server enforces order
    preferred_ciphers: List[CipherInfo]
    all_ciphers: List[CipherInfo]
    client_preference_result: Optional[List[CipherInfo]] = None
    
    @property
    def preferred_count(self) -> int:
        return len(self.preferred_ciphers)
    
    @property
    def total_count(self) -> int:
        return len(self.all_ciphers)
    
    @property
    def strong_count(self) -> int:
        return sum(1 for c in self.all_ciphers if c.security_level == "STRONG")


# ===============================
# TLS EXTENSIONS MODELS
# ===============================

@dataclass
class TLSExtension:
    """TLS extension information"""
    type: int
    name: str
    data: Optional[Any] = None
    critical: bool = False
    description: Optional[str] = None


@dataclass
class ALPNProtocol:
    """Application-Layer Protocol Negotiation"""
    protocol: str  # h2, http/1.1, spdy/3.1, etc.
    selected: bool = False
    advertised: bool = True


@dataclass
class SNIInfo:
    """Server Name Indication"""
    supported: bool
    required: bool  # Server requires SNI (may fail without it)
    default_certificate: Optional[str] = None  # Cert served without SNI
    virtual_hosts: List[str] = field(default_factory=list)  # Hosts with different certs


@dataclass
class OCSPStaplingInfo:
    """OCSP stapling information"""
    supported: bool
    enabled: bool
    response_stapled: bool
    response_valid: Optional[bool] = None
    response_age_seconds: Optional[int] = None
    must_staple: bool = False  # OCSP-Must-Staple extension
    responder_url: Optional[str] = None


@dataclass
class SessionInfo:
    """TLS session management"""
    session_id_supported: bool = False
    session_id_reused: Optional[bool] = None
    session_ticket_supported: bool = False
    session_ticket_reused: Optional[bool] = None
    ticket_lifetime_hint: Optional[int] = None
    ticket_rotation: Optional[str] = None
    session_cache_size: Optional[int] = None
    session_timeout: Optional[int] = None


@dataclass
class RenegotiationInfo:
    """TLS renegotiation information"""
    secure_renegotiation: bool
    renegotiation_allowed: bool
    client_initiated_allowed: bool
    vulnerability_mitigated: bool  # CVE-2009-3555


# ===============================
# VULNERABILITY MODELS
# ===============================

@dataclass
class VulnerabilityInfo:
    """TLS vulnerability information"""
    name: str
    cve: str
    severity: VulnerabilitySeverity
    description: str
    impact: str
    affected_versions: List[TLSVersion]
    vulnerable: bool
    exploited: Optional[bool] = None
    proof: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityScan:
    """Complete vulnerability scan results"""
    heartbleed: VulnerabilityInfo = None
    poodle: VulnerabilityInfo = None
    freak: VulnerabilityInfo = None
    logjam: VulnerabilityInfo = None
    drown: VulnerabilityInfo = None
    sweet32: VulnerabilityInfo = None
    robot: VulnerabilityInfo = None
    ticketbleed: VulnerabilityInfo = None
    cachebleed: VulnerabilityInfo = None
    crime: VulnerabilityInfo = None
    breach: VulnerabilityInfo = None
    rc4_nom: VulnerabilityInfo = None
    beast: VulnerabilityInfo = None
    lucks: VulnerabilityInfo = None
    
    @property
    def all_vulnerabilities(self) -> List[VulnerabilityInfo]:
        """Get all vulnerabilities"""
        vulns = []
        for attr in dir(self):
            if attr.endswith('bleed') or attr in ['poodle', 'freak', 'logjam', 'drown', 'robot']:
                vuln = getattr(self, attr)
                if vuln and vuln.vulnerable:
                    vulns.append(vuln)
        return vulns
    
    @property
    def vulnerable(self) -> bool:
        """Check if any vulnerability was found"""
        return len(self.all_vulnerabilities) > 0
    
    @property
    def critical_count(self) -> int:
        """Count critical vulnerabilities"""
        return sum(1 for v in self.all_vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count high severity vulnerabilities"""
        return sum(1 for v in self.all_vulnerabilities if v.severity == VulnerabilitySeverity.HIGH)


# ===============================
# PERFORMANCE MODELS
# ===============================

@dataclass
class HandshakeTiming:
    """TLS handshake timing metrics"""
    full_handshake_ms: float
    resumed_handshake_ms: Optional[float] = None
    tls13_0rtt_ms: Optional[float] = None
    dns_time_ms: Optional[float] = None
    tcp_handshake_ms: Optional[float] = None
    certificate_validation_ms: Optional[float] = None
    ocsp_check_ms: Optional[float] = None
    
    @property
    def resumption_ratio(self) -> Optional[float]:
        """Speed improvement from session resumption"""
        if self.resumed_handshake_ms and self.full_handshake_ms:
            return self.full_handshake_ms / self.resumed_handshake_ms
        return None


@dataclass
class CipherPerformance:
    """Performance per cipher suite"""
    cipher: str
    handshake_time_ms: float
    throughput_mbps: Optional[float] = None
    cpu_usage: Optional[float] = None


@dataclass
class TLSPerformanceMetrics:
    """TLS performance analysis"""
    handshake_timings: HandshakeTiming = field(default_factory=HandshakeTiming)
    cipher_performance: List[CipherPerformance] = field(default_factory=list)
    fastest_cipher: Optional[str] = None
    slowest_cipher: Optional[str] = None
    average_handshake_ms: float = 0.0
    connection_reuse_success: bool = False
    tls_1_3_fast: bool = False
    
    @property
    def performance_grade(self) -> str:
        """Grade TLS performance"""
        if self.average_handshake_ms < 100:
            return "A+ 🚀"
        elif self.average_handshake_ms < 200:
            return "A ✓"
        elif self.average_handshake_ms < 400:
            return "B ⚠"
        elif self.average_handshake_ms < 800:
            return "C ⚠"
        else:
            return "D ✗"


# ===============================
# TLS FINGERPRINTING
# ===============================

@dataclass
class TLSFingerprint:
    """TLS stack fingerprint"""
    ja3_hash: str  # Client fingerprint
    ja3s_hash: str  # Server fingerprint
    ja3_string: str  # Raw JA3 string
    client_suites: List[str]
    client_extensions: List[int]
    client_curves: List[str]
    server_suites: List[str]
    server_extensions: List[int]
    
    # Identified software
    library: Optional[str] = None  # OpenSSL, GnuTLS, NSS, Schannel, BoringSSL
    library_version: Optional[str] = None
    os_hint: Optional[str] = None
    confidence: float = 0.0
    
    # Known signatures
    matches_bot: bool = False
    matches_malware: bool = False
    matches_browser: Optional[str] = None  # Chrome, Firefox, Safari, etc.


# ===============================
# ROOT TLS INTELLIGENCE MODEL
# ===============================

@dataclass
class TLSIntelligence:
    """
    Complete TLS intelligence container.
    Aggregates all TLS/SSL analysis results.
    """
    
    # ===============================
    # BASIC INFO
    # ===============================
    target_host: str
    target_ip: str
    port: int
    protocol: str = "TLS"
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    
    # ===============================
    # CERTIFICATE CHAIN
    # ===============================
    certificate_chain: Optional[CertificateChain] = None
    all_certificates: List[CertificateInfo] = field(default_factory=list)
    chain_validated: bool = False
    chain_issues: List[str] = field(default_factory=list)
    
    # ===============================
    # PROTOCOL SUPPORT
    # ===============================
    protocol_support: ProtocolSupport = field(default_factory=ProtocolSupport)
    cipher_preference: CipherPreference = field(default_factory=CipherPreference)
    weak_ciphers: List[CipherInfo] = field(default_factory=list)
    strong_ciphers: List[CipherInfo] = field(default_factory=list)
    export_ciphers: List[CipherInfo] = field(default_factory=list)
    null_ciphers: List[CipherInfo] = field(default_factory=list)
    anon_ciphers: List[CipherInfo] = field(default_factory=list)
    
    # ===============================
    # TLS EXTENSIONS
    # ===============================
    extensions: List[TLSExtension] = field(default_factory=list)
    alpn_protocols: List[ALPNProtocol] = field(default_factory=list)
    sni: SNIInfo = field(default_factory=lambda: SNIInfo(supported=False, required=False))
    ocsp_stapling: OCSPStaplingInfo = field(default_factory=OCSPStaplingInfo)
    session_management: SessionInfo = field(default_factory=SessionInfo)
    renegotiation: RenegotiationInfo = field(default_factory=RenegotiationInfo)
    signed_cert_timestamps: List[CTLogEntry] = field(default_factory=list)
    
    # ===============================
    # VULNERABILITIES
    # ===============================
    vulnerability_scan: VulnerabilityScan = field(default_factory=VulnerabilityScan)
    vulnerabilities_found: List[VulnerabilityInfo] = field(default_factory=list)
    vulnerable: bool = False
    vulnerability_score: int = 0
    
    # ===============================
    # PERFORMANCE
    # ===============================
    performance: TLSPerformanceMetrics = field(default_factory=TLSPerformanceMetrics)
    
    # ===============================
    # FINGERPRINTING
    # ===============================
    fingerprint: Optional[TLSFingerprint] = None
    
    # ===============================
    # CERTIFICATE TRANSPARENCY
    # ===============================
    ct_logs_queried: bool = False
    historical_certificates: List[CertificateInfo] = field(default_factory=list)
    ct_compliant: bool = False
    
    # ===============================
    # STARTTLS (for non-HTTPS ports)
    # ===============================
    starttls_supported: bool = False
    starttls_protocol: Optional[str] = None  # smtp, pop3, imap, ftp, xmpp
    starttls_result: Optional['TLSIntelligence'] = None
    
    # ===============================
    # RISK SCORING
    # ===============================
    tls_score: int = 0
    grade: TLSGrade = TLSGrade.T
    grade_details: Dict[str, int] = field(default_factory=dict)
    
    # ===============================
    # RECOMMENDATIONS
    # ===============================
    recommendations: List['TLSRecommendation'] = field(default_factory=list)
    
    # ===============================
    # METADATA
    # ===============================
    analysis_duration_ms: Optional[float] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    debug_info: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_tls_score(self) -> int:
        """Calculate TLS security score (0-100)"""
        score = 100
        
        # Protocol version deductions
        if self.protocol_support.sslv2 or self.protocol_support.sslv3:
            score -= 40
        if self.protocol_support.tlsv1_0:
            score -= 20
        if self.protocol_support.tlsv1_1:
            score -= 10
        
        # Weak cipher deductions
        score -= len(self.weak_ciphers) * 2
        score -= len(self.export_ciphers) * 5
        score -= len(self.null_ciphers) * 10
        score -= len(self.anon_ciphers) * 8
        
        # Certificate issues
        if self.certificate_chain:
            if self.certificate_chain.leaf.expired:
                score -= 40
            if self.certificate_chain.leaf.weak_crypto:
                score -= 25
            if not self.certificate_chain.complete:
                score -= 15
        
        # Vulnerability deductions
        if self.vulnerable:
            score -= self.vulnerability_score
        
        # Good practice additions
        if self.protocol_support.tlsv1_3:
            score += 15
        if self.ocsp_stapling.enabled:
            score += 10
        if len(self.strong_ciphers) > 10:
            score += 10
        if self.sni.supported:
            score += 5
        
        # Ensure score is within bounds
        self.tls_score = max(0, min(100, score))
        return self.tls_score
    
    def calculate_grade(self) -> TLSGrade:
        """Calculate SSL Labs-style grade"""
        score = self.tls_score
        
        if score >= 90:
            if self.protocol_support.tlsv1_3 and len(self.weak_versions) == 0:
                self.grade = TLSGrade.A_PLUS
            else:
                self.grade = TLSGrade.A
        elif score >= 80:
            self.grade = TLSGrade.A_MINUS
        elif score >= 70:
            self.grade = TLSGrade.B
        elif score >= 60:
            self.grade = TLSGrade.C
        elif score >= 50:
            self.grade = TLSGrade.D
        elif score >= 30:
            self.grade = TLSGrade.E
        else:
            self.grade = TLSGrade.F
        
        return self.grade
    
    def generate_recommendations(self) -> None:
        """Generate actionable TLS recommendations"""
        recommendations = []
        
        # Protocol recommendations
        if self.protocol_support.sslv2 or self.protocol_support.sslv3:
            recommendations.append(TLSRecommendation(
                category="protocol",
                severity="CRITICAL",
                issue="SSLv2/SSLv3 enabled",
                recommendation="Disable SSLv2 and SSLv3 immediately - they are completely broken"
            ))
        
        if self.protocol_support.tlsv1_0 or self.protocol_support.tlsv1_1:
            recommendations.append(TLSRecommendation(
                category="protocol",
                severity="HIGH",
                issue="TLS 1.0/1.1 enabled",
                recommendation="Disable TLS 1.0 and 1.1, enable TLS 1.2 and 1.3 only"
            ))
        
        if not self.protocol_support.tlsv1_3:
            recommendations.append(TLSRecommendation(
                category="protocol",
                severity="MEDIUM",
                issue="TLS 1.3 not supported",
                recommendation="Enable TLS 1.3 for improved security and performance"
            ))
        
        # Cipher recommendations
        if self.weak_ciphers:
            weak_names = [c.name for c in self.weak_ciphers[:5]]
            recommendations.append(TLSRecommendation(
                category="cipher",
                severity="HIGH",
                issue=f"Weak ciphers enabled: {', '.join(weak_names)}",
                recommendation="Remove all weak ciphers (RC4, DES, 3DES, etc.)"
            ))
        
        if self.export_ciphers:
            recommendations.append(TLSRecommendation(
                category="cipher",
                severity="CRITICAL",
                issue="Export-grade ciphers enabled",
                recommendation="Remove all export-grade ciphers immediately (FREAK vulnerability)"
            ))
        
        if self.null_ciphers:
            recommendations.append(TLSRecommendation(
                category="cipher",
                severity="CRITICAL",
                issue="NULL ciphers enabled - no encryption!",
                recommendation="Remove all NULL ciphers immediately"
            ))
        
        # Certificate recommendations
        if self.certificate_chain:
            if self.certificate_chain.leaf.expired:
                recommendations.append(TLSRecommendation(
                    category="certificate",
                    severity="CRITICAL",
                    issue="Certificate expired",
                    recommendation="Renew certificate immediately"
                ))
            
            days_left = self.certificate_chain.leaf.days_until_expiry
            if 0 < days_left < 30:
                recommendations.append(TLSRecommendation(
                    category="certificate",
                    severity="HIGH",
                    issue=f"Certificate expires in {days_left} days",
                    recommendation="Renew certificate soon"
                ))
            
            if self.certificate_chain.leaf.public_key.bits < 2048:
                recommendations.append(TLSRecommendation(
                    category="certificate",
                    severity="HIGH",
                    issue=f"Weak RSA key size ({self.certificate_chain.leaf.public_key.bits} bits)",
                    recommendation="Use at least 2048-bit RSA keys"
                ))
            
            if self.certificate_chain.leaf.hash_algorithm in [HashAlgorithm.MD5, HashAlgorithm.SHA1]:
                recommendations.append(TLSRecommendation(
                    category="certificate",
                    severity="HIGH",
                    issue=f"Weak signature hash: {self.certificate_chain.leaf.hash_algorithm.value}",
                    recommendation="Use SHA256 or stronger for certificate signatures"
                ))
            
            if not self.certificate_chain.complete:
                recommendations.append(TLSRecommendation(
                    category="certificate",
                    severity="MEDIUM",
                    issue="Incomplete certificate chain",
                    recommendation="Install all intermediate certificates"
                ))
        
        # OCSP recommendations
        if not self.ocsp_stapling.enabled:
            recommendations.append(TLSRecommendation(
                category="performance",
                severity="MEDIUM",
                issue="OCSP stapling not enabled",
                recommendation="Enable OCSP stapling for faster and more private revocation checks"
            ))
        
        # HSTS recommendation (if HTTPS)
        if self.port == 443:
            recommendations.append(TLSRecommendation(
                category="security",
                severity="HIGH",
                issue="Consider implementing HSTS",
                recommendation="Add HSTS header with includeSubDomains and preload"
            ))
        
        self.recommendations = recommendations
    
    @property
    def summary(self) -> Dict[str, Any]:
        """Quick summary of TLS analysis"""
        return {
            'target': f"{self.target_host}:{self.port}",
            'certificate': {
                'subject': self.certificate_chain.leaf.subject.common_name if self.certificate_chain else None,
                'issuer': self.certificate_chain.leaf.issuer.common_name if self.certificate_chain else None,
                'expires_in': self.certificate_chain.leaf.days_until_expiry if self.certificate_chain else None,
                'key': f"{self.certificate_chain.leaf.public_key.algorithm.value} {self.certificate_chain.leaf.public_key.bits} bits" if self.certificate_chain else None
            },
            'protocols': [v.value for v in self.protocol_support.supported_versions],
            'cipher_count': self.cipher_preference.total_count if self.cipher_preference else 0,
            'vulnerabilities': len(self.vulnerabilities_found),
            'score': self.tls_score,
            'grade': self.grade.value,
            'recommendations': len(self.recommendations)
        }


@dataclass
class TLSRecommendation:
    """Actionable TLS recommendation"""
    category: str  # protocol, cipher, certificate, performance, security
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    issue: str
    recommendation: str
    evidence: Optional[str] = None


# ===============================
# STARTTLS SUPPORT
# ===============================

@dataclass
class STARTTLSInfo:
    """STARTTLS support for non-HTTPS protocols"""
    protocol: str  # smtp, pop3, imap, ftp, xmpp
    supported: bool
    port: int
    tls_result: Optional[TLSIntelligence] = None
    banner: Optional[str] = None
    requires_auth: bool = False
    issues: List[str] = field(default_factory=list)