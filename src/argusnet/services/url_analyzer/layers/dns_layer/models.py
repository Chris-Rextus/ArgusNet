# src/argusnet/services/url_analyzer/layers/dns_layer/models.py

from dataclasses import dataclass, field
from typing import List, Optional


# ===============================
# INFRASTRUCTURE INTELLIGENCE
# ===============================

@dataclass
class IPIntel:

    ip: str
    asn: Optional[str] = None
    country: Optional[str] = None
    is_private: bool = False


@dataclass
class CNAMEHop:

    alias: str
    target: str


@dataclass
class MXRecord:

    priority: int
    server: str


@dataclass
class SOARecord:

    primary_ns: str
    responsible: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum_ttl: int


@dataclass
class AuthorityIntel:

    ns_servers: List[str] = field(default_factory=list)
    soa: Optional[SOARecord] = None


@dataclass
class InfrastructureIntel:

    a_records: List[IPIntel] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    cname_chain: List[CNAMEHop] = field(default_factory=list)
    authority: AuthorityIntel = field(default_factory=AuthorityIntel)
    mx_records: List[MXRecord] = field(default_factory=list)


# ===============================
# SECURITY POSTURE
# ===============================

@dataclass
class DNSSECStatus:

    enabled: bool
    status: str  # "Signed", "Unsigned", "Error"
    error: Optional[str] = None


@dataclass
class SPFStatus:

    present: bool
    raw_records: List[str] = field(default_factory=list)


@dataclass
class SecurityPosture:

    dnssec: DNSSECStatus
    spf: SPFStatus
    private_ip_leak: bool = False


# ===============================
# OPERATIONAL PATTERNS
# ===============================

@dataclass
class TTLAnalysis:

    min_ttl: Optional[int] = None
    max_ttl: Optional[int] = None
    avg_ttl: Optional[float] = None
    classification: Optional[str] = None  # "Volatile" | "Stable"


@dataclass
class WildcardStatus:

    enabled: bool
    classification: str  # "Catch-all configured" | "Strict"


@dataclass
class OperationalPatterns:

    ttl: Optional[TTLAnalysis] = None
    wildcard: Optional[WildcardStatus] = None
    domain_age_days: Optional[int] = None
    domain_age_classification: Optional[str] = None



# ===============================
# RISK INDICATORS
# ===============================

@dataclass
class RiskIndicators:

    suspicious_tld: bool = False
    excessive_cname_chain: bool = False


# ===============================
# ROOT DNS INTELLIGENCE MODEL
# ===============================

@dataclass
class DNSIntelligence:

    domain: str

    infrastructure: InfrastructureIntel
    security_posture: SecurityPosture
    operational_patterns: OperationalPatterns
    risk_indicators: RiskIndicators

    resolved: bool = False
    resolution_time_ms: Optional[float] = None