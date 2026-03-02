# src/argusnet/services/url_analyzer/models.py

from dataclasses import dataclass
from typing import Optional

from argusnet.services.url_analyzer.layers.dns_layer.models import DNSIntelligence


@dataclass
class URLAnalysisReport:
    
    """
    Root analysis object passed through all pipeline layers.
    Each layer enriches this object.
    """

    url: str

    # Layers populate these
    dns: Optional[DNSIntelligence] = None

    # Future layers:
    connectivity: Optional[object] = None
    http: Optional[object] = None
    tls: Optional[object] = None
    domain: Optional[object] = None
    ip_intel: Optional[object] = None

    # Final scoring
    score: Optional[int] = None
    risk_classification: Optional[str] = None
