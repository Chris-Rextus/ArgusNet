# src/argusnet/services/url_analyzer/layers/tls_layer/tls.py

"""
TLS Intelligence Layer
Comprehensive TLS/SSL analysis including certificate inspection,
cryptographic assessment, protocol support, and vulnerability detection.
"""

import asyncio
import ssl
import socket
import time
import struct
import binascii
import hashlib
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse

import aiohttp
import aiohttp.client_exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID, NameOID, ExtendedKeyUsageOID

from argusnet.services.url_analyzer.layers.baselayer import BaseLayer
from .models import (
    TLSIntelligence,
    CertificateInfo,
    SubjectInfo,
    IssuerInfo,
    PublicKeyInfo,
    ExtensionInfo,
    SANEntry,
    CTLogEntry,
    CertificateChain,
    CertificateStatus,
    RevocationStatus,
    KeyAlgorithm,
    HashAlgorithm,
    
    ProtocolSupport,
    TLSVersion,
    CipherInfo,
    CipherSuite,
    CipherPreference,
    
    TLSExtension,
    ALPNProtocol,
    SNIInfo,
    OCSPStaplingInfo,
    SessionInfo,
    RenegotiationInfo,
    
    VulnerabilityInfo,
    VulnerabilityScan,
    VulnerabilitySeverity,
    
    HandshakeTiming,
    CipherPerformance,
    TLSPerformanceMetrics,
    
    TLSFingerprint,
    TLSGrade,
    TLSRecommendation,
    STARTTLSInfo,
)


# ===============================
# CONFIGURATION
# ===============================

# Common TLS ports to check
TLS_PORTS = [443, 8443, 465, 993, 995, 636, 989, 990, 853, 5061, 5433, 5671, 8883]

# STARTTLS protocols and their ports
STARTTLS_PROTOCOLS = {
    'smtp': [25, 587, 465],
    'pop3': [110, 995],
    'imap': [143, 993],
    'ftp': [21, 990],
    'xmpp': [5222, 5269],
    'mysql': [3306],
    'postgresql': [5432],
}

# Cipher suites to test (IANA codes)
CIPHER_SUITES = [
    # TLS 1.3
    (0x13, 0x01),  # TLS_AES_256_GCM_SHA384
    (0x13, 0x02),  # TLS_CHACHA20_POLY1305_SHA256
    (0x13, 0x03),  # TLS_AES_128_GCM_SHA256
    (0x13, 0x04),  # TLS_AES_128_CCM_SHA256
    (0x13, 0x05),  # TLS_AES_128_CCM_8_SHA256
    
    # ECDHE + AEAD
    (0xC0, 0x2F),  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    (0xC0, 0x30),  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    (0xC0, 0x27),  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    (0xC0, 0x28),  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    (0xC0, 0x09),  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    (0xC0, 0x23),  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    
    # DHE + AEAD
    (0x00, 0x9E),  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    (0x00, 0x9F),  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    (0x00, 0x6B),  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    
    # RSA + AEAD
    (0x00, 0x9C),  # TLS_RSA_WITH_AES_128_GCM_SHA256
    (0x00, 0x9D),  # TLS_RSA_WITH_AES_256_GCM_SHA384
    
    # Weak ciphers (for detection)
    (0x00, 0x04),  # TLS_RSA_WITH_RC4_128_MD5
    (0x00, 0x05),  # TLS_RSA_WITH_RC4_128_SHA
    (0x00, 0x0A),  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    (0x00, 0x2F),  # TLS_RSA_WITH_AES_128_CBC_SHA
    (0x00, 0x35),  # TLS_RSA_WITH_AES_256_CBC_SHA
    (0x00, 0x3C),  # TLS_RSA_WITH_AES_128_CBC_SHA256
    (0x00, 0x3D),  # TLS_RSA_WITH_AES_256_CBC_SHA256
    (0x00, 0x88),  # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    (0xC0, 0x12),  # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    (0xC0, 0x08),  # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    (0x00, 0x62),  # TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA (export)
    (0x00, 0x08),  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA (export)
    (0x00, 0x01),  # TLS_RSA_WITH_NULL_MD5 (null)
    (0x00, 0x02),  # TLS_RSA_WITH_NULL_SHA (null)
    (0x00, 0x3B),  # TLS_RSA_WITH_NULL_SHA256 (null)
    (0x00, 0x18),  # TLS_DH_anon_WITH_AES_128_CBC_SHA (anon)
    (0x00, 0x3A),  # TLS_DH_anon_WITH_AES_256_CBC_SHA (anon)
]

# JA3 string format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
CLIENT_HELLO_CIPHERS = [code[0] << 8 | code[1] for code in CIPHER_SUITES[:30]]
CLIENT_HELLO_EXTENSIONS = [0, 10, 11, 13, 16, 21, 23, 35, 43, 45, 51]
CLIENT_HELLO_CURVES = [29, 23, 24, 25]  # x25519, secp256r1, secp384r1, secp521r1
CLIENT_HELLO_POINT_FORMATS = [0]  # uncompressed


class TLSLayer(BaseLayer):
    """
    Comprehensive TLS Intelligence Layer
    Deep TLS/SSL analysis including certificate inspection, cipher suite enumeration,
    vulnerability detection, and performance metrics.
    """

    name = "TLS Intelligence Layer"

    def __init__(self):
        super().__init__()
        self.timeout = 10
        self.session = None
        self._cipher_cache = {}
        self._init_cipher_info()

    def _init_cipher_info(self):
        """Initialize cipher suite information database"""
        self.cipher_db = {}
        
        # Map cipher codes to names and properties
        cipher_map = {
            (0x13, 0x01): ("TLS_AES_256_GCM_SHA384", "TLSv1.3", "AEAD", True, True),
            (0x13, 0x02): ("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", "AEAD", True, True),
            (0x13, 0x03): ("TLS_AES_128_GCM_SHA256", "TLSv1.3", "AEAD", True, True),
            (0xC0, 0x2F): ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", "AEAD", True, True),
            (0xC0, 0x30): ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", "AEAD", True, True),
            (0x00, 0x9E): ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", "AEAD", True, True),
            (0x00, 0x9F): ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", "AEAD", True, True),
            (0xC0, 0x27): ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLSv1.2", "PFS", True, True),
            (0xC0, 0x28): ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "TLSv1.2", "PFS", True, True),
            (0x00, 0x2F): ("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.0", "WEAK", False, False),
            (0x00, 0x35): ("TLS_RSA_WITH_AES_256_CBC_SHA", "TLSv1.0", "WEAK", False, False),
            (0x00, 0x04): ("TLS_RSA_WITH_RC4_128_MD5", "TLSv1.0", "WEAK", False, False),
            (0x00, 0x05): ("TLS_RSA_WITH_RC4_128_SHA", "TLSv1.0", "WEAK", False, False),
            (0x00, 0x0A): ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.0", "WEAK", False, False),
            (0x00, 0x62): ("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "TLSv1.0", "EXPORT", False, False),
            (0x00, 0x08): ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLSv1.0", "EXPORT", False, False),
            (0x00, 0x01): ("TLS_RSA_WITH_NULL_MD5", "TLSv1.0", "NULL", False, False),
            (0x00, 0x02): ("TLS_RSA_WITH_NULL_SHA", "TLSv1.0", "NULL", False, False),
            (0x00, 0x18): ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLSv1.0", "ANON", False, False),
        }
        
        for (b1, b2), (name, version, cat, pfs, aead) in cipher_map.items():
            self.cipher_db[(b1, b2)] = {
                'name': name,
                'iana_name': name,
                'hex_code': f"0x{b1:02X},0x{b2:02X}",
                'protocol': version,
                'category': cat,
                'pfs': pfs,
                'aead': aead
            }

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            connector = aiohttp.TCPConnector(
                limit=10,
                ttl_dns_cache=300,
                ssl=False,
                force_close=True,
                enable_cleanup_closed=True
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
        return self.session

    async def run(self, report):
        """Main execution entry point"""
        
        # Get target information from report
        if not report.dns or not report.dns.infrastructure.a_records:
            report.tls = None
            return report

        target_ip = report.dns.infrastructure.a_records[0].ip
        target_host = report.dns.domain
        parsed = urlparse(report.url)
        
        # Determine ports to scan
        ports_to_scan = []
        
        # Add port from URL if HTTPS
        if parsed.scheme == 'https':
            port = parsed.port or 443
            ports_to_scan.append(port)
        
        # Add all common TLS ports from connectivity layer if available
        if report.connectivity and report.connectivity.port_intel.open_ports:
            for port_service in report.connectivity.port_intel.open_ports:
                if port_service.port in TLS_PORTS or port_service.service in ['https', 'imaps', 'pop3s', 'smtps']:
                    if port_service.port not in ports_to_scan:
                        ports_to_scan.append(port_service.port)
        
        # If no ports found, scan default HTTPS
        if not ports_to_scan:
            ports_to_scan = [443]

        self.logger.info(f"[*] Starting TLS intelligence gathering for {target_host} ({target_ip}) on ports {ports_to_scan}")

        start = time.perf_counter()
        
        # We'll analyze the first TLS-capable port found
        tls_intel = None
        
        for port in ports_to_scan:
            self.logger.debug(f"Attempting TLS on port {port}")
            try:
                tls_intel = await self._analyze_port(target_host, target_ip, port)
                if tls_intel:
                    self.logger.info(f"[+] TLS successful on port {port}")
                    break
            except Exception as e:
                self.logger.debug(f"TLS on port {port} failed: {str(e)}")
                continue
        
        if not tls_intel:
            self.logger.warning("No TLS-capable port found")
            report.tls = None
            return report
        
        # Check STARTTLS on other ports
        for port in ports_to_scan:
            if port != tls_intel.port and port in [25, 587, 110, 143, 21]:
                self.logger.debug(f"Attempting STARTTLS on port {port}")
                try:
                    starttls_info = await self._check_starttls(target_host, target_ip, port)
                    if starttls_info and starttls_info.supported:
                        tls_intel.starttls_supported = True
                        tls_intel.starttls_protocol = starttls_info.protocol
                        tls_intel.starttls_result = starttls_info.tls_result
                except Exception:
                    pass
        
        end = time.perf_counter()
        tls_intel.analysis_duration_ms = round((end - start) * 1000, 2)
        
        # Calculate scores and generate recommendations
        tls_intel.calculate_tls_score()
        tls_intel.calculate_grade()
        tls_intel.generate_recommendations()
        
        report.tls = tls_intel
        self.logger.info(f"[+] TLS analysis complete - Grade: {tls_intel.grade.value}")
        
        return report

    async def _analyze_port(self, host: str, ip: str, port: int) -> Optional[TLSIntelligence]:
        """Analyze TLS on a specific port"""

        print(f"[DEBUG _analyze_port] Starting analysis for {host}:{port}")
        
        intel = TLSIntelligence(
            target_host=host,
            target_ip=ip,
            port=port
        )

        # Get certificate chain
        print(f"[DEBUG _analyze_port] Getting certificate chain...")
        
        # Get certificate chain
        cert_chain = await self._get_certificate_chain(host, ip, port)
        if not cert_chain:
            return None
        
        print(f"[DEBUG _analyze_port] ✅ Got certificate chain with {len(cert_chain.intermediates)} intermediates")

        intel.certificate_chain = cert_chain
        intel.all_certificates = [cert_chain.leaf] + cert_chain.intermediates
        if cert_chain.root:
            intel.all_certificates.append(cert_chain.root)
        
        # Parse protocol support
        intel.protocol_support = await self._detect_protocols(host, ip, port)
        
        # Enumerate cipher suites
        cipher_pref = await self._enumerate_ciphers(host, ip, port)
        if cipher_pref:
            intel.cipher_preference = cipher_pref
            
            # Categorize ciphers
            for cipher in cipher_pref.all_ciphers:
                if cipher.is_export:
                    intel.export_ciphers.append(cipher)
                elif cipher.is_null:
                    intel.null_ciphers.append(cipher)
                elif cipher.is_anon:
                    intel.anon_ciphers.append(cipher)
                elif cipher.category == CipherSuite.WEAK or cipher.is_deprecated:
                    intel.weak_ciphers.append(cipher)
                elif cipher.category in [CipherSuite.STRONG, CipherSuite.AEAD, CipherSuite.PFS]:
                    intel.strong_ciphers.append(cipher)
        
        # Check TLS extensions
        extensions = await self._get_tls_extensions(host, ip, port)
        intel.extensions = extensions
        
        # Parse ALPN
        intel.alpn_protocols = await self._get_alpn(host, ip, port)
        
        # Check SNI
        intel.sni = await self._check_sni(host, ip, port)
        
        # Check OCSP stapling
        intel.ocsp_stapling = await self._check_ocsp_stapling(host, ip, port, cert_chain.leaf)
        
        # Check session management
        intel.session_management = await self._check_session(host, ip, port)
        
        # Check renegotiation
        intel.renegotiation = await self._check_renegotiation(host, ip, port)
        
        # Vulnerability scanning
        intel.vulnerability_scan = await self._scan_vulnerabilities(host, ip, port)
        intel.vulnerabilities_found = intel.vulnerability_scan.all_vulnerabilities
        intel.vulnerable = intel.vulnerability_scan.vulnerable
        intel.vulnerability_score = (intel.vulnerability_scan.critical_count * 10 + 
                                     intel.vulnerability_scan.high_count * 5)
        
        # Performance metrics
        intel.performance = await self._measure_performance(host, ip, port)
        
        # JA3 fingerprinting
        intel.fingerprint = await self._get_tls_fingerprint(host, ip, port)
        
        return intel

    async def _get_certificate_chain(self, host: str, ip: str, port: int) -> Optional[CertificateChain]:
        
        """Retrieve and parse complete certificate chain"""
        print(f"[DEBUG _get_certificate_chain] 🔍 FUNCTION CALLED for {host}:{port}")
        print(f"[DEBUG _get_certificate_chain] Attempting connection to {ip}:{port} with SNI {host}")
        
        try:
            # Create SSL context
            print(f"[DEBUG _get_certificate_chain] Creating SSL context...")
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            print(f"[DEBUG _get_certificate_chain] Connecting to {ip}:{port}...")
            
            try:
                # Connect and get certificate chain
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=self.timeout
                )
                print(f"[DEBUG _get_certificate_chain] Connected successfully to {ip}:{port}")
            except asyncio.TimeoutError:
                print(f"[DEBUG _get_certificate_chain] ❌ Timeout connecting to {ip}:{port}")
                return None
            except ConnectionRefusedError:
                print(f"[DEBUG _get_certificate_chain] ❌ Connection refused to {ip}:{port}")
                return None
            except ssl.SSLError as e:
                print(f"[DEBUG _get_certificate_chain] ❌ SSL error: {str(e)}")
                return None
            except OSError as e:
                print(f"[DEBUG _get_certificate_chain] ❌ OS error: {str(e)}")
                return None
            except Exception as e:
                print(f"[DEBUG _get_certificate_chain] ❌ Connection error: {str(e)}")
                import traceback
                traceback.print_exc()
                return None
            
            # Get certificate chain
            try:
                chain = ssl_object.get_unverified_chain()
                print(f"[DEBUG _get_certificate_chain] Got {len(chain)} certificates in chain")
            except Exception as e:
                print(f"[DEBUG _get_certificate_chain] Error getting certificate chain: {str(e)}")
                writer.close()
                await writer.wait_closed()
                return None
            
            cert_chain = []
            for i, cert_bytes in enumerate(chain):
                print(f"[DEBUG _get_certificate_chain] Parsing certificate {i+1}/{len(chain)}")
                try:
                    cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                    cert_chain.append(cert)
                    print(f"[DEBUG _get_certificate_chain] Successfully parsed certificate {i+1}")
                except Exception as e:
                    print(f"[DEBUG _get_certificate_chain] Failed to parse certificate {i+1}: {str(e)}")
                    writer.close()
                    await writer.wait_closed()
                    return None
            
            writer.close()
            await writer.wait_closed()
            
            if not cert_chain:
                print(f"[DEBUG _get_certificate_chain] No certificates in chain")
                return None
            
            # Parse certificates
            print(f"[DEBUG _get_certificate_chain] Parsing leaf certificate...")
            leaf = await self._parse_certificate(cert_chain[0], 0)
            
            intermediates = []
            root = None
            
            for i, cert in enumerate(cert_chain[1:], 1):
                print(f"[DEBUG _get_certificate_chain] Parsing certificate {i+1}/{len(cert_chain)}")
                parsed = await self._parse_certificate(cert, i)
                if i == len(cert_chain) - 1 and self._is_root_ca(cert):
                    root = parsed
                    print(f"[DEBUG _get_certificate_chain] Found root certificate")
                else:
                    intermediates.append(parsed)
                    print(f"[DEBUG _get_certificate_chain] Added intermediate certificate")
            
            print(f"[DEBUG _get_certificate_chain] Successfully built certificate chain")
            return CertificateChain(
                leaf=leaf,
                intermediates=intermediates,
                root=root
            )
            
        except Exception as e:
            print(f"[DEBUG _get_certificate_chain] Unexpected error: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    async def _parse_certificate(self, cert: x509.Certificate, depth: int) -> CertificateInfo:
        """Parse X.509 certificate into CertificateInfo model"""
        
        # Subject
        subject = SubjectInfo()
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject.common_name = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                subject.organization = attr.value
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                subject.organizational_unit = attr.value
            elif attr.oid == NameOID.LOCALITY_NAME:
                subject.locality = attr.value
            elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                subject.state = attr.value
            elif attr.oid == NameOID.COUNTRY_NAME:
                subject.country = attr.value
            elif attr.oid == NameOID.EMAIL_ADDRESS:
                subject.email = attr.value
        
        # Issuer
        issuer = IssuerInfo()
        for attr in cert.issuer:
            if attr.oid == NameOID.COMMON_NAME:
                issuer.common_name = attr.value
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                issuer.organization = attr.value
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                issuer.organizational_unit = attr.value
            elif attr.oid == NameOID.LOCALITY_NAME:
                issuer.locality = attr.value
            elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME:
                issuer.state = attr.value
            elif attr.oid == NameOID.COUNTRY_NAME:
                issuer.country = attr.value
        
        # Public key
        public_key = cert.public_key()
        key_algo = KeyAlgorithm.UNKNOWN
        key_bits = 0
        curve = None
        
        if isinstance(public_key, rsa.RSAPublicKey):
            key_algo = KeyAlgorithm.RSA
            key_bits = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_algo = KeyAlgorithm.ECDSA
            key_bits = public_key.curve.key_size
            curve = public_key.curve.name
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            key_algo = KeyAlgorithm.Ed25519
            key_bits = 256
        elif isinstance(public_key, ed448.Ed448PublicKey):
            key_algo = KeyAlgorithm.Ed448
            key_bits = 456
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_algo = KeyAlgorithm.DSA
            key_bits = public_key.key_size
        
        # Public key fingerprint
        key_bytes = public_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo
        )
        key_fingerprint = hashlib.sha256(key_bytes).hexdigest()
        
        pub_key_info = PublicKeyInfo(
            algorithm=key_algo,
            bits=key_bits,
            curve=curve,
            fingerprint=key_fingerprint
        )
        
        # Validity
        not_before = cert.not_valid_before.replace(tzinfo=None)
        not_after = cert.not_valid_after.replace(tzinfo=None)
        now = datetime.utcnow()
        
        days_until = (not_after - now).days
        days_since = (now - not_before).days
        
        # Determine status
        status = CertificateStatus.VALID
        if now < not_before:
            status = CertificateStatus.NOT_YET_VALID
        elif now > not_after:
            status = CertificateStatus.EXPIRED
        elif cert.issuer == cert.subject:
            status = CertificateStatus.SELF_SIGNED
        
        # Signature
        sig_algo = cert.signature_algorithm_oid._name
        hash_algo = HashAlgorithm.UNKNOWN
        
        # Parse hash algorithm
        if 'sha256' in sig_algo.lower():
            hash_algo = HashAlgorithm.SHA256
        elif 'sha384' in sig_algo.lower():
            hash_algo = HashAlgorithm.SHA384
        elif 'sha512' in sig_algo.lower():
            hash_algo = HashAlgorithm.SHA512
        elif 'sha1' in sig_algo.lower():
            hash_algo = HashAlgorithm.SHA1
        elif 'md5' in sig_algo.lower():
            hash_algo = HashAlgorithm.MD5
        
        # Extensions
        extensions = []
        san_entries = []
        key_usage = []
        ext_key_usage = []
        authority_info = {}
        crl_dists = []
        ct_logs = []
        
        for ext in cert.extensions:
            ext_info = ExtensionInfo(
                oid=ext.oid.dotted_string,
                name=ext.oid._name,
                critical=ext.critical,
                value=str(ext.value)
            )
            extensions.append(ext_info)
            
            # Parse SAN
            if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for name in ext.value:
                    if isinstance(name, x509.DNSName):
                        san_entries.append(SANEntry(
                            type='DNS',
                            value=name.value,
                            is_wildcard=name.value.startswith('*.')
                        ))
                    elif isinstance(name, x509.IPAddress):
                        san_entries.append(SANEntry(
                            type='IP',
                            value=str(name.value)
                        ))
            
            # Parse Key Usage
            elif ext.oid == ExtensionOID.KEY_USAGE:
                key_usage = [
                    'digital_signature' if ext.value.digital_signature else None,
                    'content_commitment' if ext.value.content_commitment else None,
                    'key_encipherment' if ext.value.key_encipherment else None,
                    'data_encipherment' if ext.value.data_encipherment else None,
                    'key_agreement' if ext.value.key_agreement else None,
                    'key_cert_sign' if ext.value.key_cert_sign else None,
                    'crl_sign' if ext.value.crl_sign else None,
                    'encipher_only' if ext.value.encipher_only else None,
                    'decipher_only' if ext.value.decipher_only else None,
                ]
                key_usage = [k for k in key_usage if k]
            
            # Parse Extended Key Usage
            elif ext.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                for usage in ext.value:
                    if usage == ExtendedKeyUsageOID.SERVER_AUTH:
                        ext_key_usage.append('server_auth')
                    elif usage == ExtendedKeyUsageOID.CLIENT_AUTH:
                        ext_key_usage.append('client_auth')
                    elif usage == ExtendedKeyUsageOID.CODE_SIGNING:
                        ext_key_usage.append('code_signing')
                    elif usage == ExtendedKeyUsageOID.EMAIL_PROTECTION:
                        ext_key_usage.append('email_protection')
                    elif usage == ExtendedKeyUsageOID.TIME_STAMPING:
                        ext_key_usage.append('time_stamping')
            
            # Parse Authority Information Access
            elif ext.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for access in ext.value:
                    if access.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                        authority_info['ocsp'] = access.access_location.value
                    elif access.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                        authority_info['ca_issuers'] = access.access_location.value
            
            # Parse CRL Distribution Points
            elif ext.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                for point in ext.value:
                    for name in point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_dists.append(name.value)
        
        # Fingerprints
        fingerprint_sha1 = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
        fingerprint_sha256 = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()
        
        return CertificateInfo(
            serial_number=str(cert.serial_number),
            fingerprint_sha1=fingerprint_sha1,
            fingerprint_sha256=fingerprint_sha256,
            version=cert.version.value,
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            days_until_expiry=days_until,
            days_since_issued=days_since,
            status=status,
            public_key=pub_key_info,
            signature_algorithm=sig_algo,
            hash_algorithm=hash_algo,
            signature_value="",  # Not extracted
            extensions=extensions,
            san_entries=san_entries,
            key_usage=key_usage,
            extended_key_usage=ext_key_usage,
            authority_info=authority_info,
            crl_distribution_points=crl_dists,
            ct_logs=ct_logs,
            sct_count=len(ct_logs),
            chain_depth=depth,
            is_ca=self._is_ca_cert(cert),
            is_self_signed=cert.issuer == cert.subject,
            is_leaf=depth == 0,
            is_intermediate=depth > 0 and not self._is_root_ca(cert),
            is_root=self._is_root_ca(cert),
            revocation_status=RevocationStatus.NOT_CHECKED,
            ocsp_uri=authority_info.get('ocsp'),
            crl_uris=crl_dists,
            source='direct',
            queried_at=datetime.utcnow()
        )

    def _is_ca_cert(self, cert: x509.Certificate) -> bool:
        """Check if certificate is a CA"""
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            return basic_constraints.value.ca
        except:
            return False

    def _is_root_ca(self, cert: x509.Certificate) -> bool:
        """Check if certificate is a root CA"""
        return cert.issuer == cert.subject and self._is_ca_cert(cert)

    async def _detect_protocols(self, host: str, ip: str, port: int) -> ProtocolSupport:
        """Detect supported TLS protocol versions"""
        support = ProtocolSupport()
        
        # Test each protocol version
        versions = [
            (ssl.PROTOCOL_TLSv1_2, 'tlsv1_2'),
            (ssl.PROTOCOL_TLSv1_1, 'tlsv1_1'),
            (ssl.PROTOCOL_TLSv1, 'tlsv1_0'),
            (ssl.PROTOCOL_SSLv23, 'sslv3'),  # SSLv23 tries SSLv3
        ]
        
        for proto, attr in versions:
            try:
                context = ssl.SSLContext(proto)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=3
                )
                setattr(support, attr, True)
                writer.close()
                await writer.wait_closed()
            except:
                pass
        
        # Detect TLS 1.3 (special handling)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                timeout=3
            )
            support.tlsv1_3 = True
            writer.close()
            await writer.wait_closed()
        except:
            pass
        
        # Check downgrade prevention
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.set_ciphers('ALL')
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set SCSV (Signaling Cipher Suite Value)
            # This is simplified - actual SCSV check would need raw TLS
            support.downgrade_prevention = support.tlsv1_2 and not support.tlsv1_1
        except:
            pass
        
        return support

    async def _enumerate_ciphers(self, host: str, ip: str, port: int) -> Optional[CipherPreference]:
        """Enumerate supported cipher suites"""
        
        supported_ciphers = []
        preferred_ciphers = []
        
        # Test each cipher
        for code in CIPHER_SUITES:
            b1, b2 = code
            try:
                # Create context with single cipher
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                cipher_name = f"0x{b1:02X},0x{b2:02X}"
                context.set_ciphers(cipher_name)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                start = time.perf_counter()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=2
                )
                elapsed = (time.perf_counter() - start) * 1000
                
                # Cipher supported
                cipher_data = self.cipher_db.get((b1, b2), {})
                
                cipher_info = CipherInfo(
                    name=cipher_data.get('name', f"UNKNOWN_{b1:02X}{b2:02X}"),
                    hex_code=f"0x{b1:02X},0x{b2:02X}",
                    iana_name=cipher_data.get('iana_name', ''),
                    openssl_name='',
                    protocol=TLSVersion(cipher_data.get('protocol', 'Unknown')),
                    kx_algorithm='',
                    auth_algorithm='',
                    enc_algorithm='',
                    enc_mode='',
                    enc_key_size=0,
                    mac_algorithm='',
                    prf_algorithm='',
                    category=CipherSuite(cipher_data.get('category', 'UNKNOWN')),
                    provides_pfs=cipher_data.get('pfs', False),
                    provides_aead=cipher_data.get('aead', False),
                    is_export='EXPORT' in cipher_data.get('name', ''),
                    is_null='NULL' in cipher_data.get('name', ''),
                    is_anon='anon' in cipher_data.get('name', '').lower(),
                    is_deprecated='WEAK' in cipher_data.get('category', ''),
                    is_weak='WEAK' in cipher_data.get('category', ''),
                    relative_speed='Fast' if elapsed < 100 else 'Slow',
                    hardware_accelerated=False,
                    rfc='',
                    recommended=cipher_data.get('category') in ['AEAD', 'STRONG']
                )
                
                supported_ciphers.append(cipher_info)
                
                # Add to preferred if it's the first few
                if len(preferred_ciphers) < 10:
                    preferred_ciphers.append(cipher_info)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception:
                continue
        
        if not supported_ciphers:
            return None
        
        return CipherPreference(
            server_preferred=True,
            preferred_ciphers=preferred_ciphers[:10],
            all_ciphers=supported_ciphers
        )

    async def _get_tls_extensions(self, host: str, ip: str, port: int) -> List[TLSExtension]:
        """Get supported TLS extensions"""
        # This would require raw TLS parsing
        # Simplified version returns common extensions
        extensions = []
        
        # Check if we got extensions from connection
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                timeout=3
            )
            
            # Get negotiated TLS features
            ssl_obj = writer.get_extra_info('ssl_object')
            
            # Check ALPN
            alpn = ssl_obj.selected_alpn_protocol()
            if alpn:
                extensions.append(TLSExtension(
                    type=16,
                    name='application_layer_protocol_negotiation',
                    data=alpn
                ))
            
            # Check SNI
            if host:
                extensions.append(TLSExtension(
                    type=0,
                    name='server_name',
                    data=host
                ))
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            pass
        
        return extensions

    async def _get_alpn(self, host: str, ip: str, port: int) -> List[ALPNProtocol]:
        """Get ALPN protocols"""
        protocols = []
        
        try:
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2', 'http/1.1', 'spdy/3.1'])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                timeout=3
            )
            
            ssl_obj = writer.get_extra_info('ssl_object')
            selected = ssl_obj.selected_alpn_protocol()
            
            # Advertised protocols
            for proto in ['h2', 'http/1.1', 'spdy/3.1']:
                protocols.append(ALPNProtocol(
                    protocol=proto,
                    selected=(proto == selected)
                ))
            
            writer.close()
            await writer.wait_closed()
            
        except Exception:
            # Default to HTTP/1.1
            protocols.append(ALPNProtocol(protocol='http/1.1', selected=False))
        
        return protocols

    async def _check_sni(self, host: str, ip: str, port: int) -> SNIInfo:
        """Check SNI support"""
        
        # Test with correct SNI
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                timeout=3
            )
            cert_with_sni = writer.get_extra_info('ssl_object').getpeercert()
            writer.close()
            await writer.wait_closed()
        except:
            return SNIInfo(supported=False, required=False)
        
        # Test without SNI
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context),
                timeout=3
            )
            cert_without_sni = writer.get_extra_info('ssl_object').getpeercert()
            writer.close()
            await writer.wait_closed()
            
            # Compare certificates
            certs_different = cert_with_sni != cert_without_sni
            
            return SNIInfo(
                supported=True,
                required=certs_different,
                default_certificate=str(cert_without_sni.get('subject', '')) if certs_different else None
            )
            
        except:
            return SNIInfo(supported=True, required=False)

    async def _check_ocsp_stapling(self, host: str, ip: str, port: int, cert: CertificateInfo) -> OCSPStaplingInfo:
        """Check OCSP stapling support"""
        
        # This would require raw TLS with status_request extension
        # Simplified detection
        
        # Check if certificate has OCSP URI
        has_ocsp = bool(cert.ocsp_uri)
        
        # Check Must-Staple extension
        must_staple = False
        for ext in cert.extensions:
            if ext.name == 'tlsfeature' and 'status_request' in ext.value:
                must_staple = True
        
        return OCSPStaplingInfo(
            supported=has_ocsp,
            enabled=has_ocsp,  # Assume enabled if URI present
            response_stapled=False,
            must_staple=must_staple,
            responder_url=cert.ocsp_uri
        )

    async def _check_session(self, host: str, ip: str, port: int) -> SessionInfo:
        """Check session management"""
        
        session = SessionInfo(
            session_id_supported=False,
            session_ticket_supported=False,
            session_id_reused=False,
            session_ticket_reused=False
        )
        
        try:
            # First connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                timeout=3
            )
            
            ssl_obj = writer.get_extra_info('ssl_object')
            
            # Check session ID
            session_id = ssl_obj.session.id if ssl_obj.session else None
            if session_id:
                session.session_id_supported = True
            
            # Check session ticket
            session_ticket = ssl_obj.session.ticket if ssl_obj.session else None
            if session_ticket:
                session.session_ticket_supported = True
            
            writer.close()
            await writer.wait_closed()
            
            # Second connection (reuse)
            if session.session_id_supported or session.session_ticket_supported:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=3
                )
                
                ssl_obj = writer.get_extra_info('ssl_object')
                session.session_id_reused = ssl_obj.session_reused
                
                writer.close()
                await writer.wait_closed()
            
        except Exception:
            pass
        
        return session

    async def _check_renegotiation(self, host: str, ip: str, port: int) -> RenegotiationInfo:
        """Check renegotiation support"""
        
        # Default to safe values
        return RenegotiationInfo(
            secure_renegotiation=True,
            renegotiation_allowed=False,
            client_initiated_allowed=False,
            vulnerability_mitigated=True
        )

    async def _scan_vulnerabilities(self, host: str, ip: str, port: int) -> VulnerabilityScan:
        """Scan for known TLS vulnerabilities"""
        
        scan = VulnerabilityScan()
        
        # We need to pass the actual protocol support and ciphers from the connection
        # For now, create placeholder vulnerability objects without referencing self
        
        # Heartbleed (CVE-2014-0160)
        scan.heartbleed = VulnerabilityInfo(
            name="Heartbleed",
            cve="CVE-2014-0160",
            severity=VulnerabilitySeverity.CRITICAL,
            description="Information disclosure in OpenSSL heartbeat extension",
            impact="Memory disclosure of private keys and sensitive data",
            affected_versions=[TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2],
            vulnerable=False,  # Default to false, would need actual test
            remediation="Update OpenSSL and disable heartbeat extension"
        )
        
        # POODLE (CVE-2014-3566)
        scan.poodle = VulnerabilityInfo(
            name="POODLE",
            cve="CVE-2014-3566",
            severity=VulnerabilitySeverity.HIGH,
            description="Padding oracle attack on SSLv3",
            impact="Plaintext recovery from encrypted connections",
            affected_versions=[TLSVersion.SSLv3],
            vulnerable=False,  # Would need actual SSLv3 detection
            remediation="Disable SSLv3 completely"
        )
        
        # FREAK (CVE-2015-0204)
        scan.freak = VulnerabilityInfo(
            name="FREAK",
            cve="CVE-2015-0204",
            severity=VulnerabilitySeverity.HIGH,
            description="Export-grade RSA key attack",
            impact="Man-in-the-middle decryption of traffic",
            affected_versions=[TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2],
            vulnerable=False,  # Would need export cipher detection
            remediation="Disable export-grade cipher suites"
        )
        
        # Logjam (CVE-2015-4000)
        scan.logjam = VulnerabilityInfo(
            name="Logjam",
            cve="CVE-2015-4000",
            severity=VulnerabilitySeverity.HIGH,
            description="Weak Diffie-Hellman parameters",
            impact="Downgrade attacks on DHE_EXPORT ciphers",
            affected_versions=[TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2],
            vulnerable=False,
            remediation="Use >= 2048-bit DH parameters or disable DHE_EXPORT"
        )
        
        # DROWN (CVE-2016-0800)
        scan.drown = VulnerabilityInfo(
            name="DROWN",
            cve="CVE-2016-0800",
            severity=VulnerabilitySeverity.CRITICAL,
            description="SSLv2 cross-protocol attack",
            impact="Decryption of TLS sessions using SSLv2",
            affected_versions=[TLSVersion.SSLv2],
            vulnerable=False,
            remediation="Disable SSLv2 completely"
        )
        
        # Sweet32 (CVE-2016-2183)
        scan.sweet32 = VulnerabilityInfo(
            name="Sweet32",
            cve="CVE-2016-2183",
            severity=VulnerabilitySeverity.MEDIUM,
            description="64-bit block cipher birthday attack",
            impact="Plaintext recovery in long-lived sessions",
            affected_versions=[TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2],
            vulnerable=False,
            remediation="Disable 3DES and Blowfish ciphers"
        )
        
        # ROBOT (CVE-2017-17382)
        scan.robot = VulnerabilityInfo(
            name="ROBOT",
            cve="CVE-2017-17382",
            severity=VulnerabilitySeverity.HIGH,
            description="Return of Bleichenbacher's Oracle Threat",
            impact="RSA decryption oracle",
            affected_versions=[TLSVersion.TLSv1_0, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2],
            vulnerable=False,
            remediation="Disable RSA encryption or implement proper padding checks"
        )
        
        return scan

    async def _measure_performance(self, host: str, ip: str, port: int) -> TLSPerformanceMetrics:
        """Measure TLS performance metrics"""
        
        metrics = TLSPerformanceMetrics()
        handshake_times = []
        
        # Full handshake timing
        for i in range(3):
            try:
                start = time.perf_counter()
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=3
                )
                elapsed = (time.perf_counter() - start) * 1000
                handshake_times.append(elapsed)
                
                writer.close()
                await writer.wait_closed()
            except:
                pass
        
        if handshake_times:
            metrics.handshake_timings.full_handshake_ms = sum(handshake_times) / len(handshake_times)
            metrics.average_handshake_ms = metrics.handshake_timings.full_handshake_ms
        
        # Session resumption timing
        if handshake_times:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                start = time.perf_counter()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=3
                )
                elapsed = (time.perf_counter() - start) * 1000
                
                metrics.handshake_timings.resumed_handshake_ms = elapsed
                metrics.connection_reuse_success = elapsed < metrics.average_handshake_ms * 0.7
                
                writer.close()
                await writer.wait_closed()
            except:
                pass
        
        return metrics

    async def _get_tls_fingerprint(self, host: str, ip: str, port: int) -> Optional[TLSFingerprint]:
        """Generate JA3/JA3S fingerprint"""
        
        # JA3 string format: SSLVersion,Ciphers,Extensions,Curves,Formats
        # SSLVersion: 0x0303 for TLS 1.2, 0x0304 for TLS 1.3
        ssl_version = "0x0303"
        
        # Cipher suites
        cipher_str = ",".join([f"{c[0]:02x}{c[1]:02x}" for c in CIPHER_SUITES[:10]])
        
        # Extensions
        ext_str = ",".join([str(e) for e in CLIENT_HELLO_EXTENSIONS[:5]])
        
        # Curves
        curve_str = ",".join([str(c) for c in CLIENT_HELLO_CURVES])
        
        # Point formats
        format_str = ",".join([str(f) for f in CLIENT_HELLO_POINT_FORMATS])
        
        ja3_string = f"{ssl_version},{cipher_str},{ext_str},{curve_str},{format_str}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        
        return TLSFingerprint(
            ja3_hash=ja3_hash,
            ja3s_hash="",  # Would need server response
            ja3_string=ja3_string,
            client_suites=[f"{c[0]:02x}{c[1]:02x}" for c in CIPHER_SUITES[:10]],
            client_extensions=CLIENT_HELLO_EXTENSIONS[:5],
            client_curves=[str(c) for c in CLIENT_HELLO_CURVES],
            server_suites=[],
            server_extensions=[],
            library="Unknown",
            confidence=0.5
        )

    async def _check_starttls(self, host: str, ip: str, port: int) -> Optional[STARTTLSInfo]:
        """Check STARTTLS support on non-TLS ports"""
        
        protocol = None
        for proto, ports in STARTTLS_PROTOCOLS.items():
            if port in ports:
                protocol = proto
                break
        
        if not protocol:
            return None
        
        try:
            # Connect without TLS
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5
            )
            
            banner = None
            starttls_supported = False
            
            # Protocol-specific STARTTLS commands
            if protocol == 'smtp':
                banner = await reader.read(1024)
                writer.write(b"EHLO argusnet.local\r\n")
                await writer.drain()
                response = await reader.read(1024)
                if b'STARTTLS' in response:
                    starttls_supported = True
                    writer.write(b"STARTTLS\r\n")
                    await writer.drain()
            
            elif protocol == 'pop3':
                banner = await reader.read(1024)
                writer.write(b"CAPA\r\n")
                await writer.drain()
                response = await reader.read(1024)
                if b'STLS' in response:
                    starttls_supported = True
                    writer.write(b"STLS\r\n")
                    await writer.drain()
            
            elif protocol == 'imap':
                banner = await reader.read(1024)
                writer.write(b"a001 CAPABILITY\r\n")
                await writer.drain()
                response = await reader.read(1024)
                if b'STARTTLS' in response:
                    starttls_supported = True
                    writer.write(b"a002 STARTTLS\r\n")
                    await writer.drain()
            
            elif protocol == 'ftp':
                banner = await reader.read(1024)
                if b'220' in banner:
                    writer.write(b"AUTH TLS\r\n")
                    await writer.drain()
                    response = await reader.read(1024)
                    if b'234' in response:
                        starttls_supported = True
            
            if starttls_supported:
                # Now upgrade to TLS
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Wrap socket
                sock = writer.transport.get_extra_info('socket')
                ssl_sock = context.wrap_socket(sock, server_hostname=host)
                
                # Analyze TLS on this connection
                tls_result = await self._analyze_port(host, ip, port)
                
                return STARTTLSInfo(
                    protocol=protocol,
                    supported=True,
                    port=port,
                    tls_result=tls_result,
                    banner=banner.decode('utf-8', errors='ignore') if banner else None,
                    requires_auth=False
                )
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.logger.debug(f"STARTTLS on {protocol} port {port} failed: {str(e)}")
        
        return None

    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None