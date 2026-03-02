"""
Aggressive Connectivity Intelligence Layer
Strategic port scanning, service fingerprinting, TLS analysis, and architecture inference.
No exploit behavior - pure reconnaissance and intelligence gathering.
"""

import asyncio
import socket
import ssl
import time
import ipaddress
import struct
import binascii
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import aiodns
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

from argusnet.services.url_analyzer.layers.baselayer import BaseLayer
from .models import (
    ConnectivityIntelligence,
    PortService,
    PortScanResult,
    ServiceFingerprint,
    TLSIntelligence,
    CertificateInfo,
    RTTMetrics,
    IPv6Info,
    ArchitecturePattern,
    CDNDetection,
    LoadBalancerInfo,
    ResponseAnalysis,
    BannerInfo,
    TCPStackFingerprint,
)

# Comprehensive port categories for strategic scanning
PORT_CATEGORIES = {
    "web": [80, 443, 8080, 8443, 8000, 8008, 8888, 8081, 8082, 8090, 9000, 9443, 10443],
    "mail": [25, 465, 587, 110, 995, 143, 993],
    "database": [3306, 5432, 5433, 6379, 27017, 27018, 27019, 9200, 9300],
    "dns": [53, 853, 5353],
    "ftp": [20, 21, 990, 989],
    "ssh": [22, 2222, 22222],
    "telnet": [23, 2323],
    "rpc": [111, 135, 139, 445, 593],
    "ldap": [389, 636, 3268, 3269],
    "nfs": [2049],
    "snmp": [161, 162],
    "ntp": [123],
    "rsync": [873],
    "smb": [445, 139],
    "vnc": [5900, 5901, 5902, 5903, 5800],
    "rdp": [3389],
    "proxy": [3128, 8080, 8888, 1080, 1086],
    "jenkins": [8080, 8443, 50000],
    "docker": [2375, 2376, 2377, 4243],
    "kubernetes": [6443, 8443, 10250, 10255, 10256],
    "redis": [6379, 6380],
    "memcached": [11211, 11212],
    "elasticsearch": [9200, 9300],
    "mongodb": [27017, 27018, 27019],
    "cassandra": [9042, 9160],
    "rabbitmq": [5672, 5671, 15672, 15671],
    "kafka": [9092, 9093],
    "zookeeper": [2181, 2888, 3888],
    "consul": [8500, 8600],
    "etcd": [2379, 2380],
    "vault": [8200, 8201],
    "prometheus": [9090, 9091],
    "grafana": [3000],
    "jenkins": [8080, 50000],
    "git": [22, 9418, 443, 80],
    "svn": [3690],
    "nexus": [8081, 8443],
    "artifactory": [8081, 8082],
    "hadoop": [50070, 50075, 50090, 8088, 8042],
    "spark": [8080, 8081, 8082, 4040, 4041],
    "flink": [8081, 6123],
    "storm": [6627, 8080],
    "airflow": [8080, 8793],
    "jupyter": [8888, 8889],
    "tensorflow": [8500, 8501],
    "mlflow": [5000],
}

# Flatten all ports for scanning
ALL_PORTS = [port for ports in PORT_CATEGORIES.values() for port in ports]
UNIQUE_PORTS = sorted(list(set(ALL_PORTS)))

# Scanning parameters
SCAN_CONCURRENCY = 50  # Aggressive concurrent scanning
SCAN_TIMEOUT = 2.0      # Connection timeout per port
BANNER_TIMEOUT = 1.5    # Banner grabbing timeout
RTT_SAMPLES = 5        # RTT measurement samples
TCP_PROBE_COUNT = 3     # TCP stack fingerprinting probes

class ConnectivityLayer(BaseLayer):
    """
    Aggressive Connectivity Intelligence Layer
    Strategic port scanning with service fingerprinting, TLS analysis,
    and architecture inference. Pure reconnaissance - no exploits.
    """

    name = "Aggressive Connectivity Intelligence Layer"

    def __init__(self):
        super().__init__()
        self.resolver = aiodns.DNSResolver()
        self.session = None
        self._port_semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)
        self.tls_contexts = self._create_tls_contexts()
        self.service_signatures = self._load_service_signatures()

    def _create_tls_contexts(self) -> Dict[str, ssl.SSLContext]:
        """Create TLS contexts with different versions for fingerprinting"""
        contexts = {}
        
        # Default context
        contexts['default'] = ssl.create_default_context()
        contexts['default'].check_hostname = False
        contexts['default'].verify_mode = ssl.CERT_NONE
        
        # TLS 1.3 only
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            contexts['tls13'] = ctx
        except:
            pass
        
        # TLS 1.2 with specific cipher suites for fingerprinting
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        contexts['tls12'] = ctx
        
        return contexts

    def _load_service_signatures(self) -> Dict[str, List[bytes]]:
        """Load service banner signatures for fingerprinting"""
        return {
            'nginx': [b'nginx', b'Server: nginx'],
            'apache': [b'apache', b'Server: Apache', b'Apache/'],
            'iis': [b'iis', b'Microsoft-IIS', b'Server: Microsoft'],
            'tomcat': [b'tomcat', b'Apache Tomcat', b'Server: Tomcat'],
            'jetty': [b'jetty', b'Jetty'],
            'nodejs': [b'node.js', b'Node.js', b'Express'],
            'python': [b'python', b'WSGIServer', b'Django', b'Flask'],
            'php': [b'php', b'X-Powered-By: PHP'],
            'ruby': [b'ruby', b'Rails', b'Phusion'],
            'java': [b'java', b'JVM', b'Java'],
            'go': [b'go', b'Golang'],
            'ssh': [b'SSH-', b'OpenSSH'],
            'ftp': [b'220', b'FTP', b'FileZilla', b'vsFTPd'],
            'smtp': [b'220', b'ESMTP', b'Postfix', b'Exim', b'Sendmail'],
            'mysql': [b'mysql', b'MariaDB', b'5.', b'8.0'],
            'postgresql': [b'postgres', b'PostgreSQL', b'psql'],
            'redis': [b'redis', b'+OK', b'-ERR'],
            'mongodb': [b'mongodb', b'WireVersion'],
            'elasticsearch': [b'elasticsearch', b'\"version\"'],
            'docker': [b'docker', b'Docker', b'containerd'],
            'kubernetes': [b'kubernetes', b'k8s', b'apis'],
        }

    async def _ensure_session(self):
        """Ensure aiohttp session exists"""
        if self.session is None:
            connector = aiohttp.TCPConnector(
                limit=100,
                ttl_dns_cache=300,
                ssl=False,
                force_close=True
            )
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self.session

    async def run(self, report):
        """Main execution entry point"""
        
        # Validate DNS results
        if not report.dns or not report.dns.infrastructure.a_records:
            report.connectivity = None
            return report

        # Get target information
        target_ip = report.dns.infrastructure.a_records[0].ip
        target_hostname = urlparse(report.url).hostname
        
        # Initialize connectivity intelligence
        intel = ConnectivityIntelligence(
            target_ip=target_ip,
            target_hostname=target_hostname,
            scan_started_at=datetime.utcnow()
        )

        self.logger.info(f"[*] Starting aggressive connectivity scan for {target_ip} ({target_hostname})")

        try:
            # ========================================================
            # PHASE 1: REACHABILITY & RTT PROFILING
            # ========================================================
            await self._phase1_reachability(intel, target_ip, target_hostname)
            
            # ========================================================
            # PHASE 2: COMPREHENSIVE PORT SCANNING
            # ========================================================
            await self._phase2_port_scanning(intel, target_ip, target_hostname)
            
            # ========================================================
            # PHASE 3: SERVICE FINGERPRINTING & BANNER GRABBING
            # ========================================================
            await self._phase3_service_fingerprinting(intel, target_ip, target_hostname)
            
            # ========================================================
            # PHASE 4: TLS/SSL INTELLIGENCE
            # ========================================================
            await self._phase4_tls_intelligence(intel, target_ip, target_hostname)
            
            # ========================================================
            # PHASE 5: TCP STACK FINGERPRINTING
            # ========================================================
            await self._phase5_tcp_fingerprinting(intel, target_ip)
            
            # ========================================================
            # PHASE 6: RESPONSE ANALYSIS
            # ========================================================
            await self._phase6_response_analysis(intel, target_ip, target_hostname)
            
            # ========================================================
            # PHASE 7: ARCHITECTURE INFERENCE
            # ========================================================
            await self._phase7_architecture_inference(intel, report)
            
            # ========================================================
            # FINALIZE
            # ========================================================
            intel.scan_completed_at = datetime.utcnow()
            intel.scan_duration_ms = (intel.scan_completed_at - intel.scan_started_at).total_seconds() * 1000
            
            # Calculate risk scores
            self._calculate_risk_scores(intel)
            
            self.logger.info(f"[+] Connectivity scan complete - {len(intel.port_intel.open_ports)} open ports, "
                           f"{len(intel.tls_intelligence.certificates)} certificates, "
                           f"CDN: {intel.architecture.cdn_detected}, LB: {intel.architecture.load_balancer_detected}")

        except Exception as e:
            self.logger.error(f"[-] Connectivity scan failed: {str(e)}")
            intel.errors.append(f"Scan error: {str(e)}")

        finally:
            if self.session:
                await self.session.close()
                self.session = None

        report.connectivity = intel
        return report

    # ========================================================
    # PHASE 1: REACHABILITY & RTT PROFILING
    # ========================================================

    async def _phase1_reachability(self, intel: ConnectivityIntelligence, 
                                  target_ip: str, target_hostname: str):
        """Measure reachability, RTT, jitter, and packet loss"""
        
        self.logger.debug(f"[Phase 1] Profiling reachability to {target_ip}")
        
        rtt_samples = []
        successful_pings = 0
        
        # Multiple RTT measurements with different strategies
        for i in range(RTT_SAMPLES):
            try:
                # TCP RTT to common ports
                for port in [443, 80, 22, 8080]:
                    try:
                        before = time.perf_counter()
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target_ip, port),
                            timeout=2.0
                        )
                        after = time.perf_counter()
                        
                        rtt = (after - before) * 1000
                        rtt_samples.append(rtt)
                        successful_pings += 1
                        
                        writer.close()
                        await writer.wait_closed()
                        break  # Success, move to next sample
                    except:
                        continue
                        
            except Exception:
                continue
        
        if successful_pings > 0:
            intel.reachable = True
            intel.performance.baseline_rtt_ms = round(sum(rtt_samples) / len(rtt_samples), 2)
            intel.performance.min_rtt_ms = round(min(rtt_samples), 2)
            intel.performance.max_rtt_ms = round(max(rtt_samples), 2)
            
            # Calculate jitter (RTT variation)
            if len(rtt_samples) > 1:
                jitter_sum = sum(abs(rtt_samples[i] - rtt_samples[i-1]) 
                               for i in range(1, len(rtt_samples)))
                intel.performance.jitter_ms = round(jitter_sum / (len(rtt_samples) - 1), 2)
            
            # Estimate packet loss
            intel.performance.packet_loss_percent = round(
                ((RTT_SAMPLES - successful_pings) / RTT_SAMPLES) * 100, 2
            )
        else:
            intel.reachable = False
            intel.performance.baseline_rtt_ms = 0

    # ========================================================
    # PHASE 2: COMPREHENSIVE PORT SCANNING
    # ========================================================

    async def _phase2_port_scanning(self, intel: ConnectivityIntelligence,
                                   target_ip: str, target_hostname: str):
        """Aggressive but intelligent port scanning"""
        
        self.logger.debug(f"[Phase 2] Scanning {len(UNIQUE_PORTS)} ports on {target_ip}")
        
        async def scan_port(port: int) -> Optional[PortService]:
            async with self._port_semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, port),
                        timeout=SCAN_TIMEOUT
                    )
                    
                    # Port is open
                    port_service = PortService(
                        port=port,
                        protocol="tcp",
                        state="open",
                        service=self._guess_service_from_port(port),
                        banner=None,
                        response_time_ms=0,
                        is_standard=port in [80, 443, 22, 25, 53]
                    )
                    
                    writer.close()
                    await writer.wait_closed()
                    return port_service
                    
                except asyncio.TimeoutError:
                    # Filtered/dropped
                    return None
                except ConnectionRefusedError:
                    # Closed
                    return None
                except Exception:
                    return None
        
        # Scan all ports concurrently
        tasks = [scan_port(port) for port in UNIQUE_PORTS]
        results = await asyncio.gather(*tasks)
        
        # Process results
        for result in results:
            if result:
                intel.port_intel.open_ports.append(result)
                
        # Sort ports
        intel.port_intel.open_ports.sort(key=lambda x: x.port)
        
        # Categorize open ports
        self._categorize_ports(intel)
        
        self.logger.debug(f"[Phase 2] Found {len(intel.port_intel.open_ports)} open ports")

    def _guess_service_from_port(self, port: int) -> str:
        """Guess service based on port number"""
        service_map = {
            80: "http", 443: "https", 22: "ssh", 21: "ftp", 25: "smtp",
            53: "dns", 110: "pop3", 143: "imap", 993: "imaps", 995: "pop3s",
            3306: "mysql", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
            8080: "http-alt", 8443: "https-alt", 8000: "http-alt",
            9200: "elasticsearch", 9300: "elasticsearch",
            5672: "amqp", 15672: "rabbitmq", 2181: "zookeeper",
            2375: "docker", 2376: "docker-tls", 5000: "docker-registry",
            6443: "kubernetes", 10250: "kubelet", 9090: "prometheus",
            3000: "grafana", 3389: "rdp", 5900: "vnc"
        }
        return service_map.get(port, "unknown")

    def _categorize_ports(self, intel: ConnectivityIntelligence):
        """Categorize open ports by service type"""
        
        for port_service in intel.port_intel.open_ports:
            port = port_service.port
            
            for category, ports in PORT_CATEGORIES.items():
                if port in ports:
                    if category not in intel.port_intel.port_categories:
                        intel.port_intel.port_categories[category] = []
                    intel.port_intel.port_categories[category].append(port)
                    
            # Sensitive services
            if port in [22, 23, 3389, 5900, 5938]:
                intel.port_intel.exposed_sensitive_service = True
                intel.port_intel.sensitive_ports.append(port)
            
            # Database ports
            if port in [3306, 5432, 6379, 27017, 9200]:
                intel.port_intel.database_ports.append(port)
                
            # Non-standard ports (not 80, 443)
            if port not in [80, 443, 22, 53]:
                intel.port_intel.unusual_port_usage = True
                intel.port_intel.non_standard_ports.append(port)

    # ========================================================
    # PHASE 3: SERVICE FINGERPRINTING & BANNER GRABBING
    # ========================================================

    async def _phase3_service_fingerprinting(self, intel: ConnectivityIntelligence,
                                            target_ip: str, target_hostname: str):
        """Grab banners and fingerprint services on open ports"""
        
        self.logger.debug(f"[Phase 3] Fingerprinting {len(intel.port_intel.open_ports)} services")
        
        async def fingerprint_service(port_service: PortService):
            port = port_service.port
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, port),
                    timeout=SCAN_TIMEOUT
                )
                
                banner_info = await self._grab_banner(reader, writer, port, target_hostname)
                
                if banner_info:
                    port_service.banner = banner_info.banner
                    port_service.banner_raw = banner_info.banner_raw
                    port_service.service = self._identify_service_from_banner(
                        banner_info.banner_raw or b'', 
                        port_service.service
                    )
                    
                    # Create service fingerprint
                    fingerprint = ServiceFingerprint(
                        port=port,
                        service=port_service.service,
                        banner=banner_info.banner,
                        protocol=self._detect_protocol(banner_info.banner_raw),
                        version=self._extract_version(banner_info.banner, port_service.service),
                        os_hint=self._extract_os_hint(banner_info.banner),
                        confidence=0.8
                    )
                    
                    intel.port_intel.service_fingerprints.append(fingerprint)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                self.logger.debug(f"Fingerprint failed on port {port}: {str(e)}")
        
        # Fingerprint all open ports
        tasks = [fingerprint_service(p) for p in intel.port_intel.open_ports]
        await asyncio.gather(*tasks)

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                          port: int, hostname: str) -> Optional[BannerInfo]:
        """Intelligent banner grabbing based on port/service"""
        
        banner = None
        banner_raw = None
        
        try:
            # HTTP/HTTPS
            if port in [80, 8080, 8000, 8008, 8888]:
                writer.write(b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ArgusNet/2.0\r\n\r\n" % 
                           hostname.encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=BANNER_TIMEOUT)
                banner_raw = data
                banner = data.decode(errors='ignore').split('\r\n')[0][:200]
                
            # SMTP
            elif port in [25, 465, 587]:
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                banner_raw = data
                banner = data.decode(errors='ignore').strip()
                
            # FTP
            elif port in [21, 990, 989]:
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                banner_raw = data
                banner = data.decode(errors='ignore').strip()
                writer.write(b"QUIT\r\n")
                
            # SSH
            elif port == 22:
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                banner_raw = data
                banner = data.decode(errors='ignore').strip()
                
            # POP3
            elif port in [110, 995]:
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                banner_raw = data
                banner = data.decode(errors='ignore').strip()
                writer.write(b"QUIT\r\n")
                
            # IMAP
            elif port in [143, 993]:
                data = await asyncio.wait_for(reader.read(1024), timeout=BANNER_TIMEOUT)
                banner_raw = data
                banner = data.decode(errors='ignore').strip()
                writer.write(b"a001 LOGOUT\r\n")
                
            # Generic - send newline
            else:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if data:
                    banner_raw = data
                    banner = data.decode(errors='ignore').strip()[:200]
                    
        except Exception:
            pass
            
        if banner_raw:
            return BannerInfo(
                banner=banner or "Unknown",
                banner_raw=banner_raw,
                port=port,
                protocol=self._detect_protocol(banner_raw)
            )
        
        return None

    def _identify_service_from_banner(self, banner: bytes, default: str) -> str:
        """Identify service from banner content"""
        banner_lower = banner.lower()
        
        for service, signatures in self.service_signatures.items():
            for sig in signatures:
                if sig.lower() in banner_lower:
                    return service
                    
        return default

    def _detect_protocol(self, banner: bytes) -> str:
        """Detect protocol from banner"""
        banner_str = banner[:100].lower()
        
        if b'http/' in banner_str or b'get /' in banner_str:
            return 'HTTP'
        elif b'ssh' in banner_str:
            return 'SSH'
        elif b'220' in banner_str and (b'ftp' in banner_str or b'filezilla' in banner_str):
            return 'FTP'
        elif b'220' in banner_str and (b'smtp' in banner_str or b'esmtp' in banner_str):
            return 'SMTP'
        elif b'+ok' in banner_str or b'-err' in banner_str:
            return 'POP3'
        elif b'* ok' in banner_str:
            return 'IMAP'
        elif b'mysql' in banner_str or b'mariadb' in banner_str:
            return 'MySQL'
        elif b'postgresql' in banner_str:
            return 'PostgreSQL'
        elif b'redis' in banner_str:
            return 'Redis'
        elif b'mongodb' in banner_str:
            return 'MongoDB'
        
        return 'TCP'

    def _extract_version(self, banner: str, service: str) -> Optional[str]:
        """Extract version string from banner"""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+(?:\.\d+)?)',  # x.y or x.y.z
            r'version (\S+)',
            r'v(\d+\.\d+)',
            r'/(\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def _extract_os_hint(self, banner: str) -> Optional[str]:
        """Extract OS hints from banner"""
        banner_lower = banner.lower()
        
        if 'ubuntu' in banner_lower:
            return 'Ubuntu'
        elif 'debian' in banner_lower:
            return 'Debian'
        elif 'centos' in banner_lower:
            return 'CentOS'
        elif 'red hat' in banner_lower:
            return 'RHEL'
        elif 'windows' in banner_lower:
            return 'Windows'
        elif 'freebsd' in banner_lower:
            return 'FreeBSD'
        elif 'openbsd' in banner_lower:
            return 'OpenBSD'
        elif 'darwin' in banner_lower or 'mac os' in banner_lower:
            return 'macOS'
        
        return None

    # ========================================================
    # PHASE 4: TLS/SSL INTELLIGENCE
    # ========================================================

    async def _phase4_tls_intelligence(self, intel: ConnectivityIntelligence,
                                      target_ip: str, target_hostname: str):
        """Deep TLS/SSL analysis on HTTPS ports"""
        
        tls_ports = [p.port for p in intel.port_intel.open_ports 
                    if p.port in [443, 8443, 9443, 10443, 4433, 8444]]
        
        if not tls_ports:
            return
            
        self.logger.debug(f"[Phase 4] Analyzing TLS on ports: {tls_ports}")
        
        intel.tls_intelligence = TLSIntelligence()
        
        for port in tls_ports:
            cert_info = await self._get_certificate(target_ip, port, target_hostname)
            if cert_info:
                intel.tls_intelligence.certificates.append(cert_info)
                
            # Test TLS versions
            for version, ctx in self.tls_contexts.items():
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, port, ssl=ctx, server_hostname=target_hostname),
                        timeout=3.0
                    )
                    
                    if version == 'tls13':
                        intel.tls_intelligence.tls_versions.append('TLSv1.3')
                    elif version == 'tls12':
                        intel.tls_intelligence.tls_versions.append('TLSv1.2')
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception:
                    pass
            
            # Check for weak protocols
            for protocol, ctx in [('SSLv3', None), ('TLSv1.0', None), ('TLSv1.1', None)]:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    if protocol == 'SSLv3':
                        ctx.minimum_version = ssl.TLSVersion.SSLv3
                        ctx.maximum_version = ssl.TLSVersion.SSLv3
                    elif protocol == 'TLSv1.0':
                        ctx.minimum_version = ssl.TLSVersion.TLSv1
                        ctx.maximum_version = ssl.TLSVersion.TLSv1
                    elif protocol == 'TLSv1.1':
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                    
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, port, ssl=ctx, server_hostname=target_hostname),
                        timeout=2.0
                    )
                    
                    intel.tls_intelligence.weak_protocols.append(protocol)
                    intel.tls_intelligence.weak_protocols_detected = True
                    
                    writer.close()
                    await writer.wait_closed()
                    
                except Exception:
                    pass

    async def _get_certificate(self, ip: str, port: int, hostname: str) -> Optional[CertificateInfo]:
        """Retrieve and parse SSL certificate"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=hostname),
                timeout=3.0
            )
            
            ssl_object = writer.get_extra_info('ssl_object')
            cert_binary = ssl_object.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            
            writer.close()
            await writer.wait_closed()
            
            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            # Get SANs
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_list = san_ext.value.get_values_for_type(x509.DNSName)
            except:
                pass
            
            # Key algorithm and size
            public_key = cert.public_key()
            key_algorithm = "Unknown"
            key_size = 0
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_algorithm = "RSA"
                key_size = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_algorithm = "ECDSA"
                key_size = public_key.curve.key_size
            
            # Signature algorithm
            sig_algo = cert.signature_algorithm_oid._name
            
            # Validity
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            days_until_expiry = (not_after - datetime.now(timezone.utc)).days
            
            # Self-signed detection
            is_self_signed = subject == issuer
            
            return CertificateInfo(
                subject=subject,
                issuer=issuer,
                san_list=san_list,
                not_before=not_before,
                not_after=not_after,
                days_until_expiry=days_until_expiry,
                key_algorithm=key_algorithm,
                key_size=key_size,
                signature_algorithm=sig_algo,
                serial_number=str(cert.serial_number),
                fingerprint=binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode(),
                is_self_signed=is_self_signed,
                is_expired=days_until_expiry < 0,
                is_valid_hostname=hostname in san_list or hostname in subject
            )
            
        except Exception as e:
            self.logger.debug(f"Certificate retrieval failed on {ip}:{port}: {str(e)}")
            return None

    # ========================================================
    # PHASE 5: TCP STACK FINGERPRINTING
    # ========================================================

    async def _phase5_tcp_fingerprinting(self, intel: ConnectivityIntelligence, target_ip: str):
        """Passive TCP stack fingerprinting for OS detection"""
        
        self.logger.debug(f"[Phase 5] Fingerprinting TCP stack of {target_ip}")
        
        tcp_fingerprint = TCPStackFingerprint()
        
        for _ in range(TCP_PROBE_COUNT):
            try:
                # Analyze TCP options from connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_ip, 443),
                    timeout=2.0
                )
                
                sock = writer.get_extra_info('socket')
                if sock:
                    # Get TCP info
                    tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
                    
                    # Parse TCP options (simplified)
                    if hasattr(socket, 'TCP_INFO'):
                        tcp_fingerprint.window_size = self._extract_window_size(sock)
                        tcp_fingerprint.ttl = self._extract_ttl(sock)
                        tcp_fingerprint.mss = self._extract_xmss(sock)
                
                writer.close()
                await writer.wait_closed()
                
            except Exception:
                continue
        
        # Guess OS based on TTL and window size
        if tcp_fingerprint.ttl:
            if tcp_fingerprint.ttl <= 64:
                tcp_fingerprint.guessed_os = "Linux/Unix"
                tcp_fingerprint.os_confidence = 0.7
            elif tcp_fingerprint.ttl <= 128:
                tcp_fingerprint.guessed_os = "Windows"
                tcp_fingerprint.os_confidence = 0.7
            elif tcp_fingerprint.ttl <= 255:
                tcp_fingerprint.guessed_os = "Cisco/Network Device"
                tcp_fingerprint.os_confidence = 0.6
        
        intel.tcp_stack_fingerprint = tcp_fingerprint

    def _extract_window_size(self, sock) -> Optional[int]:
        try:
            raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 4)
            return struct.unpack("I", raw)[0]
        except:
            return None

    def _extract_ttl(self, sock) -> Optional[int]:
        try:
            raw = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 4)
            return struct.unpack("I", raw)[0]
        except Exception:
            return None

    def _extract_mss(self, sock) -> Optional[int]:
        """Extract TCP MSS"""
        try:
            return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 4)
        except:
            return None

    # ========================================================
    # PHASE 6: RESPONSE ANALYSIS
    # ========================================================

    async def _phase6_response_analysis(self, intel: ConnectivityIntelligence,
                                       target_ip: str, target_hostname: str):
        """Analyze HTTP/HTTPS responses for server info and technologies"""
        
        web_ports = [p.port for p in intel.port_intel.open_ports 
                    if p.port in [80, 443, 8080, 8443, 8000, 8888]]
        
        if not web_ports:
            return
            
        self.logger.debug(f"[Phase 6] Analyzing web responses on ports: {web_ports}")
        
        session = await self._ensure_session()
        
        for port in web_ports:
            protocol = "https" if port in [443, 8443, 9443] else "http"
            url = f"{protocol}://{target_hostname}:{port}"
            
            try:
                async with session.get(url, timeout=5.0, allow_redirects=False) as response:
                    
                    response_analysis = ResponseAnalysis(
                        status_code=response.status,
                        status_text=response.reason,
                        headers=dict(response.headers),
                        server_header=response.headers.get('Server'),
                        content_type=response.headers.get('Content-Type'),
                        content_length=response.headers.get('Content-Length'),
                        location=response.headers.get('Location'),
                        cookies=[{'name': k, 'value': v} for k, v in response.cookies.items()],
                        response_time_ms=response.headers.get('X-Response-Time'),
                        url=str(response.url)
                    )
                    
                    # Detect technologies
                    technologies = []
                    
                    if 'X-Powered-By' in response.headers:
                        technologies.append(response.headers['X-Powered-By'])
                    if 'X-AspNet-Version' in response.headers:
                        technologies.append(f"ASP.NET {response.headers['X-AspNet-Version']}")
                    if 'X-Drupal-Cache' in response.headers:
                        technologies.append("Drupal")
                    if 'X-Generator' in response.headers:
                        technologies.append(f"Generator: {response.headers['X-Generator']}")
                    if 'X-Varnish' in response.headers:
                        technologies.append("Varnish")
                    
                    response_analysis.technologies = technologies
                    
                    intel.http_responses[port] = response_analysis
                    
            except Exception as e:
                self.logger.debug(f"HTTP analysis failed on {url}: {str(e)}")

    # ========================================================
    # PHASE 7: ARCHITECTURE INFERENCE
    # ========================================================

    async def _phase7_architecture_inference(self, intel: ConnectivityIntelligence, report):
        """Infer infrastructure architecture patterns"""
        
        self.logger.debug(f"[Phase 7] Inferring architecture patterns")
        
        intel.architecture = ArchitecturePattern()
        intel.cdn_detection = CDNDetection()
        intel.load_balancer_info = LoadBalancerInfo()
        
        # ====================================================
        # CDN Detection
        # ====================================================
        
        # Method 1: ASN/Organization from DNS
        if report.dns and report.dns.infrastructure.a_records:
            for ip_intel in report.dns.infrastructure.a_records:
                if ip_intel.asn:
                    asn_lower = ip_intel.asn.lower()
                    
                    if 'cloudflare' in asn_lower:
                        intel.cdn_detection.provider = 'Cloudflare'
                        intel.cdn_detection.confidence = 0.95
                        intel.architecture.cdn_detected = True
                    elif 'akamai' in asn_lower:
                        intel.cdn_detection.provider = 'Akamai'
                        intel.cdn_detection.confidence = 0.95
                        intel.architecture.cdn_detected = True
                    elif 'fastly' in asn_lower:
                        intel.cdn_detection.provider = 'Fastly'
                        intel.cdn_detection.confidence = 0.95
                        intel.architecture.cdn_detected = True
                    elif 'amazon' in asn_lower or 'aws' in asn_lower:
                        intel.cdn_detection.provider = 'AWS CloudFront'
                        intel.cdn_detection.confidence = 0.90
                        intel.architecture.cdn_detected = True
                    elif 'google' in asn_lower:
                        intel.cdn_detection.provider = 'Google Cloud CDN'
                        intel.cdn_detection.confidence = 0.90
                        intel.architecture.cdn_detected = True
                    elif 'azure' in asn_lower or 'microsoft' in asn_lower:
                        intel.cdn_detection.provider = 'Azure CDN'
                        intel.cdn_detection.confidence = 0.90
                        intel.architecture.cdn_detected = True
        
        # Method 2: HTTP Headers
        for port, response in intel.http_responses.items():
            headers = response.headers
            server = response.server_header or ''
            
            if 'cf-ray' in headers or 'cf-cache-status' in headers:
                intel.cdn_detection.provider = 'Cloudflare'
                intel.cdn_detection.confidence = 0.98
                intel.cdn_detection.evidence.append(f"CF-Ray header on port {port}")
                intel.architecture.cdn_detected = True
                
            if 'x-amz-cf-id' in headers or 'x-amz-cf-pop' in headers:
                intel.cdn_detection.provider = 'AWS CloudFront'
                intel.cdn_detection.confidence = 0.98
                intel.cdn_detection.evidence.append(f"X-Amz-Cf-Id header on port {port}")
                intel.architecture.cdn_detected = True
                
            if 'x-akamai' in headers or 'x-akamai-transformed' in headers:
                intel.cdn_detection.provider = 'Akamai'
                intel.cdn_detection.confidence = 0.98
                intel.cdn_detection.evidence.append(f"X-Akamai header on port {port}")
                intel.architecture.cdn_detected = True
                
            if 'via' in headers and 'fastly' in headers['via'].lower():
                intel.cdn_detection.provider = 'Fastly'
                intel.cdn_detection.confidence = 0.98
                intel.cdn_detection.evidence.append(f"Fastly Via header on port {port}")
                intel.architecture.cdn_detected = True
                
            if 'x-varnish' in headers:
                intel.cdn_detection.evidence.append(f"Varnish cache on port {port}")
                
            if 'x-cache' in headers:
                intel.cdn_detection.evidence.append(f"X-Cache: {headers['x-cache']} on port {port}")
        
        # ====================================================
        # Load Balancer Detection
        # ====================================================
        
        # Multiple A records suggest load balancing
        if report.dns and len(report.dns.infrastructure.a_records) > 1:
            intel.load_balancer_info.detected = True
            intel.load_balancer_info.method = 'DNS Round Robin'
            intel.load_balancer_info.confidence = 0.8
            intel.load_balancer_info.evidence.append(f"{len(report.dns.infrastructure.a_records)} A records")
            intel.architecture.load_balancer_detected = True
            intel.architecture.high_availability = True
        
        # Check for load balancer headers
        for port, response in intel.http_responses.items():
            headers = response.headers
            
            if 'x-forwarded-for' in headers:
                intel.load_balancer_info.detected = True
                intel.load_balancer_info.method = 'Reverse Proxy/Load Balancer'
                intel.load_balancer_info.evidence.append(f"X-Forwarded-For header on port {port}")
                intel.architecture.load_balancer_detected = True
                
            if 'x-forwarded-proto' in headers:
                intel.load_balancer_info.evidence.append(f"X-Forwarded-Proto header on port {port}")
                
            if 'x-forwarded-host' in headers:
                intel.load_balancer_info.evidence.append(f"X-Forwarded-Host header on port {port}")
                
            if 'x-forwarded-server' in headers:
                intel.load_balancer_info.evidence.append(f"X-Forwarded-Server header on port {port}")
                intel.load_balancer_info.method = 'Microsoft NLB/ARR'
                
            if 'via' in headers and ('proxy' in headers['via'].lower() or 'lb' in headers['via'].lower()):
                intel.load_balancer_info.evidence.append(f"Via header indicates proxy/LB: {headers['via']}")
        
        # ====================================================
        # High Availability Inference
        # ====================================================
        
        ha_score = 0
        
        if len(report.dns.infrastructure.a_records) > 1:
            ha_score += 30
        if report.dns.infrastructure.aaaa_records:
            ha_score += 10
        if intel.architecture.cdn_detected:
            ha_score += 25
        if intel.load_balancer_info.detected:
            ha_score += 35
        
        intel.architecture.high_availability = ha_score > 50
        intel.architecture.ha_score = ha_score
        
        # ====================================================
        # Cloud Provider Detection
        # ====================================================
        
        if report.dns and report.dns.infrastructure.a_records:
            for ip_intel in report.dns.infrastructure.a_records:
                if ip_intel.asn:
                    asn_lower = ip_intel.asn.lower()
                    
                    if 'aws' in asn_lower or 'amazon' in asn_lower:
                        intel.architecture.cloud_provider = 'AWS'
                    elif 'google' in asn_lower:
                        intel.architecture.cloud_provider = 'GCP'
                    elif 'azure' in asn_lower or 'microsoft' in asn_lower:
                        intel.architecture.cloud_provider = 'Azure'
                    elif 'digitalocean' in asn_lower:
                        intel.architecture.cloud_provider = 'DigitalOcean'
                    elif 'linode' in asn_lower:
                        intel.architecture.cloud_provider = 'Linode'
                    elif 'vultr' in asn_lower:
                        intel.architecture.cloud_provider = 'Vultr'
                    elif 'ovh' in asn_lower:
                        intel.architecture.cloud_provider = 'OVH'
                    elif 'hetzner' in asn_lower:
                        intel.architecture.cloud_provider = 'Hetzner'

    # ========================================================
    # RISK SCORING
    # ========================================================

    def _calculate_risk_scores(self, intel: ConnectivityIntelligence):
        """Calculate risk scores based on findings"""
        
        risk_score = 0
        risk_factors = []
        
        # Exposed sensitive services
        if intel.port_intel.exposed_sensitive_service:
            risk_score += 30
            risk_factors.append(f"Sensitive services exposed: {intel.port_intel.sensitive_ports}")
        
        # Exposed databases
        if intel.port_intel.database_ports:
            risk_score += 40
            risk_factors.append(f"Databases exposed: {intel.port_intel.database_ports}")
        
        # Non-standard ports
        if intel.port_intel.unusual_port_usage:
            risk_score += 10
            risk_factors.append(f"Non-standard ports open: {intel.port_intel.non_standard_ports[:5]}")
        
        # Weak TLS protocols
        if intel.tls_intelligence and intel.tls_intelligence.weak_protocols_detected:
            risk_score += 35
            risk_factors.append(f"Weak TLS/SSL protocols: {intel.tls_intelligence.weak_protocols}")
        
        # Expired certificates
        if intel.tls_intelligence:
            for cert in intel.tls_intelligence.certificates:
                if cert.is_expired:
                    risk_score += 25
                    risk_factors.append(f"Expired SSL certificate for {cert.subject}")
        
        # Self-signed certificates
        if intel.tls_intelligence:
            for cert in intel.tls_intelligence.certificates:
                if cert.is_self_signed:
                    risk_score += 15
                    risk_factors.append(f"Self-signed SSL certificate for {cert.subject}")
        
        # Information disclosure
        for port, response in intel.http_responses.items():
            if response.server_header and 'nginx' in response.server_header.lower():
                if '1.0' in response.server_header or '1.1' in response.server_header:
                    risk_score += 5
                    risk_factors.append(f"Outdated web server: {response.server_header}")
        
        intel.risk_score = min(100, risk_score)
        intel.risk_factors = risk_factors[:10]  # Top 10 risk factors
        
        # Risk level classification
        if intel.risk_score >= 70:
            intel.risk_level = "CRITICAL"
        elif intel.risk_score >= 50:
            intel.risk_level = "HIGH"
        elif intel.risk_score >= 30:
            intel.risk_level = "MEDIUM"
        elif intel.risk_score >= 10:
            intel.risk_level = "LOW"
        else:
            intel.risk_level = "INFO"

    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
            self.session = None