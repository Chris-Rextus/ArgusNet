# src/argusnet/services/url_analyzer/layers/dns_layer/dns.py

import time
import random
import string
import ipaddress
import dns.asyncresolver
import dns.resolver
import whois
import requests

from urllib.parse import urlparse
from datetime import datetime
from argusnet.services.url_analyzer.layers.baselayer import BaseLayer
from .models import (
    DNSIntelligence,
    InfrastructureIntel,
    SecurityPosture,
    OperationalPatterns,
    RiskIndicators,
    IPIntel,
    CNAMEHop,
    MXRecord,
    SOARecord,
    AuthorityIntel,
    DNSSECStatus,
    SPFStatus,
    TTLAnalysis,
    WildcardStatus,
)


SUSPICIOUS_TLDS = {".tk", ".cm", ".ml", ".ga", ".cf", ".xyz", ".top", ".work"}


class DNSLayer(BaseLayer):

    name = "DNS Intelligence Layer"

    async def run(self, report):

        hostname = urlparse(report.url).hostname

        if not hostname:
            report.dns = None
            return report
        
        start = time.perf_counter()

        # -------------------------
        # Initialize Intelligence Object
        # -------------------------

        intel = DNSIntelligence(
            domain=hostname,
            infrastructure=InfrastructureIntel(),
            security_posture=SecurityPosture(
                dnssec=DNSSECStatus(enabled=False, status="Unknown"),
                spf=SPFStatus(present=False),
            ),
            operational_patterns=OperationalPatterns(),
            risk_indicators=RiskIndicators(),
        )

        resolver = dns.asyncresolver.Resolver()

        # =========================
        # A RECORDS + ASN
        # =========================

        try:
            
            answers = await resolver.resolve(hostname, "A")
            ttls = []

            for rdata in answers:

                ip = rdata.address
                ttls.append(answers.rrset.ttl)

                is_private = ipaddress.ip_address(ip).is_private

                asn = None
                country = None

                try:

                    resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
                    
                    if resp.status_code == 200:
                        
                        data = resp.json()
                        asn = data.get("org")
                        country = data.get("country")

                except Exception as e:

                    pass

                intel.infrastructure.a_records.append(
                    IPIntel(
                        ip=ip,
                        asn=asn,
                        country=country,
                        is_private=is_private,
                    )
                )

                if is_private:

                    intel.security_posture.private_ip_leak = True

            # TTL Analysis
            if ttls:

                min_ttl = min(ttls)
                max_ttl = max(ttls)
                avg_ttl = sum(ttls) / len(ttls)

                classification = "Volatile" if min_ttl < 300 else "Stable"

                intel.operational_patterns.ttl = TTLAnalysis(
                    min_ttl=min_ttl,
                    max_ttl=max_ttl,
                    avg_ttl=avg_ttl,
                    classification=classification,
                )

            intel.resolved = True

        except Exception:

            intel.resolved = False

        
        # =========================
        # AAAA
        # =========================

        try:

            answers = await resolver.resolve(hostname, "AAAA")

            for rdata in answers:

                intel.infrastructure.aaaa_records.append(rdata.address)
        
        except Exception:

            pass 

        # =========================
        # CNAME CHAIN
        # =========================

        current = hostname
        depth = 0

        while depth < 10:

            try:

                answers = await resolver.resolve(current, "CNAME")
                target = answers[0].target.to_text().rstrip(".")
                intel.infrastructure.cname_chain.append(
                    CNAMEHop(alias=current, target=target)
                )
                current = target
                depth += 1

            except Exception:

                break

        if len(intel.infrastructure.cname_chain) > 3:

            intel.risk_indicators.excessive_cname_chain = True

        # =========================
        # NS + SOA
        # =========================

        try:

            ns_answers = await resolver.resolve(hostname, "NS")
            ns_list = [r.target.to_text().rstrip(".") for r in ns_answers]

            soa_answers = await resolver.resolve(hostname, "SOA")
            soa = soa_answers[0]

            intel.infrastructure.authority = AuthorityIntel(
                ns_servers=ns_list,
                soa=SOARecord(
                    primary_ns=soa.mname.to_text().rstrip("."),
                    responsible=soa.rname.to_text().rstrip("."),
                    serial=soa.serial,
                    refresh=soa.refresh,
                    retry=soa.retry,
                    expire=soa.expire,
                    minimum_ttl=soa.minimum,
                ),
            )

        except Exception:

            pass

        # =========================
        # MX + SPF
        # =========================

        try:

            mx_answers = await resolver.resolve(hostname, "MX")

            for r in mx_answers:

                intel.infrastructure.mx_records.append(
                    MXRecord(priority=r.preference, server=r.exchange.to_text().rstrip("."))
                )

        except Exception:

            pass

        try:

            txt_answers = await resolver.resolve(hostname, "TXT")
            spf_records = [
                b"".join(r.strings).decode()
                for r in txt_answers
                if b"v=spf1" in b"".join(r.strings)
            ]

            if spf_records:

                intel.security_posture.spf = SPFStatus(
                    present=True,
                    raw_records=spf_records,
                )

        except Exception:

            pass

        # =========================
        # DNSSEC
        # =========================

        try:

            await resolver.resolve(hostname, "DNSKEY")

            intel.security_posture.dnssec = DNSSECStatus(
                enabled=True,
                status="Signed",
            )

        except dns.resolver.NoAnswer:

            intel.security_posture.dnssec = DNSSECStatus(
                enabled=False,
                status="Unsigned",
            )

        except Exception as e:

            intel.security_posture.dnssec = DNSSECStatus(
                enabled=False,
                status="Error",
                error=str(e),
            )

        # =========================
        # Wildcard Detection
        # =========================

        try:

            random_sub = "".join(random.choices(string.ascii_lowercase, k=10))
            test_fqdn = f"{random_sub}.{hostname}"

            await resolver.resolve(test_fqdn, "A")

            intel.operational_patterns.wildcard = WildcardStatus(
                enabled=True,
                classification="Catch-all configured",
            )

        except dns.resolver.NXDOMAIN:

            intel.operational_patterns.wildcard = WildcardStatus(
                enabled=False,
                classification="Strict",
            )

        except Exception:

            pass

        # =========================
        # Domain Age (WHOIS)
        # =========================

        try:

            w = whois.whois(hostname)
            creation = w.creation_date

            if isinstance(creation, list):

                creation = creation[0]

            if creation:

                age_days = (datetime.utcnow() - creation).days
                classification = "High risk" if age_days < 30 else "Established"

                intel.operational_patterns.domain_age_days = age_days
                intel.operational_patterns.domain_age_classification = classification

        except Exception:

            pass

        # =========================
        # Suspicious TLD
        # =========================

        tld = "." + hostname.split(".")[-1]

        if tld in SUSPICIOUS_TLDS:

            intel.risk_indicators.suspicious_tld = True

        # =========================
        # Finalize
        # =========================

        end = time.perf_counter()
        intel.resolution_time_ms = round((end - start) * 1000, 2)
        report.dns = intel

        return report



            

            
