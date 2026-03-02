# src/argusnet/services/url_analyzer/display.py

"""
URL Analyzer - Interface Renderer

Responsible for transforming intelligence models
into human-readable output.
"""

from typing import Optional
from datetime import timedelta

from argusnet.services.url_analyzer.layers.dns_layer.models import DNSIntelligence
from argusnet.services.url_analyzer.layers.connectivity_layer.models import (
    ConnectivityIntelligence
)
from argusnet.services.url_analyzer.layers.http_layer.models import HTTPIntelligence
from argusnet.services.url_analyzer.layers.tls_layer.models import TLSIntelligence
from argusnet.services.url_analyzer.layers.tls_layer.models import (
    TLSIntelligence,
    CipherSuite,
    VulnerabilitySeverity
)


class URLAnalyzerInterface:

    """
    Handles presentation of URL analysis results.
    """

    @staticmethod
    def render_dns(report: DNSIntelligence) -> None:

        print("\n" + "=" * 60)
        print("DNS INTELLIGENCE REPORT")
        print("=" * 60)

        if not report.resolved:
            print(f"\n❌ Domain '{report.domain}' could not be resolved.")
            return

        # --------------------------------------------------
        # EXECUTIVE SUMMARY
        # --------------------------------------------------
        print("\n[SUMMARY]")
        print(f"Domain: {report.domain}")
        print(f"Resolved: Yes")
        print(f"Resolution Time: {round(report.resolution_time_ms or 0, 2)} ms")

        # --------------------------------------------------
        # INFRASTRUCTURE
        # --------------------------------------------------
        infra = report.infrastructure

        print("\n[INFRASTRUCTURE]")

        print(f"A Records (IPv4): {len(infra.a_records)}")
        for ip in infra.a_records[:5]:  # show first 5 only
            print(f"  - {ip.ip} | ASN: {ip.asn} | Country: {ip.country}")

        if len(infra.a_records) > 5:
            print(f"  ... +{len(infra.a_records) - 5} more")

        print(f"AAAA Records (IPv6): {len(infra.aaaa_records)}")

        if infra.cname_chain:
            print("CNAME Chain:")
            for hop in infra.cname_chain:
                print(f"  {hop.alias} → {hop.target}")
        else:
            print("CNAME Chain: None")

        # --------------------------------------------------
        # SECURITY POSTURE
        # --------------------------------------------------
        sec = report.security_posture

        print("\n[SECURITY POSTURE]")

        print(f"DNSSEC: {sec.dnssec.status}")
        print(f"SPF Present: {'Yes' if sec.spf.present else 'No'}")
        print(f"Private IP Leak: {'Yes' if sec.private_ip_leak else 'No'}")

        # --------------------------------------------------
        # OPERATIONAL BEHAVIOR
        # --------------------------------------------------
        ops = report.operational_patterns

        print("\n[OPERATIONAL PATTERNS]")

        if ops.ttl:
            print(f"TTL Range: {ops.ttl.min_ttl} - {ops.ttl.max_ttl} seconds")
            print(f"TTL Classification: {ops.ttl.classification}")

        if ops.wildcard:
            print(f"Wildcard DNS: {ops.wildcard.classification}")

        if ops.domain_age_days is not None:
            print(f"Domain Age: {ops.domain_age_days} days")
            print(f"Age Classification: {ops.domain_age_classification}")

        # --------------------------------------------------
        # RISK INDICATORS
        # --------------------------------------------------
        risk = report.risk_indicators

        print("\n[RISK INDICATORS]")

        print(f"Suspicious TLD: {'Yes' if risk.suspicious_tld else 'No'}")
        print(f"Excessive CNAME Chain: {'Yes' if risk.excessive_cname_chain else 'No'}")

        # --------------------------------------------------
        # FINAL ASSESSMENT
        # --------------------------------------------------
        print("\n[ASSESSMENT]")

        issues = []

        if risk.suspicious_tld:
            issues.append("Suspicious top-level domain")

        if risk.excessive_cname_chain:
            issues.append("Long CNAME redirection chain")

        if sec.private_ip_leak:
            issues.append("Private IP exposure")

        if not issues:
            print("No immediate DNS-level risk indicators detected.")
        else:
            for issue in issues:
                print(f"- {issue}")



    @staticmethod
    def render_connectivity(intel: Optional[ConnectivityIntelligence]) -> None:

        if not intel:
            return

        print("\n" + "=" * 60)
        print("CONNECTIVITY INTELLIGENCE REPORT")
        print("=" * 60)

        # --------------------------------------------------
        # EXECUTIVE SUMMARY
        # --------------------------------------------------
        print("\n[SUMMARY]")
        print(f"Target IP: {intel.target_ip}")
        print(f"Reachable: {'Yes' if intel.reachable else 'No'}")

        if intel.scan_duration_ms:
            print(f"Scan Duration: {round(intel.scan_duration_ms, 2)} ms")

        if intel.performance and intel.performance.baseline_rtt_ms:
            print(f"Baseline RTT: {intel.performance.baseline_rtt_ms} ms")
            print(f"Jitter: {intel.performance.jitter_ms} ms")
            print(f"Packet Loss: {intel.performance.packet_loss_percent}%")

        # --------------------------------------------------
        # PORT EXPOSURE
        # --------------------------------------------------
        print("\n[PORT EXPOSURE]")

        open_ports = intel.port_intel.open_ports
        print(f"Open Ports: {len(open_ports)}")

        if open_ports:
            for p in open_ports[:10]:
                print(f"  - {p.port}/tcp ({p.service})")
            if len(open_ports) > 10:
                print(f"  ... +{len(open_ports) - 10} more")

        if intel.port_intel.exposed_sensitive_service:
            print(f"⚠ Sensitive Services: {intel.port_intel.sensitive_ports}")

        if intel.port_intel.database_ports:
            print(f"⚠ Exposed Databases: {intel.port_intel.database_ports}")

        if intel.port_intel.unusual_port_usage:
            print(f"Non-standard Ports: {intel.port_intel.non_standard_ports[:5]}")

        # --------------------------------------------------
        # SERVICE FINGERPRINTING
        # --------------------------------------------------
        if intel.port_intel.service_fingerprints:
            print("\n[SERVICE FINGERPRINTS]")
            for fp in intel.port_intel.service_fingerprints[:5]:
                version = f" v{fp.version}" if fp.version else ""
                print(f"  - {fp.service}{version} (Port {fp.port})")
            if len(intel.port_intel.service_fingerprints) > 5:
                print(f"  ... +{len(intel.port_intel.service_fingerprints) - 5} more")

        # --------------------------------------------------
        # TLS / SSL
        # --------------------------------------------------
        if intel.tls_intelligence:
            tls = intel.tls_intelligence
            print("\n[TLS / SSL INTELLIGENCE]")

            if tls.tls_versions:
                print(f"Supported TLS Versions: {', '.join(tls.tls_versions)}")

            if tls.weak_protocols_detected:
                print(f"⚠ Weak Protocols: {tls.weak_protocols}")

            for cert in tls.certificates[:2]:
                print(f"\nCertificate:")
                print(f"  Subject: {cert.subject}")
                print(f"  Issuer: {cert.issuer}")
                print(f"  Expires In: {cert.days_until_expiry} days")
                print(f"  Key: {cert.key_algorithm} ({cert.key_size} bits)")
                print(f"  Self-Signed: {'Yes' if cert.is_self_signed else 'No'}")
                print(f"  Expired: {'Yes' if cert.is_expired else 'No'}")

        # --------------------------------------------------
        # ARCHITECTURE
        # --------------------------------------------------
        print("\n[ARCHITECTURE]")

        if intel.architecture.cdn_detected:
            print(f"CDN Detected: {intel.cdn_detection.provider} "
                  f"(Confidence {intel.cdn_detection.confidence})")

        if intel.load_balancer_info.detected:
            print(f"Load Balancer: {intel.load_balancer_info.method}")

        if intel.architecture.cloud_provider:
            print(f"Cloud Provider: {intel.architecture.cloud_provider}")

        print(f"High Availability: {'Yes' if intel.architecture.high_availability else 'No'}")

        # --------------------------------------------------
        # TCP STACK
        # --------------------------------------------------
        if intel.tcp_stack_fingerprint:
            tcp = intel.tcp_stack_fingerprint
            print("\n[TCP STACK]")
            if tcp.guessed_os:
                print(f"Guessed OS: {tcp.guessed_os} "
                      f"(Confidence {tcp.os_confidence})")

        # --------------------------------------------------
        # RISK ASSESSMENT
        # --------------------------------------------------
        print("\n[RISK ASSESSMENT]")
        print(f"Risk Score: {intel.risk_score}/100")
        print(f"Risk Level: {intel.risk_level}")

        if intel.risk_factors:
            print("\nKey Risk Factors:")
            for factor in intel.risk_factors:
                print(f"  - {factor}")
        else:
            print("No major connectivity-level risks detected.")


    @staticmethod
    def render_http(intel: Optional[HTTPIntelligence]) -> None:
        """
        Render HTTP intelligence results in a clean, strategic format.
        Enhanced version with more detailed analysis and visual indicators.
        """
        if not intel:
            return

        print("\n" + "=" * 60)
        print("HTTP INTELLIGENCE REPORT")
        print("=" * 60)

        # --------------------------------------------------
        # EXECUTIVE SUMMARY
        # --------------------------------------------------
        print("\n[SUMMARY]")
        print(f"URL: {intel.url}")
        print(f"Final Destination: {intel.redirect_chain.final_url or intel.url}")
        print(f"Protocol: {intel.protocol.upper()}")
        print(f"Analysis Duration: {round(intel.analysis_duration_ms or 0, 2)} ms")
        
        if intel.redirect_chain.redirect_count > 0:
            print(f"Redirect Chain: {intel.redirect_chain.redirect_count} hops")
            # Show redirect path
            for i, hop in enumerate(intel.redirect_chain.hops[:3]):
                print(f"  {i+1}. {hop.status_code} → {hop.url}")
            if intel.redirect_chain.redirect_count > 3:
                print(f"     ... +{intel.redirect_chain.redirect_count - 3} more")
            
            if intel.redirect_chain.enforces_https:
                print(f"  ✓ Enforces HTTPS")
            if intel.redirect_chain.hsts_enforced:
                print(f"  ✓ HSTS Enabled")

        # --------------------------------------------------
        # PROTOCOL SUPPORT
        # --------------------------------------------------
        print("\n[PROTOCOL SUPPORT]")
        protocols = []
        if intel.protocol_support.http_1_1:
            protocols.append("HTTP/1.1")
        if intel.protocol_support.http_2:
            protocols.append("HTTP/2")
        if intel.protocol_support.http_3:
            protocols.append("HTTP/3")
        
        print(f"Supported: {', '.join(protocols) if protocols else 'Unknown'}")
        
        if intel.protocol_support.alpn_protocols:
            print(f"ALPN Protocols: {', '.join(intel.protocol_support.alpn_protocols)}")
        if intel.protocol_support.websocket_supported:
            print(f"✓ WebSocket Supported")
        if intel.protocol_support.http_2_push_supported:
            print(f"✓ HTTP/2 Push Supported")

        # --------------------------------------------------
        # TECHNOLOGY STACK (Enhanced)
        # --------------------------------------------------
        print("\n[TECHNOLOGY STACK]")
        
        tech = intel.technology_stack
        
        # Web Server with full details
        if tech.web_server.software:
            web = tech.web_server
            version = f" v{web.version}" if web.version else ""
            print(f"🖥️  Web Server: {web.software}{version}")
            if web.powered_by:
                print(f"   Powered By: {web.powered_by}")
            if web.via_header:
                print(f"   Via: {web.via_header}")
            if web.case_sensitive:
                print(f"   Case Sensitive: Yes")
            if web.custom_404_detected:
                print(f"   Custom 404 Page: Yes")
        
        # Frameworks with confidence
        if tech.frameworks:
            print(f"\n📚 Frameworks:")
            for f in tech.frameworks:
                confidence_bar = "█" * int(f.confidence * 10) + "░" * (10 - int(f.confidence * 10))
                version = f" v{f.version}" if f.version else ""
                print(f"   • {f.name}{version} [{confidence_bar}] {f.confidence:.0%}")
                if f.evidence:
                    print(f"     Evidence: {', '.join(f.evidence[:2])}")
        
        # CMS with plugin details
        if tech.cms:
            cms = tech.cms
            version = f" v{cms.version}" if cms.version else ""
            confidence_bar = "█" * int(cms.confidence * 10) + "░" * (10 - int(cms.confidence * 10))
            print(f"\n📦 CMS: {cms.name}{version} [{confidence_bar}] {cms.confidence:.0%}")
            
            if cms.plugins:
                print(f"   Plugins ({len(cms.plugins)}):")
                for plugin in cms.plugins[:5]:
                    print(f"     • {plugin}")
                if len(cms.plugins) > 5:
                    print(f"     ... +{len(cms.plugins) - 5} more")
            
            if cms.themes:
                print(f"   Themes: {', '.join(cms.themes[:3])}")
        
        # Programming Language
        if tech.programming_language:
            lang_icons = {
                'PHP': '🐘', 'Python': '🐍', 'Ruby': '💎', 
                'Java': '☕', 'Node.js': '🟢', 'Go': '🔵', 'C#': '🎯'
            }
            icon = lang_icons.get(tech.programming_language, '📝')
            print(f"\n{icon} Language: {tech.programming_language}")
        
        # JavaScript Libraries with versions
        if tech.js_libraries:
            print(f"\n📜 JavaScript Libraries ({len(tech.js_libraries)}):")
            for lib in tech.js_libraries[:8]:
                version = f" v{lib.version}" if lib.version else ""
                cdn = f" [{lib.cdn_provider}]" if lib.cdn_provider else ""
                confidence = "★" * int(lib.confidence * 5) + "☆" * (5 - int(lib.confidence * 5))
                print(f"   • {lib.name}{version}{cdn} {confidence}")
            if len(tech.js_libraries) > 8:
                print(f"   ... +{len(tech.js_libraries) - 8} more")
        
        # OS Detection
        if tech.os_detected:
            os_icons = {'Linux': '🐧', 'Windows': '🪟', 'macOS': '🍎', 'FreeBSD': '😈'}
            icon = os_icons.get(tech.os_detected, '💻')
            print(f"\n{icon} OS: {tech.os_detected}")

        # --------------------------------------------------
        # SECURITY HEADERS (Enhanced with CSP details)
        # --------------------------------------------------
        print("\n[SECURITY HEADERS]")
        
        headers = intel.security_headers
        score = headers.security_score
        score_bar = "█" * int(score/10) + "░" * (10 - int(score/10))
        print(f"Security Header Score: {score}/100 [{score_bar}]")
        
        # HSTS
        if headers.hsts.present:
            hsts = headers.hsts
            max_age_days = hsts.max_age // 86400 if hsts.max_age else 0
            print(f"✓ HSTS: max-age={hsts.max_age}s ({max_age_days} days)" + 
                (", includeSubDomains" if hsts.include_subdomains else "") +
                (", preload" if hsts.preload else ""))
            if hsts.preload_ready:
                print(f"   ✓ Preload Ready")
        else:
            print(f"✗ HSTS: Not configured")
        
        # CSP - Enhanced details
        if headers.csp.present:
            csp = headers.csp
            print(f"✓ CSP: Configured")
            if csp.directives:
                print(f"   Directives:")
                for name, values in list(csp.directives.items())[:5]:
                    print(f"     • {name}: {', '.join(values[:2])}" + 
                        (f" ... +{len(values)-2}" if len(values) > 2 else ""))
            if csp.unsafe_inline or csp.unsafe_eval or csp.wildcard_sources:
                print(f"   ⚠ Issues:")
                if csp.unsafe_inline:
                    print(f"     • unsafe-inline detected")
                if csp.unsafe_eval:
                    print(f"     • unsafe-eval detected")
                if csp.wildcard_sources:
                    print(f"     • Wildcard sources: {', '.join(csp.wildcard_sources)}")
        else:
            print(f"✗ CSP: Missing")
        
        # Other Security Headers with icons
        other_headers = []
        if headers.x_frame_options:
            other_headers.append(f"X-Frame-Options: {headers.x_frame_options}")
        if headers.x_content_type_options:
            other_headers.append("X-Content-Type-Options: nosniff")
        if headers.referrer_policy:
            other_headers.append(f"Referrer-Policy: {headers.referrer_policy}")
        if headers.permissions_policy:
            other_headers.append("Permissions-Policy: ✓")
        if headers.x_xss_protection:
            other_headers.append("X-XSS-Protection: ✓")
        
        if other_headers:
            print(f"\n   Other Headers:")
            for h in other_headers:
                print(f"     • {h}")
        
        # Cookie Analysis - Enhanced
        if headers.cookies:
            print(f"\n🍪 Cookies ({len(headers.cookies)}):")
            for cookie in headers.cookies[:5]:
                flags = []
                if cookie.secure:
                    flags.append("Secure")
                if cookie.http_only:
                    flags.append("HttpOnly")
                if cookie.same_site:
                    flags.append(f"SameSite={cookie.same_site}")
                
                security = "🔒" if cookie.secure and cookie.http_only else "⚠"
                expiry = " (Session)" if cookie.session_cookie else f" (Expires: {cookie.expires.date() if cookie.expires else 'Unknown'})"
                
                print(f"   {security} {cookie.name}{expiry}")
                if flags:
                    print(f"     Flags: {', '.join(flags)}")
        
        # CORS Analysis
        if headers.cors.present:
            cors = headers.cors
            print(f"\n🌐 CORS Configuration:")
            if cors.allow_origin:
                origin_display = "Wildcard (*)" if cors.wildcard_origin else cors.allow_origin
                print(f"   Allow-Origin: {origin_display}")
            if cors.allow_methods:
                print(f"   Allow-Methods: {', '.join(cors.allow_methods)}")
            if cors.allow_credentials:
                print(f"   Allow-Credentials: Yes")
            if cors.misconfigured:
                print(f"   ⚠ Misconfigured: Wildcard with credentials")

        # --------------------------------------------------
        # ENDPOINT DISCOVERY (Enhanced)
        # --------------------------------------------------
        print("\n[ENDPOINT DISCOVERY]")
        
        discovery = intel.endpoint_discovery
        print(f"🔍 Total Endpoints: {discovery.total_discovered}")
        
        if discovery.admin_interfaces:
            print(f"\n   👑 Admin Interfaces ({len(discovery.admin_interfaces)}):")
            for path in discovery.admin_interfaces[:4]:
                status_color = "✓" if path.status_code == 200 else "🔒" if path.status_code == 401 else "⚠"
                print(f"     {status_color} {path.path} ({path.status_code})")
        
        if discovery.api_endpoints:
            print(f"\n   🔌 API Endpoints ({len(discovery.api_endpoints)}):")
            for api in discovery.api_endpoints[:4]:
                print(f"     • {api}")
        
        if discovery.sensitive_files:
            print(f"\n   ⚠ Sensitive Files ({len(discovery.sensitive_files)}):")
            for file in discovery.sensitive_files[:4]:
                severity = "🔴" if '.git' in file.path or '.env' in file.path else "🟠"
                print(f"     {severity} {file.path} ({file.status_code})")
        
        if discovery.config_files:
            print(f"\n   ⚙️ Config Files ({len(discovery.config_files)}):")
            for cfg in discovery.config_files[:4]:
                print(f"     • {cfg.path}")
        
        if discovery.cloud_metadata_endpoints:
            print(f"\n   ☁️ Cloud Metadata Exposed!")
            for meta in discovery.cloud_metadata_endpoints:
                print(f"     • {meta.path}")
        
        # Parameter Analysis
        params = discovery.parameter_analysis
        if params.xss_reflection_points > 0 or params.open_redirect_candidates:
            print(f"\n   🎯 Parameter Vulnerabilities:")
            if params.xss_reflection_points > 0:
                print(f"     • XSS Reflection Points: {params.xss_reflection_points}")
            if params.open_redirect_candidates:
                print(f"     • Open Redirect Parameters: {', '.join(params.open_redirect_candidates)}")
            if params.sql_error_patterns:
                print(f"     • SQL Error Patterns: {', '.join(params.sql_error_patterns)}")

        # --------------------------------------------------
        # CONTENT ANALYSIS (Enhanced)
        # --------------------------------------------------
        print("\n[CONTENT ANALYSIS]")
        
        content = intel.content_analysis
        
        if content.title:
            print(f"📌 Title: {content.title[:80]}" + ("..." if len(content.title) > 80 else ""))
        
        if content.meta_tags:
            print(f"\n📋 Meta Tags ({len(content.meta_tags)}):")
            important_meta = ['description', 'keywords', 'author', 'robots']
            for meta in content.meta_tags:
                if meta.name in important_meta:
                    value = meta.content[:60] + "..." if meta.content and len(meta.content) > 60 else meta.content
                    print(f"   • {meta.name}: {value}")
        
        if content.favicon_hash:
            print(f"🖼️ Favicon Hash: {content.favicon_hash[:16]}...")
        
        if content.forms:
            print(f"\n📝 Forms ({len(content.forms)}):")
            for i, form in enumerate(content.forms[:3]):
                form_type = "🔐" if form.is_login_form else "📄" if form.is_search_form else "📋"
                csrf = "✓ CSRF" if form.has_csrf_token else "⚠ No CSRF"
                upload = "📎 Upload" if form.has_file_upload else ""
                print(f"   {form_type} Form {i+1}: {form.method} → {form.action or '/'} [{csrf}] {upload}")
                if form.fields:
                    field_types = [f.type for f in form.fields]
                    print(f"     Fields: {', '.join(set(field_types)[:5])}")
        
        if content.links:
            print(f"\n🔗 Links: {content.links.total_links} total")
            print(f"   Internal: {len(content.links.internal_links)} | External: {len(content.links.external_links)}")
            if content.links.javascript_files:
                print(f"   📜 JS Files: {len(content.links.js_files)}")
            if content.links.css_files:
                print(f"   🎨 CSS Files: {len(content.links.css_files)}")
            if content.links.image_sources:
                print(f"   🖼️ Images: {len(content.links.image_sources)}")
        
        # robots.txt
        if content.robots_txt.present:
            print(f"\n🤖 robots.txt: Present")
            if content.robots_txt.disallowed_paths:
                print(f"   Disallowed ({len(content.robots_txt.disallowed_paths)}): {', '.join(content.robots_txt.disallowed_paths[:5])}")
            if content.robots_txt.sitemaps:
                print(f"   Sitemaps: {len(content.robots_txt.sitemaps)} found")
            if content.robots_txt.crawl_delay:
                print(f"   Crawl-Delay: {content.robots_txt.crawl_delay}s")
        
        # sitemap.xml
        if content.sitemap_xml.present:
            print(f"🗺️ sitemap.xml: {content.sitemap_xml.url_count} URLs")

        # --------------------------------------------------
        # MODERN WEB FEATURES (Enhanced)
        # --------------------------------------------------
        print("\n[MODERN WEB FEATURES]")
        
        modern = intel.modern_web
        
        if modern.rest_apis:
            print(f"   🔌 REST APIs: {len(modern.rest_apis)} endpoints")
            for api in modern.rest_apis[:3]:
                methods = ', '.join(api.methods[:3])
                print(f"     • {api.path} [{methods}]")
        
        if modern.graphql and modern.graphql.present:
            graphql = modern.graphql
            print(f"   ⚡ GraphQL: {graphql.endpoint}")
            if graphql.introspection_enabled:
                print(f"     ⚠ Introspection Enabled - Security Risk")
            if graphql.queries_detected:
                print(f"     Queries: {', '.join(graphql.queries_detected[:3])}")
        
        if modern.websocket and modern.websocket.present:
            ws = modern.websocket
            protocol = "WSS" if ws.secure else "WS"
            print(f"   🔄 WebSocket: {protocol} Supported")
            if ws.endpoints:
                print(f"     Endpoints: {', '.join(ws.endpoints[:3])}")
        
        if modern.spa and modern.spa.is_spa:
            spa = modern.spa
            print(f"   📱 SPA: {spa.framework or 'Detected'}")
            if spa.client_side_routing:
                print(f"     • Client-side Routing")
            if spa.api_driven:
                print(f"     • API-driven")

        # --------------------------------------------------
        # HTTP METHODS
        # --------------------------------------------------
        if intel.method_analysis.unsafe_methods_allowed:
            print("\n[HTTP METHODS]")
            print(f"⚠ Unsafe Methods Allowed: {', '.join(intel.method_analysis.unsafe_methods_allowed)}")
            
            if intel.method_analysis.trace_vulnerable:
                print(f"   • TRACE method enabled (XST vulnerability)")
            if intel.method_analysis.put_enabled:
                print(f"   • PUT method enabled (file upload risk)")
            if intel.method_analysis.delete_enabled:
                print(f"   • DELETE method enabled")

        # --------------------------------------------------
        # VULNERABILITY INDICATORS
        # --------------------------------------------------
        if intel.vulnerability_indicators:
            vuln = intel.vulnerability_indicators
            
            critical_findings = []
            
            if vuln.information_disclosure.git_folder_exposed:
                critical_findings.append("🔴 .git folder exposed!")
            if vuln.information_disclosure.env_file_exposed:
                critical_findings.append("🔴 .env file exposed!")
            if vuln.information_disclosure.backup_files_found:
                critical_findings.append(f"🔴 Backup files: {len(vuln.information_disclosure.backup_files_found)}")
            if vuln.information_disclosure.directory_listing_enabled:
                critical_findings.append(f"🟠 Directory listing: {', '.join(vuln.information_disclosure.directory_listing_enabled[:3])}")
            if vuln.information_disclosure.debug_mode_detected:
                critical_findings.append("🟠 Debug mode detected")
            if vuln.information_disclosure.php_info_detected:
                critical_findings.append("🟠 phpinfo() exposed")
            
            if critical_findings:
                print("\n[CRITICAL FINDINGS]")
                for finding in critical_findings:
                    print(f"  {finding}")
            
            if vuln.waf.present:
                print(f"\n[WAF DETECTION]")
                conf_bar = "█" * int(vuln.waf.confidence * 10) + "░" * (10 - int(vuln.waf.confidence * 10))
                print(f"🛡️  WAF: {vuln.waf.provider} [{conf_bar}] {vuln.waf.confidence:.0%} confidence")
                if vuln.waf.evidence:
                    print(f"   Evidence: {', '.join(vuln.waf.evidence[:3])}")

        # --------------------------------------------------
        # PERFORMANCE METRICS (Enhanced)
        # --------------------------------------------------
        print("\n[PERFORMANCE METRICS]")
        
        perf = intel.performance
        
        if 'main_page' in perf.response_times:
            rt = perf.response_times['main_page']
            
            # Performance grade based on TTFB
            if rt.ttfb_ms < 200:
                grade = "A+ 🚀"
            elif rt.ttfb_ms < 500:
                grade = "A ✓"
            elif rt.ttfb_ms < 1000:
                grade = "B ⚠"
            elif rt.ttfb_ms < 2000:
                grade = "C ⚠"
            else:
                grade = "D ✗"
            
            print(f"⏱️  Time to First Byte (TTFB): {round(rt.ttfb_ms, 2)} ms [{grade}]")
            print(f"   Total Load Time: {round(rt.total_time_ms, 2)} ms")
            
            if rt.dns_time_ms:
                print(f"   DNS: {round(rt.dns_time_ms, 2)} ms")
            if rt.connect_time_ms:
                print(f"   Connect: {round(rt.connect_time_ms, 2)} ms")
            if rt.ssl_time_ms:
                print(f"   SSL/TLS: {round(rt.ssl_time_ms, 2)} ms")
        
        if perf.caching:
            cache_status = "✓ Enabled" if perf.caching.cacheable else "✗ Disabled"
            print(f"\n📦 Caching: {cache_status}")
            if perf.caching.cache_control:
                print(f"   Cache-Control: {perf.caching.cache_control}")
            if perf.caching.cdn_cache_hit:
                print(f"   CDN Cache Hit: Yes")
            if perf.caching.etag:
                print(f"   ETag: {perf.caching.etag[:20]}...")
        
        if perf.compression:
            comp = perf.compression
            if comp.content_encoding:
                ratio_display = f"{round(comp.compression_ratio, 2)}x" if comp.compression_ratio else "Unknown"
                print(f"\n🗜️  Compression: {comp.content_encoding.upper()} ({ratio_display})")
            else:
                print(f"\n🗜️  Compression: Not enabled")
        
        if perf.keep_alive.keep_alive_supported:
            ka = perf.keep_alive
            print(f"\n🔁 Keep-Alive: Supported")
            if ka.timeout_seconds:
                print(f"   Timeout: {ka.timeout_seconds}s")
            if ka.max_requests:
                print(f"   Max Requests: {ka.max_requests}")

        # --------------------------------------------------
        # RISK ASSESSMENT (Enhanced)
        # --------------------------------------------------
        print("\n[RISK ASSESSMENT]")
        
        # Visual score bars
        sec_bar = "█" * int(intel.risk_scores.security_score/10) + "░" * (10 - int(intel.risk_scores.security_score/10))
        perf_bar = "█" * int(intel.risk_scores.performance_score/10) + "░" * (10 - int(intel.risk_scores.performance_score/10))
        rel_bar = "█" * int(intel.risk_scores.reliability_score/10) + "░" * (10 - int(intel.risk_scores.reliability_score/10))
        
        print(f"🔒 Security:    {intel.risk_scores.security_score:3d}/100 [{sec_bar}]")
        print(f"⚡ Performance: {intel.risk_scores.performance_score:3d}/100 [{perf_bar}]")
        print(f"🛡️  Reliability: {intel.risk_scores.reliability_score:3d}/100 [{rel_bar}]")
        print(f"📊 Overall:     {intel.risk_scores.overall_score:3d}/100")
        
        # Risk level with color indicator
        risk_level = intel.risk_scores.risk_level
        risk_colors = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🟢 LOW",
            "INFO": "🔵 INFO"
        }
        print(f"\nRisk Level: {risk_colors.get(risk_level, risk_level)}")

        # --------------------------------------------------
        # RECOMMENDATIONS (Enhanced)
        # --------------------------------------------------
        if intel.recommendations:
            print("\n[RECOMMENDATIONS]")
            
            # Group by severity
            critical = [r for r in intel.recommendations if r.severity == "CRITICAL"]
            high = [r for r in intel.recommendations if r.severity == "HIGH"]
            medium = [r for r in intel.recommendations if r.severity == "MEDIUM"]
            low = [r for r in intel.recommendations if r.severity == "LOW"]
            
            if critical:
                print("\n  🔴 CRITICAL - Fix Immediately:")
                for i, rec in enumerate(critical[:3], 1):
                    print(f"    {i}. {rec.issue}")
                    print(f"       → {rec.recommendation}")
            
            if high:
                print("\n  🟠 HIGH - Prioritize:")
                for i, rec in enumerate(high[:3], 1):
                    print(f"    {i}. {rec.issue}")
                    print(f"       → {rec.recommendation}")
            
            if medium:
                print("\n  🟡 MEDIUM - Schedule:")
                for i, rec in enumerate(medium[:3], 1):
                    print(f"    {i}. {rec.issue}")
            
            if low:
                print("\n  🔵 LOW - Consider:")
                for i, rec in enumerate(low[:3], 1):
                    print(f"    {i}. {rec.issue}")
            
            if len(intel.recommendations) > 10:
                print(f"\n   ... +{len(intel.recommendations) - 10} more recommendations")

    @staticmethod
    def render_tls(intel: Optional[TLSIntelligence]) -> None:
        """
        Render TLS intelligence results in a clean, strategic format.
        """
        print(f"\n[DEBUG] render_tls called with intel: {intel is not None}")  # Debug
        
        if not intel:
            print("[DEBUG] intel is None, skipping TLS report")
            return

        print(f"[DEBUG] intel.target_host: {intel.target_host}")  # Debug
        print(f"[DEBUG] intel.port: {intel.port}")  # Debug
        print(f"[DEBUG] intel.certificate_chain: {intel.certificate_chain is not None}")  # Debug
        
        if not intel:
            return

        print("\n" + "=" * 60)
        print("TLS/SSL INTELLIGENCE REPORT")
        print("=" * 60)

        # --------------------------------------------------
        # EXECUTIVE SUMMARY
        # --------------------------------------------------
        print("\n[SUMMARY]")
        print(f"Target: {intel.target_host}:{intel.port}")
        print(f"Analysis Duration: {round(intel.analysis_duration_ms or 0, 2)} ms")
        
        # Grade with visual indicator
        grade_colors = {
            "A+": "🟢 A+", "A": "🟢 A", "A-": "🟢 A-",
            "B": "🟡 B", "C": "🟠 C", "D": "🔴 D",
            "E": "🔴 E", "F": "⛔ F", "T": "⚪ T"
        }
        grade_display = grade_colors.get(intel.grade.value, intel.grade.value)
        print(f"TLS Grade: {grade_display}  (Score: {intel.tls_score}/100)")
        
        # Certificate summary
        if intel.certificate_chain:
            leaf = intel.certificate_chain.leaf
            expiry_emoji = "✅" if leaf.days_until_expiry > 30 else "⚠️" if leaf.days_until_expiry > 7 else "🔴"
            print(f"Certificate: {leaf.subject.common_name or 'Unknown'}")
            print(f"  Issuer: {leaf.issuer.common_name or 'Unknown'}")
            print(f"  {expiry_emoji} Expires: {leaf.not_after.strftime('%Y-%m-%d')} ({leaf.days_until_expiry} days)")
            print(f"  Key: {leaf.public_key.algorithm.value} {leaf.public_key.bits} bits")
            
            if leaf.san_entries:
                domains = [s.value for s in leaf.san_entries if s.type == 'DNS'][:3]
                print(f"  SANs: {', '.join(domains)}{' ...' if len(leaf.san_entries) > 3 else ''}")

        # Vulnerability summary
        if intel.vulnerable:
            vuln_count = len(intel.vulnerabilities_found)
            critical = intel.vulnerability_scan.critical_count
            high = intel.vulnerability_scan.high_count
            print(f"\n⚠️  Vulnerabilities: {vuln_count} total (🔴 {critical} critical, 🟠 {high} high)")

        # --------------------------------------------------
        # CERTIFICATE CHAIN
        # --------------------------------------------------
        if intel.certificate_chain:
            print("\n[CERTIFICATE CHAIN]")
            
            chain = intel.certificate_chain
            total_certs = chain.length
            
            # Chain completeness
            if chain.complete:
                print(f"✓ Chain Complete ({total_certs} certificates)")
            else:
                print(f"⚠ Chain Incomplete - Missing certificates")
                for issue in chain.issues:
                    print(f"  • {issue}")
            
            # Leaf certificate
            print("\n  📄 LEAF CERTIFICATE:")
            leaf = chain.leaf
            print(f"    Subject: {leaf.subject.full_string}")
            print(f"    Issuer: {leaf.issuer.full_string}")
            print(f"    Serial: {leaf.serial_number[:16]}..." if len(leaf.serial_number) > 16 else leaf.serial_number)
            print(f"    Validity: {leaf.not_before.strftime('%Y-%m-%d')} to {leaf.not_after.strftime('%Y-%m-%d')}")
            
            # Expiry warning
            if leaf.days_until_expiry < 0:
                print(f"    ❌ EXPIRED ({abs(leaf.days_until_expiry)} days ago)")
            elif leaf.days_until_expiry < 7:
                print(f"    🔴 EXPIRING SOON ({leaf.days_until_expiry} days left)")
            elif leaf.days_until_expiry < 30:
                print(f"    🟠 Expires in {leaf.days_until_expiry} days")
            else:
                print(f"    ✅ Valid for {leaf.days_until_expiry} days")
            
            # Key details
            key = leaf.public_key
            key_strength = "✅ Strong" if key.bits >= 2048 else "⚠️ Weak" if key.bits >= 1024 else "❌ Very Weak"
            print(f"    Key: {key.algorithm.value} {key.bits} bits [{key_strength}]")
            if key.curve:
                print(f"    Curve: {key.curve}")
            if key.fingerprint:
                print(f"    Fingerprint: {key.fingerprint[:32]}...")
            
            # SAN entries
            if leaf.san_entries:
                print(f"\n    🌐 Subject Alternative Names ({len(leaf.san_entries)}):")
                dns_sans = [s for s in leaf.san_entries if s.type == 'DNS']
                ip_sans = [s for s in leaf.san_entries if s.type == 'IP']
                
                if dns_sans:
                    for san in dns_sans[:8]:
                        wildcard = "🟡 Wildcard" if san.is_wildcard else "✓"
                        print(f"      {wildcard} {san.value}")
                    if len(dns_sans) > 8:
                        print(f"      ... +{len(dns_sans) - 8} more")
                if ip_sans:
                    print(f"      IP: {', '.join([s.value for s in ip_sans])}")
            
            # Key Usage
            if leaf.key_usage:
                print(f"\n    🔑 Key Usage: {', '.join(leaf.key_usage)}")
            if leaf.extended_key_usage:
                print(f"    🎯 Extended Key Usage: {', '.join(leaf.extended_key_usage)}")
            
            # Intermediate certificates
            if chain.intermediates:
                print(f"\n  📦 INTERMEDIATE CERTIFICATES ({len(chain.intermediates)}):")
                for i, cert in enumerate(chain.intermediates, 1):
                    issuer_name = cert.issuer.common_name or cert.issuer.organization or "Unknown"
                    subject_name = cert.subject.common_name or cert.subject.organization or "Unknown"
                    print(f"    {i}. {subject_name}")
                    print(f"       Issuer: {issuer_name}")
                    print(f"       Expires: {cert.not_after.strftime('%Y-%m-%d')} ({cert.days_until_expiry} days)")
            
            # Root certificate
            if chain.root:
                print(f"\n  🌳 ROOT CERTIFICATE:")
                root = chain.root
                print(f"    {root.subject.common_name or root.subject.organization or 'Unknown'}")
                print(f"    Expires: {root.not_after.strftime('%Y-%m-%d')} ({root.days_until_expiry} days)")
                if root.issuer.is_trusted:
                    print(f"    ✓ Trusted by: {', '.join(root.issuer.trust_store[:2]) if root.issuer.trust_store else 'Major browsers'}")
            
            # Certificate Transparency
            if leaf.sct_count > 0:
                print(f"\n    📋 Certificate Transparency: {leaf.sct_count} SCTs")
                if leaf.ct_compliant:
                    print(f"      ✓ Chrome CT compliance met")

        # --------------------------------------------------
        # PROTOCOL SUPPORT
        # --------------------------------------------------
        print("\n[PROTOCOL SUPPORT]")
        
        proto = intel.protocol_support
        
        # Version support with visual indicators
        versions = []
        if proto.tlsv1_3:
            versions.append("✅ TLS 1.3")
        if proto.tlsv1_2:
            versions.append("✅ TLS 1.2")
        if proto.tlsv1_1:
            versions.append("⚠️ TLS 1.1")
        if proto.tlsv1_0:
            versions.append("⚠️ TLS 1.0")
        if proto.sslv3:
            versions.append("❌ SSLv3")
        if proto.sslv2:
            versions.append("❌ SSLv2")
        
        if versions:
            print(f"Supported: {', '.join(versions)}")
        else:
            print("❌ No TLS/SSL supported")
        
        # Version details
        if proto.weak_versions:
            print(f"  Weak protocols enabled: {', '.join([v.value for v in proto.weak_versions])}")
        
        if proto.tlsv1_3_early_data:
            print(f"  🚀 TLS 1.3 Early Data (0-RTT): Enabled")
        
        if proto.downgrade_prevention:
            print(f"  🛡️ Downgrade Prevention: Active (TLS_FALLBACK_SCSV)")
        else:
            print(f"  ⚠ Downgrade Prevention: Not detected")
        
        # Preferred version
        if proto.preferred_version:
            print(f"  Preferred: {proto.preferred_version.value}")

        # --------------------------------------------------
        # CIPHER SUITES
        # --------------------------------------------------
        if intel.cipher_preference:
            print("\n[CIPHER SUITES]")
            
            cipher_pref = intel.cipher_preference
            total = cipher_pref.total_count
            strong = cipher_pref.strong_count
            
            # Summary
            print(f"Total ciphers: {total} ({strong} strong, {len(intel.weak_ciphers)} weak)")
            
            # Strong ciphers (AEAD/PFS)
            if intel.strong_ciphers:
                print(f"\n  ✅ Strong Ciphers ({len(intel.strong_ciphers)}):")
                for cipher in intel.strong_ciphers[:5]:
                    pfs = "🔒 PFS" if cipher.provides_pfs else ""
                    aead = "🔐 AEAD" if cipher.provides_aead else ""
                    tags = " | ".join([t for t in [pfs, aead] if t])
                    print(f"    • {cipher.name} [{tags}]")
                if len(intel.strong_ciphers) > 5:
                    print(f"      ... +{len(intel.strong_ciphers) - 5} more")
            
            # Weak ciphers
            if intel.weak_ciphers:
                print(f"\n  ⚠ Weak Ciphers ({len(intel.weak_ciphers)}):")
                for cipher in intel.weak_ciphers[:5]:
                    reason = []
                    if cipher.is_deprecated:
                        reason.append("deprecated")
                    if cipher.category == CipherSuite.WEAK:
                        reason.append("weak")
                    print(f"    • {cipher.name} [{', '.join(reason)}]")
                if len(intel.weak_ciphers) > 5:
                    print(f"      ... +{len(intel.weak_ciphers) - 5} more")
            
            # Dangerous ciphers
            dangerous = []
            dangerous.extend([(c, "EXPORT") for c in intel.export_ciphers])
            dangerous.extend([(c, "NULL") for c in intel.null_ciphers])
            dangerous.extend([(c, "ANONYMOUS") for c in intel.anon_ciphers])
            
            if dangerous:
                print(f"\n  ❌ DANGEROUS CIPHERS ({len(dangerous)}):")
                for cipher, reason in dangerous[:5]:
                    print(f"    • {cipher.name} [{reason}]")
                if len(dangerous) > 5:
                    print(f"      ... +{len(dangerous) - 5} more")
            
            # Cipher preference
            if cipher_pref.server_preferred:
                print(f"\n  🎯 Server enforces cipher order")
                if cipher_pref.preferred_ciphers:
                    top = cipher_pref.preferred_ciphers[0]
                    print(f"     Preferred: {top.name}")

        # --------------------------------------------------
        # TLS EXTENSIONS & FEATURES
        # --------------------------------------------------
        print("\n[TLS EXTENSIONS & FEATURES]")
        
        # SNI
        sni = intel.sni
        if sni.supported:
            print(f"✓ SNI: Supported")
            if sni.required:
                print(f"  ⚠ SNI Required - connections without SNI may fail")
            if sni.default_certificate:
                print(f"  Default certificate without SNI: {sni.default_certificate[:60]}...")
        else:
            print(f"✗ SNI: Not supported")
        
        # ALPN
        if intel.alpn_protocols:
            selected = [p.protocol for p in intel.alpn_protocols if p.selected]
            advertised = [p.protocol for p in intel.alpn_protocols if p.advertised and not p.selected]
            
            if selected:
                print(f"✓ ALPN: Selected {', '.join(selected)}")
            if advertised:
                print(f"  Advertised: {', '.join(advertised)}")
        
        # OCSP Stapling
        ocsp = intel.ocsp_stapling
        if ocsp.supported:
            status = "✓ Enabled" if ocsp.enabled else "✓ Supported but not enabled"
            print(f"✓ OCSP Stapling: {status}")
            if ocsp.must_staple:
                print(f"  ⚠ OCSP Must-Staple extension present")
            if ocsp.responder_url:
                print(f"  Responder: {ocsp.responder_url}")
        else:
            print(f"✗ OCSP Stapling: Not supported")
        
        # Session Management
        sess = intel.session_management
        if sess.session_id_supported or sess.session_ticket_supported:
            print(f"✓ Session Resumption:")
            if sess.session_id_supported:
                print(f"  • Session IDs: {'✓ Reused' if sess.session_id_reused else 'Supported'}")
            if sess.session_ticket_supported:
                ticket_status = "✓ Reused" if sess.session_ticket_reused else "Supported"
                print(f"  • Session Tickets: {ticket_status}")
                if sess.ticket_lifetime_hint:
                    print(f"    Ticket lifetime: {sess.ticket_lifetime_hint}s")
        else:
            print(f"✗ Session Resumption: Not supported")
        
        # Renegotiation
        reneg = intel.renegotiation
        if reneg.secure_renegotiation:
            print(f"✓ Secure Renegotiation: Supported")
        if reneg.client_initiated_allowed:
            print(f"⚠ Client-initiated renegotiation: Allowed")

        # --------------------------------------------------
        # VULNERABILITY SCAN
        # --------------------------------------------------
        if intel.vulnerabilities_found:
            print("\n[VULNERABILITY SCAN]")
            
            vuln = intel.vulnerability_scan
            
            # Critical vulnerabilities
            critical = [v for v in intel.vulnerabilities_found if v.severity == VulnerabilitySeverity.CRITICAL]
            if critical:
                print(f"\n  🔴 CRITICAL VULNERABILITIES:")
                for v in critical:
                    print(f"    • {v.name} ({v.cve})")
                    print(f"      Impact: {v.impact}")
                    print(f"      Fix: {v.remediation}")
            
            # High vulnerabilities
            high = [v for v in intel.vulnerabilities_found if v.severity == VulnerabilitySeverity.HIGH]
            if high:
                print(f"\n  🟠 HIGH VULNERABILITIES:")
                for v in high:
                    print(f"    • {v.name} ({v.cve})")
                    print(f"      Impact: {v.impact}")
            
            # Medium vulnerabilities
            medium = [v for v in intel.vulnerabilities_found if v.severity == VulnerabilitySeverity.MEDIUM]
            if medium:
                print(f"\n  🟡 MEDIUM VULNERABILITIES:")
                for v in medium[:3]:
                    print(f"    • {v.name} ({v.cve})")
                if len(medium) > 3:
                    print(f"      ... +{len(medium) - 3} more")
        else:
            print("\n[VULNERABILITY SCAN]")
            print("✅ No known vulnerabilities detected")

        # --------------------------------------------------
        # TLS FINGERPRINT
        # --------------------------------------------------
        if intel.fingerprint:
            print("\n[TLS FINGERPRINT]")
            
            fp = intel.fingerprint
            print(f"JA3: {fp.ja3_hash}")
            print(f"JA3S: {fp.ja3s_hash or 'N/A'}")
            
            if fp.library:
                print(f"TLS Library: {fp.library} {fp.library_version or ''} (Confidence: {fp.confidence:.0%})")
            if fp.os_hint:
                print(f"OS Hint: {fp.os_hint}")
            
            if fp.matches_browser:
                print(f"Matches: {fp.matches_browser}")
            if fp.matches_bot:
                print(f"⚠ Matches known bot signature")
            if fp.matches_malware:
                print(f"❌ Matches known malware signature")

        # --------------------------------------------------
        # STARTTLS
        # --------------------------------------------------
        if intel.starttls_supported:
            print("\n[STARTTLS]")
            print(f"✓ {intel.starttls_protocol.upper()} STARTTLS supported on port {intel.port}")
            if intel.starttls_result:
                print(f"  TLS Grade after STARTTLS: {intel.starttls_result.grade.value}")

        # --------------------------------------------------
        # PERFORMANCE METRICS
        # --------------------------------------------------
        print("\n[PERFORMANCE METRICS]")
        
        perf = intel.performance
        
        if perf.handshake_timings.full_handshake_ms > 0:
            full = perf.handshake_timings.full_handshake_ms
            
            # Performance grade
            if full < 100:
                perf_grade = "🚀 Excellent"
            elif full < 200:
                perf_grade = "✓ Good"
            elif full < 400:
                perf_grade = "⚠ Moderate"
            elif full < 800:
                perf_grade = "⚠ Slow"
            else:
                perf_grade = "❌ Very Slow"
            
            print(f"Full Handshake: {round(full, 2)} ms [{perf_grade}]")
            
            if perf.handshake_timings.resumed_handshake_ms:
                resumed = perf.handshake_timings.resumed_handshake_ms
                ratio = perf.handshake_timings.resumption_ratio
                print(f"Resumed Handshake: {round(resumed, 2)} ms ({ratio:.1f}x faster)" if ratio else f"{round(resumed, 2)} ms")
            
            if perf.handshake_timings.tls13_0rtt_ms:
                print(f"TLS 1.3 0-RTT: {round(perf.handshake_timings.tls13_0rtt_ms, 2)} ms")
        
        if perf.connection_reuse_success:
            print(f"✓ Connection reuse: Successful")
        
        if perf.average_handshake_ms > 0:
            print(f"Average handshake: {round(perf.average_handshake_ms, 2)} ms")

        # --------------------------------------------------
        # RISK ASSESSMENT
        # --------------------------------------------------
        print("\n[RISK ASSESSMENT]")
        
        # Visual score bars
        score = intel.tls_score
        score_bar = "█" * int(score/10) + "░" * (10 - int(score/10))
        
        # Risk level based on grade
        risk_map = {
            "A+": "🟢 VERY LOW", "A": "🟢 LOW", "A-": "🟢 LOW",
            "B": "🟡 MODERATE", "C": "🟠 ELEVATED", 
            "D": "🔴 HIGH", "E": "🔴 HIGH", "F": "⛔ CRITICAL"
        }
        risk_level = risk_map.get(intel.grade.value, "⚪ UNKNOWN")
        
        print(f"TLS Score: {score}/100 [{score_bar}]")
        print(f"Risk Level: {risk_level}")
        print(f"SSL Labs Grade: {intel.grade.value}")
        
        # Risk factors summary
        risk_factors = []
        
        if intel.protocol_support.weak_versions:
            risk_factors.append(f"Weak protocols: {len(intel.protocol_support.weak_versions)}")
        
        if intel.weak_ciphers:
            risk_factors.append(f"Weak ciphers: {len(intel.weak_ciphers)}")
        
        if intel.export_ciphers or intel.null_ciphers or intel.anon_ciphers:
            dangerous_count = len(intel.export_ciphers) + len(intel.null_ciphers) + len(intel.anon_ciphers)
            risk_factors.append(f"Dangerous ciphers: {dangerous_count}")
        
        if intel.certificate_chain and intel.certificate_chain.leaf.expired:
            risk_factors.append("Certificate expired")
        elif intel.certificate_chain and intel.certificate_chain.leaf.days_until_expiry < 30:
            risk_factors.append(f"Certificate expires in {intel.certificate_chain.leaf.days_until_expiry} days")
        
        if intel.vulnerable:
            risk_factors.append(f"Vulnerabilities: {len(intel.vulnerabilities_found)}")
        
        if risk_factors:
            print("\nKey Risk Factors:")
            for factor in risk_factors[:5]:
                print(f"  • {factor}")

        # --------------------------------------------------
        # RECOMMENDATIONS
        # --------------------------------------------------
        if intel.recommendations:
            print("\n[RECOMMENDATIONS]")
            
            # Group by severity
            critical = [r for r in intel.recommendations if r.severity == "CRITICAL"]
            high = [r for r in intel.recommendations if r.severity == "HIGH"]
            medium = [r for r in intel.recommendations if r.severity == "MEDIUM"]
            low = [r for r in intel.recommendations if r.severity == "LOW"]
            
            if critical:
                print("\n  🔴 CRITICAL - Fix Immediately:")
                for i, rec in enumerate(critical[:3], 1):
                    print(f"    {i}. {rec.issue}")
                    print(f"       → {rec.recommendation}")
            
            if high:
                print("\n  🟠 HIGH - Prioritize:")
                for i, rec in enumerate(high[:3], 1):
                    print(f"    {i}. {rec.issue}")
                    print(f"       → {rec.recommendation}")
            
            if medium:
                print("\n  🟡 MEDIUM - Schedule:")
                for i, rec in enumerate(medium[:3], 1):
                    print(f"    {i}. {rec.issue}")
                    if i <= 2:  # Show recommendation for first two
                        print(f"       → {rec.recommendation}")
            
            if low:
                print("\n  🔵 LOW - Consider:")
                for i, rec in enumerate(low[:3], 1):
                    print(f"    {i}. {rec.issue}")
            
            if len(intel.recommendations) > 10:
                print(f"\n   ... +{len(intel.recommendations) - 10} more recommendations")
        
        # --------------------------------------------------
        # RAW DATA REFERENCE
        # --------------------------------------------------
        print("\n" + "-" * 60)
        print(f"Full certificate details available in report.tls.all_certificates")
        print(f"Cipher suite details available in report.tls.cipher_preference.all_ciphers")