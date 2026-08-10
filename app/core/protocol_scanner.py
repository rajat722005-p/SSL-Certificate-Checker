"""
TLS Protocol, Cipher Suite and Security Configuration Scanner.
"""
import ssl
import socket
import requests
import urllib3
from typing import Dict, List, Any, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProtocolScanner:
    """Probes TLS protocol versions, cipher suites, HSTS and HTTP security configurations."""

    # Weak & deprecated cipher indicators
    VULNERABLE_CIPHER_KEYWORDS = ["RC4", "3DES", "DES", "NULL", "EXPORT", "anon", "MD5"]
    CBC_CIPHER_KEYWORDS = ["CBC"]

    @classmethod
    def scan_protocols_and_ciphers(cls, host: str, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
        """
        Tests support for TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, and SSLv3.
        Retrieves active cipher suite, forward secrecy status, ALPN, and weak configuration flags.
        """
        protocol_support = {
            "tls_1_3": cls._probe_tls_version(host, port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, timeout),
            "tls_1_2": cls._probe_tls_version(host, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, timeout),
            "tls_1_1": cls._probe_tls_version(host, port, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1, timeout),
            "tls_1_0": cls._probe_tls_version(host, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1, timeout),
            "ssl_3_0": False # SSLv3 is disabled/unsupported by modern OpenSSL
        }

        # Active Handshake Probe for default negotiation
        active_details = cls._probe_active_connection(host, port, timeout)

        # Cipher Suite Analysis
        cipher_name = active_details.get("cipher_name") or "Unknown"
        cipher_audit = cls._audit_cipher(cipher_name)

        # Warnings / Security Findings
        findings = []
        if protocol_support["tls_1_0"]:
            findings.append({
                "severity": "HIGH",
                "message": "Deprecated Protocol TLS 1.0 Supported: Insecure and non-compliant with modern standards (PCI-DSS)."
            })
        if protocol_support["tls_1_1"]:
            findings.append({
                "severity": "MEDIUM",
                "message": "Deprecated Protocol TLS 1.1 Supported: Should be disabled in favor of TLS 1.2 and TLS 1.3."
            })
        if not protocol_support["tls_1_2"] and not protocol_support["tls_1_3"]:
            findings.append({
                "severity": "CRITICAL",
                "message": "No Modern TLS Protocol Supported: Server does not support TLS 1.2 or TLS 1.3."
            })

        if cipher_audit["is_vulnerable"]:
            findings.append({
                "severity": "CRITICAL",
                "message": f"Insecure Cipher Suite Detected ({cipher_name}): Uses deprecated/broken cryptographic algorithms."
            })
        elif cipher_audit["is_cbc"]:
            findings.append({
                "severity": "MEDIUM",
                "message": f"CBC Mode Cipher Suite in Use ({cipher_name}): Vulnerable to padding oracle attacks (e.g. Lucky13). Use AEAD ciphers like AES-GCM or ChaCha20-Poly1305."
            })

        if not cipher_audit["has_forward_secrecy"]:
            findings.append({
                "severity": "HIGH",
                "message": "No Perfect Forward Secrecy (PFS): Key exchange does not use ECDHE or DHE. Past traffic could be decrypted if server private key is compromised."
            })

        return {
            "protocol_support": protocol_support,
            "active_connection": active_details,
            "cipher_audit": cipher_audit,
            "findings": findings
        }

    @classmethod
    def _probe_tls_version(cls, host: str, port: int, min_ver: ssl.TLSVersion, max_ver: ssl.TLSVersion, timeout: float) -> bool:
        """Attempts a handshake restricting to a specific TLS version."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = min_ver
            ctx.maximum_version = max_ver
        except Exception:
            return False

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except Exception:
            return False

    @classmethod
    def _probe_active_connection(cls, host: str, port: int, timeout: float) -> Dict[str, Any]:
        """Probes the default negotiated parameters (version, cipher, ALPN)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_tuple = ssock.cipher()
                    return {
                        "tls_version": ssock.version(),
                        "cipher_name": cipher_tuple[0] if cipher_tuple else None,
                        "cipher_protocol": cipher_tuple[1] if cipher_tuple else None,
                        "cipher_bits": cipher_tuple[2] if cipher_tuple else None,
                        "alpn_protocol": ssock.selected_alpn_protocol()
                    }
        except Exception as e:
            return {
                "tls_version": "Unknown",
                "cipher_name": "Unknown",
                "cipher_protocol": None,
                "cipher_bits": None,
                "alpn_protocol": None,
                "error": str(e)
            }

    @classmethod
    def _audit_cipher(cls, cipher_name: str) -> Dict[str, Any]:
        """Audits a cipher suite string for Forward Secrecy, AEAD, and known vulnerabilities."""
        c_upper = cipher_name.upper()
        
        # Forward Secrecy
        has_pfs = any(k in c_upper for k in ["ECDHE", "DHE", "TLS_AES", "TLS_CHACHA20"])
        
        # Vulnerable / Broken algorithms
        is_vulnerable = any(k in c_upper for k in cls.VULNERABLE_CIPHER_KEYWORDS)
        
        # CBC Mode
        is_cbc = "CBC" in c_upper
        
        # AEAD (Modern authenticated encryption)
        is_aead = any(k in c_upper for k in ["GCM", "POLY1305", "CCM"])

        # Strength description
        if is_vulnerable:
            rating = "INSECURE"
            description = "Deprecated / Vulnerable algorithm (High Risk)"
        elif not has_pfs:
            rating = "WEAK"
            description = "Lacks Forward Secrecy (Static Key Exchange)"
        elif is_cbc:
            rating = "MODERATE"
            description = "CBC Mode (Legacy, consider switching to AEAD)"
        elif is_aead and has_pfs:
            rating = "STRONG"
            description = "Modern AEAD with Forward Secrecy (Optimal Security)"
        else:
            rating = "ACCEPTABLE"
            description = "Standard Cipher Suite"

        return {
            "cipher_name": cipher_name,
            "has_forward_secrecy": has_pfs,
            "is_aead": is_aead,
            "is_cbc": is_cbc,
            "is_vulnerable": is_vulnerable,
            "rating": rating,
            "description": description
        }

    @classmethod
    def check_http_security_headers(cls, host: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
        """
        Inspects HTTP Strict Transport Security (HSTS) headers and HTTPS redirection.
        """
        scheme = "https" if port == 443 else "http"
        url = f"https://{host}:{port}" if port != 443 else f"https://{host}"
        
        hsts_header = None
        hsts_max_age = None
        hsts_include_subdomains = False
        hsts_preload = False
        hsts_status = "NOT_CONFIGURED"
        hsts_score = 0 # out of 100
        http_redirects_to_https = False
        server_header = None

        # 1. Fetch HTTPS response headers
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
            server_header = resp.headers.get("Server")
            hsts = resp.headers.get("Strict-Transport-Security")
            if hsts:
                hsts_header = hsts
                # Parse directives
                parts = [p.strip().lower() for p in hsts.split(";")]
                for p in parts:
                    if p.startswith("max-age="):
                        try:
                            hsts_max_age = int(p.split("=")[1])
                        except ValueError:
                            pass
                    elif p == "includesubdomains":
                        hsts_include_subdomains = True
                    elif p == "preload":
                        hsts_preload = True

                # Evaluate strength
                # 6 months = 15552000 seconds, 1 year = 31536000 seconds
                if hsts_max_age and hsts_max_age >= 31536000 and hsts_include_subdomains and hsts_preload:
                    hsts_status = "PRELOAD_READY"
                    hsts_score = 100
                elif hsts_max_age and hsts_max_age >= 15552000:
                    hsts_status = "STRONG"
                    hsts_score = 85
                elif hsts_max_age and hsts_max_age > 0:
                    hsts_status = "MODERATE"
                    hsts_score = 60
                else:
                    hsts_status = "WEAK"
                    hsts_score = 30
        except Exception:
            pass

        # 2. Check if HTTP redirects to HTTPS
        if port == 443:
            try:
                http_resp = requests.get(f"http://{host}", timeout=timeout, allow_redirects=False)
                if http_resp.status_code in [301, 302, 307, 308]:
                    loc = http_resp.headers.get("Location", "")
                    if loc.startswith(f"https://{host}") or loc.startswith("https://"):
                        http_redirects_to_https = True
            except Exception:
                pass

        return {
            "hsts": {
                "header_present": (hsts_header is not None),
                "raw_header": hsts_header,
                "max_age_seconds": hsts_max_age,
                "max_age_days": round(hsts_max_age / 86400, 1) if hsts_max_age else None,
                "include_subdomains": hsts_include_subdomains,
                "preload": hsts_preload,
                "status": hsts_status,
                "score": hsts_score
            },
            "http_redirects_to_https": http_redirects_to_https,
            "server_header": server_header
        }
