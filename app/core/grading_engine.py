"""
SSL/TLS Security Rating and Grading Engine (SSL Labs methodology inspired).
"""
from typing import Dict, List, Any, Optional


class GradingEngine:
    """Calculates overall security grade (A+ to F), subscores, and remediation advice."""

    @classmethod
    def calculate_grade(cls,
                        cert_data: Dict[str, Any],
                        chain_data: Dict[str, Any],
                        protocol_data: Dict[str, Any],
                        http_data: Dict[str, Any],
                        vuln_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculates letter grade (A+, A, B, C, D, F) and weighted category scores.
        """
        critical_issues = []
        warnings = []
        recommendations = []
        strengths = []

        # --- 1. Certificate Score (0 - 100) ---
        cert_score = 100
        validity = cert_data.get("validity", {})
        expiry_status = validity.get("expiry_status", "VALID")
        hostname_match = cert_data.get("hostname_match", {})
        is_self_signed = cert_data.get("is_self_signed", False)
        is_trusted = chain_data.get("is_trusted", False)
        public_key = cert_data.get("public_key", {})
        signature = cert_data.get("signature", {})

        # Hard failures
        if expiry_status == "EXPIRED":
            cert_score = 0
            critical_issues.append("Certificate is Expired: All TLS connections will display browser warnings.")
        elif expiry_status == "NOT_YET_VALID":
            cert_score = 0
            critical_issues.append("Certificate is Not Yet Valid: Activation date is in the future.")
        elif expiry_status == "EXPIRING_CRITICAL":
            cert_score = min(cert_score, 40)
            critical_issues.append(f"Certificate Expiring Imminently: Less than {validity.get('days_remaining')} day(s) left.")
        elif expiry_status == "EXPIRING_SOON":
            cert_score = min(cert_score, 70)
            warnings.append(f"Certificate Expiring Soon: {validity.get('days_remaining')} days remaining. Plan renewal.")
        else:
            strengths.append(f"Certificate Validity: Healthy ({validity.get('days_remaining')} days remaining).")

        if hostname_match and not hostname_match.get("is_matched", True):
            cert_score = 0
            critical_issues.append(f"Hostname Mismatch: Certificate does not cover '{hostname_match.get('target_host')}'.")
        elif hostname_match and hostname_match.get("is_matched"):
            strengths.append(f"Hostname Match: Valid for {hostname_match.get('matched_pattern')}.")

        if is_self_signed:
            cert_score = 0
            critical_issues.append("Self-Signed Certificate: Not signed by a trusted public Certificate Authority.")
        elif not is_trusted:
            cert_score = min(cert_score, 20)
            critical_issues.append(f"Untrusted Root / Chain Error: {chain_data.get('trust_error', 'Failed validation')}.")
        else:
            strengths.append("Trust Chain: Verified against Mozilla Root CA store.")

        if not chain_data.get("is_complete", True):
            cert_score = min(cert_score, 65)
            warnings.append("Incomplete Certificate Chain: Intermediate CA certificates were omitted by server.")

        if signature.get("is_weak"):
            cert_score = min(cert_score, 30)
            critical_issues.append(f"Weak Signature Algorithm: Uses {signature.get('algorithm')} ({signature.get('hash')}).")
        else:
            strengths.append(f"Signature Algorithm: Modern hash ({signature.get('hash')}).")

        if public_key.get("is_weak"):
            cert_score = min(cert_score, 50)
            warnings.append(f"Weak Public Key: {public_key.get('description')}.")
        elif public_key.get("is_strong"):
            strengths.append(f"Strong Public Key: {public_key.get('description')}.")

        # --- 2. Protocol Score (0 - 100) ---
        protocol_score = 90
        proto_support = protocol_data.get("protocol_support", {})
        
        if proto_support.get("tls_1_3"):
            protocol_score = 100
            strengths.append("Protocol Support: Modern TLS 1.3 enabled.")
        elif proto_support.get("tls_1_2"):
            protocol_score = 90
            strengths.append("Protocol Support: TLS 1.2 enabled.")
        else:
            protocol_score = 0
            critical_issues.append("No Modern TLS Protocol: Neither TLS 1.2 nor TLS 1.3 is supported.")

        if proto_support.get("tls_1_0"):
            protocol_score = min(protocol_score, 65)
            warnings.append("Deprecated TLS 1.0 Enabled: Non-compliant with PCI-DSS 3.2+.")
            recommendations.append("Disable TLS 1.0 on the web server or load balancer.")
            
        if proto_support.get("tls_1_1"):
            protocol_score = min(protocol_score, 75)
            warnings.append("Deprecated TLS 1.1 Enabled: Considered weak.")
            recommendations.append("Disable TLS 1.1 in favor of TLS 1.2 and TLS 1.3 only.")

        # --- 3. Cipher Suite & Key Exchange Score (0 - 100) ---
        cipher_score = 80
        cipher_audit = protocol_data.get("cipher_audit", {})
        
        if cipher_audit.get("is_vulnerable"):
            cipher_score = 0
            critical_issues.append(f"Vulnerable Cipher Suite in Use: {cipher_audit.get('cipher_name')}.")
        elif cipher_audit.get("rating") == "STRONG":
            cipher_score = 100
            strengths.append(f"Cipher Suite: {cipher_audit.get('cipher_name')} (AEAD + Forward Secrecy).")
        elif cipher_audit.get("is_cbc"):
            cipher_score = 65
            warnings.append(f"Legacy CBC Mode Cipher: {cipher_audit.get('cipher_name')}.")
            recommendations.append("Prioritize GCM or Poly1305 AEAD cipher suites over CBC.")

        if not cipher_audit.get("has_forward_secrecy"):
            cipher_score = min(cipher_score, 60)
            warnings.append("No Forward Secrecy: Static RSA key exchange in use.")
            recommendations.append("Enable ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange.")

        # --- 4. Vulnerabilities & Attack Defenses Assessment ---
        if vuln_data:
            for v in vuln_data.get("vulnerabilities", []):
                if v["status"] == "VULNERABLE":
                    if v["severity"] in ["CRITICAL", "HIGH"]:
                        cipher_score = min(cipher_score, 40)
                        critical_issues.append(f"Vulnerability Detected: {v['name']}.")
                        if v.get("remediation"):
                            recommendations.append(v["remediation"])
                elif v["id"] == "ocsp_stapling" and v["status"] == "ACTIVE":
                    strengths.append("OCSP Stapling: Active (reduces handshake latency and enhances client privacy).")
                elif v["id"] == "session_resumption" and v["status"] == "SUPPORTED":
                    strengths.append("TLS Session Resumption: Supported.")

        # --- 5. HSTS & Headers Assessment ---
        hsts = http_data.get("hsts", {})
        hsts_present = hsts.get("header_present", False)
        hsts_status = hsts.get("status", "NOT_CONFIGURED")

        if hsts_present:
            if hsts_status in ["PRELOAD_READY", "STRONG"]:
                strengths.append(f"HSTS Enabled: max-age={hsts.get('max_age_days')} days with strong directives.")
            else:
                recommendations.append("Increase HSTS max-age to at least 180 days (15552000s) and include subdomains.")
        else:
            recommendations.append("Enable HTTP Strict Transport Security (HSTS) with a minimum 6-month max-age.")

        # --- 6. Overall Grade Determination ---
        weighted_score = round(
            (cert_score * 0.40) +
            (protocol_score * 0.30) +
            (cipher_score * 0.30)
        )

        # Grade assignment with hard-cap rules
        if cert_score == 0 or cipher_score == 0 or len(critical_issues) > 0:
            letter_grade = "F"
            grade_color = "#ef4444"
            summary_status = "CRITICAL FAIL"
        elif not chain_data.get("is_complete", True) or proto_support.get("tls_1_0") or cipher_score < 70:
            letter_grade = "C" if proto_support.get("tls_1_0") or cipher_score < 70 else "B"
            grade_color = "#f59e0b"
            summary_status = "WARNING"
        elif weighted_score < 70:
            letter_grade = "D"
            grade_color = "#f97316"
            summary_status = "POOR"
        elif weighted_score < 85:
            letter_grade = "B"
            grade_color = "#eab308"
            summary_status = "MODERATE"
        else:
            # Grade A or A+
            has_strong_hsts = hsts_present and hsts.get("max_age_seconds", 0) >= 15552000
            has_no_deprecated = not proto_support.get("tls_1_0") and not proto_support.get("tls_1_1")
            
            if has_strong_hsts and has_no_deprecated and cipher_audit.get("has_forward_secrecy"):
                letter_grade = "A+"
                grade_color = "#10b981"
                summary_status = "EXCELLENT"
                strengths.append("A+ Security: Meets all enterprise best practices including HSTS and Forward Secrecy.")
            else:
                letter_grade = "A"
                grade_color = "#22c55e"
                summary_status = "GOOD"
                if not has_strong_hsts:
                    recommendations.append("To reach Grade A+, enable HSTS with max-age of at least 6 months (15552000s).")

        return {
            "letter_grade": letter_grade,
            "grade_color": grade_color,
            "overall_score": weighted_score,
            "summary_status": summary_status,
            "subscores": {
                "certificate": cert_score,
                "protocol": protocol_score,
                "cipher": cipher_score,
                "hsts": hsts.get("score", 0)
            },
            "critical_issues": critical_issues,
            "warnings": warnings,
            "recommendations": recommendations,
            "strengths": strengths
        }
