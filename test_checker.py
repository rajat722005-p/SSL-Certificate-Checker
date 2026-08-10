"""
Automated Test Suite for SSL Certificate Checker.
"""
import unittest
import datetime
from fastapi.testclient import TestClient

from app.core.cert_analyzer import CertificateAnalyzer
from app.core.grading_engine import GradingEngine
from app.core.alert_notifier import AlertNotifier
from app.core.monitor import DomainMonitor
from app.main import app


class TestSSLChecker(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_normalize_target(self):
        """Test hostname and port normalization."""
        h, p = CertificateAnalyzer.normalize_target("https://google.com:443/test?query=1")
        self.assertEqual(h, "google.com")
        self.assertEqual(p, 443)

        h, p = CertificateAnalyzer.normalize_target("api.domain.io:8443")
        self.assertEqual(h, "api.domain.io")
        self.assertEqual(p, 8443)

        h, p = CertificateAnalyzer.normalize_target("http://192.168.1.1:9000/")
        self.assertEqual(h, "192.168.1.1")
        self.assertEqual(p, 9000)

    def test_hostname_matching(self):
        """Test SAN and CN wildcard and exact matching."""
        # Exact match
        res = CertificateAnalyzer.check_hostname_match("example.com", "example.com", ["example.com", "www.example.com"])
        self.assertTrue(res["is_matched"])
        self.assertEqual(res["matched_pattern"], "example.com")

        # Wildcard match
        res = CertificateAnalyzer.check_hostname_match("api.example.com", None, ["*.example.com"])
        self.assertTrue(res["is_matched"])
        self.assertEqual(res["matched_pattern"], "*.example.com")

        # Nested wildcard should NOT match
        res = CertificateAnalyzer.check_hostname_match("deep.sub.example.com", None, ["*.example.com"])
        self.assertFalse(res["is_matched"])

        # Complete mismatch
        res = CertificateAnalyzer.check_hostname_match("phishing.com", "mybank.com", ["mybank.com", "www.mybank.com"])
        self.assertFalse(res["is_matched"])

    def test_grading_engine_rules(self):
        """Test calculation of security grades under various scenarios."""
        # Scenario 1: Expired cert
        mock_cert = {
            "validity": {"expiry_status": "EXPIRED", "days_remaining": -5},
            "hostname_match": {"is_matched": True},
            "is_self_signed": False,
            "public_key": {"is_weak": False, "is_strong": True, "description": "RSA 2048"},
            "signature": {"is_weak": False, "hash": "SHA256"}
        }
        mock_chain = {"is_trusted": False, "is_complete": True}
        mock_proto = {"protocol_support": {"tls_1_3": True, "tls_1_2": True}, "cipher_audit": {"has_forward_secrecy": True, "rating": "STRONG"}}
        mock_http = {"hsts": {"header_present": True, "status": "STRONG"}}

        grade = GradingEngine.calculate_grade(mock_cert, mock_chain, mock_proto, mock_http)
        self.assertEqual(grade["letter_grade"], "F")
        self.assertEqual(grade["subscores"]["certificate"], 0)

        # Scenario 2: Perfect A+ Setup
        mock_cert["validity"] = {"expiry_status": "VALID", "days_remaining": 90}
        mock_chain["is_trusted"] = True
        mock_http["hsts"] = {"header_present": True, "max_age_seconds": 31536000, "status": "PRELOAD_READY", "score": 100}

        grade = GradingEngine.calculate_grade(mock_cert, mock_chain, mock_proto, mock_http)
        self.assertEqual(grade["letter_grade"], "A+")

    def test_alert_generation(self):
        """Test alert extraction logic."""
        mock_report = {
            "target": {"host": "test.com", "port": 443},
            "grading": {"letter_grade": "F", "critical_issues": ["Certificate is Expired"]},
            "certificate": {
                "validity": {"expiry_status": "EXPIRED", "days_remaining": -10, "not_after_formatted": "2026-01-01"},
                "hostname_match": {"is_matched": True},
                "is_self_signed": False
            },
            "chain": {"is_trusted": False, "is_complete": True}
        }
        alerts = AlertNotifier.generate_alerts(mock_report)
        self.assertTrue(any(a["severity"] == "CRITICAL" for a in alerts))
        self.assertTrue(any("Expired" in a["title"] for a in alerts))

    def test_api_test_presets(self):
        """Test the presets endpoint."""
        resp = self.client.get("/api/test-presets")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("production_benchmarks", data)
        self.assertIn("vulnerability_badssl_benchmarks", data)

    def test_api_email_preview(self):
        """Test email preview endpoint."""
        mock_report = {
            "target": {"host": "example.com", "port": 443},
            "grading": {"letter_grade": "A", "overall_score": 90, "grade_color": "#22c55e"},
            "certificate": {
                "issuer": {"common_name": "Test CA"},
                "public_key": {"description": "RSA 2048"},
                "validity": {"days_remaining": 60, "expiry_status": "VALID", "not_after_formatted": "2026-10-10"}
            },
            "chain": {"is_trusted": True, "is_complete": True}
        }
        resp = self.client.post("/api/notify/email-preview", json={"report": mock_report})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("html", resp.json())
        self.assertIn("SSL Certificate Audit Report", resp.json()["html"])


if __name__ == "__main__":
    unittest.main()
