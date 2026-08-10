"""
Watchlist Manager and Continuous Domain SSL Monitor.
"""
import os
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional
from app.core.cert_analyzer import CertificateAnalyzer
from app.core.chain_validator import CertificateChainValidator
from app.core.protocol_scanner import ProtocolScanner
from app.core.vulnerability_scanner import VulnerabilityScanner
from app.core.grading_engine import GradingEngine
from app.core.alert_notifier import AlertNotifier


class DomainMonitor:
    """Manages continuous monitoring of target domains and persistent watchlist storage."""

    def __init__(self, data_file: str = "data/watchlist.json"):
        self.data_file = data_file
        self._ensure_storage()

    def _ensure_storage(self):
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        if not os.path.exists(self.data_file):
            initial_data = [
                {
                    "id": str(uuid.uuid4()),
                    "host": "google.com",
                    "port": 443,
                    "label": "Google Main",
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "last_scan": None,
                    "last_grade": "A+",
                    "last_days_remaining": None,
                    "last_status": "PENDING"
                },
                {
                    "id": str(uuid.uuid4()),
                    "host": "github.com",
                    "port": 443,
                    "label": "GitHub Production",
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "last_scan": None,
                    "last_grade": "A+",
                    "last_days_remaining": None,
                    "last_status": "PENDING"
                },
                {
                    "id": str(uuid.uuid4()),
                    "host": "expired.badssl.com",
                    "port": 443,
                    "label": "BadSSL - Expired Test",
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "last_scan": None,
                    "last_grade": "F",
                    "last_days_remaining": 0,
                    "last_status": "EXPIRED"
                }
            ]
            self._save_data(initial_data)

    def _load_data(self) -> List[Dict[str, Any]]:
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_data(self, data: List[Dict[str, Any]]):
        with open(self.data_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def get_all(self) -> List[Dict[str, Any]]:
        return self._load_data()

    def add_target(self, host: str, port: int = 443, label: Optional[str] = None) -> Dict[str, Any]:
        targets = self._load_data()
        clean_host, clean_port = CertificateAnalyzer.normalize_target(host, port)
        
        for t in targets:
            if t["host"].lower() == clean_host.lower() and t["port"] == clean_port:
                return t

        new_item = {
            "id": str(uuid.uuid4()),
            "host": clean_host,
            "port": clean_port,
            "label": label or clean_host,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "last_scan": None,
            "last_grade": None,
            "last_days_remaining": None,
            "last_status": "PENDING",
            "last_report": None
        }
        targets.insert(0, new_item)
        self._save_data(targets)
        return new_item

    def remove_target(self, target_id: str) -> bool:
        targets = self._load_data()
        filtered = [t for t in targets if t["id"] != target_id]
        if len(filtered) != len(targets):
            self._save_data(filtered)
            return True
        return False

    def update_scan_result(self, target_id: str, report: Dict[str, Any]):
        targets = self._load_data()
        for t in targets:
            if t["id"] == target_id:
                t["last_scan"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                t["last_grade"] = report.get("grading", {}).get("letter_grade", "N/A")
                t["last_days_remaining"] = report.get("certificate", {}).get("validity", {}).get("days_remaining")
                t["last_status"] = report.get("certificate", {}).get("validity", {}).get("expiry_status", "UNKNOWN")
                t["last_report"] = report
                break
        self._save_data(targets)

    @classmethod
    def execute_full_scan(cls, host: str, port: int = 443) -> Dict[str, Any]:
        """Runs the complete diagnostic scan on a host and aggregates all components."""
        clean_host, clean_port = CertificateAnalyzer.normalize_target(host, port)
        
        # 1. Fetch raw certificates and analyze leaf
        raw_leaf_der, chain_ders, tls_version = CertificateAnalyzer.fetch_raw_certificates(clean_host, clean_port)
        cert_data = CertificateAnalyzer.parse_x509(raw_leaf_der, target_host=clean_host)

        # 2. Analyze full trust chain
        chain_data = CertificateChainValidator.analyze_chain(clean_host, clean_port)

        # 3. Scan protocols, ciphers, and security headers
        protocol_data = ProtocolScanner.scan_protocols_and_ciphers(clean_host, clean_port)
        http_data = ProtocolScanner.check_http_security_headers(clean_host, clean_port)

        # 4. Deep Vulnerability & Supported Cipher Suite Matrix Probe
        vuln_data = VulnerabilityScanner.audit_vulnerabilities(clean_host, clean_port)

        # 5. Compute comprehensive security grade
        grading_data = GradingEngine.calculate_grade(cert_data, chain_data, protocol_data, http_data, vuln_data)

        # 6. Build full composite report
        report = {
            "target": {
                "host": clean_host,
                "port": clean_port,
                "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "tls_version": tls_version
            },
            "grading": grading_data,
            "certificate": cert_data,
            "chain": chain_data,
            "protocols": protocol_data,
            "http_security": http_data,
            "vulnerabilities": vuln_data
        }

        # 7. Generate alerts
        report["alerts"] = AlertNotifier.generate_alerts(report)
        return report
