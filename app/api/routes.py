"""
RESTful API Routes for SSL Certificate Checker.
"""
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

from app.core.cert_analyzer import CertificateAnalyzer
from app.core.chain_validator import CertificateChainValidator
from app.core.protocol_scanner import ProtocolScanner
from app.core.grading_engine import GradingEngine
from app.core.alert_notifier import AlertNotifier
from app.core.monitor import DomainMonitor

router = APIRouter()
monitor = DomainMonitor()


class ScanRequest(BaseModel):
    host: str = Field(..., example="google.com", description="Hostname, IP or domain to verify")
    port: int = Field(default=443, example=443, description="Port number (default 443)")


class BatchScanRequest(BaseModel):
    hosts: List[str] = Field(..., example=["google.com", "github.com", "expired.badssl.com"])


class WatchlistAddRequest(BaseModel):
    host: str
    port: int = 443
    label: Optional[str] = None


class WebhookRequest(BaseModel):
    webhook_url: str
    webhook_type: str = "generic" # slack, discord, teams, generic
    report: Dict[str, Any]


class EmailPreviewRequest(BaseModel):
    report: Dict[str, Any]


@router.post("/check", summary="Deep scan a single host certificate")
def check_ssl(req: ScanRequest):
    """
    Performs deep X.509 certificate extraction, chain validation, protocol/cipher security checks,
    calculates security score/grade, and generates alerts.
    """
    try:
        report = DomainMonitor.execute_full_scan(req.host, req.port)
        return report
    except ConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error analyzing host: {str(e)}")


@router.post("/batch", summary="Scan multiple domains concurrently")
def batch_check(req: BatchScanRequest):
    """
    Runs scans across multiple target domains and returns summaries and grades.
    """
    results = []
    for host_entry in req.hosts:
        if not host_entry.strip():
            continue
        host, port = CertificateAnalyzer.normalize_target(host_entry)
        try:
            report = DomainMonitor.execute_full_scan(host, port)
            results.append({
                "host": host,
                "port": port,
                "success": True,
                "grade": report["grading"]["letter_grade"],
                "score": report["grading"]["overall_score"],
                "status": report["certificate"]["validity"]["expiry_status"],
                "days_remaining": report["certificate"]["validity"]["days_remaining"],
                "expires_on": report["certificate"]["validity"]["not_after_formatted"],
                "issuer": report["certificate"]["issuer"]["common_name"] or report["certificate"]["issuer"]["organization"],
                "is_trusted": report["chain"]["is_trusted"],
                "report": report
            })
        except Exception as e:
            results.append({
                "host": host,
                "port": port,
                "success": False,
                "error": str(e),
                "grade": "F",
                "score": 0,
                "status": "ERROR",
                "days_remaining": None
            })
    return {"count": len(results), "results": results}


@router.get("/watchlist", summary="Retrieve all monitored watchlist targets")
def get_watchlist():
    return monitor.get_all()


@router.post("/watchlist", summary="Add domain to continuous watchlist")
def add_to_watchlist(req: WatchlistAddRequest):
    return monitor.add_target(req.host, req.port, req.label)


@router.delete("/watchlist/{target_id}", summary="Remove domain from watchlist")
def delete_from_watchlist(target_id: str):
    success = monitor.remove_target(target_id)
    if not success:
        raise HTTPException(status_code=404, detail="Target not found in watchlist")
    return {"success": True, "message": "Target removed from watchlist"}


@router.post("/watchlist/scan", summary="Trigger scan for all watchlist targets")
def scan_watchlist():
    targets = monitor.get_all()
    updated = []
    for t in targets:
        try:
            report = DomainMonitor.execute_full_scan(t["host"], t["port"])
            monitor.update_scan_result(t["id"], report)
            updated.append({"id": t["id"], "host": t["host"], "grade": report["grading"]["letter_grade"], "success": True})
        except Exception as e:
            updated.append({"id": t["id"], "host": t["host"], "error": str(e), "success": False})
    return {"scanned_count": len(updated), "results": updated}


@router.post("/notify/webhook", summary="Send audit alert to external Webhook")
def dispatch_webhook(req: WebhookRequest):
    result = AlertNotifier.dispatch_webhook(req.webhook_url, req.report, req.webhook_type)
    return result


@router.post("/notify/email-preview", summary="Generate HTML email report preview")
def email_preview(req: EmailPreviewRequest):
    html = AlertNotifier.render_email_html(req.report)
    return {"html": html}


@router.get("/test-presets", summary="Get catalog of real-world and BadSSL test cases")
def get_test_presets():
    return {
        "production_benchmarks": [
            {"label": "Google", "host": "google.com", "port": 443, "expected": "A+", "desc": "Enterprise Grade with HSTS & TLS 1.3"},
            {"label": "GitHub", "host": "github.com", "port": 443, "expected": "A+", "desc": "Strict HSTS Preload & Modern ECC Ciphers"},
            {"label": "Cloudflare", "host": "cloudflare.com", "port": 443, "expected": "A+", "desc": "Multi-SAN ECDSA Certificate"},
            {"label": "Wikipedia", "host": "wikipedia.org", "port": 443, "expected": "A+", "desc": "Let's Encrypt / DigiCert Standard"}
        ],
        "vulnerability_badssl_benchmarks": [
            {"label": "Expired Cert", "host": "expired.badssl.com", "port": 443, "expected": "F", "desc": "Simulates expired certificate"},
            {"label": "Wrong Hostname", "host": "wrong.host.badssl.com", "port": 443, "expected": "F", "desc": "SAN mismatch / hostname error"},
            {"label": "Self-Signed", "host": "self-signed.badssl.com", "port": 443, "expected": "F", "desc": "Self-signed certificate without CA"},
            {"label": "Untrusted Root", "host": "untrusted-root.badssl.com", "port": 443, "expected": "F", "desc": "Root CA not in trust store"},
            {"label": "Legacy RC4 Cipher", "host": "rc4.badssl.com", "port": 443, "expected": "F", "desc": "Weak deprecated RC4 cipher test"},
            {"label": "Deprecated TLS 1.0", "host": "tls-v1-0.badssl.com", "port": 1010, "expected": "C", "desc": "Deprecated TLS 1.0 protocol"},
            {"label": "Deprecated TLS 1.1", "host": "tls-v1-1.badssl.com", "port": 1011, "expected": "C", "desc": "Deprecated TLS 1.1 protocol"}
        ]
    }
