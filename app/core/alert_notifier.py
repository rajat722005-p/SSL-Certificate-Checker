"""
Alerts Generation and Multi-Channel Notification Dispatcher (Webhooks, Email, In-App).
"""
import json
import datetime
import requests
from typing import Dict, List, Any, Optional


class AlertNotifier:
    """Evaluates security reports and dispatches notifications across multiple channels."""

    @classmethod
    def generate_alerts(cls, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts structured alert objects from a complete scan report."""
        alerts = []
        host = report.get("target", {}).get("host", "Unknown")
        port = report.get("target", {}).get("port", 443)
        grade = report.get("grading", {})
        letter_grade = grade.get("letter_grade", "N/A")
        cert = report.get("certificate", {})
        validity = cert.get("validity", {})
        days_remaining = validity.get("days_remaining", 0)
        expiry_status = validity.get("expiry_status", "VALID")
        hostname_match = cert.get("hostname_match", {})
        chain = report.get("chain", {})

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Expiration alerts
        if expiry_status == "EXPIRED":
            alerts.append({
                "id": f"exp-{host}",
                "severity": "CRITICAL",
                "title": f"Certificate Expired on {host}:{port}",
                "message": f"The SSL certificate expired on {validity.get('not_after_formatted')}. Users will see security warnings.",
                "recommendation": "Immediately renew and re-deploy your SSL/TLS certificate.",
                "timestamp": now_str
            })
        elif expiry_status == "EXPIRING_CRITICAL":
            alerts.append({
                "id": f"exp-crit-{host}",
                "severity": "CRITICAL",
                "title": f"Certificate Expires in {days_remaining} Days ({host})",
                "message": f"Urgent renewal needed before {validity.get('not_after_formatted')}.",
                "recommendation": "Renew certificate now to prevent production downtime.",
                "timestamp": now_str
            })
        elif expiry_status == "EXPIRING_SOON":
            alerts.append({
                "id": f"exp-warn-{host}",
                "severity": "WARNING",
                "title": f"Certificate Expiring Soon ({days_remaining} Days Left)",
                "message": f"Certificate for {host} will expire on {validity.get('not_after_formatted')}.",
                "recommendation": "Schedule certificate renewal with your CA provider (e.g. Let's Encrypt, DigiCert).",
                "timestamp": now_str
            })

        # 2. Hostname Mismatch
        if hostname_match and not hostname_match.get("is_matched", True):
            alerts.append({
                "id": f"host-mismatch-{host}",
                "severity": "CRITICAL",
                "title": f"Hostname Mismatch on {host}",
                "message": f"The certificate is issued for '{cert.get('subject', {}).get('common_name')}' and does not cover '{host}'.",
                "recommendation": "Ensure the target domain is added to Subject Alternative Names (SANs).",
                "timestamp": now_str
            })

        # 3. Self-Signed / Untrusted Root
        if cert.get("is_self_signed"):
            alerts.append({
                "id": f"self-signed-{host}",
                "severity": "CRITICAL",
                "title": f"Self-Signed Certificate Detected ({host})",
                "message": "Certificate was signed by itself and is not trusted by public root stores.",
                "recommendation": "Replace self-signed cert with a certificate from a trusted public CA.",
                "timestamp": now_str
            })
        elif not chain.get("is_trusted", True):
            alerts.append({
                "id": f"untrusted-{host}",
                "severity": "CRITICAL",
                "title": f"Untrusted Certificate Authority ({host})",
                "message": f"Trust validation error: {chain.get('trust_error', 'Root not in trust store')}",
                "recommendation": "Verify root and intermediate CA chain configuration.",
                "timestamp": now_str
            })

        # 4. Incomplete Chain
        if not chain.get("is_complete", True):
            alerts.append({
                "id": f"incomplete-chain-{host}",
                "severity": "HIGH",
                "title": f"Incomplete Certificate Chain ({host})",
                "message": "Server failed to send intermediate certificate(s) during handshake.",
                "recommendation": "Bundle intermediate CA certificates with your server certificate file (fullchain.pem).",
                "timestamp": now_str
            })

        # 5. Weak Ciphers / Deprecated Protocols
        for issue in grade.get("critical_issues", []):
            if "Cipher" in issue or "Protocol" in issue:
                alerts.append({
                    "id": f"crypto-{host}-{abs(hash(issue)) % 10000}",
                    "severity": "HIGH",
                    "title": f"Cryptographic Issue on {host}",
                    "message": issue,
                    "recommendation": "Update server TLS cipher suite configuration and disable legacy protocols.",
                    "timestamp": now_str
                })

        # If healthy
        if not alerts:
            alerts.append({
                "id": f"ok-{host}",
                "severity": "GOOD",
                "title": f"SSL Certificate is Healthy ({host})",
                "message": f"Rated Grade {letter_grade}. Certificate valid for {days_remaining} days with strong encryption.",
                "recommendation": "No immediate actions required.",
                "timestamp": now_str
            })

        return alerts

    @classmethod
    def dispatch_webhook(cls, webhook_url: str, report: Dict[str, Any], webhook_type: str = "generic") -> Dict[str, Any]:
        """
        Dispatches a formatted alert notification to Slack, Discord, MS Teams, or a generic JSON webhook.
        """
        host = report.get("target", {}).get("host", "Unknown")
        grade = report.get("grading", {})
        letter_grade = grade.get("letter_grade", "N/A")
        validity = report.get("certificate", {}).get("validity", {})
        days_left = validity.get("days_remaining", 0)
        alerts = cls.generate_alerts(report)

        headers = {"Content-Type": "application/json"}
        payload = {}

        if webhook_type == "slack":
            color = "#10b981" if letter_grade.startswith("A") else ("#f59e0b" if letter_grade in ["B", "C"] else "#ef4444")
            alert_lines = "\n".join([f"• *[{a['severity']}]* {a['title']}: {a['message']}" for a in alerts[:5]])
            payload = {
                "text": f"🔒 *SSL Certificate Audit: {host} (Grade {letter_grade})*",
                "attachments": [
                    {
                        "color": color,
                        "fields": [
                            {"title": "Target Domain", "value": host, "short": True},
                            {"title": "Security Grade", "value": letter_grade, "short": True},
                            {"title": "Days Remaining", "value": f"{days_left} days", "short": True},
                            {"title": "Expires On", "value": validity.get("not_after_formatted", "N/A"), "short": True},
                            {"title": "Active Alerts", "value": alert_lines, "short": False}
                        ],
                        "footer": "SSL Certificate Checker • Automated Security Monitoring"
                    }
                ]
            }
        elif webhook_type == "discord":
            embed_color = 0x10b981 if letter_grade.startswith("A") else (0xf59e0b if letter_grade in ["B", "C"] else 0xef4444)
            fields = [
                {"name": "Domain", "value": host, "inline": True},
                {"name": "Grade", "value": letter_grade, "inline": True},
                {"name": "Days Left", "value": str(days_left), "inline": True},
                {"name": "Expiry Date", "value": validity.get("not_after_formatted", "N/A"), "inline": True}
            ]
            for a in alerts[:4]:
                fields.append({"name": f"[{a['severity']}] {a['title']}", "value": a['message'], "inline": False})

            payload = {
                "username": "SSL Certificate Checker",
                "embeds": [{
                    "title": f"🔒 SSL Audit Report: {host}",
                    "color": embed_color,
                    "fields": fields,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }]
            }
        elif webhook_type == "teams":
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "10b981" if letter_grade.startswith("A") else "ef4444",
                "summary": f"SSL Alert for {host}",
                "sections": [{
                    "activityTitle": f"🔒 SSL Certificate Audit: {host} (Grade {letter_grade})",
                    "facts": [
                        {"name": "Host", "value": host},
                        {"name": "Security Grade", "value": letter_grade},
                        {"name": "Days Remaining", "value": f"{days_left} days"},
                        {"name": "Expiry Date", "value": validity.get("not_after_formatted", "N/A")}
                    ],
                    "text": "\n\n".join([f"**[{a['severity']}]** {a['title']} - {a['message']}" for a in alerts[:4]])
                }]
            }
        else: # Generic JSON
            payload = {
                "event": "ssl_certificate_audit",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "host": host,
                "letter_grade": letter_grade,
                "days_remaining": days_left,
                "expiry_status": validity.get("expiry_status"),
                "not_after": validity.get("not_after"),
                "alerts": alerts,
                "score": grade.get("overall_score")
            }

        try:
            resp = requests.post(webhook_url, json=payload, headers=headers, timeout=5.0)
            return {
                "success": (resp.status_code in [200, 201, 204]),
                "status_code": resp.status_code,
                "response_text": resp.text[:200]
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @classmethod
    def render_email_html(cls, report: Dict[str, Any]) -> str:
        """Generates a responsive HTML email digest for certificate alerts."""
        host = report.get("target", {}).get("host", "Unknown")
        grade = report.get("grading", {})
        letter_grade = grade.get("letter_grade", "N/A")
        grade_color = grade.get("grade_color", "#10b981")
        validity = report.get("certificate", {}).get("validity", {})
        cert = report.get("certificate", {})
        alerts = cls.generate_alerts(report)

        alert_rows_html = ""
        for a in alerts:
            badge_bg = "#ef4444" if a['severity'] == "CRITICAL" else ("#f59e0b" if a['severity'] == "WARNING" else "#10b981")
            alert_rows_html += f"""
            <tr style="border-bottom: 1px solid #2d3748;">
                <td style="padding: 12px 0;">
                    <span style="background: {badge_bg}; color: #ffffff; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-right: 8px;">{a['severity']}</span>
                    <strong style="color: #f7fafc; font-size: 14px;">{a['title']}</strong>
                    <div style="color: #a0aec0; font-size: 13px; margin-top: 4px;">{a['message']}</div>
                    <div style="color: #63b3ed; font-size: 12px; margin-top: 4px;">💡 <em>{a['recommendation']}</em></div>
                </td>
            </tr>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
                .card {{ max-width: 620px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 28px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
                .badge {{ display: inline-block; font-size: 28px; font-weight: bold; color: {grade_color}; background: rgba(255,255,255,0.05); border: 2px solid {grade_color}; border-radius: 8px; padding: 4px 16px; }}
                .stat-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 20px 0; }}
                .stat-box {{ background: #0f172a; padding: 12px; border-radius: 8px; border: 1px solid #334155; }}
            </style>
        </head>
        <body>
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px;">
                    <div>
                        <h2 style="margin: 0; color: #38bdf8; font-size: 20px;">🔒 SSL Certificate Audit Report</h2>
                        <div style="color: #94a3b8; font-size: 14px; margin-top: 4px;">Target: <strong>{host}</strong></div>
                    </div>
                    <div class="badge">{letter_grade}</div>
                </div>

                <div style="margin: 20px 0;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="color: #94a3b8; padding: 6px 0; font-size: 13px;">Issuer:</td>
                            <td style="color: #f1f5f9; padding: 6px 0; font-size: 13px; text-align: right; font-weight: 500;">{cert.get('issuer', {}).get('common_name') or 'N/A'}</td>
                        </tr>
                        <tr>
                            <td style="color: #94a3b8; padding: 6px 0; font-size: 13px;">Valid Until:</td>
                            <td style="color: #f1f5f9; padding: 6px 0; font-size: 13px; text-align: right; font-weight: 500;">{validity.get('not_after_formatted')}</td>
                        </tr>
                        <tr>
                            <td style="color: #94a3b8; padding: 6px 0; font-size: 13px;">Days Remaining:</td>
                            <td style="color: #38bdf8; padding: 6px 0; font-size: 13px; text-align: right; font-weight: bold;">{validity.get('days_remaining')} day(s)</td>
                        </tr>
                        <tr>
                            <td style="color: #94a3b8; padding: 6px 0; font-size: 13px;">Key Algorithm:</td>
                            <td style="color: #f1f5f9; padding: 6px 0; font-size: 13px; text-align: right;">{cert.get('public_key', {}).get('description')}</td>
                        </tr>
                    </table>
                </div>

                <h3 style="color: #f1f5f9; font-size: 15px; margin: 24px 0 12px 0; border-top: 1px solid #334155; padding-top: 16px;">Security Findings & Active Alerts</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    {alert_rows_html}
                </table>

                <div style="margin-top: 24px; text-align: center; color: #64748b; font-size: 12px; border-top: 1px solid #334155; padding-top: 16px;">
                    Generated by SSL Certificate Checker • Automated Security Inspection
                </div>
            </div>
        </body>
        </html>
        """
        return html
