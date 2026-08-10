#!/usr/bin/env python3
"""
SSL Certificate Checker - Standalone CLI Utility.
Author: Antigravity AI
"""
import sys
import os
import argparse
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from app.core.monitor import DomainMonitor
from app.core.cert_analyzer import CertificateAnalyzer


def render_cli_report(console: Console, report: dict):
    target = report["target"]
    grading = report["grading"]
    cert = report["certificate"]
    chain = report["chain"]
    proto = report["protocols"]
    http_sec = report["http_security"]
    alerts = report["alerts"]

    # 1. Top Grade Banner
    grade_letter = grading["letter_grade"]
    grade_color = "green" if grade_letter.startswith("A") else ("yellow" if grade_letter in ["B", "C"] else "red")
    
    score_txt = Text(f"\n  Grade: {grade_letter}  (Score: {grading['overall_score']}/100) - {grading['summary_status']}\n", style=f"bold {grade_color}")
    console.print(Panel(score_txt, title=f"[bold white]SSL/TLS Audit: {target['host']}:{target['port']}[/bold white]", border_style=grade_color))

    # 2. Certificate Details Table
    cert_table = Table(title="Certificate Details", show_header=True, header_style="bold cyan")
    cert_table.add_column("Property", style="dim", width=24)
    cert_table.add_column("Value")

    cert_table.add_row("Common Name (CN)", cert["subject"]["common_name"] or "N/A")
    cert_table.add_row("Subject Organization", cert["subject"]["organization"] or "N/A")
    cert_table.add_row("Issuer Authority", f"{cert['issuer']['common_name']} ({cert['issuer']['organization'] or cert['issuer']['country'] or ''})")
    
    # SANs
    sans = cert["subject_alternative_names"]
    sans_str = ", ".join(sans[:8]) + (f" ... (+{len(sans)-8} more)" if len(sans) > 8 else "") if sans else "None"
    cert_table.add_row("Alternative Names (SANs)", sans_str)

    # Expiry
    validity = cert["validity"]
    days_left = validity["days_remaining"]
    exp_style = "green" if days_left > 30 else ("yellow" if days_left > 7 else "bold red")
    exp_str = f"[{exp_style}]{days_left} Days Remaining[/{exp_style}] (Expires: {validity['not_after_formatted']})"
    cert_table.add_row("Validity Window", exp_str)

    cert_table.add_row("Public Key", cert["public_key"]["description"])
    cert_table.add_row("Signature Algorithm", f"{cert['signature']['algorithm']} ({cert['signature']['hash']})")
    cert_table.add_row("Serial Number", cert["serial_number"]["hex"])
    cert_table.add_row("SHA-256 Fingerprint", cert["fingerprints"]["sha256"])

    console.print(cert_table)
    console.print("")

    # 3. Certificate Chain Table
    chain_table = Table(title=f"Certificate Chain of Trust ({chain['chain_length']} Nodes)", show_header=True, header_style="bold cyan")
    chain_table.add_column("#", width=4)
    chain_table.add_column("Role", width=22)
    chain_table.add_column("Subject CN")
    chain_table.add_column("Issuer CN")
    chain_table.add_column("Trust Status", width=16)

    for node in chain.get("certificates", []):
        t_style = "green" if chain["is_trusted"] else "red"
        t_text = "Trusted" if chain["is_trusted"] else "Untrusted"
        chain_table.add_row(
            str(node["index"] + 1),
            node["role"],
            node["subject_cn"],
            node["issuer_cn"],
            f"[{t_style}]{t_text}[/{t_style}]"
        )
    console.print(chain_table)
    console.print("")

    # 4. Protocols & Ciphers Table
    proto_table = Table(title="Protocols & Cipher Suite Audit", show_header=True, header_style="bold cyan")
    proto_table.add_column("Check", width=24)
    proto_table.add_column("Status / Value")

    ps = proto["protocol_support"]
    proto_str = f"TLS 1.3: {'[green]Yes[/green]' if ps['tls_1_3'] else '[dim]No[/dim]'} | " \
                f"TLS 1.2: {'[green]Yes[/green]' if ps['tls_1_2'] else '[dim]No[/dim]'} | " \
                f"TLS 1.1: {'[red]Yes (Deprecated)[/red]' if ps['tls_1_1'] else '[green]Disabled[/green]'} | " \
                f"TLS 1.0: {'[red]Yes (Insecure)[/red]' if ps['tls_1_0'] else '[green]Disabled[/green]'}"
    proto_table.add_row("Protocol Support", proto_str)

    active_conn = proto["active_connection"]
    proto_table.add_row("Negotiated Cipher", active_conn.get("cipher_name") or "Unknown")
    
    pfs = proto["cipher_audit"]["has_forward_secrecy"]
    proto_table.add_row("Forward Secrecy (PFS)", "[green]Enabled (ECDHE/DHE)[/green]" if pfs else "[red]Disabled (Static RSA)[/red]")

    hsts = http_sec["hsts"]
    hsts_str = f"[green]Active ({hsts.get('status')}) - max-age={hsts.get('max_age_days')} days[/green]" if hsts["header_present"] else "[yellow]Not Configured[/yellow]"
    proto_table.add_row("HSTS Header", hsts_str)

    console.print(proto_table)
    console.print("")

    # 5. Security Alerts & Remediation
    alerts_table = Table(title="Security Findings & Active Alerts", show_header=True, header_style="bold cyan")
    alerts_table.add_column("Severity", width=12)
    alerts_table.add_column("Finding", width=36)
    alerts_table.add_column("Remediation / Recommendation")

    for a in alerts:
        sev = a["severity"]
        sev_color = "red" if sev == "CRITICAL" else ("yellow" if sev in ["WARNING", "HIGH"] else "green")
        alerts_table.add_row(
            f"[{sev_color}]{sev}[/{sev_color}]",
            a["title"],
            a["recommendation"]
        )

    console.print(alerts_table)
    console.print("")


def main():
    parser = argparse.ArgumentParser(description="CertGuard - SSL/TLS Certificate Verification and Health Auditor")
    parser.add_argument("host", nargs="?", help="Target domain, IP, or hostname (e.g. google.com or myhost:8443)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port number (default: 443)")
    parser.add_argument("-j", "--json", action="store_true", help="Output raw report in JSON format")
    parser.add_argument("-o", "--output", help="Save report to file (.json or .md)")
    parser.add_argument("-f", "--file", help="Scan multiple domains from a text file (one host per line)")

    args = parser.parse_args()
    console = Console(highlight=False)

    if not args.host and not args.file:
        parser.print_help()
        sys.exit(1)

    # Batch File Mode
    if args.file:
        if not os.path.exists(args.file):
            console.print(f"[red]Error: File {args.file} not found.[/red]")
            sys.exit(1)

        with open(args.file, "r", encoding="utf-8") as f:
            hosts = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        console.print(f"[bold cyan]Starting batch audit on {len(hosts)} targets...[/bold cyan]\n")
        batch_table = Table(title="Batch SSL Audit Results", show_header=True, header_style="bold cyan")
        batch_table.add_column("Host:Port")
        batch_table.add_column("Grade")
        batch_table.add_column("Status")
        batch_table.add_column("Days Left")
        batch_table.add_column("Issuer")

        for h in hosts:
            host_clean, port_clean = CertificateAnalyzer.normalize_target(h, args.port)
            try:
                report = DomainMonitor.execute_full_scan(host_clean, port_clean)
                grade = report["grading"]["letter_grade"]
                g_col = "green" if grade.startswith("A") else ("yellow" if grade in ["B", "C"] else "red")
                status = report["certificate"]["validity"]["expiry_status"]
                days = report["certificate"]["validity"]["days_remaining"]
                issuer = report["certificate"]["issuer"]["common_name"] or report["certificate"]["issuer"]["organization"] or "N/A"

                batch_table.add_row(
                    f"{host_clean}:{port_clean}",
                    f"[{g_col}]{grade}[/{g_col}]",
                    status,
                    f"{days} days" if days is not None else "-",
                    issuer
                )
            except Exception as e:
                batch_table.add_row(f"{host_clean}:{port_clean}", "[red]F[/red]", "[red]ERROR[/red]", "-", str(e)[:30])

        console.print(batch_table)
        sys.exit(0)

    # Single Host Mode
    host_clean, port_clean = CertificateAnalyzer.normalize_target(args.host, args.port)
    
    if not args.json:
        console.print(f"\n[bold cyan]Connecting and inspecting[/bold cyan] [bold white]{host_clean}:{port_clean}[/bold white]...\n")

    try:
        report = DomainMonitor.execute_full_scan(host_clean, port_clean)

        if args.json:
            print(json.dumps(report, indent=2))
        else:
            render_cli_report(console, report)

        # File Output
        if args.output:
            if args.output.endswith(".json"):
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
                console.print(f"[green]Saved JSON report to {args.output}[/green]")
            elif args.output.endswith(".md"):
                md = f"# SSL Audit Report: {host_clean}\n\n- Grade: **{report['grading']['letter_grade']}**\n- Days Left: **{report['certificate']['validity']['days_remaining']}**\n"
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(md)
                console.print(f"[green]Saved Markdown report to {args.output}[/green]")

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"\n[bold red]Audit Failed:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
