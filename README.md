# CertGuard • SSL/TLS Certificate Checker & Security Auditor

An enterprise-grade SSL/TLS Certificate Verification, Trust Chain Inspection, and Security Auditing suite. It performs deep cryptographic analysis of remote and local X.509 certificates, validates complete trust chains against the Mozilla Root CA store, monitors expiration countdowns, audits cipher suites and protocols for vulnerabilities, computes an SSL Labs-style rating (**A+ to F**), and dispatches automated alerts.

---

## 🌟 Key Features

1. **Deep X.509 Certificate Inspection**:
   - **Subject & Issuer**: Common Name (CN), Organization (O), Organizational Unit (OU), Country, State, Locality.
   - **Subject Alternative Names (SANs)**: DNS Names, IP Addresses, URIs, and RFC-compliant wildcard domain validation (`*.example.com`).
   - **Key & Signature Specs**: RSA (2048/4096-bit), ECDSA (NIST P-256, P-384), Ed25519, Ed448, DSA detection; SHA-256, SHA-384, SHA-1 (weak), MD5 (vulnerable) signature analysis.
   - **X.509 Extensions**: Basic Constraints (CA flag, Path Length), Key Usages, Extended Key Usage (Server/Client Auth), CRL Distribution Points, OCSP URLs, Authority Information Access (AIA).
   - **Fingerprints & PEM**: SHA-256, SHA-1, MD5 fingerprints with 1-click PEM copy and `.crt` certificate download.

2. **Certificate Chain & Trust Path Validation**:
   - Extracts complete hierarchy: **Leaf (End-Entity) $\rightarrow$ Intermediate CA(s) $\rightarrow$ Root CA**.
   - Validates signatures and issuer links along the chain against the **Mozilla Root CA Trust Store** (`certifi`).
   - Auto-retrieves missing intermediate certificates via AIA `caIssuers` HTTP endpoints.
   - Identifies **Self-Signed Certificates**, **Incomplete Chains**, **Untrusted Roots**, and **Expired Intermediates**.

3. **Expiration Tracking & Urgency Alerts**:
   - Exact days, hours, and percentage remaining calculation.
   - Status classification: `VALID`, `EXPIRING_SOON` (<30 days), `EXPIRING_CRITICAL` (<7 days), `EXPIRED`, `NOT_YET_VALID`.
   - Visual expiration timeline bar.

4. **Weak Encryption & Protocol Scanner**:
   - **Protocol Probing**: TLS 1.3, TLS 1.2, TLS 1.1 (deprecated warning), TLS 1.0 (PCI-DSS violation), SSL 3.0 (POODLE vulnerable).
   - **Cipher Suite Audit**: Perfect Forward Secrecy (PFS - ECDHE/DHE), AEAD authenticated encryption (GCM, ChaCha20-Poly1305), Legacy CBC mode warning, Vulnerable cipher detection (RC4, 3DES, DES, NULL).
   - **HTTP Security Headers**: HSTS (`Strict-Transport-Security`, `max-age`, `includeSubDomains`, `preload` readiness), HTTP to HTTPS automatic redirection check.
   - **ALPN Protocol Negotiation**: HTTP/2 (`h2`) and HTTP/1.1 detection.

5. **Security Rating Engine (A+ to F)**:
   - SSL Labs-style grade: **A+**, **A**, **B**, **C**, **D**, **F**.
   - Categorized scores for Certificate, Protocols, Cipher Suites, and HSTS.
   - Actionable remediation advice and security recommendations.

6. **Continuous Monitoring & Notification Center**:
   - **Watchlist**: Persistently monitor multiple infrastructure domains.
   - **Batch Scanner**: Audit dozens of domains at once with CSV export.
   - **Multi-Platform Webhooks**: Dispatch alert payloads formatted for **Slack**, **Discord**, **Microsoft Teams**, or **Generic Webhooks**.
   - **HTML Email Reports**: Responsive HTML email digests with color-coded grade badges.

7. **Dual Interfaces**:
   - **Web UI Dashboard**: Modern, responsive dark/light UI with interactive chain tree graph, live scan animations, and export tools (JSON, Markdown, PDF).
   - **Terminal CLI**: Rich colored tables, panels, and JSON flags for automation / CI/CD pipelines.

---

## 🚀 Quick Start

### 1. Launch the Web Application
```bash
python run_server.py
```
Open your browser at **`http://localhost:8000`** to access the dashboard and **`http://localhost:8000/docs`** for the interactive Swagger API documentation.

### 2. Standalone CLI Utility
```bash
# Scan a single domain
python ssl_checker_cli.py google.com

# Scan custom port
python ssl_checker_cli.py myhost.example.com -p 8443

# Output raw JSON for automation
python ssl_checker_cli.py google.com --json

# Save audit report to JSON or Markdown
python ssl_checker_cli.py google.com -o google_report.json
python ssl_checker_cli.py google.com -o google_report.md

# Batch scan domains from a text file
python ssl_checker_cli.py -f domains.txt
```

---

## 🧪 Testing with BadSSL Benchmarks

The application includes built-in test targets from `badssl.com` to verify vulnerability detection:
- `expired.badssl.com` ➔ **Grade F** (Expired certificate)
- `wrong.host.badssl.com` ➔ **Grade F** (Hostname mismatch)
- `self-signed.badssl.com` ➔ **Grade F** (Self-signed certificate)
- `rc4.badssl.com` ➔ **Grade F** (Weak RC4 cipher suite)
- `tls-v1-0.badssl.com:1010` ➔ **Grade C** (Deprecated TLS 1.0)
- `google.com` / `github.com` ➔ **Grade A+** (Enterprise standards)

---

## 📡 REST API Documentation

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/check` | Deep scan a single host (`{"host": "google.com", "port": 443}`) |
| `POST` | `/api/batch` | Scan multiple domains (`{"hosts": ["google.com", "github.com"]}`) |
| `GET` | `/api/watchlist` | Retrieve all monitored watchlist targets |
| `POST` | `/api/watchlist` | Add a domain to the continuous watchlist |
| `DELETE` | `/api/watchlist/{id}` | Remove a domain from the watchlist |
| `POST` | `/api/watchlist/scan` | Trigger a scan across all watchlist targets |
| `POST` | `/api/notify/webhook` | Dispatch alert payload to Slack, Discord, Teams or Webhook |
| `POST` | `/api/notify/email-preview` | Generate responsive HTML email digest |
| `GET` | `/api/test-presets` | Retrieve benchmark and BadSSL test cases |

---

## 🛠️ Project Architecture

```
JOVAC/
├── app/
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py              # RESTful API endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   ├── cert_analyzer.py       # X.509 extraction, parsing & SANs
│   │   ├── chain_validator.py     # Trust chain validation & AIA fetcher
│   │   ├── protocol_scanner.py    # TLS 1.0-1.3, ciphers & HSTS audit
│   │   ├── grading_engine.py      # A+ to F security scoring engine
│   │   ├── alert_notifier.py      # Multi-channel webhook & email alerts
│   │   └── monitor.py             # Watchlist & scan runner
│   ├── static/
│   │   ├── index.html             # Responsive UI dashboard
│   │   ├── css/styles.css         # Custom CSS design system
│   │   └── js/app.js              # Interactive frontend client logic
│   ├── __init__.py
│   └── main.py                    # FastAPI application entry point
├── ssl_checker_cli.py             # Rich terminal CLI utility
├── run_server.py                  # Web server launcher
├── test_checker.py                # Automated test suite
└── README.md                      # Documentation
```

---

## 🛡️ License
MIT License. Built for cybersecurity engineers, devops teams, and infrastructure administrators.
Feature: Add core analyzer
Feature: Add API routes
Feature: Add monitoring module
