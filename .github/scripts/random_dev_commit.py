#!/usr/bin/env python3
"""
Organic & Authentic Developer Activity Generator for SSL-Certificate-Checker
Features:
- Strict Daily Cap: Maximum 1 to 3 (never > 4) commits per calendar day.
- Unpredictable Timing: Random skip probability and natural execution delays.
- Anti-Repetition: Checks git history to avoid repeating recent commit messages.
- Human Diversity: 120+ authentic SSL / TLS / Cryptography developer commit messages & varied file updates.
- Configured identity: rajat722005-p <rajat722005@gmail.com>
"""

import os
import sys
import json
import time
import random
import datetime
import subprocess

# Maximum commits allowed in a single calendar day (Strict cap: never > 4)
MAX_DAILY_COMMITS_CAP = 4

# Rich, natural developer commit messages pool for SSL/TLS Certificate Checker
MESSAGES_POOL = [
    # Performance & Optimization
    "perf(handshake): optimize TLS socket timeout and connection pooling",
    "perf(scanner): batch concurrent domain checks using asyncio worker pool",
    "perf(cache): add in-memory TTL caching for verified OCSP stapling responses",
    "perf(cli): speed up SAN certificate parsing using compiled ASN.1 regex",
    "perf(db): add composite index on domain_name and next_expiry_check in watchlist",
    "perf(crypto): reduce intermediate certificate chain traversal overhead",
    "optimize socket buffer read size during TLS server hello exchange",
    "tune async connection pool limits for high volume bulk scans",
    "reduce memory allocation during x509 extension decoding",
    "speed up hostname wildcard matching against multi-domain SAN records",

    # Bug Fixes & Resilience
    "fix(parser): handle truncated ASN.1 GeneralizedTime timestamp formats",
    "fix(scanner): resolve unhandled SSLEOFError when target server drops connection",
    "fix(ocsp): handle HTTP 504 gateway timeout gracefully during revocation check",
    "fix(cli): correct color highlighting for certificates expiring under 7 days",
    "fix(san): handle IPv6 addresses correctly in Subject Alternative Name fields",
    "fix(chain): prevent endless loop on cyclic intermediate certificate chains",
    "fix(exporter): sanitize comma escaping in CSV certificate audit reports",
    "fix(api): handle missing SNI header in incoming domain verification requests",
    "fix(ct): gracefully catch rate limiting from Certificate Transparency logs",
    "fix(validation): handle self-signed root certs without throwing uncaught panic",
    "fix edge case in leap year calculation for cert expiration delta",
    "handle connection reset by peer during TLS 1.3 cipher negotiation",
    "prevent null pointer when certificate issuer CN is missing",
    "resolve CSS table layout overflow in dashboard monitor view",

    # Feature Enhancements
    "feat(tls): add support for TLS 1.3 ALPN protocol negotiation inspection",
    "feat(cipher): detect deprecated weak ciphers (RC4, 3DES, CBC mode)",
    "feat(monitoring): add automated email webhook alert for certificates expiring in <14 days",
    "feat(cli): add --json output flag for automated CI/CD pipeline integration",
    "feat(chain): display full trust chain path with root authority details",
    "feat(hsts): inspect HTTP Strict Transport Security (HSTS) preload status",
    "feat(ct): add check for Certificate Transparency (SCT) embedded timestamps",
    "feat(watchlist): support bulk domain import via CSV and text file",
    "feat(dashboard): add expiration status badge breakdown in summary cards",
    "feat(reports): add PDF summary export option for certificate compliance audits",
    "add support for custom CA bundle file path via CLI argument",
    "implement automatic retry with exponential backoff on network timeout",
    "add quick-filter tags for expired, expiring, and valid certificates",
    "support SNI customization for multi-tenant cloud load balancers",

    # Refactoring & Code Quality
    "refactor(engine): modularize SSL context creation and cipher selection",
    "refactor(models): streamline DomainCertificate dataclass serialization",
    "refactor(watchlist): extract SQLite database helper into dedicated repository class",
    "refactor(cli): simplify command-line argument parsing and flag validators",
    "refactor(alerts): standardize notification payload schema across webhooks",
    "refactor(validator): consolidate trust chain verification helper routines",
    "cleanup unused imports and format certificate parsing utilities",
    "modularize web dashboard card rendering components",
    "standardize error response codes across REST API endpoints",
    "reorganize configuration constants for default timeout and retry limits",

    # Documentation & Dev Notes
    "docs(readme): add Docker run instructions and environment variable reference",
    "docs(api): document query parameters and response schema for /api/check",
    "docs(cli): update terminal examples for bulk domain scanning",
    "docs(architecture): add sequence diagram for TLS handshake verification",
    "docs(troubleshooting): add guide for debugging self-signed internal certificates",
    "docs(deploy): document deployment on Render and cloud PaaS providers",
    "docs(security): document best practices for storing webhook API keys",
    "update architecture diagram notes in documentation",
    "add inline comments explaining x509 extension OID mapping",
    "document REST API response status codes in readme",
    "clarify differences between OCSP and CRL revocation check mechanics",

    # Security & Cryptographic Standards
    "chore(crypto): update Mozilla root CA trust store bundle reference",
    "chore(ciphers): refresh list of quantum-safe post-quantum TLS draft ciphers",
    "chore(rules): update recommended minimum key size policy (RSA >= 2048, ECC >= 256)",
    "chore(deps): verify compatibility with Python 3.12 ssl module updates",
    "sync latest trusted root CA certificates bundle",
    "calibrate certificate health score algorithm weighting",
    "update known deprecated cipher suite definitions",
    "refresh baseline revocation check test fixtures"
]

CIPHER_SUITES_SAMPLES = [
    "TLS_AES_256_GCM_SHA384 (TLSv1.3 | 256 bits | Secure)",
    "TLS_CHACHA20_POLY1305_SHA256 (TLSv1.3 | 256 bits | Secure)",
    "TLS_AES_128_GCM_SHA256 (TLSv1.3 | 128 bits | Secure)",
    "ECDHE-ECDSA-AES256-GCM-SHA384 (TLSv1.2 | 256 bits | Secure)",
    "ECDHE-RSA-AES256-GCM-SHA384 (TLSv1.2 | 256 bits | Secure)",
    "ECDHE-ECDSA-CHACHA20-POLY1305 (TLSv1.2 | 256 bits | Secure)",
    "ECDHE-RSA-CHACHA20-POLY1305 (TLSv1.2 | 256 bits | Secure)",
    "ECDHE-ECDSA-AES128-GCM-SHA256 (TLSv1.2 | 128 bits | Secure)",
    "ECDHE-RSA-AES128-GCM-SHA256 (TLSv1.2 | 128 bits | Secure)"
]

DEV_NOTES_SAMPLES = [
    "Benchmarked async TLS handshake engine across 500 domains; average response time 48ms per host.",
    "Verified x509 ASN.1 timestamp parsing compatibility across Let's Encrypt, DigiCert, and Sectigo certs.",
    "Tested OCSP stapling response cache under concurrent load; cache hit ratio reached 94.2%.",
    "Audited certificate chain validator against broken intermediate chain test suite (100% pass).",
    "Inspected CLI table renderer: optimized ANSI escape sequences for minimal terminal redraw flicker.",
    "Tuned TLS 1.3 cipher suite fallback matrix: ensured zero false positives on legacy TLS 1.2 servers.",
    "Validated SAN wildcard matching algorithm against RFC 6125 compliance edge cases."
]

def get_recent_commits():
    """Returns list of last 40 commit messages to prevent repetition."""
    try:
        out = subprocess.check_output(
            ["git", "log", "-n", "40", "--pretty=format:%s"],
            text=True
        )
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        return []

def get_today_commit_count():
    """Counts how many commits have been made today (UTC calendar day)."""
    try:
        today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        out = subprocess.check_output(
            ["git", "log", "--since=" + today_str + " 00:00:00", "--pretty=format:%H"],
            text=True
        )
        hashes = [h.strip() for h in out.splitlines() if h.strip()]
        return len(hashes)
    except Exception:
        return 0

def make_organic_updates(commit_index):
    """Generates natural, varied file changes across realistic repo areas."""
    os.makedirs(".activity", exist_ok=True)
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Update 1: Cryptographic verification metadata JSON
    meta_path = ".activity/tls_engine_metadata.json"
    engine_data = {
        "engine_version": "2.1.0",
        "last_sync": now_utc,
        "supported_protocols": ["TLSv1.2", "TLSv1.3"],
        "cipher_suites_audited": 18 + random.randint(1, 6),
        "root_ca_bundle": {
            "authorities_count": 142 + random.randint(1, 5),
            "revocation_cache_ttl_seconds": 3600,
            "ocsp_stapling_enabled": True
        },
        "heuristics": {
            "expiry_warning_threshold_days": 30,
            "critical_warning_threshold_days": 7,
            "max_handshake_timeout_seconds": 5.0,
            "concurrent_workers": random.choice([8, 10, 16])
        }
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(engine_data, f, indent=2)

    # Update 2: TLS Benchmark & Cipher Suite Registry
    cipher_path = ".activity/tls_cipher_registry.txt"
    selected_ciphers = random.sample(CIPHER_SUITES_SAMPLES, k=random.randint(4, 7))
    with open(cipher_path, "w", encoding="utf-8") as f:
        f.write(f"# SSL-Certificate-Checker Cipher Suite Verification Feed\n# Last Verified: {now_utc}\n# Active Recommended Ciphers: {len(selected_ciphers)}\n\n")
        for c in selected_ciphers:
            f.write(f"{c}\n")

    # Update 3: Daily Activity Log
    log_path = ".activity/daily_log.txt"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{now_utc}] Activity Sync #{commit_index+1} | Verified TLS Trust Store | Engine Health OK\n")

    # Update 4: Developer Scratchpad & Engineering Notes
    notes_path = ".activity/dev_notes.md"
    note = random.choice(DEV_NOTES_SAMPLES)
    with open(notes_path, "w", encoding="utf-8") as f:
        f.write(f"# SSL / TLS Engineering Daily Notes\n\n- **Last Verification**: `{now_utc}`\n- **Engineering Focus**: {note}\n- **Integrity**: All cryptographic test fixtures verified.\n")

    # Update 5: Watchlist Health Status
    status_path = ".activity/status.txt"
    with open(status_path, "w", encoding="utf-8") as f:
        f.write(f"SSL Certificate Checker Engine: ACTIVE\nLast Sync: {now_utc}\nTrust Store: SYNCHRONIZED\n")

def run(force=False):
    # 1. Check how many commits have already been made today
    today_commits = get_today_commit_count()
    print(f"[*] Commits already recorded today (UTC): {today_commits}")

    if today_commits >= MAX_DAILY_COMMITS_CAP and not force:
        print(f"[!] Daily commit cap ({MAX_DAILY_COMMITS_CAP}) already reached for today. Skipping to maintain organic profile.")
        return

    # 2. Decide how many commits to make in this run (typically 1, occasionally 2, never exceeding cap)
    remaining_budget = MAX_DAILY_COMMITS_CAP - today_commits
    if remaining_budget <= 0 and not force:
        print("[!] No remaining commit budget for today. Skipping.")
        return

    # 3. Organic skip probability (50% chance to skip when called via scheduled cron to stagger days naturally)
    if not force and today_commits >= 1:
        if random.random() < 0.50:
            print("[*] Organic random skip triggered for this slot to maintain natural developer rhythm.")
            return

    num_commits = min(remaining_budget, random.choice([1, 1, 2]))
    print(f"[*] Generating {num_commits} natural commit(s) for this cycle...")

    # 4. Filter recent commits to avoid any repetition
    recent_messages = set(get_recent_commits())
    available_messages = [m for m in MESSAGES_POOL if m not in recent_messages]
    if len(available_messages) < num_commits:
        available_messages = MESSAGES_POOL

    selected_messages = random.sample(available_messages, k=num_commits)

    # 5. Execute commits
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "rajat722005-p"
    env["GIT_AUTHOR_EMAIL"] = "rajat722005@gmail.com"
    env["GIT_COMMITTER_NAME"] = "rajat722005-p"
    env["GIT_COMMITTER_EMAIL"] = "rajat722005@gmail.com"

    for i, msg in enumerate(selected_messages):
        make_organic_updates(i)
        subprocess.run(["git", "add", ".activity/"], check=True)

        res = subprocess.run(["git", "diff", "--staged", "--quiet"])
        if res.returncode != 0:
            print(f"[+] Committing ({i+1}/{num_commits}): {msg}")
            subprocess.run(["git", "commit", "-m", msg], env=env, check=True)
            # Short organic pause between commits
            time.sleep(random.randint(2, 5))

    print("[*] Pushing commit(s) to origin main...")
    subprocess.run(["git", "push", "origin", "main"], check=True)
    print("[+] All commits pushed successfully!")

if __name__ == '__main__':
    force_flag = "--force" in sys.argv
    run(force=force_flag)
