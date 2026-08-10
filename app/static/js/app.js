/**
 * CertGuard Frontend Application Logic
 */

class CertGuardApp {
  constructor() {
    this.currentReport = null;
    this.watchlist = [];
    this.batchResults = [];
    this.initTheme();
    this.initNavigation();
    this.initDetailTabs();
    this.loadWatchlist();
  }

  // Theme Management
  initTheme() {
    const savedTheme = localStorage.getItem('certguard_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    this.updateThemeIcon(savedTheme);

    const toggleBtn = document.getElementById('theme-toggle-btn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('certguard_theme', next);
        this.updateThemeIcon(next);
      });
    }
  }

  updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
      icon.textContent = theme === 'dark' ? '🌙' : '☀️';
    }
  }

  // View Navigation
  initNavigation() {
    const navButtons = document.querySelectorAll('.nav-tab-btn');
    navButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const viewId = btn.getAttribute('data-view');
        
        navButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));
        const targetSec = document.getElementById(viewId);
        if (targetSec) targetSec.classList.add('active');

        if (viewId === 'view-watchlist') {
          this.loadWatchlist();
        }
      });
    });
  }

  // Sub Tabs in Single View
  initDetailTabs() {
    const tabButtons = document.querySelectorAll('.detail-tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabId = btn.getAttribute('data-tab');
        tabButtons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
        const targetPane = document.getElementById(tabId);
        if (targetPane) targetPane.classList.add('active');
      });
    });
  }

  // Presets Loader
  loadPreset(host, port = 443) {
    document.getElementById('host-input').value = host;
    document.getElementById('port-input').value = port;
    this.handleSingleScan();
  }

  // Single Host Scan Execution
  async handleSingleScan() {
    const hostInput = document.getElementById('host-input');
    const portInput = document.getElementById('port-input');
    const host = hostInput.value.trim();
    const port = parseInt(portInput.value) || 443;

    if (!host) {
      this.showToast('Please enter a valid hostname or domain.', 'warning');
      return;
    }

    const loadingDiv = document.getElementById('scan-loading');
    const errorCard = document.getElementById('scan-error-card');
    const resultsWrapper = document.getElementById('scan-results-wrapper');
    const scanBtn = document.getElementById('btn-run-scan');

    loadingDiv.style.display = 'block';
    errorCard.style.display = 'none';
    resultsWrapper.style.display = 'none';
    scanBtn.disabled = true;

    try {
      const resp = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, port })
      });

      if (!resp.ok) {
        const errData = await resp.json();
        throw new Error(errData.detail || 'Failed to inspect host.');
      }

      const report = await resp.json();
      this.currentReport = report;
      this.renderReport(report);
      resultsWrapper.style.display = 'block';
      this.showToast(`Scan completed for ${host}`, 'success');
    } catch (err) {
      errorCard.style.display = 'block';
      document.getElementById('scan-error-msg').textContent = err.message;
      this.showToast(`Error: ${err.message}`, 'danger');
    } finally {
      loadingDiv.style.display = 'none';
      scanBtn.disabled = false;
    }
  }

  // Render Single Scan Report
  renderReport(report) {
    const { target, grading, certificate, chain, protocols, http_security, vulnerabilities, alerts } = report;

    // 1. Overview Banner
    const gradeLetter = document.getElementById('res-grade-letter');
    gradeLetter.textContent = grading.letter_grade;
    gradeLetter.style.color = grading.grade_color;

    document.getElementById('res-grade-status').textContent = grading.summary_status;
    document.getElementById('res-target-host').textContent = `${target.host}:${target.port}`;

    const statusBadge = document.getElementById('res-status-badge');
    statusBadge.className = 'status-badge';
    const expStatus = certificate.validity.expiry_status;
    statusBadge.textContent = expStatus.replace('_', ' ');

    if (expStatus === 'VALID') {
      statusBadge.classList.add('status-valid');
    } else if (expStatus.startsWith('EXPIRING_')) {
      statusBadge.classList.add('status-warning');
    } else {
      statusBadge.classList.add('status-critical');
    }

    const trustBadge = document.getElementById('res-trust-badge');
    if (chain.is_trusted) {
      trustBadge.textContent = 'TRUSTED CA';
      trustBadge.className = 'badge-pill strong';
    } else if (certificate.is_self_signed) {
      trustBadge.textContent = 'SELF-SIGNED';
      trustBadge.className = 'badge-pill weak';
    } else {
      trustBadge.textContent = 'UNTRUSTED';
      trustBadge.className = 'badge-pill weak';
    }

    // Expiry progress
    const daysRemaining = certificate.validity.days_remaining;
    document.getElementById('res-days-left').textContent = daysRemaining >= 0 ? `${daysRemaining} Days Remaining` : `Expired ${Math.abs(daysRemaining)} Days Ago`;
    document.getElementById('res-expiry-date').textContent = `Expires ${certificate.validity.not_after_formatted}`;

    const expiryFill = document.getElementById('res-expiry-fill');
    const pct = Math.max(0, Math.min(100, 100 - (certificate.validity.validity_percentage || 0)));
    expiryFill.style.width = `${pct}%`;
    expiryFill.style.background = (daysRemaining > 30) ? 'var(--color-success)' : (daysRemaining > 7 ? 'var(--color-warning)' : 'var(--color-danger)');

    // Stats
    document.getElementById('res-stat-score').textContent = grading.overall_score;
    document.getElementById('res-stat-tls').textContent = protocols.active_connection.tls_version || 'TLS 1.3';
    document.getElementById('res-stat-alerts').textContent = alerts.filter(a => a.severity !== 'GOOD').length;

    // 2. Chain Diagram
    this.renderChainGraph(chain);

    // 3. Tab 1: Findings & Alerts
    this.renderFindings(alerts);

    // 4. Tab 2: Vulnerability Audit (Feature 1)
    this.renderVulnerabilities(vulnerabilities);

    // 5. Tab 3: Supported Ciphers Matrix (Feature 1)
    this.renderCipherMatrix(vulnerabilities);

    // 6. Tab 4: Certificate Properties
    document.getElementById('prop-cn').textContent = certificate.subject.common_name || 'N/A';
    document.getElementById('prop-org').textContent = certificate.subject.organization || 'N/A';
    document.getElementById('prop-issuer').textContent = `${certificate.issuer.common_name || 'N/A'} (${certificate.issuer.organization || certificate.issuer.country || ''})`;

    const sansDiv = document.getElementById('prop-sans');
    sansDiv.innerHTML = '';
    if (certificate.subject_alternative_names && certificate.subject_alternative_names.length > 0) {
      certificate.subject_alternative_names.forEach(san => {
        const span = document.createElement('span');
        span.className = 'badge-pill';
        span.textContent = san;
        sansDiv.appendChild(span);
      });
    } else {
      sansDiv.textContent = 'None specified';
    }

    document.getElementById('prop-validity').textContent = `${certificate.validity.not_before_formatted} ➔ ${certificate.validity.not_after_formatted} (${certificate.validity.total_validity_days} days)`;
    document.getElementById('prop-pubkey').textContent = certificate.public_key.description;
    document.getElementById('prop-sigalgo').textContent = `${certificate.signature.algorithm} (${certificate.signature.hash})`;
    document.getElementById('prop-serial').textContent = certificate.serial_number.hex;

    document.getElementById('prop-keyusage').textContent = (certificate.extensions.key_usage || []).join(', ') || 'N/A';
    document.getElementById('prop-eku').textContent = (certificate.extensions.extended_key_usage || []).join(', ') || 'N/A';
    document.getElementById('prop-ocsp').textContent = (certificate.extensions.ocsp_urls || []).join(', ') || 'None';

    // 7. Tab 5: HTTP & HSTS
    const hsts = http_security.hsts;
    document.getElementById('hdr-hsts-status').innerHTML = hsts.header_present 
      ? `<span class="badge-pill strong">${hsts.status}</span>` 
      : '<span class="badge-pill weak">NOT CONFIGURED</span>';
    document.getElementById('hdr-hsts-age').textContent = hsts.max_age_days ? `${hsts.max_age_days} Days (${hsts.max_age_seconds}s)` : 'None';
    document.getElementById('hdr-hsts-preload').textContent = hsts.preload ? 'Yes' : 'No';
    document.getElementById('hdr-hsts-subdomains').textContent = hsts.include_subdomains ? 'Yes' : 'No';
    document.getElementById('hdr-redirect').innerHTML = http_security.http_redirects_to_https
      ? '<span class="badge-pill strong">HTTP ➔ HTTPS Active</span>'
      : '<span class="badge-pill weak">No Automatic Redirect</span>';
    document.getElementById('hdr-raw-hsts').textContent = hsts.raw_header || 'None';

    // 8. Tab 6: Raw PEM
    document.getElementById('hash-sha256').textContent = certificate.fingerprints.sha256;
    document.getElementById('hash-sha1').textContent = certificate.fingerprints.sha1;
    document.getElementById('raw-pem-text').value = certificate.pem;
  }

  // Render Vulnerability Cards (Feature 1)
  renderVulnerabilities(vulnData) {
    const container = document.getElementById('vulns-cards-grid');
    container.innerHTML = '';

    if (!vulnData || !vulnData.vulnerabilities) {
      container.innerHTML = '<div style="color: var(--text-secondary);">No vulnerability data available.</div>';
      return;
    }

    vulnData.vulnerabilities.forEach(v => {
      const card = document.createElement('div');
      card.className = 'protocol-card';
      card.style.textAlign = 'left';
      card.style.padding = '18px';

      const isVuln = (v.status === 'VULNERABLE');
      const isGood = (v.status === 'PROTECTED' || v.status === 'ACTIVE' || v.status === 'SUPPORTED');
      const badgeClass = isGood ? 'enabled-good' : (isVuln ? 'enabled-bad' : 'disabled');

      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
          <div>
            <div style="font-weight: 700; font-size: 14px;">${v.name}</div>
            ${v.cve ? `<span class="badge-pill" style="font-size: 10px; margin-top: 2px;">${v.cve}</span>` : ''}
          </div>
          <span class="protocol-card-status ${badgeClass}">${v.status}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">
          ${v.details}
        </div>
        ${v.remediation ? `<div class="alert-recommendation" style="margin-top: 10px; font-size: 11px;">🛠️ <strong>Fix:</strong> ${v.remediation}</div>` : ''}
      `;
      container.appendChild(card);
    });
  }

  // Render Supported Cipher Suites Matrix (Feature 1)
  renderCipherMatrix(vulnData) {
    const statsContainer = document.getElementById('cipher-stats-pills');
    const tbody = document.getElementById('ciphers-matrix-body');
    tbody.innerHTML = '';
    statsContainer.innerHTML = '';

    if (!vulnData || !vulnData.supported_ciphers) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 20px;">No cipher suite data available.</td></tr>';
      return;
    }

    const stats = vulnData.cipher_stats || {};
    statsContainer.innerHTML = `
      <span class="badge-pill strong">${stats.total_supported || 0} Supported</span>
      <span class="badge-pill strong">${stats.recommended_count || 0} AEAD / Recommended</span>
      ${stats.weak_count > 0 ? `<span class="badge-pill weak">${stats.weak_count} Legacy</span>` : ''}
      ${stats.insecure_count > 0 ? `<span class="badge-pill weak" style="background: var(--color-danger-bg);">${stats.insecure_count} Insecure</span>` : ''}
    `;

    vulnData.supported_ciphers.forEach(c => {
      const tr = document.createElement('tr');
      let ratingClass = 'strong';
      if (c.rating === 'WEAK') ratingClass = 'badge-pill';
      else if (c.rating === 'INSECURE') ratingClass = 'weak';

      tr.innerHTML = `
        <td class="code-font" style="font-weight: 600; font-size: 12px;">${c.name}</td>
        <td><span class="badge-pill">${c.tls_ver}</span></td>
        <td style="color: var(--text-secondary); font-size: 12px;">${c.kex}</td>
        <td style="color: var(--text-secondary); font-size: 12px;">${c.enc} (${c.bits}-bit)</td>
        <td>${c.pfs ? '<span class="badge-pill strong">PFS</span>' : '<span style="color: var(--text-muted); font-size: 11px;">No</span>'}</td>
        <td><span class="badge-pill ${ratingClass}">${c.rating}</span></td>
      `;
      tbody.appendChild(tr);
    });
  }

  renderChainGraph(chain) {
    const container = document.getElementById('chain-graph-container');
    container.innerHTML = '';
    const certs = chain.certificates || [];
    document.getElementById('chain-length-badge').textContent = `${certs.length} Certificate${certs.length > 1 ? 's' : ''}`;

    certs.forEach((node, idx) => {
      const nodeEl = document.createElement('div');
      nodeEl.className = `chain-node ${idx === 0 ? 'active' : ''}`;
      nodeEl.innerHTML = `
        <div class="chain-node-role">${node.role}</div>
        <div class="chain-node-cn">${node.subject_cn}</div>
        <div class="chain-node-meta">Issuer: ${node.issuer_cn}</div>
        <div class="chain-node-meta" style="margin-top: 4px;">Expires: ${node.parsed.validity.not_after_formatted.split(' ')[0]} ${node.parsed.validity.not_after_formatted.split(' ')[1]}</div>
      `;
      container.appendChild(nodeEl);

      if (idx < certs.length - 1) {
        const connector = document.createElement('div');
        connector.className = 'chain-connector';
        connector.textContent = '➔';
        container.appendChild(connector);
      }
    });
  }

  renderFindings(alerts) {
    const container = document.getElementById('findings-list');
    container.innerHTML = '';

    if (!alerts || alerts.length === 0) {
      container.innerHTML = '<div style="color: var(--text-secondary); text-align: center; padding: 20px;">No alerts or issues detected.</div>';
      return;
    }

    alerts.forEach(a => {
      const item = document.createElement('div');
      item.className = `alert-item severity-${a.severity}`;

      let icon = '🔔';
      if (a.severity === 'CRITICAL') icon = '🚨';
      else if (a.severity === 'WARNING' || a.severity === 'HIGH') icon = '⚠️';
      else if (a.severity === 'GOOD') icon = '✅';

      item.innerHTML = `
        <div class="alert-icon">${icon}</div>
        <div class="alert-content">
          <div class="alert-title">${a.title}</div>
          <div class="alert-message">${a.message}</div>
          <div class="alert-recommendation">💡 <strong>Remediation:</strong> ${a.recommendation}</div>
        </div>
      `;
      container.appendChild(item);
    });
  }

  // Copy PEM
  copyPem() {
    const text = document.getElementById('raw-pem-text').value;
    navigator.clipboard.writeText(text);
    this.showToast('Certificate PEM copied to clipboard!', 'success');
  }

  // Download Cert
  downloadCert() {
    if (!this.currentReport) return;
    const text = this.currentReport.certificate.pem;
    const blob = new Blob([text], { type: 'application/x-x509-ca-cert' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${this.currentReport.target.host}.crt`;
    a.click();
    URL.revokeObjectURL(url);
    this.showToast('Certificate (.crt) downloaded!', 'success');
  }

  // Export JSON
  exportJson() {
    if (!this.currentReport) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.currentReport, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `ssl-audit-${this.currentReport.target.host}.json`;
    a.click();
    this.showToast('JSON report exported.', 'success');
  }

  // Export Markdown
  exportMarkdown() {
    if (!this.currentReport) return;
    const r = this.currentReport;
    const md = `# SSL Certificate Security Audit Report: ${r.target.host}

- **Date:** ${r.target.scanned_at}
- **Security Grade:** **${r.grading.letter_grade}** (Score: ${r.grading.overall_score}/100)
- **Status:** ${r.certificate.validity.expiry_status} (${r.certificate.validity.days_remaining} days remaining)
- **Issuer:** ${r.certificate.issuer.common_name} (${r.certificate.issuer.organization || 'N/A'})
- **Valid Until:** ${r.certificate.validity.not_after_formatted}
- **Cipher Suite:** ${r.protocols.active_connection.cipher_name}
- **TLS Protocol:** ${r.protocols.active_connection.tls_version}

## Vulnerability & Exploit Defenses
${(r.vulnerabilities?.vulnerabilities || []).map(v => `- **${v.name}**: ${v.status} (${v.details})`).join('\n')}

## Key Findings & Alerts
${r.alerts.map(a => `- **[${a.severity}] ${a.title}**: ${a.message}\n  *Remediation*: ${a.recommendation}`).join('\n\n')}
`;
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssl-audit-${r.target.host}.md`;
    a.click();
    URL.revokeObjectURL(url);
    this.showToast('Markdown summary exported.', 'success');
  }

  // Add Current Host to Watchlist
  async addCurrentToWatchlist() {
    if (!this.currentReport) return;
    const host = this.currentReport.target.host;
    const port = this.currentReport.target.port;

    try {
      const resp = await fetch('/api/watchlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, port, label: host })
      });
      if (resp.ok) {
        this.showToast(`${host} added to Watchlist!`, 'success');
      }
    } catch (e) {
      this.showToast('Failed to add to watchlist', 'danger');
    }
  }

  // Batch Scanner
  async runBatchScan() {
    const text = document.getElementById('batch-domains-input').value;
    const lines = text.split(/[\n,]+/).map(s => s.trim()).filter(s => s.length > 0);

    if (lines.length === 0) {
      this.showToast('Please enter at least one domain to scan.', 'warning');
      return;
    }

    const btn = document.getElementById('btn-start-batch');
    btn.disabled = true;
    btn.innerHTML = '<span>Scanning Targets...</span> <div class="spinner" style="width: 14px; height: 14px; margin: 0; border-width: 2px;"></div>';

    try {
      const resp = await fetch('/api/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hosts: lines })
      });

      const data = await resp.json();
      this.batchResults = data.results || [];
      this.renderBatchTable(this.batchResults);
      document.getElementById('batch-results-wrapper').style.display = 'block';
      this.showToast(`Batch scan completed for ${data.count} targets.`, 'success');
    } catch (e) {
      this.showToast(`Batch scan error: ${e.message}`, 'danger');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>Run Batch Audit</span> ➔';
    }
  }

  renderBatchTable(results) {
    const tbody = document.getElementById('batch-table-body');
    tbody.innerHTML = '';

    results.forEach(res => {
      const tr = document.createElement('tr');
      const gradeColor = res.grade === 'A+' ? 'var(--color-success)' : (res.grade === 'A' ? '#22c55e' : (res.grade === 'B' || res.grade === 'C' ? 'var(--color-warning)' : 'var(--color-danger)'));
      const statusClass = res.status === 'VALID' ? 'status-valid' : (res.status === 'EXPIRED' ? 'status-critical' : 'status-warning');

      tr.innerHTML = `
        <td class="code-font" style="font-weight: 600;">${res.host}:${res.port}</td>
        <td><strong style="color: ${gradeColor}; font-size: 15px;">${res.grade}</strong></td>
        <td><span class="status-badge ${statusClass}">${res.status || 'ERROR'}</span></td>
        <td>${res.days_remaining !== null && res.days_remaining !== undefined ? `${res.days_remaining} days` : 'N/A'}</td>
        <td style="color: var(--text-secondary);">${res.expires_on || 'N/A'}</td>
        <td style="color: var(--text-secondary);">${res.issuer || (res.error || 'N/A')}</td>
        <td>
          ${res.report ? `<button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick='window.app.viewBatchDetail("${res.host}", ${res.port})'>Inspect</button>` : ''}
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  viewBatchDetail(host, port) {
    const found = this.batchResults.find(r => r.host === host && r.port === port);
    if (found && found.report) {
      this.currentReport = found.report;
      this.renderReport(found.report);
      document.getElementById('nav-btn-single').click();
      document.getElementById('scan-results-wrapper').style.display = 'block';
    }
  }

  exportBatchCsv() {
    if (!this.batchResults.length) return;
    let csv = "Host,Port,Grade,Score,Status,DaysRemaining,ExpiresOn,Issuer\n";
    this.batchResults.forEach(r => {
      csv += `"${r.host}",${r.port},"${r.grade}",${r.score || 0},"${r.status || ''}",${r.days_remaining || ''},"${r.expires_on || ''}","${r.issuer || ''}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ssl-batch-audit-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    this.showToast('Batch CSV exported.', 'success');
  }

  // Watchlist Management
  async loadWatchlist() {
    try {
      const resp = await fetch('/api/watchlist');
      if (resp.ok) {
        this.watchlist = await resp.json();
        this.renderWatchlistTable(this.watchlist);
      }
    } catch (e) {
      console.error(e);
    }
  }

  renderWatchlistTable(items) {
    const tbody = document.getElementById('watchlist-table-body');
    tbody.innerHTML = '';

    if (!items || items.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 24px;">No domains in watchlist yet. Click "Add Domain" to begin monitoring.</td></tr>';
      return;
    }

    items.forEach(item => {
      const tr = document.createElement('tr');
      const grade = item.last_grade || 'N/A';
      const gradeColor = grade.startsWith('A') ? 'var(--color-success)' : (grade === 'F' ? 'var(--color-danger)' : 'var(--color-warning)');
      const statusClass = item.last_status === 'VALID' ? 'status-valid' : (item.last_status === 'EXPIRED' ? 'status-critical' : 'status-warning');

      tr.innerHTML = `
        <td>
          <div style="font-weight: 600;">${item.label || item.host}</div>
          <div class="code-font" style="font-size: 11px; color: var(--text-muted);">${item.host}</div>
        </td>
        <td>${item.port}</td>
        <td><strong style="color: ${gradeColor}; font-size: 14px;">${grade}</strong></td>
        <td><span class="status-badge ${statusClass}">${item.last_status || 'PENDING'}</span></td>
        <td>${item.last_days_remaining !== null && item.last_days_remaining !== undefined ? `${item.last_days_remaining} days` : '-'}</td>
        <td style="color: var(--text-secondary); font-size: 12px;">${item.last_scan ? new Date(item.last_scan).toLocaleString() : 'Never'}</td>
        <td>
          <div style="display: flex; gap: 6px;">
            <button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="window.app.scanSingleWatchlist('${item.host}', ${item.port})">Scan</button>
            <button class="btn-danger-outline" onclick="window.app.deleteWatchlistTarget('${item.id}')">Delete</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  openAddTargetModal() {
    document.getElementById('modal-add-target').classList.add('active');
  }

  closeModal(id) {
    document.getElementById(id).classList.remove('active');
  }

  async submitAddTarget() {
    const host = document.getElementById('target-host-add').value.trim();
    const port = parseInt(document.getElementById('target-port-add').value) || 443;
    const label = document.getElementById('target-label-add').value.trim();

    try {
      const resp = await fetch('/api/watchlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, port, label })
      });

      if (resp.ok) {
        this.closeModal('modal-add-target');
        this.loadWatchlist();
        this.showToast(`Added ${host} to watchlist.`, 'success');
      }
    } catch (e) {
      this.showToast('Failed to save target.', 'danger');
    }
  }

  async deleteWatchlistTarget(id) {
    if (!confirm('Remove this domain from watchlist?')) return;
    try {
      const resp = await fetch(`/api/watchlist/${id}`, { method: 'DELETE' });
      if (resp.ok) {
        this.loadWatchlist();
        this.showToast('Domain removed from watchlist.', 'info');
      }
    } catch (e) {
      this.showToast('Error removing domain.', 'danger');
    }
  }

  async scanAllWatchlist() {
    const btn = document.getElementById('btn-scan-all-watchlist');
    btn.disabled = true;
    btn.textContent = 'Scanning Watchlist...';

    try {
      const resp = await fetch('/api/watchlist/scan', { method: 'POST' });
      if (resp.ok) {
        const res = await resp.json();
        this.loadWatchlist();
        this.showToast(`Scanned ${res.scanned_count} watchlist targets.`, 'success');
      }
    } catch (e) {
      this.showToast('Error scanning watchlist.', 'danger');
    } finally {
      btn.disabled = false;
      btn.textContent = '🔄 Scan All Now';
    }
  }

  scanSingleWatchlist(host, port) {
    document.getElementById('host-input').value = host;
    document.getElementById('port-input').value = port;
    document.getElementById('nav-btn-single').click();
    this.handleSingleScan();
  }

  // Webhooks & Alerts Dispatcher
  async sendTestWebhook() {
    const url = document.getElementById('webhook-url-input').value.trim();
    const type = document.getElementById('webhook-type-select').value;

    if (!url) {
      this.showToast('Please enter a Webhook URL.', 'warning');
      return;
    }

    const reportToSend = this.currentReport || {
      target: { host: "example.com", port: 443 },
      grading: { letter_grade: "A+", overall_score: 95 },
      certificate: { validity: { days_remaining: 85, expiry_status: "VALID", not_after_formatted: "Nov 07, 2026" } },
      chain: { is_trusted: true, is_complete: true }
    };

    const resBox = document.getElementById('webhook-result-box');
    const resText = document.getElementById('webhook-result-text');
    resBox.style.display = 'block';
    resText.textContent = 'Sending payload...';

    try {
      const resp = await fetch('/api/notify/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          webhook_url: url,
          webhook_type: type,
          report: reportToSend
        })
      });

      const data = await resp.json();
      if (data.success) {
        resText.innerHTML = `<span style="color: var(--color-success);">✅ Webhook delivered successfully! (Status: ${data.status_code})</span>`;
        this.showToast('Webhook alert sent!', 'success');
      } else {
        resText.innerHTML = `<span style="color: var(--color-danger);">❌ Webhook delivery failed: ${data.error || 'Check endpoint URL'}</span>`;
        this.showToast('Webhook delivery failed.', 'danger');
      }
    } catch (e) {
      resText.innerHTML = `<span style="color: var(--color-danger);">❌ Error: ${e.message}</span>`;
    }
  }

  async openEmailPreviewModal() {
    const reportToSend = this.currentReport || {
      target: { host: "example.com", port: 443 },
      grading: { letter_grade: "A+", overall_score: 95, grade_color: "#10b981" },
      certificate: { 
        issuer: { common_name: "GTS Root R1", organization: "Google Trust Services" },
        public_key: { description: "ECDSA P-256 (256-bit)" },
        validity: { days_remaining: 85, expiry_status: "VALID", not_after_formatted: "Nov 07, 2026" } 
      },
      chain: { is_trusted: true, is_complete: true }
    };

    try {
      const resp = await fetch('/api/notify/email-preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report: reportToSend })
      });
      const data = await resp.json();
      document.getElementById('email-preview-container').innerHTML = data.html;
      document.getElementById('modal-email-preview').classList.add('active');
    } catch (e) {
      this.showToast('Failed to generate email preview.', 'danger');
    }
  }

  // Toast Helper
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'success') toast.style.borderLeftColor = 'var(--color-success)';
    if (type === 'danger') toast.style.borderLeftColor = 'var(--color-danger)';
    if (type === 'warning') toast.style.borderLeftColor = 'var(--color-warning)';
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }
}

// Global App Instance
window.addEventListener('DOMContentLoaded', () => {
  window.app = new CertGuardApp();
});
