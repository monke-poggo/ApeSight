
import { getTechIconUrl, getTechInitials } from "../detector/tech_icons.js";
let APE_LOGO_DATA_URI = null;

async function loadApeLogoDataUri() {
  if (APE_LOGO_DATA_URI) return APE_LOGO_DATA_URI;
  try {
    const resp = await fetch(chrome.runtime.getURL("icons/icon128.png"));
    const blob = await resp.blob();
    APE_LOGO_DATA_URI = await new Promise((resolve) => {
      const reader = new FileReader();
      reader.onloadend = () => resolve(reader.result);
      reader.readAsDataURL(blob);
    });
  } catch {
    APE_LOGO_DATA_URI = "";
  }
  return APE_LOGO_DATA_URI;
}

/**
 * Generates the HTML report (async because it needs to embed the logo as data URI).
 */
export async function generateReportHTML(result) {
  const logo = await loadApeLogoDataUri();
  const now = new Date();
  const dateStr = now.toLocaleDateString("fr-FR");
  const timeStr = now.toLocaleTimeString("fr-FR");
  const host = safeHost(result.url);

  const allVulns = Object.values(result.vulns || {}).flat();
  const critCount = allVulns.filter((v) => v.score >= 9).length;
  const highCount = allVulns.filter((v) => v.score >= 7 && v.score < 9).length;
  const medCount = allVulns.filter((v) => v.score >= 4 && v.score < 7).length;
  const lowCount = allVulns.filter((v) => v.score > 0 && v.score < 4).length;

  const rating = computeRating(critCount, highCount, medCount);
  const techsByCategory = groupByCategory(result.technologies || []);

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport ApeSight - ${escapeHtml(host)}</title>
<link rel="icon" href="${logo}">
<style>${getStyles()}</style>
</head>
<body>
  ${renderTopBar(logo)}
  ${renderHero(logo, host, dateStr, timeStr, rating)}

  <main class="container">
    ${renderSummaryCard(result, host, dateStr, allVulns, rating)}
    ${renderStatsGrid(result.technologies?.length || 0, allVulns.length, critCount, highCount)}
    ${renderTechnologiesSection(techsByCategory, result.vulns || {})}
    ${renderIssuesSection(result.vulns || {})}
  </main>

  ${renderFooter(logo)}
</body>
</html>`;
}

/**
 * Downloads the HTML report.
 */
export async function downloadReport(result) {
  const html = await generateReportHTML(result);
  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const host = safeHost(result.url);
  const date = new Date().toISOString().slice(0, 10);
  const a = document.createElement("a");
  a.href = url;
  a.download = `apesight-${host}-${date}.html`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// --- Sections ---

function renderTopBar(logo) {
  return `
  <nav class="topbar">
    <div class="topbar-inner">
      <div class="topbar-brand">
        <img src="${logo}" alt="ApeSight" class="topbar-logo" />
        <span class="topbar-title">ApeSight</span>
        <span class="topbar-sep"></span>
        <span class="topbar-tagline">Security Report</span>
      </div>
      <div class="topbar-actions">
        <button class="btn-ghost" onclick="window.print()">Print</button>
      </div>
    </div>
  </nav>`;
}

function renderHero(logo, host, dateStr, timeStr, rating) {
  const ratingColor = getRatingColor(rating);
  const ratingLabel = getRatingLabel(rating);

  return `
  <header class="hero">
    <div class="hero-inner">
      <div class="hero-left">
        <div class="hero-badge">
          <img src="${logo}" alt="ApeSight" class="hero-logo" />
          <div class="hero-badge-text">
            <div class="hero-brand">ApeSight</div>
            <div class="hero-brand-sub">Application Security Report</div>
          </div>
        </div>
        <h1 class="hero-title">${escapeHtml(host)}</h1>
        <div class="hero-meta">
          <span class="hero-date-chip">${dateStr} · ${timeStr}</span>
        </div>
      </div>

      <div class="hero-rating">
        <div class="rating-large" style="background:${ratingColor}">${rating}</div>
        <div class="rating-label">${ratingLabel}</div>
      </div>
    </div>
  </header>`;
}

function renderSummaryCard(result, host, dateStr, allVulns, rating) {
  const techCount = (result.technologies || []).length;
  const cveCount = allVulns.length;
  const tags = extractTags(host);
  const tagsHtml = tags.map((t) => `<span class="chip chip-blue">${escapeHtml(t)}</span>`).join("");
  const versionedTechs = (result.technologies || []).filter((t) => t.version).length;

  return `
  <section class="card card-summary">
    <div class="card-header">
      <h2 class="card-title">
        <span class="title-accent"></span>
        Analysis Summary
      </h2>
    </div>
    <div class="card-body">
      <table class="kv-table">
        <tr>
          <td class="kv-label">Web Application</td>
          <td><a href="${escapeHtml(result.url)}" target="_blank" class="link-primary">${escapeHtml(result.url)}</a></td>
        </tr>
        <tr>
          <td class="kv-label">Tags</td>
          <td>${tagsHtml || '<span class="muted">—</span>'}</td>
        </tr>
        <tr>
          <td class="kv-label">Scan Date</td>
          <td>${dateStr}</td>
        </tr>
        <tr>
          <td class="kv-label">HTTP Status</td>
          <td><span class="chip chip-green">${result.status || 200}</span></td>
        </tr>
        <tr>
          <td class="kv-label">Detected Technologies</td>
          <td><strong>${techCount}</strong> <span class="muted">of which ${versionedTechs} with version</span></td>
        </tr>
        <tr>
          <td class="kv-label">Vulnerabilities (CVE)</td>
          <td><strong>${cveCount}</strong></td>
        </tr>
      </table>
    </div>
  </section>`;
}

function renderStatsGrid(techCount, cveCount, critCount, highCount) {
  return `
  <section class="stats-grid">
    <div class="stat-card">
      <div class="stat-icon stat-icon-blue">◆</div>
      <div class="stat-value">${techCount}</div>
      <div class="stat-label">Technologies</div>
    </div>
    <div class="stat-card ${cveCount > 0 ? 'stat-card-warning' : ''}">
      <div class="stat-icon stat-icon-gold">▲</div>
      <div class="stat-value">${cveCount}</div>
      <div class="stat-label">CVEs Found</div>
    </div>
    <div class="stat-card ${critCount > 0 ? 'stat-card-critical' : ''}">
      <div class="stat-icon stat-icon-red">●</div>
      <div class="stat-value">${critCount}</div>
      <div class="stat-label">Criticals</div>
    </div>
    <div class="stat-card ${highCount > 0 ? 'stat-card-warning' : ''}">
      <div class="stat-icon stat-icon-orange">■</div>
      <div class="stat-value">${highCount}</div>
      <div class="stat-label">High</div>
    </div>
  </section>`;
}

function renderTechnologiesSection(techsByCategory, vulnsByKey) {
  const cvesByTechName = {};
  for (const [key, vulns] of Object.entries(vulnsByKey)) {
    const name = key.split("|")[0];
    cvesByTechName[name] = (cvesByTechName[name] || 0) + vulns.length;
  }

  const categoryOrder = [
    "Server", "Application Server", "Runtime", "Web Framework", "Framework",
    "JS Framework", "JS Library", "Build Tool", "UI Framework", "CSS Framework",
    "CMS", "E-commerce", "Analytics", "Monitoring", "Consent Management",
    "CDN", "Cloud Storage", "PaaS", "Font", "Payment", "Security", "Live Chat", "Misc",
  ];

  const sorted = categoryOrder
    .filter((cat) => techsByCategory[cat])
    .concat(Object.keys(techsByCategory).filter((c) => !categoryOrder.includes(c)));

  let cards = "";
  for (const category of sorted) {
    const techs = techsByCategory[category];
    if (!techs || techs.length === 0) continue;

    const techItems = techs.map((t) => {
      const iconUrl = getTechIconUrl(t.name, false);
      const version = t.version
        ? `<span class="tech-version">${escapeHtml(t.version)}</span>`
        : "";
      const cveCount = cvesByTechName[t.name] || 0;
      const cveBadge = cveCount > 0
        ? `<span class="tech-cve-badge">${cveCount} CVE</span>`
        : "";
      const iconHtml = iconUrl
        ? `<img src="${iconUrl}" alt="" class="tech-icon-img" onerror="this.style.display='none';this.nextElementSibling.style.display='flex';">
           <span class="tech-initials" style="display:none">${getTechInitials(t.name)}</span>`
        : `<span class="tech-initials">${getTechInitials(t.name)}</span>`;

      return `
        <div class="tech-item">
          <div class="tech-icon">${iconHtml}</div>
          <div class="tech-info">
            <div class="tech-name">${escapeHtml(t.name)}</div>
            <div class="tech-source">${escapeHtml(t.source || "")}</div>
          </div>
          ${version}
          ${cveBadge}
        </div>`;
    }).join("");

    cards += `
      <div class="tech-category">
        <h4 class="category-title">${escapeHtml(category)}</h4>
        <div class="tech-list">${techItems}</div>
      </div>`;
  }

  return `
  <section class="card">
    <div class="card-header">
      <h2 class="card-title">
        <span class="title-accent"></span>
        Detected Technologies
      </h2>
    </div>
    <div class="card-body">
      <div class="tech-grid">
        ${cards || '<p class="muted">No technologies detected.</p>'}
      </div>
    </div>
  </section>`;
}

function renderIssuesSection(vulnsByKey) {
  const allVulns = [];
  for (const [key, vulns] of Object.entries(vulnsByKey)) {
    const [techName, version] = key.split("|");
    for (const v of vulns) {
      allVulns.push({ ...v, techName, techVersion: version });
    }
  }

  if (allVulns.length === 0) {
    return `
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">
          <span class="title-accent"></span>
          Vulnerabilities
        </h2>
      </div>
      <div class="card-body">
        <div class="empty-state">
          <div class="empty-icon">✓</div>
          <p><strong>No vulnerabilities detected</strong></p>
          <p class="muted">No known CVEs affect the detected versions.</p>
        </div>
      </div>
    </section>`;
  }

  allVulns.sort((a, b) => (b.score || 0) - (a.score || 0));

  const critCount = allVulns.filter((v) => v.score >= 9).length;
  const highCount = allVulns.filter((v) => v.score >= 7 && v.score < 9).length;
  const medCount = allVulns.filter((v) => v.score >= 4 && v.score < 7).length;
  const lowCount = allVulns.filter((v) => v.score > 0 && v.score < 4).length;

  const rows = allVulns.map((v) => {
    const sev = severityLabel(v.score);
    const sevClass = severityClass(v.score);
    const cveId = v.cve || v.id;
    const tech = v.techVersion ? `${v.techName} ${v.techVersion}` : v.techName;
    const score = v.score ? v.score.toFixed(1) : "—";
    return `
      <tr>
        <td><span class="sev-pill sev-${sevClass}">${sev}</span></td>
        <td><a href="${escapeHtml(v.url)}" target="_blank" class="cve-link">${escapeHtml(cveId)}</a></td>
        <td>${escapeHtml(tech)}</td>
        <td class="num">${score}</td>
        <td><span class="source-badge">${escapeHtml(v.source || "")}</span></td>
        <td class="summary-cell">${escapeHtml((v.summary || "").slice(0, 140))}</td>
      </tr>`;
  }).join("");

  return `
  <section class="card">
    <div class="card-header">
      <h2 class="card-title">
        <span class="title-accent"></span>
        Identified Vulnerabilities
      </h2>
    </div>
    <div class="card-body">
      <table class="severity-summary">
        <thead>
          <tr>
            <th>Severity</th>
            <th class="num-col">Total</th>
          </tr>
        </thead>
        <tbody>
          <tr><td><span class="sev-pill sev-critical">Critical</span></td><td class="num">${critCount}</td></tr>
          <tr><td><span class="sev-pill sev-high">High</span></td><td class="num">${highCount}</td></tr>
          <tr><td><span class="sev-pill sev-medium">Medium</span></td><td class="num">${medCount}</td></tr>
          <tr><td><span class="sev-pill sev-low">Low</span></td><td class="num">${lowCount}</td></tr>
        </tbody>
      </table>

      <h3 class="subsection-title">Liste des CVE</h3>
      <table class="issues-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>CVE / ID</th>
            <th>Technologie</th>
            <th>CVSS</th>
            <th>Source</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </section>`;
}

function renderFooter(logo) {
  return `
  <footer class="footer">
    <div class="footer-inner">
      <div class="footer-brand">
        <img src="${logo}" alt="ApeSight" class="footer-logo" />
        <span>ApeSight · Sources: OSV.dev, GitHub Advisories</span>
      </div>
      <div class="footer-right">Confidential</div>
    </div>
  </footer>`;
}

// --- Helpers ---

function groupByCategory(techs) {
  const map = {};
  for (const t of techs) {
    const cat = t.category || "Misc";
    map[cat] = map[cat] || [];
    map[cat].push(t);
  }
  for (const cat of Object.keys(map)) {
    map[cat].sort((a, b) => {
      if (a.version && !b.version) return -1;
      if (!a.version && b.version) return 1;
      return a.name.localeCompare(b.name);
    });
  }
  return map;
}

function extractTags(host) {
  const tags = [];
  try {
    const parts = host.split(".");
    if (parts.length >= 2) tags.push(parts.slice(-2).join("."));
    if (parts.length > 2) tags.push(parts[0]);
  } catch {}
  return tags;
}

function computeRating(critical, high, medium) {
  if (critical > 0) return "F";
  if (high > 2) return "D";
  if (high > 0) return "C";
  if (medium > 0) return "B";
  return "A";
}

function getRatingColor(rating) {
  return {
    "A": "#16A34A",
    "B": "#65A30D",
    "C": "#D97706",
    "D": "#EA580C",
    "F": "#DC2626",
  }[rating] || "#78716C";
}

function getRatingLabel(rating) {
  return {
    "A": "Excellent",
    "B": "Acceptable",
    "C": "Needs Attention",
    "D": "Degraded",
    "F": "Critical",
  }[rating] || "";
}

function severityLabel(score) {
  if (!score) return "None";
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

function severityClass(score) {
  if (!score) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function safeHost(url) {
  try { return new URL(url).hostname; } catch { return url || ""; }
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// --- ApeSight styles ---

function getStyles() {
  return `
  :root {
    /* Palette ApeSight */
    --ape-blue: #4F46E5;
    --ape-blue-dark: #3730A3;
    --ape-blue-darker: #1E1B4B;
    --ape-blue-light: #6366F1;
    --ape-gold: #F59E0B;
    --ape-gold-dark: #D97706;

    /* Neutrals */
    --bg: #FAFAF9;
    --bg-card: #FFFFFF;
    --bg-subtle: #F5F5F4;
    --text: #1C1917;
    --text-muted: #57534E;
    --text-dim: #78716C;
    --border: #E7E5E4;
    --border-strong: #D6D3D1;

    /* Severities */
    --critical: #DC2626;
    --high: #EA580C;
    --medium: #D97706;
    --low: #16A34A;

    --shadow-sm: 0 1px 2px rgba(28, 25, 23, 0.04);
    --shadow: 0 4px 12px rgba(28, 25, 23, 0.07);
    --shadow-lg: 0 8px 24px rgba(28, 25, 23, 0.1);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  html, body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  a { color: var(--ape-blue); text-decoration: none; }
  a:hover { text-decoration: underline; }
  strong { font-weight: 700; }

  /* --- Topbar (fine barre de navigation sombre) --- */
  .topbar {
    background: linear-gradient(90deg, var(--ape-blue-darker) 0%, var(--ape-blue-dark) 100%);
    color: white;
    height: 56px;
    display: flex;
    align-items: center;
    box-shadow: var(--shadow-sm);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .topbar-inner {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 32px;
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .topbar-brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .topbar-logo {
    width: 32px;
    height: 32px;
    border-radius: 6px;
    background: white;
    padding: 3px;
    object-fit: contain;
  }
  .topbar-title {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: -0.01em;
  }
  .topbar-sep {
    width: 1px;
    height: 20px;
    background: rgba(255,255,255,0.25);
  }
  .topbar-tagline {
    font-size: 12px;
    color: rgba(255,255,255,0.75);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .btn-ghost {
    background: rgba(255,255,255,0.1);
    border: 1px solid rgba(255,255,255,0.2);
    color: white;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
    font-family: inherit;
  }
  .btn-ghost:hover { background: rgba(255,255,255,0.2); }

  /* --- Hero (bandeau principal avec logo + rating) --- */
  .hero {
    background: linear-gradient(135deg, var(--ape-blue) 0%, var(--ape-blue-dark) 60%, var(--ape-blue-darker) 100%);
    color: white;
    padding: 40px 32px;
    position: relative;
    overflow: hidden;
    border-bottom: 4px solid var(--ape-gold);
  }
  .hero::before {
    content: "";
    position: absolute;
    top: -50%; right: -10%;
    width: 500px; height: 500px;
    background: radial-gradient(circle, rgba(245,158,11,0.15) 0%, transparent 60%);
    pointer-events: none;
  }
  .hero-inner {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 40px;
    position: relative;
  }
  .hero-left { flex: 1; min-width: 0; }
  .hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.15);
    padding: 8px 16px 8px 8px;
    border-radius: 999px;
    margin-bottom: 16px;
  }
  .hero-logo {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: white;
    padding: 3px;
    object-fit: contain;
  }
  .hero-badge-text { line-height: 1.2; }
  .hero-brand {
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 0.02em;
  }
  .hero-brand-sub {
    font-size: 11px;
    color: rgba(255,255,255,0.75);
  }
  .hero-title {
    font-size: 36px;
    font-weight: 800;
    letter-spacing: -0.02em;
    word-break: break-word;
    margin-bottom: 10px;
  }
  .hero-meta {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .hero-date-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: var(--ape-gold);
    color: var(--ape-blue-darker);
    padding: 5px 12px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.03em;
  }

  .hero-rating {
    text-align: center;
    flex-shrink: 0;
  }
  .rating-large {
    width: 100px;
    height: 100px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
    font-size: 56px;
    font-weight: 900;
    letter-spacing: -0.04em;
    box-shadow: var(--shadow-lg), 0 0 0 4px rgba(255,255,255,0.15);
    margin-bottom: 10px;
  }
  .rating-label {
    color: rgba(255,255,255,0.9);
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.04em;
  }

  /* --- Container --- */
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px;
  }

  /* --- Card --- */
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 24px;
    overflow: hidden;
    box-shadow: var(--shadow-sm);
  }
  .card-header {
    padding: 18px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-card);
  }
  .card-title {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 16px;
    font-weight: 700;
    color: var(--ape-blue-darker);
  }
  .title-accent {
    display: inline-block;
    width: 4px;
    height: 20px;
    background: var(--ape-gold);
    border-radius: 2px;
  }
  .card-body {
    padding: 20px 24px;
  }

  /* --- Summary KV table --- */
  .kv-table {
    width: 100%;
    border-collapse: collapse;
  }
  .kv-table td {
    padding: 10px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    vertical-align: top;
  }
  .kv-table tr:last-child td { border-bottom: none; }
  .kv-label {
    font-weight: 600;
    color: var(--text-muted);
    width: 200px;
  }
  .link-primary { color: var(--ape-blue); font-weight: 500; word-break: break-all; }

  .chip {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.02em;
    margin-right: 4px;
  }
  .chip-blue { background: var(--ape-blue); color: white; }
  .chip-green { background: #DCFCE7; color: #166534; border: 1px solid #BBF7D0; }

  /* --- Stats grid --- */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    box-shadow: var(--shadow-sm);
    position: relative;
    overflow: hidden;
  }
  .stat-card::after {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--ape-gold);
  }
  .stat-card-warning::after { background: var(--high); }
  .stat-card-critical::after { background: var(--critical); }

  .stat-icon {
    font-size: 22px;
    font-weight: 700;
    line-height: 1;
  }
  .stat-icon-blue { color: var(--ape-blue); }
  .stat-icon-gold { color: var(--ape-gold-dark); }
  .stat-icon-red { color: var(--critical); }
  .stat-icon-orange { color: var(--high); }

  .stat-value {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -0.03em;
    line-height: 1;
    color: var(--ape-blue-darker);
  }
  .stat-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  /* --- Technologies grid --- */
  .tech-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 24px 32px;
  }
  .tech-category { break-inside: avoid; }
  .category-title {
    font-size: 11px;
    font-weight: 700;
    color: var(--ape-blue-dark);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 2px solid var(--ape-gold);
    display: inline-block;
  }
  .tech-list {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .tech-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 0;
    border-bottom: 1px dashed var(--border);
  }
  .tech-item:last-child { border-bottom: none; }

  .tech-icon {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 5px;
    flex-shrink: 0;
    overflow: hidden;
  }
  .tech-icon-img { max-width: 100%; max-height: 100%; object-fit: contain; }
  .tech-initials {
    font-size: 10px;
    font-weight: 700;
    color: var(--ape-blue);
  }

  .tech-info { flex: 1; min-width: 0; }
  .tech-name {
    font-size: 13px;
    color: var(--text);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tech-source {
    font-size: 10px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .tech-version {
    background: var(--bg-subtle);
    color: var(--ape-blue);
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-weight: 700;
    border: 1px solid var(--border);
    flex-shrink: 0;
  }
  .tech-cve-badge {
    background: var(--critical);
    color: white;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 10px;
    font-weight: 700;
    flex-shrink: 0;
  }

  /* --- Empty state --- */
  .empty-state {
    text-align: center;
    padding: 40px 20px;
  }
  .empty-icon {
    display: inline-block;
    width: 56px;
    height: 56px;
    line-height: 56px;
    border-radius: 50%;
    background: #DCFCE7;
    color: #15803D;
    font-size: 28px;
    font-weight: 800;
    margin-bottom: 12px;
  }

  /* --- Issues tables --- */
  .severity-summary,
  .issues-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 24px;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    font-size: 12.5px;
  }
  .severity-summary th,
  .issues-table th {
    background: var(--ape-blue-darker);
    color: white;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 12px 14px;
    text-align: left;
  }
  .severity-summary td,
  .issues-table td {
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  .severity-summary tr:last-child td,
  .issues-table tr:last-child td { border-bottom: none; }
  .issues-table tr:hover td { background: var(--bg-subtle); }

  .num { font-family: ui-monospace, monospace; font-weight: 600; text-align: center; }
  .num-col { text-align: center; }
  .summary-cell { color: var(--text-muted); font-size: 12px; max-width: 400px; }
  .cve-link { font-family: ui-monospace, monospace; font-size: 12px; font-weight: 700; }
  .source-badge {
    background: var(--bg-subtle);
    color: var(--text-muted);
    border: 1px solid var(--border);
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    padding: 3px 7px;
    border-radius: 3px;
  }

  .subsection-title {
    font-size: 14px;
    font-weight: 700;
    color: var(--ape-blue-darker);
    margin: 24px 0 12px;
    padding-left: 10px;
    border-left: 4px solid var(--ape-gold);
  }

  /* --- Severity pills --- */
  .sev-pill {
    display: inline-block;
    min-width: 72px;
    padding: 4px 10px;
    color: white;
    font-weight: 700;
    font-size: 11px;
    text-align: center;
    border-radius: 4px;
    letter-spacing: 0.02em;
    text-transform: uppercase;
  }
  .sev-critical { background: var(--critical); }
  .sev-high { background: var(--high); }
  .sev-medium { background: var(--medium); }
  .sev-low { background: var(--low); }
  .sev-none { background: #94a3b8; }

  /* --- Footer --- */
  .footer {
    margin-top: 40px;
    background: var(--ape-blue-darker);
    color: white;
    padding: 24px 32px;
    border-top: 4px solid var(--ape-gold);
  }
  .footer-inner {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    font-size: 12px;
  }
  .footer-brand {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .footer-logo {
    width: 28px;
    height: 28px;
    border-radius: 5px;
    background: white;
    padding: 3px;
    object-fit: contain;
  }
  .footer-right {
    color: rgba(255,255,255,0.7);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }

  .muted { color: var(--text-dim); }

  /* --- Print --- */
  @media print {
    body { font-size: 11px; background: white; }
    .topbar { display: none; }
    .hero { padding: 24px; break-inside: avoid; }
    .hero-title { font-size: 26px; }
    .rating-large { width: 70px; height: 70px; font-size: 40px; }
    .container { padding: 20px; }
    .tech-grid { grid-template-columns: repeat(2, 1fr); gap: 16px 24px; }
    .card, .stat-card, .tech-category { break-inside: avoid; }
    .stats-grid { grid-template-columns: repeat(4, 1fr); }
    .btn-ghost { display: none; }
  }

  /* --- Responsive --- */
  @media (max-width: 900px) {
    .hero-inner { flex-direction: column; align-items: flex-start; }
    .hero-title { font-size: 28px; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
    .tech-grid { grid-template-columns: 1fr; }
    .container, .topbar-inner, .hero-inner, .footer-inner { padding: 0 16px; }
    .hero { padding: 30px 16px; }
    .container { padding: 24px 16px; }
  }
  `;
}
