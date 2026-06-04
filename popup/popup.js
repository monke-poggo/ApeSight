// Popup: shows cached results immediately, updates live via storage.onChanged.

import { getTechIconUrl, getTechInitials } from "../detector/tech_icons.js";
import { downloadReport } from "./report_generator.js";

const el = (id) => document.getElementById(id);

const state = {
  result: null,
  tabId: null,
  origin: null,
};

async function init() {
  wireTabs();
  wireButtons();
  wireStorageUpdates();
  await loadResult();
}

function wireStorageUpdates() {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (!state.origin) return;
    const key = "scan_" + state.origin;
    if (changes[key]?.newValue) {
      state.result = changes[key].newValue;
      render();
    }
  });
}

async function loadResult() {
  try {
    const tab = await getCurrentTab();
    if (tab?.url) {
      try {
        state.origin = new URL(tab.url).origin;
        state.tabId = tab.id;
      } catch {}
    }

    // Read directly from storage
    if (state.origin) {
      const key = "scan_" + state.origin;
      try {
        const stored = await chrome.storage.local.get(key);
        if (stored[key]) {
          state.result = stored[key];
          render();
        }
      } catch (e) {
        console.warn("[popup] storage.get error:", e);
      }
    }

    // Dire au background de re-scanner si besoin 
    chrome.runtime.sendMessage({ type: "GET_RESULT" }).then((resp) => {
      if (resp?.result && !state.result) {
        state.result = resp.result;
        render();
      }
    }).catch(() => {});

    // Not an HTTP page
    if (!state.origin || !/^https?:/.test(tab?.url || "")) {
      renderError("Open an HTTP/HTTPS page to scan.");
      return;
    }

    
    if (!state.result) {
      setTimeout(() => {
        if (!state.result) renderEmpty();
      }, 2000);
    }
  } catch (err) {
    console.error(err);
    renderError("Erreur de communication avec l'extension.");
  }
}

async function getCurrentTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

function wireTabs() {
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const panel = document.getElementById(btn.dataset.tab + "-panel");
      if (panel) panel.classList.add("active");
    });
  });
}

function wireButtons() {
  el("rescanBtn").addEventListener("click", async () => {
    el("rescanBtn").classList.add("spinning");
    chrome.runtime.sendMessage({ type: "RESCAN" }).catch(() => {});
    // Don't wait, results will come through storage.onChanged
    setTimeout(() => el("rescanBtn").classList.remove("spinning"), 1200);
  });

  el("exportBtn").addEventListener("click", () => {
    if (!state.result) return;
    const blob = new Blob([JSON.stringify(state.result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `apesight-${safeHost(state.result.url)}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  el("reportBtn").addEventListener("click", async () => {
    if (!state.result) return;
    try {
      await downloadReport(state.result);
    } catch (e) {
      console.error("report error:", e);
    }
  });
}

function render() {
  if (!state.result) {
    renderEmpty();
    return;
  }

  const { url, technologies, vulns, scanning, ts } = state.result;

  // Subtitle: host + cache age (subtle, no intrusive "scanning..." text)
  const age = scanning ? "" : cacheAge(ts);
  el("currentHost").textContent = safeHost(url) + age;

  // Subtle indicator: pulsing dot on header during scan
  updateScanningIndicator(!!scanning);

  const techCount = technologies.length;
  const allVulns = Object.values(vulns).flat();
  const cveCount = allVulns.length;
  const criticalCount = allVulns.filter((v) => v.score >= 9).length;

  el("techCount").textContent = techCount;
  el("cveCount").textContent = cveCount;
  el("criticalCount").textContent = criticalCount;

  el("cveStat").dataset.count = cveCount > 0;
  el("criticalStat").dataset.count = criticalCount > 0;

  renderTechs(technologies);
  renderVulns(vulns);
  renderExploits(vulns);
}

function updateScanningIndicator(scanning) {
  let dot = document.getElementById("scanDot");
  if (!dot) {
    dot = document.createElement("span");
    dot.id = "scanDot";
    dot.className = "scan-dot";
    const rescan = el("rescanBtn");
    rescan.parentNode.insertBefore(dot, rescan);
  }
  dot.hidden = !scanning;
}

function cacheAge(ts) {
  if (!ts) return "";
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return " · just now";
  if (mins < 60) return ` · ago ${mins}min`;
  const hours = Math.floor(mins / 60);
  return ` · ago ${hours}h`;
}

function renderEmpty() {
  el("currentHost").textContent = safeHost(state.result?.url || "") || "—";
  el("techCount").textContent = "0";
  el("cveCount").textContent = "0";
  el("criticalCount").textContent = "0";
  el("techs-list").innerHTML = "";
  el("vulns-list").innerHTML = "";
  el("exploits-list").innerHTML = "";
  el("techs-empty").hidden = false;
  el("techs-empty").textContent = "No technologies detected yet.";
  el("vulns-empty").hidden = false;
  el("vulns-empty").textContent = "No vulnerabilities found yet.";
  el("exploits-empty").hidden = false;
  el("exploits-empty").textContent = "Aucun exploit/PoC disponible.";
}

function renderTechs(technologies) {
  const list = el("techs-list");
  list.innerHTML = "";

  if (technologies.length === 0) {
    el("techs-empty").hidden = false;
    el("techs-empty").textContent = "No technologies detected.";
    return;
  }
  el("techs-empty").hidden = true;

  const sorted = [...technologies].sort((a, b) => {
    if (!a.version && b.version) return 1;
    if (a.version && !b.version) return -1;
    return (a.category || "").localeCompare(b.category || "");
  });

  for (const tech of sorted) {
    const item = document.createElement("div");
    item.className = "tech-item";

    // Icon
    const iconBox = document.createElement("div");
    iconBox.className = "tech-icon";
    const iconUrl = getTechIconUrl(tech.name);
    if (iconUrl) {
      const img = document.createElement("img");
      img.src = iconUrl;
      img.alt = tech.name;
      img.loading = "lazy";
      img.onerror = () => {
        iconBox.classList.add("no-icon");
        iconBox.textContent = getTechInitials(tech.name);
      };
      iconBox.appendChild(img);
    } else {
      iconBox.classList.add("no-icon");
      iconBox.textContent = getTechInitials(tech.name);
    }

    const info = document.createElement("div");
    info.className = "tech-info";
    const name = document.createElement("div");
    name.className = "tech-name";
    name.textContent = tech.name;
    const meta = document.createElement("div");
    meta.className = "tech-meta";
    meta.textContent = `${tech.category || "—"} · ${tech.source || ""}`;
    info.appendChild(name);
    info.appendChild(meta);

    const ver = document.createElement("div");
    ver.className = "tech-version";
    if (tech.version) {
      ver.textContent = tech.version;
    } else {
      ver.textContent = "N/A";
      ver.classList.add("no-version");
    }

    item.appendChild(iconBox);
    item.appendChild(info);
    item.appendChild(ver);
    list.appendChild(item);
  }
}

function renderVulns(vulnsByTech) {
  const list = el("vulns-list");
  list.innerHTML = "";

  const entries = Object.entries(vulnsByTech);
  if (entries.length === 0) {
    el("vulns-empty").hidden = false;
    el("vulns-empty").textContent = "No known vulnerabilities.";
    return;
  }
  el("vulns-empty").hidden = true;

  entries.sort((a, b) => {
    const ca = a[1].filter((v) => v.score >= 9).length;
    const cb = b[1].filter((v) => v.score >= 9).length;
    return cb - ca;
  });

  for (const [techKey, vulns] of entries) {
    const [name, version] = techKey.split("|");
    const group = document.createElement("div");
    group.className = "vuln-group";

    const header = document.createElement("div");
    header.className = "vuln-group-header";

    const titleWrap = document.createElement("div");
    titleWrap.className = "vuln-group-title-wrap";

    // Tech icon
    const iconBox = document.createElement("div");
    iconBox.className = "vuln-group-icon";
    const iconUrl = getTechIconUrl(name);
    if (iconUrl) {
      const img = document.createElement("img");
      img.src = iconUrl;
      img.alt = name;
      img.loading = "lazy";
      img.onerror = () => { iconBox.textContent = getTechInitials(name); };
      iconBox.appendChild(img);
    } else {
      iconBox.textContent = getTechInitials(name);
    }

    const title = document.createElement("div");
    title.className = "vuln-group-title";
    title.textContent = version ? `${name} ${version}` : name;

    titleWrap.appendChild(iconBox);
    titleWrap.appendChild(title);

    const count = document.createElement("div");
    count.className = "vuln-group-count";
    count.textContent = String(vulns.length);

    header.appendChild(titleWrap);
    header.appendChild(count);

    const items = document.createElement("div");
    items.className = "vuln-items";

    for (const v of vulns.slice(0, 15)) {
      const row = document.createElement("div");
      row.className = "vuln-item";
      const sevClass = severityClass(v.score);

      const badge = document.createElement("div");
      badge.className = `severity-badge severity-${sevClass}`;
      badge.textContent = severityLabel(v.score);

      const body = document.createElement("div");
      body.className = "vuln-body";

      const headerRow = document.createElement("div");
      headerRow.className = "vuln-header-row";

      const link = document.createElement("a");
      link.className = "vuln-id";
      link.href = v.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = v.cve || v.id;

      const src = document.createElement("span");
      src.className = "vuln-source";
      src.textContent = v.source || "";

      headerRow.appendChild(link);
      headerRow.appendChild(src);

      const summary = document.createElement("div");
      summary.className = "vuln-summary";
      summary.textContent = v.summary || "";

      body.appendChild(headerRow);
      body.appendChild(summary);

      row.appendChild(badge);
      row.appendChild(body);
      items.appendChild(row);
    }

    group.appendChild(header);
    group.appendChild(items);
    list.appendChild(group);
  }
}

function renderExploits(vulnsByTech) {
  const list = el("exploits-list");
  list.innerHTML = "";

  const allVulns = Object.values(vulnsByTech).flat();
  if (allVulns.length === 0) {
    el("exploits-empty").hidden = false;
    return;
  }
  el("exploits-empty").hidden = true;

  // Sort by severity (most critical first)
  const sorted = [...allVulns].sort((a, b) => (b.score || 0) - (a.score || 0));

  // Render progressively - don't block the UI
  let index = 0;
  const BATCH_SIZE = 3;

  // Show loading indicator
  const loader = document.createElement("div");
  loader.className = "exploits-loader";
  loader.textContent = "Recherche des PoC/exploits...";
  list.appendChild(loader);

  function renderBatch() {
    if (index >= sorted.length) {
      loader.remove();
      if (list.children.length === 0) {
        el("exploits-empty").hidden = false;
      }
      return;
    }

    const end = Math.min(index + BATCH_SIZE, sorted.length);
    for (let i = index; i < end; i++) {
      const v = sorted[i];
      const cveId = v.cve || v.id;
      if (!cveId) continue;

      const item = document.createElement("div");
      item.className = "exploit-item";

      // Severity badge
      const badge = document.createElement("div");
      badge.className = `severity-badge severity-${severityClass(v.score)}`;
      badge.textContent = severityLabel(v.score);

      // Content
      const content = document.createElement("div");
      content.className = "exploit-content";

      const header = document.createElement("div");
      header.className = "exploit-header";
      header.textContent = cveId;

      const summary = document.createElement("div");
      summary.className = "exploit-summary";
      summary.textContent = (v.summary || "").slice(0, 100);

      // Links container - populated async
      const links = document.createElement("div");
      links.className = "exploit-links";

      // Static links (instant, no fetch needed)
      const staticLinks = getExploitLinks(cveId);
      for (const link of staticLinks) {
        const a = document.createElement("a");
        a.href = link.url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.className = "exploit-link " + link.type;
        a.textContent = link.label;
        links.appendChild(a);
      }

      content.appendChild(header);
      content.appendChild(summary);
      content.appendChild(links);

      item.appendChild(badge);
      item.appendChild(content);

      // Insert before loader
      list.insertBefore(item, loader);

      // Async: check if PoC-in-GitHub actually exists (non-blocking)
      checkPocExists(cveId, links);
    }

    index = end;
    // Update loader text
    loader.textContent = `Chargement... (${index}/${sorted.length})`;

    // Schedule next batch with requestAnimationFrame for smooth rendering
    requestAnimationFrame(() => setTimeout(renderBatch, 50));
  }

  // Start first batch on next frame
  requestAnimationFrame(renderBatch);
}

/**
 * Async check if a PoC repo exists on GitHub for this CVE 
 * Adds check mark if true
 */
async function checkPocExists(cveId, linksContainer) {
  if (!cveId.startsWith("CVE-")) return;
  try {
    const resp = await fetch(
      `https://api.github.com/search/repositories?q=${encodeURIComponent(cveId)}+poc&per_page=1`,
      { headers: { Accept: "application/vnd.github+json" } }
    );
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.total_count > 0) {
      const badge = document.createElement("a");
      badge.href = data.items[0].html_url;
      badge.target = "_blank";
      badge.rel = "noopener noreferrer";
      badge.className = "exploit-link poc-verified";
      badge.textContent = `✓ PoC (${data.total_count} repo${data.total_count > 1 ? "s" : ""})`;
      linksContainer.prepend(badge);
    }
  } catch (_) {
    // Silently fail - non-critical
  }
}

/**
 * feature in dev... plz do not bully
 * Generate exploit/PoC links for a given CVE ID.
 */
function getExploitLinks(cveId) {
  const links = [];
  const encoded = encodeURIComponent(cveId);

  // GitHub PoC search
  links.push({
    label: "GitHub PoC",
    url: `https://github.com/search?q=${encoded}+poc&type=repositories`,
    type: "github",
  });

  
  if (cveId.startsWith("CVE-")) {
    const year = cveId.split("-")[1];
    links.push({
      label: "PoC-in-GitHub",
      url: `https://github.com/nomi-sec/PoC-in-GitHub/blob/master/${year}/${cveId}.json`,
      type: "github",
    });
  }

  // ExploitDB
  links.push({
    label: "ExploitDB",
    url: `https://www.exploit-db.com/search?cve=${cveId.replace("CVE-", "")}`,
    type: "exploitdb",
  });

  // Nuclei templates
  links.push({
    label: "Nuclei",
    url: `https://github.com/projectdiscovery/nuclei-templates/search?q=${encoded}`,
    type: "nuclei",
  });

  // PacketStorm
  links.push({
    label: "PacketStorm",
    url: `https://packetstormsecurity.com/search/?q=${encoded}`,
    type: "packetstorm",
  });

  // NVD references (often contain PoC links)
  if (cveId.startsWith("CVE-")) {
    links.push({
      label: "NVD Refs",
      url: `https://nvd.nist.gov/vuln/detail/${cveId}#vulnTechnicalDetailsDiv`,
      type: "nvd",
    });
  }

  return links;
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "";
  }
}

function severityClass(score) {
  if (!score) return "none";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function severityLabel(score) {
  if (!score) return "—";
  return score.toFixed(1);
}

function renderError(message) {
  el("currentHost").textContent = message;
  el("techs-empty").hidden = false;
  el("vulns-empty").hidden = false;
  el("techs-empty").textContent = message;
  el("vulns-empty").textContent = "";
}

init();
