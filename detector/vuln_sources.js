// Vulnerability sources: OSV.dev and GitHub Security Advisories.
// In-memory cache (service worker) + chrome.storage.local.

import { TECH_TO_NPM } from "./detector.js";

const CACHE_TTL_MS = 24 * 3600 * 1000;

const TECH_TO_GHSA = {
  "Next.js": ["npm", "next"],
  "React": ["npm", "react"],
  "Vue.js": ["npm", "vue"],
  "Angular": ["npm", "@angular/core"],
  "jQuery": ["npm", "jquery"],
  "Bootstrap": ["npm", "bootstrap"],
  "Express": ["npm", "express"],
  "webpack": ["npm", "webpack"],
  "styled-components": ["npm", "styled-components"],
  "Emotion": ["npm", "@emotion/react"],
  "core-js": ["npm", "core-js"],
  "Laravel": ["composer", "laravel/framework"],
  "Django": ["pip", "django"],
  "WordPress": ["composer", "wordpress/wordpress"],
  "Drupal": ["composer", "drupal/core"],
};

export async function lookupVulns(tech) {
  if (!tech.version) return [];

  const cacheKey = `vuln:${tech.name}:${tech.version}`;
  const cached = await getCache(cacheKey);
  if (cached) return cached;

  const [osv, ghsa] = await Promise.all([
    queryOSV(tech),
    queryGHSA(tech),
  ]);

  const merged = deduplicate([...osv, ...ghsa]);
  await setCache(cacheKey, merged);
  return merged;
}

async function queryOSV(tech) {
  const npmName = TECH_TO_NPM[tech.name];
  if (!npmName) return [];

  try {
    const resp = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version: tech.version,
        package: { name: npmName, ecosystem: "npm" },
      }),
    });
    if (!resp.ok) return [];
    const data = await resp.json();
    return (data.vulns || []).map((v) => {
      const aliases = v.aliases || [];
      const cve = aliases.find((a) => a.startsWith("CVE-")) || "";
      const severity = (v.severity || []).find((s) => s.type === "CVSS_V3")?.score || "";
      return {
        id: v.id,
        cve,
        summary: v.summary || (v.details || "").slice(0, 200),
        severity,
        score: parseCvssScore(severity),
        published: (v.published || "").slice(0, 10),
        url: cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : `https://osv.dev/vulnerability/${v.id}`,
        source: "OSV",
      };
    });
  } catch (_) {
    return [];
  }
}

async function queryGHSA(tech) {
  const mapping = TECH_TO_GHSA[tech.name];
  if (!mapping) return [];
  const [ecosystem, pkg] = mapping;

  try {
    const url = new URL("https://api.github.com/advisories");
    url.searchParams.set("ecosystem", ecosystem);
    url.searchParams.set("affects", `${pkg}@${tech.version}`);
    url.searchParams.set("per_page", "50");

    const resp = await fetch(url.toString(), {
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!resp.ok) return [];
    const data = await resp.json();

    return data.map((adv) => ({
      id: adv.ghsa_id,
      cve: adv.cve_id || "",
      summary: (adv.summary || "").slice(0, 200),
      severity: adv.cvss?.score ? String(adv.cvss.score) : adv.severity,
      score: adv.cvss?.score || severityFromString(adv.severity),
      published: (adv.published_at || "").slice(0, 10),
      url: adv.html_url,
      source: "GHSA",
    }));
  } catch (_) {
    return [];
  }
}

function deduplicate(vulns) {
  const seen = new Map();
  for (const v of vulns) {
    const key = v.cve || v.id;
    if (!key) continue;
    const existing = seen.get(key);
    if (!existing || (v.score > existing.score)) {
      seen.set(key, v);
    }
  }
  return Array.from(seen.values()).sort((a, b) => b.score - a.score);
}

function parseCvssScore(cvssVector) {
  if (!cvssVector) return 0;
  // Format possible: "7.5" ou "CVSS:3.1/AV:N/AC:L/..." ou juste un score
  const num = parseFloat(cvssVector);
  return Number.isNaN(num) ? 0 : num;
}

function severityFromString(s) {
  const map = { critical: 9.5, high: 7.5, medium: 5.5, low: 3.0 };
  return map[(s || "").toLowerCase()] || 0;
}

async function getCache(key) {
  try {
    const obj = await chrome.storage.local.get(key);
    const entry = obj[key];
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL_MS) return null;
    return entry.data;
  } catch (_) {
    return null;
  }
}

async function setCache(key, data) {
  try {
    await chrome.storage.local.set({ [key]: { ts: Date.now(), data } });
  } catch (_) {}
}
