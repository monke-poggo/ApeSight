// Uses FINGERPRINTS database and matches against headers / cookies / HTML / scripts

import { FINGERPRINTS, TECH_TO_NPM } from "./fingerprints.js";
import { probePhp } from "./php_probe.js";

export { TECH_TO_NPM };

const MAX_BUNDLE_SIZE = 3 * 1024 * 1024;
const MAX_BUNDLES = 8;

// Special patterns to extract versions from modern JS bundles
const BUNDLE_VERSION_PATTERNS = [
  // Next.js
  [/"name":\s*"next"\s*,\s*"version":\s*"([\d.]+(?:-[\w.]+)?)"/, "Next.js"],
  [/next(?:\.js)?\s+v?(\d+\.\d+\.\d+)/i, "Next.js"],
  [/window\.next\s*=\s*\{[^}]*version:\s*"(\d+\.\d+\.\d+)"/, "Next.js"],
  [/__NEXT_VERSION__\s*=\s*["'](\d+\.\d+\.\d+)["']/, "Next.js"],

  // React
  [/react(?:-dom)?[@/]([\d.]+)/, "React"],
  [/React\.version\s*=\s*["']([\d.]+)["']/, "React"],
  [/"react"\s*:\s*"([\d.]+)"/, "React"],

  // Angular
  [/"@angular\/core"\s*:\s*"[~^]?([\d.]+)"/, "Angular"],
  [/@angular\/core@(\d+\.\d+\.\d+)/, "Angular"],

  // Vue.js
  [/"version":\s*"([\d.]+)"[^}]*?"name":\s*"vue"/, "Vue.js"],
  [/Vue\.version\s*=\s*["']([\d.]+)["']/, "Vue.js"],
  [/vue@(\d+\.\d+\.\d+)/, "Vue.js"],

  // Nuxt.js
  [/nuxt@(\d+\.\d+\.\d+)/, "Nuxt.js"],
  [/"nuxt"\s*:\s*"[~^]?([\d.]+)"/, "Nuxt.js"],

  // Svelte
  [/svelte@(\d+\.\d+\.\d+)/, "Svelte"],
  [/"svelte"\s*:\s*"[~^]?([\d.]+)"/, "Svelte"],

  // Gatsby
  [/"gatsby"\s*:\s*"[~^]?([\d.]+)"/, "Gatsby"],
  [/gatsby@(\d+\.\d+\.\d+)/, "Gatsby"],

  // Remix
  [/@remix-run\/react@(\d+\.\d+\.\d+)/, "Remix"],
  [/"@remix-run\/react"\s*:\s*"[~^]?([\d.]+)"/, "Remix"],

  // styled-components
  [/styled-components(?:@|\/v?)([\d.]+)/, "styled-components"],
  [/"styled-components"\s*:\s*"([\d.]+)"/, "styled-components"],

  // Emotion
  [/@emotion\/(?:react|core|styled)[@/]([\d.]+)/, "Emotion"],

  // core-js
  [/core-js(?:@|\/v?)([\d.]+)/, "core-js"],
  [/"core-js"\s*:\s*"([\d.]+)"/, "core-js"],

  // webpack
  [/\/\*+!?\s*webpack[@ /]([\d.]+)/, "webpack"],
  [/__webpack_require__\.v\s*=\s*["']([\d.]+)["']/, "webpack"],

  // Vite
  [/vite@(\d+\.\d+\.\d+)/, "Vite"],
  [/"vite"\s*:\s*"[~^]?([\d.]+)"/, "Vite"],

  // jQuery
  [/\/\*\*?\s*@license\s+jQuery\s+v([\d.]+)/i, "jQuery"],
  [/jQuery\s+v?([\d.]+)/i, "jQuery"],

  // Bootstrap
  [/Bootstrap\s+v?([\d.]+)/i, "Bootstrap"],
  [/"bootstrap"\s*:\s*"([\d.]+)"/, "Bootstrap"],

  // Tailwind CSS
  [/tailwindcss@(\d+\.\d+\.\d+)/, "Tailwind CSS"],
  [/"tailwindcss"\s*:\s*"[~^]?([\d.]+)"/, "Tailwind CSS"],

  // Lodash
  [/lodash@(\d+\.\d+\.\d+)/, "Lodash"],
  [/"lodash"\s*:\s*"[~^]?([\d.]+)"/, "Lodash"],

  // Axios
  [/axios@(\d+\.\d+\.\d+)/, "Axios"],
  [/axios\.VERSION\s*=\s*["']([\d.]+)["']/, "Axios"],

  // D3.js
  [/d3\.version\s*=\s*["']([\d.]+)["']/, "D3.js"],
  [/d3@(\d+\.\d+\.\d+)/, "D3.js"],

  // Socket.io
  [/socket\.io[/-]([\d.]+)/, "Socket.io"],

  // Three.js
  [/REVISION\s*=\s*["']?(\d+)["']?/, "Three.js"],
  [/three@(\d+\.\d+\.\d+)/, "Three.js"],

  // TypeScript (from source maps)
  [/typescript@(\d+\.\d+\.\d+)/, "TypeScript"],

  // Express
  [/express@(\d+\.\d+\.\d+)/, "Express"],

  // WordPress
  [/wp-emoji-release\.min\.js\?ver=([\d.]+)/, "WordPress"],
  [/\/wp-includes\/js\/[^"']+\?ver=([\d.]+)/, "WordPress"],

  // Moment.js
  [/moment(?:\.min)?\.js.*?(\d+\.\d+\.\d+)/, "Moment.js"],

  // Day.js
  [/dayjs@(\d+\.\d+\.\d+)/, "Day.js"],

  // RxJS
  [/rxjs@(\d+\.\d+\.\d+)/, "RxJS"],

  // Zustand
  [/zustand@(\d+\.\d+\.\d+)/, "Zustand"],

  // Redux
  [/redux@(\d+\.\d+\.\d+)/, "Redux"],
  [/"redux"\s*:\s*"[~^]?([\d.]+)"/, "Redux"],

  // Framer Motion
  [/framer-motion@(\d+\.\d+\.\d+)/, "Framer Motion"],
  
  // GSAP
  [/gsap@(\d+\.\d+\.\d+)/, "GSAP"],
];

/**
 * Main entry point.
 * @param {string} tabUrl
 * @param {object} headers - dict lowercase
 * @param {object} cookies - dict cookie name -> value
 * @param {string} html
 * @param {object} domProbe - snapshot du runtime de la page (window.*, meta, scripts)
 */
export async function detectAll(tabUrl, headers, cookies, html, domProbe = null) {
  const found = new Map(); // name -> { name, version, category, source }

  // Normalisation
  const headersLower = lowercaseKeys(headers || {});
  const cookieNames = new Set(Object.keys(cookies || {}).map((c) => c.toLowerCase()));

  // Merge scripts from HTML + scripts detected at runtime (domProbe)
  const htmlScripts = extractScriptSrcs(html);
  const runtimeScripts = (domProbe?.scripts || []);
  const scriptSrcs = Array.from(new Set([...htmlScripts, ...runtimeScripts]));
  const metas = { ...extractMetas(html), ...(domProbe?.meta || {}) };

  // 1. Matching de la base fingerprints
  for (const [name, def] of Object.entries(FINGERPRINTS)) {
    const match = matchFingerprint(def, {
      headers: headersLower,
      cookies: cookieNames,
      html,
      scriptSrcs,
      metas,
    });
    if (match) {
      addTech(found, name, match.version, def.category, match.source);
    }
  }

  // 2. Merge runtime detections (higher priority since they're more reliable)
  if (domProbe?.detections) {
    for (const [name, version] of Object.entries(domProbe.detections)) {
      const def = FINGERPRINTS[name];
      const category = def?.category || guessCategory(name);
      const actualVersion = (version === "detected" ? null : version);
      addTech(found, name, actualVersion, category, "Runtime");
    }
  }

  // 3. Deep scan via JS bundles (versions not visible in HTML)
  await deepScan(tabUrl, html, scriptSrcs, found);

  // 3. Probe active PHP (easter egg)
  try {
    const phpResults = await probePhp(tabUrl);
    for (const r of phpResults) {
      addTech(found, "PHP", r.version, "Runtime", r.source);
    }
  } catch (_) {}

  // 4. Probe Next.js buildManifest (to get version when not in HTML)
  if (found.has("Next.js") && !found.get("Next.js").version) {
    const v = await probeNextVersion(tabUrl, html);
    if (v) {
      const t = found.get("Next.js");
      found.set("Next.js", { ...t, version: v, source: "Next.js buildManifest" });
    }
  }

  // 5. Probe Matomo
  if (found.has("Matomo") && !found.get("Matomo").version) {
    const v = await probeMatomoVersion(tabUrl);
    if (v) {
      const t = found.get("Matomo");
      found.set("Matomo", { ...t, version: v, source: "Matomo endpoint" });
    }
  }

  return Array.from(found.values());
}

// --- Matching fingerprint ---

function matchFingerprint(def, ctx) {
  // Headers
  if (def.headers) {
    for (const [name, pattern] of Object.entries(def.headers)) {
      const value = ctx.headers[name.toLowerCase()];
      if (value === undefined) continue;
      if (pattern === "") return { version: null, source: `Header: ${name}` };
      const m = matchPattern(pattern, value);
      if (m) return { version: m.version, source: `Header: ${name}` };
    }
  }

  // Cookies (present = match)
  if (def.cookies) {
    for (const cookieName of Object.keys(def.cookies)) {
      if (ctx.cookies.has(cookieName.toLowerCase())) {
        return { version: null, source: `Cookie: ${cookieName}` };
      }
    }
  }

  // Meta tags
  if (def.meta) {
    for (const [name, pattern] of Object.entries(def.meta)) {
      const value = ctx.metas[name.toLowerCase()];
      if (value === undefined) continue;
      if (pattern === "") return { version: null, source: `Meta: ${name}` };
      const m = matchPattern(pattern, value);
      if (m) return { version: m.version, source: `Meta: ${name}` };
    }
  }

  // Script src
  if (def.scriptSrc) {
    for (const pattern of def.scriptSrc) {
      for (const src of ctx.scriptSrcs) {
        const m = matchPattern(pattern, src);
        if (m) return { version: m.version, source: "Script URL" };
      }
    }
  }

  // HTML content
  if (def.html) {
    for (const pattern of def.html) {
      const m = matchPattern(pattern, ctx.html);
      if (m) return { version: m.version, source: "HTML" };
    }
  }

  return null;
}

/**
 * Pattern can be:
 *   "regex"          -> match sans version
 *   "regex\\;version:\\1"  -> match et extrait groupe 1 comme version
 */
function matchPattern(pattern, text) {
  const { regex, versionIdx } = parsePattern(pattern);
  if (!regex) return null;
  const m = text.match(regex);
  if (!m) return null;

  let version = null;
  if (versionIdx !== null && m[versionIdx]) {
    version = m[versionIdx];
  }
  return { version };
}

function parsePattern(pattern) {
  // Separator: \;
  const parts = pattern.split("\\;");
  const regexSrc = parts[0];
  let versionIdx = null;
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    if (p.startsWith("version:\\")) {
      versionIdx = parseInt(p.substring("version:\\".length), 10);
    }
  }
  let regex;
  try {
    regex = new RegExp(regexSrc, "i");
  } catch {
    return { regex: null, versionIdx };
  }
  return { regex, versionIdx };
}

// --- Helpers HTML ---

function extractScriptSrcs(html) {
  const result = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    result.push(m[1]);
  }
  // Also grab <link rel="stylesheet" href=...>
  const linkRe = /<link[^>]+href=["']([^"']+\.css[^"']*)["']/gi;
  while ((m = linkRe.exec(html)) !== null) {
    result.push(m[1]);
  }
  return result;
}

function extractMetas(html) {
  const result = {};
  const re = /<meta\s+[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    result[m[1].toLowerCase()] = m[2];
  }
  // Also match content before name
  const re2 = /<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']([^"']+)["']/gi;
  while ((m = re2.exec(html)) !== null) {
    result[m[2].toLowerCase()] = m[1];
  }
  return result;
}

function lowercaseKeys(obj) {
  const out = {};
  for (const k of Object.keys(obj)) out[k.toLowerCase()] = obj[k];
  return out;
}

function addTech(map, name, version, category, source) {
  const existing = map.get(name);
  if (!existing) {
    map.set(name, { name, version, category, source });
    return;
  }
  if (version && !existing.version) {
    map.set(name, { name, version, category, source });
  } else if (version && existing.version && version.length > existing.version.length) {
    map.set(name, { name, version, category, source });
  }
}

/**
 * Guesses the category of a tech detected via DOM probe without a matching fingerprint.
 */
function guessCategory(name) {
  const n = name.toLowerCase();
  if (/(analytics|pixel|tag manager|matomo|piano|hotjar|segment|mixpanel)/.test(n)) return "Analytics";
  if (/(rum|sentry|dynatrace|contentsquare|newrelic|datadog|new relic)/.test(n)) return "Monitoring";
  if (/(react|vue|angular|svelte|solid|next|nuxt|gatsby|remix|astro)/.test(n)) return "JS Framework";
  if (/(jquery|lodash|moment|dayjs|axios|swiper|emotion|styled)/.test(n)) return "JS Library";
  if (/(bootstrap|tailwind|material|chakra|ant design)/.test(n)) return "UI Framework";
  if (/(onetrust|cookiebot|didomi|tcf)/.test(n)) return "Consent Management";
  if (/(stripe|paypal)/.test(n)) return "Payment";
  if (/(intercom|zendesk)/.test(n)) return "Live Chat";
  if (/(recaptcha|hcaptcha)/.test(n)) return "Security";
  if (/(font|typekit)/.test(n)) return "Font";
  return "Misc";
}

// --- Deep scan of JS bundles ---

async function deepScan(tabUrl, html, scriptSrcs, found) {
  const base = tryURL(tabUrl);
  if (!base) return;

  // Resolve absolute URLs, prioritize same-origin + keywords
  const candidates = [];
  const priorityKeywords = ["framework", "vendor", "main", "polyfill", "app", "runtime", "webpack", "_next/static", "_nuxt"];
  for (const src of scriptSrcs) {
    const abs = tryURL(src, base);
    if (!abs) continue;
    const same = abs.origin === base.origin;
    const lower = abs.pathname.toLowerCase();
    const hasKeyword = priorityKeywords.some(k => lower.includes(k));
    const priority = (same ? 0 : 2) + (hasKeyword ? 0 : 1);
    candidates.push({ url: abs.toString(), priority });
  }
  candidates.sort((a, b) => a.priority - b.priority);
  const toFetch = candidates.slice(0, MAX_BUNDLES).map((c) => c.url);

  const contents = await Promise.all(toFetch.map(safeFetch));

  for (let i = 0; i < contents.length; i++) {
    const content = contents[i];
    if (!content) continue;
    const short = toFetch[i].split("/").pop().slice(0, 40);
    for (const [regex, name] of BUNDLE_VERSION_PATTERNS) {
      const m = content.match(regex);
      if (m && isPlausibleVersion(m[1])) {
        const def = FINGERPRINTS[name];
        addTech(found, name, m[1], def?.category || "JS Library", `Bundle: ${short}`);
      }
    }
  }
}

async function probeNextVersion(tabUrl, html) {
  const base = tryURL(tabUrl);
  if (!base) return null;

  const buildIdMatch = html.match(/"buildId":"([^"]+)"/);
  const paths = [];
  if (buildIdMatch) {
    paths.push(`/_next/static/${buildIdMatch[1]}/_buildManifest.js`);
    paths.push(`/_next/static/${buildIdMatch[1]}/_ssgManifest.js`);
  }
  // Also try framework.js and main.js
  const frameworkChunks = Array.from(
    html.matchAll(/src=["']([^"']*_next\/static\/chunks\/(?:framework|main|webpack|app-)[^"']*\.js)["']/gi)
  ).map((m) => m[1]);
  paths.push(...frameworkChunks.slice(0, 3));

  for (const p of paths) {
    const url = new URL(p, base).toString();
    const content = await safeFetch(url);
    if (!content) continue;
    for (const regex of [
      /"name":\s*"next"\s*,\s*"version":\s*"([\d.]+(?:-[\w.]+)?)"/,
      /next(?:\.js)?\s+v?(\d+\.\d+\.\d+)/i,
      /NEXT_VERSION\s*=\s*["']([\d.]+)["']/,
    ]) {
      const m = content.match(regex);
      if (m && isPlausibleVersion(m[1])) return m[1];
    }
  }
  return null;
}

async function probeMatomoVersion(tabUrl) {
  const base = tryURL(tabUrl);
  if (!base) return null;
  const candidates = [
    new URL("/matomo.js", base).toString(),
    new URL("/piwik.js", base).toString(),
  ];
  for (const url of candidates) {
    const text = await safeFetch(url);
    if (!text) continue;
    const m =
      text.match(/\/\*!?\s*Matomo[^*]*?v?([\d.]+)/i) ||
      text.match(/Matomo\s*(?:-\s*)?(?:free\/libre\s*)?(?:web\s*analytics)?[^\d]*([\d.]+)/i);
    if (m && isPlausibleVersion(m[1])) return m[1];
  }
  return null;
}

async function safeFetch(url) {
  try {
    const resp = await fetch(url, { method: "GET", credentials: "omit" });
    if (!resp.ok) return null;
    const reader = resp.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let total = 0;
    let text = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      text += decoder.decode(value, { stream: true });
      if (total >= MAX_BUNDLE_SIZE) {
        reader.cancel();
        break;
      }
    }
    return text;
  } catch {
    return null;
  }
}

function tryURL(raw, base) {
  try {
    return base ? new URL(raw, base) : new URL(raw);
  } catch {
    return null;
  }
}

function isPlausibleVersion(v) {
  if (!v) return false;
  const parts = v.split(/[.-]/);
  if (parts.length < 2 || parts.length > 5) return false;
  const major = parseInt(parts[0], 10);
  return !Number.isNaN(major) && major < 100;
}
