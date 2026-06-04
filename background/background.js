// Service worker: scans ONCE per origin and caches the result
// in chrome.storage.local (persists across sessions).

import { detectAll } from "../detector/detector.js";
import { lookupVulns } from "../detector/vuln_sources.js";

// --- DOM probe injected in the page (world: MAIN) ---
// Standalone function: must work without any imports.
function probeInPageContext() {
  const r = { detections: {}, scripts: [], meta: {} };
  try {
    if (window.React?.version) r.detections.React = window.React.version;
    if (window.next?.version) r.detections["Next.js"] = window.next.version;
    if (window.Vue?.version) r.detections["Vue.js"] = window.Vue.version;
    if (window.ng?.version) r.detections.Angular = window.ng.version;
    const ngV = document.querySelector("[ng-version]")?.getAttribute("ng-version");
    if (ngV) r.detections.Angular = ngV;
    if (window.jQuery?.fn?.jquery) r.detections.jQuery = window.jQuery.fn.jquery;
    if (window.$?.fn?.jquery) r.detections.jQuery = window.$.fn.jquery;
    if (window.bootstrap?.Tooltip?.VERSION) r.detections.Bootstrap = window.bootstrap.Tooltip.VERSION;
    if (window._?.VERSION) r.detections.Lodash = window._.VERSION;
    if (window.moment?.version) r.detections["Moment.js"] = window.moment.version;
    if (window.axios) r.detections.axios = window.axios.VERSION || "detected";
    if (window.Swiper) r.detections.Swiper = window.Swiper.version || "detected";

    if (window.__REACT_NATIVE_WEB__ || document.querySelector('[data-rn-root]')) {
      r.detections["React Native for Web"] = "detected";
    }

    // Next.js - inspection approfondie
    const nd = document.getElementById("__NEXT_DATA__");
    if (nd) {
      try {
        const parsed = JSON.parse(nd.textContent);
        if (parsed.buildId) r.nextBuildId = parsed.buildId;
        if (parsed.runtimeConfig?.version) r.detections["Next.js"] = parsed.runtimeConfig.version;
        r.detections["Next.js"] = r.detections["Next.js"] || "detected";
      } catch (_) {}
    }

    if (window.__NUXT__) r.detections["Nuxt.js"] = "detected";

    // core-js via shared polyfill
    const cjs = window["__core-js_shared__"];
    if (cjs?.versions?.length) {
      const v = cjs.versions[cjs.versions.length - 1];
      if (v?.version) r.detections["core-js"] = v.version;
    }

    // styled-components
    const scV = document.querySelector("[data-styled-version]")?.getAttribute("data-styled-version");
    if (scV) r.detections["styled-components"] = scV;
    else if (document.querySelector('[data-styled], style[data-styled]') ||
             document.querySelector('[class^="sc-"]')) {
      r.detections["styled-components"] = "detected";
    }

    if (document.querySelector('[data-emotion], style[data-emotion]')) {
      r.detections["Emotion"] = "detected";
    }

    // Analytics globaux
    if (window.dataLayer && Array.isArray(window.dataLayer)) r.detections["Google Tag Manager"] = "detected";
    if (window.gtag || window.ga) r.detections["Google Analytics"] = "detected";
    if (window.fbq) r.detections["Facebook Pixel"] = "detected";
    if (window._paq) r.detections["Matomo"] = "detected";
    if (window.hj) r.detections["Hotjar"] = "detected";
    if (window.mixpanel) r.detections["Mixpanel"] = "detected";
    if (window.analytics?.identify) r.detections["Segment"] = "detected";

    // Piano / AT Internet
    if (window.pa || window.ATInternet || window.tag_internet) r.detections["Piano Analytics"] = "detected";

    // APM
    if (window.dtrum || window.dT_) r.detections["Dynatrace"] = window.dtrum?.version || "detected";
    if (window._uxa || window.CS_CONF || window.__ls) r.detections["Contentsquare"] = "detected";
    if (window.NREUM || window.newrelic) r.detections["New Relic"] = "detected";
    if (window.Sentry) r.detections["Sentry"] = window.Sentry.SDK_VERSION || "detected";
    if (window.DD_RUM || window.DD_LOGS) r.detections["Datadog RUM"] = "detected";

    // Consent
    if (window.OneTrust || window.Optanon) r.detections["OneTrust"] = "detected";
    if (window.Cookiebot) r.detections["Cookiebot"] = "detected";
    if (window.Didomi) r.detections["Didomi"] = "detected";

    // Chat / Payment / Captcha
    if (window.Intercom) r.detections["Intercom"] = "detected";
    if (window.zE) r.detections["Zendesk"] = "detected";
    if (window.Stripe) r.detections["Stripe"] = window.Stripe.version || "detected";
    if (window.paypal) r.detections["PayPal"] = "detected";
    if (window.grecaptcha) r.detections["reCAPTCHA"] = "detected";
    if (window.hcaptcha) r.detections["hCaptcha"] = "detected";

    // Meta tags
    document.querySelectorAll("meta[name]").forEach(m => {
      const n = (m.getAttribute("name") || "").toLowerCase();
      if (["generator", "application-name"].includes(n)) {
        r.meta[n] = m.getAttribute("content");
      }
    });

    // Script srcs - for additional analysis by the detector
    document.querySelectorAll("script[src]").forEach(s => r.scripts.push(s.src));

    // Link hrefs
    document.querySelectorAll("link[href]").forEach(l => {
      const h = l.getAttribute("href") || "";
      if (h.includes("fonts.googleapis.com") || h.includes("fonts.gstatic.com")) {
        r.detections["Google Font API"] = "detected";
      }
      if (h.includes("use.typekit.net")) {
        r.detections["Adobe Fonts"] = "detected";
      }
    });

    // Piano Analytics / Contentsquare via script src (fallback)
    r.scripts.forEach(src => {
      if (/tag\.aticdn\.net|piano-analytics|xiti\.com/.test(src)) r.detections["Piano Analytics"] = r.detections["Piano Analytics"] || "detected";
      if (/contentsquare|clicktale/.test(src)) r.detections["Contentsquare"] = r.detections["Contentsquare"] || "detected";
      if (/dynatrace|ruxit/.test(src)) r.detections["Dynatrace"] = r.detections["Dynatrace"] || "detected";
      if (/connect\.facebook\.net.*fbevents/.test(src)) r.detections["Facebook Pixel"] = r.detections["Facebook Pixel"] || "detected";
    });

  } catch (e) { r.error = String(e); }
  return r;
}

// --- Cache config ---
const CACHE_TTL_MS = 6 * 3600 * 1000;   // 6h per origin
const CACHE_PREFIX = "scan_";            // key: scan_<origin>
const META_PREFIX = "meta_";             // headers per tabId (session)

// --- In-memory state ---
const inflight = new Map();              // origin -> in-flight Promise (dedup)

// --- Capture headers ---
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type !== "main_frame") return;
    const headers = {};
    for (const h of details.responseHeaders || []) {
      headers[h.name.toLowerCase()] = h.value || "";
    }
    try {
      await chrome.storage.session.set({
        [META_PREFIX + details.tabId]: {
          url: details.url,
          headers,
          status: details.statusCode,
        },
      });
    } catch (_) {}
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

// Auto-scan once per origin when page finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !/^https?:/.test(tab.url)) return;
  ensureScanned(tabId, tab.url).catch((err) =>
    console.error("[apesight] auto-scan error:", err)
  );
});

// When switching active tab, just update the badge (no rescan)
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || !/^https?:/.test(tab.url)) return;
    const cached = await getCached(tab.url);
    if (cached) {
      const critCount = Object.values(cached.vulns || {}).flat().length;
      setBadge(tabId, cached.technologies.length, critCount, "done");
    }
  } catch (_) {}
});

// Messages from popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "GET_RESULT") {
    (async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab || !tab.url || !/^https?:/.test(tab.url)) {
        return sendResponse({ result: null, reason: "not-http", tabId: tab?.id });
      }
      const cached = await getCached(tab.url);
      if (cached) {
        sendResponse({ result: cached, tabId: tab.id, fromCache: true });
        return;
      }
      // No cache yet -> trigger scan, popup will get results via storage.onChanged
      sendResponse({ result: null, tabId: tab.id, fromCache: false });
      ensureScanned(tab.id, tab.url).catch(() => {});
    })();
    return true;
  }

  if (msg.type === "RESCAN") {
    (async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const tab = tabs[0];
      if (!tab || !tab.url || !/^https?:/.test(tab.url)) {
        return sendResponse({ ok: false });
      }
      await invalidateCache(tab.url);
      ensureScanned(tab.id, tab.url, { force: true }).catch(() => {});
      sendResponse({ ok: true, tabId: tab.id });
    })();
    return true;
  }
});

// --- Logique de scan ---

async function ensureScanned(tabId, url, { force = false } = {}) {
  const origin = getOrigin(url);
  if (!origin) return null;

  // 1. Cache valide ?
  if (!force) {
    const cached = await getCached(url);
    if (cached) {
      const critCount = Object.values(cached.vulns || {}).flat().length;
      setBadge(tabId, cached.technologies.length, critCount, "done");
      return cached;
    }
  }

  // 2. Scan already in progress for this origin? -> wait for it
  if (inflight.has(origin)) {
    console.log("[apesight] scan already running for", origin, ", waiting...");
    return inflight.get(origin);
  }

  // 3. Start scan
  const promise = runScan(tabId, url, origin);
  inflight.set(origin, promise);
  try {
    return await promise;
  } finally {
    inflight.delete(origin);
  }
}

async function runScan(tabId, url, origin) {
  console.log("[apesight] === scan start", origin);
  setBadge(tabId, 0, 0, "loading");

  // Publish "scanning" state immediately (for the popup)
  await setCache(origin, {
    origin,
    url,
    status: 0,
    technologies: [],
    vulns: {},
    totalCves: 0,
    ts: Date.now(),
    scanning: true,
    stage: "detecting",
  });

  let technologies = [];
  let vulns = {};
  let totalCves = 0;
  let status = 200;

  try {
    const meta = await getStoredMeta(tabId) || { url, headers: {}, status: 200 };
    status = meta.status;

  // Cookies
  const cookies = {};
  try {
    const list = await chrome.cookies.getAll({ url });
    for (const c of list) cookies[c.name] = c.value;
  } catch (e) {
    console.warn("[apesight] cookies err:", e);
  }

  // HTML via executeScript
  let html = "";
  try {
    const [r] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => document.documentElement.outerHTML,
    });
    html = r?.result || "";
  } catch (e) {
    console.warn("[apesight] executeScript err:", e);
  }

  // DOM probe: inspect JS runtime (window.*, React/Next version, etc.)
  // This is what gives us real versions like Wappalyzer does.
  let domProbe = null;
  try {
    const probePromise = chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: probeInPageContext,
    });
    const [r] = await withTimeout(probePromise, 8000, "DOM probe");
    domProbe = r?.result || null;
  } catch (e) {
    console.warn("[apesight] DOM probe err:", e.message || e);
  }

  // Detection
  try {
    technologies = await withTimeout(
      detectAll(url, meta.headers, cookies, html, domProbe),
      20_000,
      "detectAll"
    );
  } catch (e) {
    console.error("[apesight] detectAll err:", e);
  }

  // Publish techs as soon as they're ready (partial result)
  await setCache(origin, {
    origin,
    url,
    status: meta.status,
    technologies,
    vulns: {},
    totalCves: 0,
    ts: Date.now(),
    scanning: true,
    stage: "cve-lookup",
  });
  setBadge(tabId, technologies.length, 0, "loading");

  // CVE lookup in parallel (one API call per tech+version thanks to internal cache)
  const withVersion = technologies.filter((t) => t.version);
  const lookups = await Promise.all(
    withVersion.map(async (tech) => {
      try {
        const cves = await withTimeout(lookupVulns(tech), 10_000, `lookup ${tech.name}`);
        return [tech, cves];
      } catch (e) {
        console.warn(`[apesight] ${tech.name}:`, e.message);
        return [tech, []];
      }
    })
  );

  vulns = {};
  totalCves = 0;
  for (const [tech, found] of lookups) {
    if (found && found.length > 0) {
      vulns[`${tech.name}|${tech.version || ""}`] = found;
      totalCves += found.length;
    }
  }

  const final = {
    origin,
    url,
    status,
    technologies,
    vulns,
    totalCves,
    ts: Date.now(),
    scanning: false,
    stage: "done",
  };
  await setCache(origin, final);
  setBadge(tabId, technologies.length, totalCves, "done");
  console.log("[apesight] === scan done", origin, "CVE:", totalCves);
  return final;

  } catch (err) {
    // Error recovery: ensure scan state is never stuck on "scanning: true"
    console.error("[apesight] scan failed for", origin, err);
    const errorResult = {
      origin,
      url,
      status,
      technologies,
      vulns,
      totalCves,
      ts: Date.now(),
      scanning: false,
      stage: "done",
      error: err.message || String(err),
    };
    await setCache(origin, errorResult);
    setBadge(tabId, technologies.length, totalCves, "done");
    return errorResult;
  }
}

// --- Cache helpers ---

function getOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

async function getCached(url) {
  const origin = getOrigin(url);
  if (!origin) return null;
  try {
    const key = CACHE_PREFIX + origin;
    const obj = await chrome.storage.local.get(key);
    const entry = obj[key];
    if (!entry) return null;
    // Valid if scan is done AND not expired
    if (entry.scanning) return entry; // still running: return current state
    if (Date.now() - entry.ts > CACHE_TTL_MS) return null;
    return entry;
  } catch (_) {
    return null;
  }
}

async function setCache(origin, data) {
  try {
    await chrome.storage.local.set({ [CACHE_PREFIX + origin]: data });
  } catch (e) {
    console.error("[apesight] setCache err:", e);
  }
}

async function invalidateCache(url) {
  const origin = getOrigin(url);
  if (!origin) return;
  try {
    await chrome.storage.local.remove(CACHE_PREFIX + origin);
  } catch (_) {}
}

async function getStoredMeta(tabId) {
  try {
    const obj = await chrome.storage.session.get(META_PREFIX + tabId);
    return obj[META_PREFIX + tabId] || null;
  } catch (_) {
    return null;
  }
}

function setBadge(tabId, techCount, cveCount, state) {
  const safe = (fn) => { try { fn(); } catch (_) {} };
  if (state === "loading") {
    safe(() => chrome.action.setBadgeBackgroundColor({ color: "#4b5bdc", tabId }));
    safe(() => chrome.action.setBadgeText({ text: "...", tabId }));
    return;
  }
  if (cveCount > 0) {
    safe(() => chrome.action.setBadgeBackgroundColor({ color: "#e02424", tabId }));
    safe(() => chrome.action.setBadgeText({ text: String(cveCount), tabId }));
  } else if (techCount > 0) {
    safe(() => chrome.action.setBadgeBackgroundColor({ color: "#10b981", tabId }));
    safe(() => chrome.action.setBadgeText({ text: String(techCount), tabId }));
  } else {
    safe(() => chrome.action.setBadgeText({ text: "", tabId }));
  }
}

function withTimeout(promise, ms, label = "op") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timeout ${ms}ms`)), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}
