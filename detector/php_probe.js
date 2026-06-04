// Advanced PHP detection via easter eggs and logo signatures.
// These GUIDs are internal PHP functions that return images.
// Many sites forget to disable expose_php, which leaks the version.

const PHP_EASTER_EGGS = {
  PHP_LOGO: "PHPE9568F34-D428-11d2-A769-00AA001ACF42",
  PHP_LOGO_VERTICAL: "PHPE9568F35-D428-11d2-A769-00AA001ACF42",
  CREDITS: "PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
  ZEND_LOGO: "PHPE9568F35-D428-11d2-A769-00AA001ACF42",
};

// Approximate PHP logo sizes by major version (in bytes)
// Used as fallback when X-Powered-By is hidden
const PHP_LOGO_SIZES = {
  4752: "5.x",   // PHP 5.x
  4772: "5.x",
  2196: "8.x",   // PHP 8.x (smaller elephant logo)
  2226: "8.x",
  4820: "7.x",   // PHP 7.x
  4834: "7.x",
};

export async function probePhp(baseUrl) {
  const results = [];

  // 1. Main easter egg (X-Powered-By header often present here even if hidden elsewhere)
  const logoUrl = addEasterEgg(baseUrl, PHP_EASTER_EGGS.PHP_LOGO);
  const logoData = await fetchWithHeaders(logoUrl);
  if (logoData) {
    const version = extractPhpVersion(logoData.headers) ||
                    guessFromLogoSize(logoData.contentLength);
    if (version) {
      results.push({ version, source: "PHP easter egg" });
    } else if (isLikelyPhpLogo(logoData)) {
      // PHP confirmed but version unknown
      results.push({ version: null, source: "PHP easter egg (version hidden)" });
    }
  }

  // 2. Credits page (often accessible, gives a text dump with version info)
  if (results.length === 0) {
    const creditsUrl = addEasterEgg(baseUrl, PHP_EASTER_EGGS.CREDITS);
    const credits = await fetchText(creditsUrl);
    if (credits) {
      const m = credits.match(/PHP\s+(\d+\.\d+\.\d+)/);
      if (m) {
        results.push({ version: m[1], source: "PHP credits page" });
      }
    }
  }

  return results;
}

function addEasterEgg(baseUrl, guid) {
  try {
    const u = new URL(baseUrl);
    // Easter egg works on root: example.com/?=GUID
    u.search = "?=" + guid;
    return u.toString();
  } catch {
    return baseUrl;
  }
}

async function fetchWithHeaders(url) {
  try {
    const resp = await fetch(url, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
    });
    if (!resp.ok) return null;

    const headers = {};
    resp.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    // Check if it's actually a PHP image (content-type image/gif or image/png)
    const ct = (headers["content-type"] || "").toLowerCase();
    const isImage = ct.startsWith("image/");

    let contentLength = parseInt(headers["content-length"] || "0", 10);
    if (!contentLength) {
      const blob = await resp.blob();
      contentLength = blob.size;
    }

    return { headers, contentLength, isImage, contentType: ct };
  } catch {
    return null;
  }
}

async function fetchText(url) {
  try {
    const resp = await fetch(url, { credentials: "omit", cache: "no-store" });
    if (!resp.ok) return null;
    const text = await resp.text();
    if (text.length > 500_000) return null; // skip large files
    return text;
  } catch {
    return null;
  }
}

function extractPhpVersion(headers) {
  // Variations possibles
  for (const key of ["x-powered-by", "server", "x-generator"]) {
    const value = headers[key];
    if (!value) continue;
    const m = value.match(/PHP\/?\s*(\d+\.\d+\.\d+)/i);
    if (m) return m[1];
  }
  return null;
}

function guessFromLogoSize(size) {
  const guess = PHP_LOGO_SIZES[size];
  return guess || null;
}

function isLikelyPhpLogo(data) {
  // PHP renvoie un GIF ou PNG du logo, de quelques Ko
  return data.isImage && data.contentLength > 500 && data.contentLength < 20000;
}
