// Format: each tech = { category, patterns: { ... } }
// Patterns support a capture group \\;version:\\1 to extract the version.
//
// Pattern syntax: "regex\\;version:\\1" => regex is compiled, if it matches,
// group 1 (or the specified index) is used as the version.

export const FINGERPRINTS = {

  // --- Web servers ---
  "Apache": {
    category: "Server",
    headers: { server: "Apache(?:/([\\d.]+))?\\;version:\\1" },
  },
  "Nginx": {
    category: "Server",
    headers: { server: "nginx(?:/([\\d.]+))?\\;version:\\1" },
  },
  "Microsoft IIS": {
    category: "Server",
    headers: { server: "Microsoft-IIS/([\\d.]+)\\;version:\\1" },
  },
  "LiteSpeed": {
    category: "Server",
    headers: { server: "LiteSpeed(?:/([\\d.]+))?\\;version:\\1" },
  },
  "Caddy": {
    category: "Server",
    headers: { server: "Caddy(?:/([\\d.]+))?\\;version:\\1" },
  },
  "OpenResty": {
    category: "Server",
    headers: { server: "openresty(?:/([\\d.]+))?\\;version:\\1" },
  },
  "Tomcat": {
    category: "Application Server",
    headers: { server: "(?:Apache[ -])?Tomcat(?:/([\\d.]+))?\\;version:\\1" },
  },
  "Jetty": {
    category: "Application Server",
    headers: { server: "Jetty\\(([\\d.]+)\\)\\;version:\\1" },
  },
  "Envoy": {
    category: "Server",
    headers: { server: "envoy" },
  },

  // --- Runtimes ---
  "PHP": {
    category: "Runtime",
    headers: { "x-powered-by": "PHP/([\\d.]+)\\;version:\\1" },
    cookies: { phpsessid: "", phpsession: "" },
  },
  "ASP.NET": {
    category: "Runtime",
    headers: {
      "x-powered-by": "ASP\\.NET",
      "x-aspnet-version": "([\\d.]+)\\;version:\\1",
    },
    cookies: { "asp.net_sessionid": "", aspxauth: "" },
  },
  "ASP.NET MVC": {
    category: "Framework",
    headers: { "x-aspnetmvc-version": "([\\d.]+)\\;version:\\1" },
  },
  "Java": {
    category: "Runtime",
    cookies: { jsessionid: "" },
  },
  "Node.js": {
    category: "Runtime",
    headers: { "x-powered-by": "^Express(?:/([\\d.]+))?\\;version:\\1" },
  },

  // --- Web Frameworks ---
  "Next.js": {
    category: "Web Framework",
    headers: {
      "x-powered-by": "Next\\.js(?:/([\\d.]+))?\\;version:\\1",
      "x-nextjs-cache": "",
      "x-nextjs-prerender": "",
      "x-nextjs-matched-path": "",
    },
    html: [
      "<script[^>]+id=\"__NEXT_DATA__\"",
      "/_next/static/",
    ],
    scriptSrc: ["/_next/static/chunks/"],
  },
  "Nuxt.js": {
    category: "Web Framework",
    html: ["window\\.__NUXT__", "/_nuxt/"],
    meta: { "generator": "Nuxt" },
  },
  "Gatsby": {
    category: "Web Framework",
    html: ["id=\"___gatsby\"", "/page-data\\.json"],
    meta: { "generator": "Gatsby (?:([\\d.]+))?\\;version:\\1" },
  },
  "Remix": {
    category: "Web Framework",
    html: ["__remixContext", "window\\.__remixManifest"],
  },
  "SvelteKit": {
    category: "Web Framework",
    html: ["id=\"svelte-announcer\"", "window\\.__sveltekit"],
  },
  "Astro": {
    category: "Web Framework",
    html: ["data-astro-", "astro-island"],
    meta: { "generator": "Astro v?([\\d.]+)\\;version:\\1" },
  },

  // --- JS Frameworks & libraries ---
  "React": {
    category: "JS Framework",
    html: ["data-reactroot", "data-reactid", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    scriptSrc: ["react(?:-dom)?(?:\\.production)?[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1"],
  },
  "Vue.js": {
    category: "JS Framework",
    html: ["data-v-", "vuetify"],
    scriptSrc: ["vue[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1"],
  },
  "Angular": {
    category: "JS Framework",
    html: ["ng-app", "ng-controller", "ng-version=\"([\\d.]+)\"\\;version:\\1"],
    scriptSrc: ["angular[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1"],
  },
  "AngularJS": {
    category: "JS Framework",
    html: ["ng-binding", "ng-scope"],
    scriptSrc: ["angular\\.([\\d.]+)\\.js\\;version:\\1"],
  },
  "jQuery": {
    category: "JS Library",
    scriptSrc: [
      "jquery[.-]?([\\d.]+)?(?:\\.min)?\\.js\\;version:\\1",
      "/jquery/([\\d.]+)/\\;version:\\1",
    ],
  },
  "jQuery UI": {
    category: "JS Library",
    scriptSrc: ["jquery-ui[.-]?([\\d.]+)?\\;version:\\1"],
  },
  "Lodash": {
    category: "JS Library",
    scriptSrc: ["lodash[.-]([\\d.]+)(?:\\.min)?\\.js\\;version:\\1"],
  },
  "Bootstrap": {
    category: "CSS Framework",
    scriptSrc: ["bootstrap[.-]([\\d.]+)(?:\\.min)?\\.(?:js|css)\\;version:\\1"],
    html: ["class=\"[^\"]*\\b(?:container-fluid|navbar-expand)\\b"],
  },
  "Tailwind CSS": {
    category: "CSS Framework",
    html: ["class=\"[^\"]*\\b(?:bg-|text-|flex|grid)[\\w-]*", "/tailwind"],
  },
  "Material-UI": {
    category: "UI Framework",
    html: ["MuiButton", "MuiTypography"],
  },
  "Ant Design": {
    category: "UI Framework",
    html: ["ant-btn", "ant-layout"],
  },
  "Chakra UI": {
    category: "UI Framework",
    html: ["chakra-"],
  },
  "styled-components": {
    category: "JS Library",
    html: ["data-styled", "data-styled-version=\"([\\d.]+)\"\\;version:\\1"],
  },
  "Emotion": {
    category: "JS Library",
    html: ["data-emotion", "css-[\\w]{6,}"],
  },
  "core-js": {
    category: "JS Library",
    scriptSrc: ["core-js[@/]([\\d.]+)\\;version:\\1"],
  },
  "webpack": {
    category: "Build Tool",
    html: ["webpackJsonp", "__webpack_require__"],
  },
  "Vite": {
    category: "Build Tool",
    html: ["/@vite/client", "/@id/"],
    scriptSrc: ["/assets/index-[\\w]+\\.js"],
  },
  "Parcel": {
    category: "Build Tool",
    html: ["parcelRequire"],
  },

  // --- CMS ---
  "WordPress": {
    category: "CMS",
    meta: { "generator": "WordPress(?:\\s+([\\d.]+))?\\;version:\\1" },
    html: ["/wp-(?:content|includes)/", "wp-embed\\.min\\.js"],
  },
  "Drupal": {
    category: "CMS",
    meta: { "generator": "Drupal\\s+([\\d.]+)\\;version:\\1" },
    html: ["/sites/(?:default|all)/files"],
    headers: { "x-generator": "Drupal" },
  },
  "Joomla": {
    category: "CMS",
    meta: { "generator": "Joomla!?\\s*-?\\s*([\\d.]+)?\\;version:\\1" },
    html: ["/media/jui/", "/templates/system/"],
  },
  "Shopify": {
    category: "E-commerce",
    html: ["cdn\\.shopify\\.com", "Shopify\\.theme"],
    headers: { "x-shopify-stage": "" },
  },
  "Magento": {
    category: "E-commerce",
    html: ["Mage\\.Cookies", "static/version\\d+"],
    cookies: { "mage-cache-sessid": "" },
  },
  "PrestaShop": {
    category: "E-commerce",
    meta: { "generator": "PrestaShop" },
    html: ["var prestashop"],
  },
  "WooCommerce": {
    category: "E-commerce",
    html: ["/plugins/woocommerce/", "woocommerce-"],
  },
  "Ghost": {
    category: "CMS",
    html: ["ghost-"],
    meta: { "generator": "Ghost\\s+([\\d.]+)\\;version:\\1" },
  },
  "Sitecore": {
    category: "CMS",
    html: ["/sitecore/", "sc_site="],
  },
  "Adobe Experience Manager": {
    category: "CMS",
    html: ["/etc/designs/", "/content/dam/"],
  },

  // --- PHP Frameworks ---
  "Laravel": {
    category: "Framework",
    cookies: { laravel_session: "", xsrf_token: "" },
    html: ["laravel_token"],
  },
  "Symfony": {
    category: "Framework",
    headers: { "x-powered-by": "Symfony" },
    cookies: { "symfony": "" },
    html: ["_sf2_meta", "sf-toolbar"],
  },
  "CodeIgniter": {
    category: "Framework",
    cookies: { ci_session: "" },
  },

  // --- Python Frameworks ---
  "Django": {
    category: "Framework",
    cookies: { csrftoken: "", sessionid: "" },
    html: ["/static/admin/"],
  },
  "Flask": {
    category: "Framework",
    cookies: { session: "" },
  },

  // --- Analytics ---
  "Google Analytics": {
    category: "Analytics",
    scriptSrc: [
      "google-analytics\\.com/(?:ga|analytics|gtag)",
      "googletagmanager\\.com/gtag",
    ],
    html: ["gtag\\s*\\(", "_gaq\\.push"],
  },
  "Google Tag Manager": {
    category: "Analytics",
    scriptSrc: ["googletagmanager\\.com/gtm\\.js"],
    html: ["dataLayer\\s*=\\s*\\["],
  },
  "Matomo": {
    category: "Analytics",
    html: ["_paq\\.push", "/matomo\\.js", "/piwik\\.js"],
    cookies: { "_pk_id": "", "_pk_ses": "", "mtm_consent": "" },
  },
  "Hotjar": {
    category: "Analytics",
    scriptSrc: ["static\\.hotjar\\.com"],
    html: ["hjSetting"],
  },
  "Mixpanel": {
    category: "Analytics",
    scriptSrc: ["cdn\\.mxpnl\\.com"],
    cookies: { mp_mixpanel: "" },
  },
  "Segment": {
    category: "Analytics",
    scriptSrc: ["cdn\\.segment\\.com/analytics"],
  },
  "Facebook Pixel": {
    category: "Analytics",
    scriptSrc: ["connect\\.facebook\\.net/[^\"']*/fbevents\\.js"],
    html: ["fbq\\s*\\("],
  },
  "Adobe Analytics": {
    category: "Analytics",
    scriptSrc: ["assets\\.adobedtm\\.com"],
  },
  "New Relic": {
    category: "Analytics",
    html: ["NREUM", "newrelic"],
  },
  "Datadog": {
    category: "Analytics",
    scriptSrc: ["datadoghq-browser-agent"],
  },

  // --- CDN & Cloud ---
  "Cloudflare": {
    category: "CDN",
    headers: {
      "cf-ray": "",
      "server": "^cloudflare",
      "cf-cache-status": "",
    },
  },
  "CloudFront": {
    category: "CDN",
    headers: { "x-amz-cf-id": "", via: "CloudFront" },
    html: ["\\.cloudfront\\.net"],
  },
  "Fastly": {
    category: "CDN",
    headers: { "x-served-by": "cache-", "x-fastly-request-id": "" },
  },
  "Akamai": {
    category: "CDN",
    headers: { "x-akamai-transformed": "", "akamai-grn": "" },
    html: ["\\.akamaihd\\.net", "\\.akamaized\\.net"],
  },
  "Amazon S3": {
    category: "Cloud Storage",
    headers: { server: "AmazonS3", "x-amz-request-id": "" },
    html: ["\\.s3[.-](?:[\\w-]+\\.)?amazonaws\\.com"],
  },
  "Vercel": {
    category: "PaaS",
    headers: {
      "x-vercel-cache": "",
      "x-vercel-id": "",
      server: "Vercel",
    },
  },
  "Netlify": {
    category: "PaaS",
    headers: { "x-nf-request-id": "", server: "Netlify" },
  },
  "Heroku": {
    category: "PaaS",
    headers: { "x-request-id": "", via: "vegur" },
  },
  "jsDelivr": {
    category: "CDN",
    scriptSrc: ["cdn\\.jsdelivr\\.net"],
  },
  "unpkg": {
    category: "CDN",
    scriptSrc: ["unpkg\\.com"],
  },
  "Cloudflare CDN": {
    category: "CDN",
    scriptSrc: ["cdnjs\\.cloudflare\\.com"],
  },

  // --- Consent / Privacy ---
  "OneTrust": {
    category: "Consent Management",
    scriptSrc: ["cookielaw\\.org", "onetrust-cdn"],
    cookies: { OptanonConsent: "" },
    html: ["onetrust-banner"],
  },
  "Cookiebot": {
    category: "Consent Management",
    scriptSrc: ["consent\\.cookiebot\\.com"],
  },
  "Didomi": {
    category: "Consent Management",
    scriptSrc: ["sdk\\.privacy-center\\.org", "static\\.didomi\\.io"],
  },

  // --- Fonts ---
  "Google Fonts": {
    category: "Font",
    html: ["fonts\\.googleapis\\.com", "fonts\\.gstatic\\.com"],
  },
  "Adobe Fonts": {
    category: "Font",
    html: ["use\\.typekit\\.net"],
  },
  "Font Awesome": {
    category: "Font",
    scriptSrc: ["fontawesome", "fa-[\\d.]+"],
  },

  // --- Misc / Security ---
  "reCAPTCHA": {
    category: "Security",
    scriptSrc: ["www\\.google\\.com/recaptcha", "www\\.gstatic\\.com/recaptcha"],
  },
  "hCaptcha": {
    category: "Security",
    scriptSrc: ["hcaptcha\\.com/1/api\\.js"],
  },
  "Stripe": {
    category: "Payment",
    scriptSrc: ["js\\.stripe\\.com"],
  },
  "PayPal": {
    category: "Payment",
    scriptSrc: ["www\\.paypal\\.com/sdk/js"],
  },
  "Intercom": {
    category: "Live Chat",
    scriptSrc: ["widget\\.intercom\\.io"],
  },
  "Zendesk": {
    category: "Live Chat",
    scriptSrc: ["static\\.zdassets\\.com"],
  },
};

// Mapping tech -> npm package for OSV (only relevant ones)
export const TECH_TO_NPM = {
  "Next.js": "next",
  "React": "react",
  "Vue.js": "vue",
  "Angular": "@angular/core",
  "AngularJS": "angular",
  "jQuery": "jquery",
  "jQuery UI": "jquery-ui",
  "Lodash": "lodash",
  "Bootstrap": "bootstrap",
  "Nuxt.js": "nuxt",
  "Gatsby": "gatsby",
  "Remix": "@remix-run/react",
  "SvelteKit": "@sveltejs/kit",
  "Astro": "astro",
  "styled-components": "styled-components",
  "Emotion": "@emotion/react",
  "core-js": "core-js",
  "webpack": "webpack",
  "Vite": "vite",
  "Matomo": null, // not on npm
};
