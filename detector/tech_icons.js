// Mapping tech name -> Simple Icons slug.
// Icons loaded from https://cdn.simpleicons.org/{slug}/{color}
// If slug is null, we show a placeholder instead.

export const TECH_ICON_SLUGS = {
  // Servers
  "Apache": "apache",
  "Nginx": "nginx",
  "Microsoft IIS": null,
  "LiteSpeed": null,
  "Caddy": null,
  "OpenResty": null,
  "Tomcat": "apachetomcat",
  "Jetty": null,
  "Envoy": "envoyproxy",

  // Runtimes
  "PHP": "php",
  "ASP.NET": "dotnet",
  "ASP.NET MVC": "dotnet",
  "Java": "openjdk",
  "Node.js": "nodedotjs",

  // Frameworks web
  "Next.js": "nextdotjs",
  "Nuxt.js": "nuxtdotjs",
  "Gatsby": "gatsby",
  "Remix": "remix",
  "SvelteKit": "svelte",
  "Astro": "astro",

  // JS frameworks
  "React": "react",
  "Vue.js": "vuedotjs",
  "Angular": "angular",
  "AngularJS": "angularjs",
  "jQuery": "jquery",
  "jQuery UI": "jquery",
  "Lodash": "lodash",

  // UI / CSS
  "Bootstrap": "bootstrap",
  "Tailwind CSS": "tailwindcss",
  "Material-UI": "mui",
  "Ant Design": "antdesign",
  "Chakra UI": "chakraui",
  "styled-components": "styledcomponents",
  "Emotion": null,

  // Build
  "webpack": "webpack",
  "Vite": "vite",
  "Parcel": null,
  "core-js": "javascript",

  // CMS
  "WordPress": "wordpress",
  "Drupal": "drupal",
  "Joomla": "joomla",
  "Ghost": "ghost",
  "Sitecore": null,
  "Adobe Experience Manager": "adobe",

  // E-commerce
  "Shopify": "shopify",
  "Magento": "magento",
  "PrestaShop": "prestashop",
  "WooCommerce": "woocommerce",

  // Frameworks backend
  "Laravel": "laravel",
  "Symfony": "symfony",
  "CodeIgniter": "codeigniter",
  "Django": "django",
  "Flask": "flask",

  // Analytics
  "Google Analytics": "googleanalytics",
  "Google Tag Manager": "googletagmanager",
  "Matomo": "matomo",
  "Hotjar": "hotjar",
  "Mixpanel": "mixpanel",
  "Segment": "segment",
  "Facebook Pixel": "meta",
  "Adobe Analytics": "adobe",
  "New Relic": "newrelic",
  "Datadog": "datadog",

  // CDN / Cloud
  "Cloudflare": "cloudflare",
  "CloudFront": "amazonaws",
  "Fastly": "fastly",
  "Akamai": "akamai",
  "Amazon S3": "amazons3",
  "Vercel": "vercel",
  "Netlify": "netlify",
  "Heroku": "heroku",
  "jsDelivr": "jsdelivr",
  "unpkg": null,
  "Cloudflare CDN": "cloudflare",

  // Privacy
  "OneTrust": null,
  "Cookiebot": null,
  "Didomi": null,

  // Fonts
  "Google Fonts": "googlefonts",
  "Adobe Fonts": "adobe",
  "Font Awesome": "fontawesome",

  // Security
  "reCAPTCHA": "googleforms",
  "hCaptcha": "hcaptcha",

  // Payment
  "Stripe": "stripe",
  "PayPal": "paypal",

  // Chat
  "Intercom": "intercom",
  "Zendesk": "zendesk",

  // New ones (added via DOM probe)
  "Piano Analytics": null,
  "Dynatrace": "dynatrace",
  "Contentsquare": null,
  "Sentry": "sentry",
  "Datadog RUM": "datadog",
  "Swiper": "swiper",
  "React Native for Web": "react",
  "Moment.js": null,
  "Day.js": null,
  "axios": "axios",
  "Lodash": "lodash",
  "TCF": null,
  "Google Font API": "googlefonts",
};

// Official colors (hex without #) to pass to Simple Icons URL
export const TECH_ICON_COLORS = {
  "Apache": "D22128",
  "Nginx": "009639",
  "PHP": "777BB4",
  "Node.js": "339933",
  "Next.js": "000000",
  "React": "61DAFB",
  "Vue.js": "4FC08D",
  "Angular": "DD0031",
  "jQuery": "0769AD",
  "Bootstrap": "7952B3",
  "Tailwind CSS": "06B6D4",
  "WordPress": "21759B",
  "Drupal": "0678BE",
  "Joomla": "5091CD",
  "Laravel": "FF2D20",
  "Symfony": "000000",
  "Django": "092E20",
  "webpack": "8DD6F9",
  "Vite": "646CFF",
  "Cloudflare": "F38020",
  "Vercel": "000000",
  "Netlify": "00C7B7",
  "Stripe": "635BFF",
  "Google Analytics": "E37400",
  "Matomo": "3152A0",
  "Shopify": "7AB55C",
};

/**
 * Returns the Simple Icons URL for a tech, or null.
 * Colored by default, white fallback.
 */
export function getTechIconUrl(techName, whiteFallback = true) {
  const slug = TECH_ICON_SLUGS[techName];
  if (!slug) return null;
  const color = TECH_ICON_COLORS[techName];
  if (color) {
    return `https://cdn.simpleicons.org/${slug}/${color}`;
  }
  // White for dark mode, black for light theme
  return whiteFallback
    ? `https://cdn.simpleicons.org/${slug}/FFFFFF`
    : `https://cdn.simpleicons.org/${slug}/000000`;
}

/**
 * Returns initials for a placeholder when no icon is available.
 */
export function getTechInitials(techName) {
  if (!techName) return "?";
  const parts = techName.split(/[\s.-]/).filter(Boolean);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}
