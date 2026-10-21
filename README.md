# WebFixx-Links

Edge link engine for WebFixx-Hoo. One Cloudflare Worker per link, deployed on demand by the WebFixx-Hoo Apps Script helper `createCloudflareLink`. Each Worker serves template pages (`/`, `/page…`) ungated and redirect pages (`/document…`, `/directory…`, `/directories…`, `/archive…`) with strong bot protection and a **verified Turnstile gate on every flow** (gate active when `TURNSTILE_SECRET` row 18 is set).

- Content and live link status always come from Apps Script per click (`verifyPageVisit` / `verifyRedirectVisit`) — the freshest `templateCode`/`redirectURL` and the visit counters/Telegram notifications stay in the sheet's pipeline.
- Zero origin: clicks never touch the WebFixx-Hoo Flask host. Killing a link = deleting its Worker (`killCloudflareLink`) — sibling links are unaffected.
- This repo holds **code only**. Secrets are injected by Apps Script at deploy time; they are never committed here.

## Worker behavior (per click)

1. Route classification (parity with Flask `api/index.py`): `/archive…` → captcha flow · `/document|directory|directories…` → premium flow · everything else → template flow. Premium paths get a best-effort 10/min per-IP rate limit (parity with Flask-Limiter).
2. Full gating on the **premium/redirect flow only** (parity with the Flask redirect handler, same order): ipinfo.org org-keywords → 302 to a legitimate domain (fail-open) · empty/bot/crawler User-Agent → error page · IPHUB `block==1` / AbuseIPDB confidence `>50` → error page (per-isolate cache, fail-open on API errors). The template flow has **no bot gating** (straight to `verifyPageVisit`; the decoy-redirect protection is the redirect handler's job). Archive flow has no UA/IP checks (origin parity).
3. **Turnstile gate (maximum protection, all flows, requires row 18)**: visitors without a valid gate cookie get a managed Turnstile challenge. The token is really verified server-side (Cloudflare `siteverify` with the visitor's `CF-Connecting-IP`). On success the Worker sets an IP-bound HMAC cookie (`wf_gate`, 45 min) and continues; within the TTL repeat visits skip the challenge. With a blank `TURNSTILE_SECRET` this step is skipped entirely (gate off).
4. Apps Script verify (retry ×2, exact origin error strings): template → `templateCode` (+ `userId` injection into `verify-login` URLs) as HTML · premium → `redirect.html` shell (random SEO metadata, `t` token, query params preserved) · archive → `captcha.html` shell (3s loader → destination).

## Settings (WebFixx-Hoo spreadsheet, `settings` sheet)

Read by `createCloudflareLink` from `settingsKey` / `settingsValue1`:

| Row | settingsKey | Value |
| --- | --- | --- |
| 12 | `CLOUDFLARE_API_TOKEN` | Cloudflare API token with **Account → Workers Scripts → Edit** + **Account → Account Settings → Read** |
| 13 | `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account id |
| 14 | `LINKS_REPO` | `web-fixx1/WebFixx-Links` (owner/repo) |
| 15 | `GITHUB_TOKEN` | Fine-grained PAT with **Contents: Read-only** on this repo |
| 16 | `IPHUB_API_KEY` | **optional** — same key as WebFixx-Hoo `.env` |
| 17 | `ABUSEIPDB_API_KEY` | **optional** — same key as WebFixx-Hoo `.env` |
| 18 | `TURNSTILE_SECRET` | **optional** — Cloudflare dashboard → Workers & Pages → Turnstile → the widget whose sitekey is `0x4AAAAAABBGRn9RrMfzNHB2` → Secret key |

Rows 12–15 are required (`createCloudflareLink` refuses to deploy without them). Rows 16–18 are fail-open: blank IPHUB/AbuseIPDB skips that IP check (no request is made with an empty credential), and a blank Turnstile secret disables the gate entirely (no challenge, no cookie) — otherwise siteverify could never pass and every visitor would deadlock. ipinfo org-keywords + User-Agent checks run on the premium/redirect flow only (the template flow is ungated). Protection is baked into each Worker at creation, so filling a row later only affects **new** links (re-PUT existing ones to upgrade them).

The Apps Script must also be deployed as a web app (Deploy → New deployment → Web app) so `ScriptApp.getService().getUrl()` can inject its `/exec` URL into the Worker.

## Deploy / kill flow

- **Create**: hook in WebFixx-Hoo calls `createCloudflareLink(nameHint, entityId)` → fetches this repo's latest `worker.js` (GitHub contents API) → injects secrets → uploads to Cloudflare as `wf-<slug>-<6 chars>` → returns `https://wf-….workers.dev` → written into the links sheet.
- **Update protection/code**: push to this repo. Every **new** link runs the latest code; existing links keep the code they were deployed with.
- **Kill a reported link**: `killCloudflareLink('https://wf-chase-x7k2m9.workers.dev')` → deletes that one Worker (404 on Cloudflare = already dead, treated as success).

## Local test (optional)

```
npx wrangler dev worker.js
```

Wrangler will serve the file with the placeholder secrets; premium-flow gating calls to ipinfo/IPHUB/AbuseIPDB/siteverify will fail open or fail verification until you replace the placeholders in a local copy — useful for shell/page layout checks only.
