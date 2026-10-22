/* Surface — client logic. Vanilla JS, no libraries, no build step.
 *
 * Security: every value in a report comes from an arbitrary third-party
 * server and is treated as untrusted. Report data only ever reaches the DOM
 * through textContent, createTextNode or setAttribute on inert attributes.
 * Icons are cloned from static <template> elements in index.html.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Example report (Contract 2). Same ids, titles, evidence, order, score and
  // counts that api/_lib/analyze.js produces for this snapshot:
  //   server: nginx/1.18.0, x-powered-by: PHP/7.4.3, cf-ray present,
  //   HSTS max-age=31536000; includeSubDomains, x-content-type-options: nosniff,
  //   no CSP, no X-Frame-Options, no Referrer-Policy, no Permissions-Policy,
  //   Set-Cookie: PHPSESSID (Secure; HttpOnly), theme (Secure; SameSite=Lax),
  //   http:// -> 301 to https, valid Let's Encrypt cert with 84 days left.
  // Scoring: 4 warn x 8 + 5 info x 1 = 37 -> "moderate" (25-54).
  // test/sample.test.js fails when this drifts from analyze(); regenerate it then.
  // ---------------------------------------------------------------------------
  var SAMPLE_REPORT = {
    "target": {
      "input": "example.com",
      "url": "https://example.com/",
      "host": "example.com",
      "status": 200,
      "timingMs": 312,
      "redirects": 0,
      "scannedAt": "2026-10-22T15:20:00.000Z"
    },
    "score": 37,
    "level": "moderate",
    "counts": {
      "total": 18,
      "crit": 0,
      "warn": 4,
      "info": 5,
      "ok": 9
    },
    "findings": [
      {
        "id": "server-header",
        "category": "versions",
        "severity": "warn",
        "title": "Server version exposed",
        "desc": "The exact version is public, so anyone can look up known security holes for it.",
        "evidence": "Server: nginx/1.18.0",
        "fix": "Hide the version number. Nginx: add `server_tokens off;` to the `http` block; Apache: set `ServerTokens Prod` and `ServerSignature Off`, then reload. IIS on Windows Server 2019 or later: add `<security><requestFiltering removeServerHeader=\"true\" /></security>` under `<system.webServer>` in web.config; older IIS needs a URL Rewrite outbound rule that blanks `RESPONSE_SERVER`."
      },
      {
        "id": "powered-by",
        "category": "versions",
        "severity": "warn",
        "title": "Backend version leaked",
        "desc": "The exact backend version is public, so anyone can check it against lists of known exploits.",
        "evidence": "X-Powered-By: PHP/7.4.3",
        "fix": "Remove the header. PHP: set `expose_php = Off` in php.ini; Express: call `app.disable('x-powered-by')`; Next.js: set `poweredByHeader: false` in next.config.js. On IIS, add `<remove name=\"X-Powered-By\" />` under `customHeaders` in web.config."
      },
      {
        "id": "csp",
        "category": "headers",
        "severity": "warn",
        "title": "No content security policy",
        "desc": "Nothing limits which scripts can run on your pages, so a single injected script can steal data or sessions.",
        "evidence": "CSP: —",
        "fix": "Start with `Content-Security-Policy: default-src 'self'` and add the domains your pages really load from. Nginx: `add_header Content-Security-Policy \"default-src 'self'\" always;`; Apache: `Header always set Content-Security-Policy \"default-src 'self'\"`; Next.js: return it from `headers()` in next.config.js. Try it as `Content-Security-Policy-Report-Only` first so nothing breaks."
      },
      {
        "id": "clickjacking",
        "category": "headers",
        "severity": "warn",
        "title": "Clickjacking protection missing",
        "desc": "Another site can load your page in a hidden frame and trick visitors into clicking things they can't see.",
        "evidence": "X-Frame-Options: —",
        "fix": "Add `Content-Security-Policy: frame-ancestors 'self'`, or `X-Frame-Options: SAMEORIGIN` for older browsers. Nginx: `add_header X-Frame-Options SAMEORIGIN always;`; Apache: `Header always set X-Frame-Options SAMEORIGIN`; Express: `res.set('X-Frame-Options', 'SAMEORIGIN')`. Next.js: return it from `headers()` in next.config.js."
      },
      {
        "id": "referrer-policy",
        "category": "headers",
        "severity": "info",
        "title": "No referrer policy",
        "desc": "Modern browsers default to a safe setting that hides your full page addresses from other sites, so this is low risk.",
        "evidence": "Referrer-Policy: —",
        "fix": "Set it explicitly so older browsers behave the same: `Referrer-Policy: strict-origin-when-cross-origin`. Nginx: `add_header Referrer-Policy strict-origin-when-cross-origin always;`; Apache: `Header always set Referrer-Policy strict-origin-when-cross-origin`."
      },
      {
        "id": "permissions-policy",
        "category": "headers",
        "severity": "info",
        "title": "No permissions policy",
        "desc": "You haven't limited which browser features, such as camera or location, your pages and embeds may ask for.",
        "evidence": "Permissions-Policy: —",
        "fix": "Switch off features you don't use, for example `Permissions-Policy: camera=(), microphone=(), geolocation=()`. Nginx: `add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;`; Apache: `Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"`."
      },
      {
        "id": "cookie-httponly",
        "category": "cookies",
        "severity": "info",
        "title": "Some cookies readable by scripts",
        "desc": "Scripts can read some cookies, which is fine for preferences but not for anything that identifies a visitor.",
        "evidence": "theme",
        "fix": "Add `HttpOnly` to every cookie your own JavaScript doesn't need to read."
      },
      {
        "id": "cookie-samesite",
        "category": "cookies",
        "severity": "info",
        "title": "Cookies without SameSite",
        "desc": "Chrome and Edge treat these as Lax by default but other browsers may not, so setting it yourself keeps behavior the same everywhere.",
        "evidence": "PHPSESSID",
        "fix": "Add `SameSite=Lax` to your cookies, or `SameSite=Strict` for admin sessions. PHP: `session.cookie_samesite = \"Lax\"`; Express: `cookie: { sameSite: 'lax' }`; nginx 1.19.3+: put all flags for a cookie on one line, such as `proxy_cookie_flags PHPSESSID secure httponly samesite=lax;` (drop `httponly` if your own JavaScript reads it), because nginx applies only the first line that matches a cookie."
      },
      {
        "id": "hosting",
        "category": "disclosure",
        "severity": "info",
        "title": "Hosting provider identified",
        "desc": "Anyone can see that Cloudflare serves your site, which is normal and gives attackers only a small hint.",
        "evidence": "CF-Ray: 8d2f1c3b9a7e4f21-FRA",
        "fix": "No action needed. Make sure your origin server only accepts traffic from Cloudflare, so nobody can bypass it by finding the server's own address."
      },
      {
        "id": "fingerprints",
        "category": "versions",
        "severity": "ok",
        "title": "No CMS fingerprints",
        "desc": "Your responses don't carry headers that point to a specific CMS or framework.",
        "evidence": "CMS headers: —",
        "fix": "Nothing to change."
      },
      {
        "id": "https",
        "category": "transport",
        "severity": "ok",
        "title": "Served over HTTPS",
        "desc": "Pages travel encrypted, so nobody between your visitors and your server can read or change them.",
        "evidence": "TLS: TLSv1.3",
        "fix": "Nothing to change. Keep certificate renewal automatic so HTTPS never lapses."
      },
      {
        "id": "http-redirect",
        "category": "transport",
        "severity": "ok",
        "title": "HTTP redirects to HTTPS",
        "desc": "Visitors who type your address without https:// are sent straight to the secure version.",
        "evidence": "301 → https",
        "fix": "Nothing to change."
      },
      {
        "id": "hsts",
        "category": "transport",
        "severity": "ok",
        "title": "HSTS enabled",
        "desc": "Browsers remember to use HTTPS for your site, even when someone types the plain address.",
        "evidence": "max-age=31536000; includeSubDomains",
        "fix": "Nothing to change. To have browsers enforce HTTPS before the very first visit, add `preload` (with a `max-age` of at least 31536000) and submit your domain at hstspreload.org."
      },
      {
        "id": "certificate",
        "category": "transport",
        "severity": "ok",
        "title": "Certificate valid",
        "desc": "Browsers trust your certificate and it has plenty of time left before it expires.",
        "evidence": "84 days left · Let's Encrypt",
        "fix": "Nothing to change. Keep automatic renewal on so it never lapses."
      },
      {
        "id": "nosniff",
        "category": "headers",
        "severity": "ok",
        "title": "MIME sniffing blocked",
        "desc": "Browsers use the file types you declare instead of guessing.",
        "evidence": "X-Content-Type-Options: nosniff",
        "fix": "Nothing to change."
      },
      {
        "id": "cookie-secure",
        "category": "cookies",
        "severity": "ok",
        "title": "Cookies marked Secure",
        "desc": "Your cookies are only ever sent over encrypted connections.",
        "evidence": "2 cookies, all Secure",
        "fix": "Nothing to change."
      },
      {
        "id": "cors",
        "category": "cors",
        "severity": "ok",
        "title": "No cross-origin access",
        "desc": "Your page sends no CORS headers to a normal request, so other websites can't read it from a visitor's browser.",
        "evidence": "ACAO: —",
        "fix": "Nothing to change."
      },
      {
        "id": "debug-headers",
        "category": "disclosure",
        "severity": "ok",
        "title": "No debug headers",
        "desc": "Responses don't carry debug tokens or the names of internal servers.",
        "evidence": "X-Debug-Token: —",
        "fix": "Nothing to change."
      }
    ]
  };

  // ---------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------
  var SEVERITIES = ['crit', 'warn', 'info', 'ok'];
  var SEV_LABEL = { crit: 'Urgent', warn: 'To fix', info: 'Info', ok: 'Good' };
  var LEVELS = ['low', 'moderate', 'high'];
  var LEVEL_LABEL = { low: 'Low', moderate: 'Moderate', high: 'High' };
  var FILTERS = ['all', 'crit', 'warn', 'info', 'ok'];
  var CLIENT_TIMEOUT_MS = 25000;
  var MAX_FINDINGS = 200;

  var MSG_OFFLINE = 'Couldn\'t reach Surface. Check your connection and try again.';
  var MSG_NOT_FOUND = 'The checker isn\'t available right now. Try again later.';
  var MSG_TIMEOUT = 'The check took too long. Try again in a moment.';
  var MSG_GENERIC = 'Something went wrong on our side. Try again.';
  var MSG_EMPTY = 'Enter a website address.';
  var MSG_CONSENT = 'Confirm you own this site or have permission.';
  var MSG_TOO_LONG = 'That address is too long. Try just the domain, like example.com.';

  var ERROR_MESSAGES = {
    invalid_url: 'That doesn\'t look like a website address. Try something like example.com.',
    blocked_target: 'That address points to a private or local network, so it can\'t be checked.',
    rate_limited: 'Too many checks in a short time. Wait a minute and try again.',
    dns_failed: 'We couldn\'t find that domain. Check the spelling.',
    unreachable: 'The site didn\'t respond. It may be down or blocking automated checks.',
    timeout: 'The site took too long to answer. Try again in a moment.',
    method_not_allowed: 'Use GET.',
    forbidden: 'This request was blocked. Reload the page and try again.',
    internal: MSG_GENERIC
  };

  // Server errors about the address itself: the input gets marked invalid.
  var INPUT_ERROR_CODES = ['invalid_url', 'blocked_target', 'dns_failed'];

  /** Message for a response without a usable JSON body (proxy, CDN or platform error page). */
  function messageForStatus(status) {
    if (status === 429) return ERROR_MESSAGES.rate_limited;
    if (status === 408 || status === 504) return MSG_TIMEOUT;
    if (status === 403) return ERROR_MESSAGES.forbidden;
    if (status === 404) return MSG_NOT_FOUND;
    return MSG_GENERIC;
  }

  // ---------------------------------------------------------------------------
  // DOM references
  // ---------------------------------------------------------------------------
  function $(id) { return document.getElementById(id); }

  var form = $('scan-form');
  var input = $('scan-input');
  var field = $('scan-field');
  var consent = $('scan-consent');
  var agree = $('scan-agree');
  var submitBtn = $('scan-submit');
  var submitLabel = $('scan-submit-label');
  var alertSlot = $('scan-alert');
  var statusLine = $('scan-status');

  var reportSection = $('report');
  var reportTitle = $('report-title');
  var reportFav = $('report-fav');
  var reportUrl = $('report-url');
  var reportExample = $('report-example');
  var reportHttp = $('report-http');
  var reportWhen = $('report-when');
  var reportExampleNote = $('report-example-note');
  var levelPill = $('report-level');
  var levelText = $('report-level-text');
  var meterNum = $('meter-num');
  var meterScore = $('meter-score');
  var meterTrack = $('meter-track');
  var meterFill = $('meter-fill');
  var statCrit = $('stat-crit');
  var statWarn = $('stat-warn');
  var statInfo = $('stat-info');
  var statOk = $('stat-ok');
  var filterBar = $('filter-bar');
  var findingsCount = $('findings-count');
  var findingsList = $('findings-list');
  var findingsSkeleton = $('findings-skeleton');

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  // Control characters and bidi overrides could disguise evidence text.
  var UNSAFE_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/g;

  /** Untrusted value -> plain, trimmed, length-capped string ('' when unusable). */
  function clean(value, max) {
    var s;
    if (typeof value === 'string') s = value;
    else if (typeof value === 'number' && isFinite(value)) s = String(value);
    else return '';
    s = s.replace(UNSAFE_CHARS, '').replace(/\s+/g, ' ').trim();
    if (max && s.length > max) s = s.slice(0, max - 1).trimEnd() + '…';
    return s;
  }

  function isCount(n) {
    return typeof n === 'number' && isFinite(n) && n >= 0 && Math.floor(n) === n;
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function icon(templateId) {
    var tpl = $(templateId);
    if (!tpl || !tpl.content || !tpl.content.firstElementChild) return document.createTextNode('');
    return tpl.content.firstElementChild.cloneNode(true);
  }

  function prefersReducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  /** Appends text to `parent`, turning `backtick spans` into <code> nodes. */
  function appendCodeText(parent, text) {
    var parts = text.split('`');
    // An odd number of backticks leaves the last one unmatched: keep it literal.
    if (parts.length % 2 === 0) {
      var tail = parts.pop();
      parts[parts.length - 1] += '`' + tail;
    }
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      if (i % 2 === 1) parent.appendChild(el('code', null, parts[i]));
      else parent.appendChild(document.createTextNode(parts[i]));
    }
  }

  function hostFrom(urlString) {
    try { return new URL(urlString).hostname; } catch (e) { return ''; }
  }

  function displayUrl(url) {
    // "https://example.com/" -> "https://example.com"
    return /^https?:\/\/[^/?#]+\/$/i.test(url) ? url.slice(0, -1) : url;
  }

  function formatScannedAt(iso) {
    var d = new Date(iso);
    if (!iso || isNaN(d.getTime())) return null;
    var now = new Date();
    var sameDay = d.getFullYear() === now.getFullYear() &&
      d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
    var text;
    try {
      text = sameDay
        ? d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
        : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
    } catch (e) {
      text = d.toLocaleString();
    }
    return { text: text, iso: d.toISOString() };
  }

  // ---------------------------------------------------------------------------
  // Report normalization: every field is untrusted and possibly missing.
  // ---------------------------------------------------------------------------
  function normalizeFinding(raw) {
    if (!raw || typeof raw !== 'object') return null;
    var sev = typeof raw.severity === 'string' ? raw.severity.toLowerCase() : '';
    if (SEVERITIES.indexOf(sev) === -1) sev = 'info';
    return {
      id: clean(raw.id, 80),
      severity: sev,
      title: clean(raw.title, 140) || 'Untitled finding',
      desc: clean(raw.desc, 400),
      evidence: clean(raw.evidence, 240),
      fix: clean(raw.fix, 1500)
    };
  }

  function normalizeReport(raw) {
    var r = raw && typeof raw === 'object' ? raw : {};
    var t = r.target && typeof r.target === 'object' ? r.target : {};

    var findings = [];
    if (Array.isArray(r.findings)) {
      for (var i = 0; i < r.findings.length && findings.length < MAX_FINDINGS; i++) {
        var f = normalizeFinding(r.findings[i]);
        if (f) findings.push(f);
      }
    }
    // Stable sort by severity (the API already sorts; this is a safety net).
    findings = findings
      .map(function (f, idx) { return { f: f, idx: idx }; })
      .sort(function (a, b) {
        return (SEVERITIES.indexOf(a.f.severity) - SEVERITIES.indexOf(b.f.severity)) || (a.idx - b.idx);
      })
      .map(function (x) { return x.f; });

    var derived = { total: findings.length, crit: 0, warn: 0, info: 0, ok: 0 };
    findings.forEach(function (f) { derived[f.severity]++; });

    var rc = r.counts && typeof r.counts === 'object' ? r.counts : {};
    var counts = {};
    ['total', 'crit', 'warn', 'info', 'ok'].forEach(function (k) {
      counts[k] = isCount(rc[k]) ? rc[k] : derived[k];
    });

    var score;
    if (typeof r.score === 'number' && isFinite(r.score)) {
      score = Math.round(Math.min(100, Math.max(0, r.score)));
    } else {
      score = Math.min(100, 20 * counts.crit + 8 * counts.warn + counts.info);
    }

    var level = typeof r.level === 'string' ? r.level.toLowerCase() : '';
    if (LEVELS.indexOf(level) === -1) {
      level = score < 25 ? 'low' : score < 55 ? 'moderate' : 'high';
    }

    var url = clean(t.url, 2048);
    var host = clean(t.host, 253) || hostFrom(url) || clean(t.input, 253);
    var status = isCount(t.status) && t.status >= 100 && t.status <= 599 ? t.status : null;
    var timingMs = typeof t.timingMs === 'number' && isFinite(t.timingMs) && t.timingMs >= 0
      ? Math.round(t.timingMs) : null;

    return {
      target: {
        input: clean(t.input, 2048),
        url: url || host,
        host: host,
        status: status,
        timingMs: timingMs,
        scannedAt: typeof t.scannedAt === 'string' ? t.scannedAt : ''
      },
      score: score,
      level: level,
      counts: counts,
      derived: derived,
      findings: findings
    };
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------
  var state = {
    report: null,      // normalized report currently shown
    example: true,     // true while the SAMPLE_REPORT is shown
    filter: 'all',
    busy: false,
    renderSeq: 0,
    presetHost: ''     // host from a ?url= link, named in the example note
  };

  function setLevelClass(node, level) {
    LEVELS.forEach(function (l) { node.classList.remove('lvl-' + l); });
    node.classList.add('lvl-' + level);
  }

  function renderHead(report, isExample) {
    var t = report.target;
    var letterSource = (t.host || '').replace(/^[^0-9a-z]+/i, '');
    reportFav.textContent = letterSource ? letterSource.charAt(0).toUpperCase() : '◆';
    reportUrl.textContent = displayUrl(t.url) || 'Unknown address';

    reportExample.hidden = !isExample;
    reportExampleNote.hidden = !isExample;
    reportExampleNote.textContent = state.presetHost
      ? 'Tick the box and press Check my site to check ' + state.presetHost + '.'
      : 'This is an example report. Run a check to see yours.';

    var httpParts = [];
    if (t.status !== null) httpParts.push('HTTP ' + t.status);
    if (t.timingMs !== null) httpParts.push(t.timingMs + ' ms');
    reportHttp.textContent = httpParts.join(' · ');
    reportHttp.hidden = httpParts.length === 0;

    var when = isExample ? null : formatScannedAt(t.scannedAt);
    clear(reportWhen);
    if (when) {
      reportWhen.appendChild(document.createTextNode('Scanned '));
      var time = el('time', null, when.text);
      time.setAttribute('datetime', when.iso);
      reportWhen.appendChild(time);
    }
    reportWhen.hidden = !when;

    setLevelClass(levelPill, report.level);
    levelText.textContent = 'Exposure: ' + LEVEL_LABEL[report.level];
  }

  function renderScore(report) {
    meterScore.textContent = String(report.score);
    setLevelClass(meterNum, report.level);
    setLevelClass(meterFill, report.level);
    meterFill.style.width = report.score + '%';
    meterTrack.setAttribute('aria-valuenow', String(report.score));
    meterTrack.setAttribute('aria-valuetext',
      report.score + ' out of 100, ' + LEVEL_LABEL[report.level] + ' exposure');

    // Same numbers as the filter bar, so the four tiles always add up to "All".
    statCrit.textContent = String(report.derived.crit);
    statWarn.textContent = String(report.derived.warn);
    statInfo.textContent = String(report.derived.info);
    statOk.textContent = String(report.derived.ok);
  }

  function renderFilterCounts(report) {
    var buttons = filterBar.querySelectorAll('.seg-btn');
    for (var i = 0; i < buttons.length; i++) {
      var btn = buttons[i];
      var key = btn.getAttribute('data-filter');
      var n = key === 'all' ? report.derived.total : (report.derived[key] || 0);
      var countEl = btn.querySelector('.seg-n');
      if (countEl) countEl.textContent = String(n);
      btn.disabled = key !== 'all' && n === 0;
    }
  }

  function buildFindingRow(f, idx, seq) {
    var rowId = 'finding-' + seq + '-' + idx;
    var panelId = 'fix-' + seq + '-' + idx;
    var sevId = rowId + '-sev';
    var titleId = rowId + '-title';
    var described = [];

    var item = el('div', 'f-item');
    item.setAttribute('role', 'listitem');
    item.setAttribute('data-sev', f.severity);

    var row = el('div', 'f-row');
    row.id = rowId;
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');
    row.setAttribute('aria-expanded', 'false');
    row.setAttribute('aria-controls', panelId);

    var sev = el('span', 'sev sev-' + f.severity);
    sev.id = sevId;
    sev.appendChild(icon('tpl-ic-' + f.severity));
    sev.appendChild(document.createTextNode(SEV_LABEL[f.severity]));
    row.appendChild(sev);

    var main = el('span', 'f-main');
    var title = el('span', 'f-title', f.title);
    title.id = titleId;
    main.appendChild(title);
    if (f.desc) {
      var desc = el('span', 'f-desc', f.desc);
      desc.id = rowId + '-desc';
      described.push(desc.id);
      main.appendChild(desc);
    }
    row.appendChild(main);

    if (f.evidence) {
      var val = el('span', 'f-val', f.evidence);
      val.id = rowId + '-val';
      described.push(val.id);
      val.setAttribute('title', f.evidence);
      row.appendChild(val);
    }

    // Short name ("Urgent Server version exposed"); the rest is the description.
    row.setAttribute('aria-labelledby', sevId + ' ' + titleId);
    if (described.length) row.setAttribute('aria-describedby', described.join(' '));

    var chev = icon('tpl-chev');
    if (chev.classList) chev.classList.add('f-chev');
    row.appendChild(chev);

    var panel = el('div', 'f-fix');
    panel.id = panelId;
    panel.hidden = true;
    var inner = el('div', 'f-fix-inner');
    inner.appendChild(el('div', 'f-fix-label', 'How to fix'));
    var text = el('p', 'f-fix-text');
    appendCodeText(text, f.fix || (f.severity === 'ok'
      ? 'Nothing to change.'
      : 'No fix details came back for this finding.'));
    inner.appendChild(text);
    panel.appendChild(inner);

    item.appendChild(row);
    item.appendChild(panel);
    return item;
  }

  function renderFindings(report) {
    var seq = ++state.renderSeq;
    var frag = document.createDocumentFragment();
    if (report.findings.length === 0) {
      var empty = el('p', 'f-empty', 'No findings came back for this site.');
      empty.setAttribute('role', 'listitem');
      frag.appendChild(empty);
    } else {
      report.findings.forEach(function (f, i) {
        frag.appendChild(buildFindingRow(f, i, seq));
      });
    }
    clear(findingsList);
    findingsList.appendChild(frag);
  }

  function applyFilter(filter) {
    if (FILTERS.indexOf(filter) === -1) filter = 'all';
    state.filter = filter;

    var buttons = filterBar.querySelectorAll('.seg-btn');
    for (var i = 0; i < buttons.length; i++) {
      var on = buttons[i].getAttribute('data-filter') === filter;
      buttons[i].classList.toggle('active', on);
      buttons[i].setAttribute('aria-pressed', on ? 'true' : 'false');
    }

    var items = findingsList.querySelectorAll('.f-item');
    var shown = 0;
    for (var j = 0; j < items.length; j++) {
      var show = filter === 'all' || items[j].getAttribute('data-sev') === filter;
      items[j].hidden = !show;
      if (show) shown++;
    }
    updateCount(shown, items.length);
  }

  function updateCount(shown, total) {
    if (state.filter === 'all' || shown === total) {
      findingsCount.textContent = total + (total === 1 ? ' finding' : ' findings');
    } else {
      findingsCount.textContent = shown + ' of ' + total + ' shown';
    }
  }

  function renderReport(report, isExample) {
    state.report = report;
    state.example = isExample;
    renderHead(report, isExample);
    renderScore(report);
    renderFilterCounts(report);
    renderFindings(report);
    applyFilter('all');
  }

  // ---------------------------------------------------------------------------
  // Finding rows: click, Enter, Space toggle the "How to fix" panel
  // ---------------------------------------------------------------------------
  function toggleRow(row) {
    var panel = $(row.getAttribute('aria-controls'));
    if (!panel) return;
    var open = row.getAttribute('aria-expanded') !== 'true';
    row.setAttribute('aria-expanded', open ? 'true' : 'false');
    panel.hidden = !open;
    if (row.parentNode) row.parentNode.classList.toggle('open', open);
  }

  findingsList.addEventListener('click', function (e) {
    var row = e.target.closest ? e.target.closest('.f-row') : null;
    if (!row || !findingsList.contains(row)) return;
    // Let people select and copy evidence text without toggling the row.
    var sel = window.getSelection ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && row.contains(sel.anchorNode)) return;
    toggleRow(row);
  });

  findingsList.addEventListener('keydown', function (e) {
    var row = e.target;
    if (!row.classList || !row.classList.contains('f-row')) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      toggleRow(row);
    } else if (e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault(); // stop the page from scrolling; toggle on keyup
    }
  });

  findingsList.addEventListener('keyup', function (e) {
    var row = e.target;
    if (!row.classList || !row.classList.contains('f-row')) return;
    if (e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      toggleRow(row);
    }
  });

  filterBar.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('.seg-btn') : null;
    if (!btn || btn.disabled || state.busy) return;
    applyFilter(btn.getAttribute('data-filter'));
    setStatus(findingsCount.textContent);
  });

  // ---------------------------------------------------------------------------
  // Form: validation, loading, success, error
  // ---------------------------------------------------------------------------
  function setStatus(text) {
    statusLine.textContent = text || '';
  }

  function clearInvalid() {
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
    consent.removeAttribute('aria-invalid');
    consent.removeAttribute('aria-describedby');
    field.classList.remove('is-invalid');
    agree.classList.remove('is-invalid');
  }

  function clearError() {
    clear(alertSlot);
    clearInvalid();
  }

  /** Shows an inline alert under the form. `target` = field to mark invalid. */
  function showError(message, target) {
    clear(alertSlot);
    var box = el('div', 'alert');
    box.id = 'scan-error';
    box.setAttribute('role', 'alert');
    box.appendChild(icon('tpl-ic-alert'));
    box.appendChild(el('span', 'alert-text', message));
    alertSlot.appendChild(box);

    if (target) {
      target.setAttribute('aria-invalid', 'true');
      target.setAttribute('aria-describedby', 'scan-error');
      if (target === input) field.classList.add('is-invalid');
      if (target === consent) agree.classList.add('is-invalid');
      target.focus();
    }
  }

  function setBusy(busy, label) {
    state.busy = busy;
    submitBtn.disabled = busy;
    submitBtn.classList.toggle('is-loading', busy);
    submitLabel.textContent = busy ? 'Checking…' : 'Check my site';
    reportSection.setAttribute('aria-busy', busy ? 'true' : 'false');
    findingsList.hidden = busy;
    findingsSkeleton.hidden = !busy;
    if (busy) {
      findingsCount.textContent = 'Checking…';
      setStatus('Checking ' + label + '…');
    } else {
      var items = findingsList.querySelectorAll('.f-item');
      var shown = 0;
      for (var i = 0; i < items.length; i++) if (!items[i].hidden) shown++;
      updateCount(shown, items.length);
    }
  }

  function errorCode(err) {
    var code = err && typeof err === 'object' && typeof err.code === 'string' ? err.code : '';
    return Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, code) ? code : '';
  }

  function messageFromError(err, status) {
    if (err && typeof err === 'object') {
      var msg = clean(err.message, 300);
      if (msg) return msg;
      var code = errorCode(err);
      if (code) return ERROR_MESSAGES[code];
    }
    return messageForStatus(status);
  }

  /** Calls the API. Resolves to { report } or { error: message, code }; never throws. */
  function requestScan(value) {
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timedOut = false;
    var timer = setTimeout(function () {
      timedOut = true;
      if (controller) controller.abort();
    }, CLIENT_TIMEOUT_MS);

    // The server ignores the query and fragment; don't send them (they'd land in request logs).
    var url = '/api/scan?url=' + encodeURIComponent(value.split(/[?#]/)[0]);
    var opts = {
      method: 'GET',
      // X-Surface marks the request as coming from this page; the API refuses others.
      headers: { Accept: 'application/json', 'X-Surface': '1' },
      cache: 'no-store',
      credentials: 'same-origin'
    };
    if (controller) opts.signal = controller.signal;

    function fail(message, code) { return { error: message, code: code || '' }; }

    return fetch(url, opts)
      .then(function (res) {
        return res.json().then(function (data) {
          if (res.ok && data && data.ok === true && data.report && typeof data.report === 'object') {
            return { report: data.report };
          }
          if (data && data.ok === false) {
            return fail(messageFromError(data.error, res.status), errorCode(data.error));
          }
          return fail(res.ok ? MSG_GENERIC : messageForStatus(res.status));
        }, function () {
          // Not JSON: a platform, proxy or CDN error page. Go by the status.
          if (timedOut) return fail(MSG_TIMEOUT);
          return fail(res.ok ? MSG_GENERIC : messageForStatus(res.status));
        });
      }, function () {
        return fail(timedOut ? MSG_TIMEOUT : MSG_OFFLINE);
      })
      .then(function (result) {
        clearTimeout(timer);
        return result;
      });
  }

  function onSuccess(rawReport, value) {
    var report = normalizeReport(rawReport);
    setBusy(false);
    renderReport(report, false);

    var host = report.target.host || value;
    document.title = 'Report for ' + host + ' · Surface';
    try {
      var shareable = value.split(/[?#]/)[0]; // never copy a query or fragment into history
      var next = new URL(window.location.href);
      next.searchParams.set('url', shareable);
      next.hash = '';
      window.history.replaceState(null, '', next.pathname + next.search);
    } catch (e) { /* history is optional */ }

    var c = report.derived;
    setStatus('Report ready for ' + host + '. Exposure ' + LEVEL_LABEL[report.level] +
      ', ' + report.score + ' out of 100. ' + c.crit + ' urgent, ' + c.warn + ' to fix.');

    reportSection.scrollIntoView({
      behavior: prefersReducedMotion() ? 'auto' : 'smooth',
      block: 'start'
    });
    reportTitle.focus({ preventScroll: true });
  }

  function onFailure(message, code) {
    setBusy(false);
    setStatus('');
    if (INPUT_ERROR_CODES.indexOf(code) !== -1) {
      showError(message, input); // marks the field and moves focus to it
      return;
    }
    showError(message);
    var active = document.activeElement;
    if (!active || active === document.body || active === submitBtn) input.focus();
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (state.busy) return;
    clearError();

    var value = clean(input.value, 0);
    if (!value) { showError(MSG_EMPTY, input); return; }
    if (value.length > 2048) { showError(MSG_TOO_LONG, input); return; }
    if (!consent.checked) { showError(MSG_CONSENT, consent); return; }

    setBusy(true, value);
    requestScan(value).then(function (result) {
      if (result.report) onSuccess(result.report, value);
      else onFailure(result.error || MSG_GENERIC, result.code);
    }, function () {
      onFailure(MSG_GENERIC);
    });
  });

  input.addEventListener('input', function () {
    if (input.getAttribute('aria-invalid')) clearError();
    // The deep-link note names the preset host; drop it once the address changes.
    if (state.presetHost && state.example) {
      state.presetHost = '';
      renderHead(state.report, true);
    }
  });
  consent.addEventListener('change', function () {
    if (consent.getAttribute('aria-invalid')) clearError();
  });

  // ---------------------------------------------------------------------------
  // "Scan a site" / CTA buttons: scroll to the form and focus the input
  // ---------------------------------------------------------------------------
  document.addEventListener('click', function (e) {
    var trigger = e.target.closest ? e.target.closest('[data-action="focus-scan"]') : null;
    if (!trigger) return;
    e.preventDefault();
    form.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'center' });
    input.focus({ preventScroll: true });
  });

  // ---------------------------------------------------------------------------
  // FAQ accordion
  // ---------------------------------------------------------------------------
  var accButtons = document.querySelectorAll('.acc-q');

  function setAccordion(item, open) {
    var btn = item.querySelector('.acc-q');
    item.classList.toggle('open', open);
    if (btn) btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function openOnly(item) {
    var openItems = document.querySelectorAll('.acc-item.open');
    for (var i = 0; i < openItems.length; i++) {
      if (openItems[i] !== item) setAccordion(openItems[i], false);
    }
    setAccordion(item, true);
  }

  for (var a = 0; a < accButtons.length; a++) {
    accButtons[a].addEventListener('click', function () {
      var item = this.closest('.acc-item');
      if (!item) return;
      if (item.classList.contains('open')) setAccordion(item, false);
      else openOnly(item);
    });
  }

  // Links such as the footer "Privacy" (#faq-data) open their FAQ item.
  function openFaqFromHash(hash) {
    if (!hash || hash.charAt(0) !== '#') return;
    var target = document.getElementById(hash.slice(1));
    if (target && target.classList.contains('acc-item')) openOnly(target);
  }

  document.addEventListener('click', function (e) {
    var link = e.target.closest ? e.target.closest('a[href^="#faq-"]') : null;
    if (link) openFaqFromHash(link.getAttribute('href'));
  });
  window.addEventListener('hashchange', function () { openFaqFromHash(window.location.hash); });

  // ---------------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------------
  try {
    var preset = clean(new URLSearchParams(window.location.search).get('url'), 2048);
    if (preset) {
      input.value = preset;
      state.presetHost = hostFrom(/^[a-z][a-z0-9+.-]*:\/\//i.test(preset) ? preset : 'https://' + preset) ||
        clean(preset, 80);
    }
  } catch (e) { /* ignore malformed query strings */ }

  renderReport(normalizeReport(SAMPLE_REPORT), true);

  openFaqFromHash(window.location.hash);
})();
