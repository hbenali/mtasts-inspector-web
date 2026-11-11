/* MTA-STS Checker: client-side MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) inspector over DNS-over-HTTPS (dns.google),
   policy validator for pasted text, and generator. The policy file itself is NOT fetched by the page:
   browsers block it (CORS) for nearly every domain and the CSP only allows dns.google.
   No dependencies, no inline code (CSP: script-src 'self'). */
(function () {
  'use strict';

  var DOH = 'https://dns.google/resolve';
  var MAX_AGE_MIN = 86400, MAX_AGE_MAX = 31557600;
  var $ = function (id) { return document.getElementById(id); };

  // ---- DNS helpers ----
  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/[\/?#].*$/, '').replace(/\.+$/, '');
  }
  function validDomain(d) {
    if (!d || d.length > 253 || d.indexOf('.') === -1) return false;
    return d.split('.').every(function (l) { return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(l); });
  }
  function isIp(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') !== -1; }
  async function doh(name, type) {
    var res = await fetch(DOH + '?name=' + encodeURIComponent(name) + '&type=' + type);
    if (!res.ok) throw new Error('DNS query failed (HTTP ' + res.status + ')');
    return res.json();
  }
  async function txtRecords(name) {
    var d = await doh(name, 'TXT');
    if (d.Status !== 0 && d.Status !== 3) throw new Error('DNS lookup error for ' + name + ': ' + (d.Comment || 'code ' + d.Status));
    return (d.Answer || []).filter(function (x) { return x.type === 16; })
      .map(function (x) { return x.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''); });
  }
  async function mxHosts(domain) {
    var d = await doh(domain, 'MX');
    if (d.Status === 3) throw new Error('Domain "' + domain + '" does not exist (NXDOMAIN)');
    if (d.Status !== 0) throw new Error('DNS lookup error: ' + (d.Comment || 'code ' + d.Status));
    return (d.Answer || []).filter(function (r) { return r.type === 15; }).map(function (r) {
      var m = String(r.data).trim().match(/^(\d+)\s+(\S+)$/);
      return m ? { pref: parseInt(m[1], 10), host: m[2].replace(/\.$/, '').toLowerCase() || '.' } : null;
    }).filter(Boolean).sort(function (a, b) { return a.pref - b.pref || a.host.localeCompare(b.host); });
  }

  // ---- Parsers / validators (pure) ----
  // "v=STSv1; id=2024" -> {v, id, ...} (tag names lowercased)
  function parseTags(txt) {
    var out = {};
    txt.split(';').forEach(function (part) {
      var i = part.indexOf('=');
      if (i < 0) return;
      var k = part.slice(0, i).trim().toLowerCase();
      if (k && !(k in out)) out[k] = part.slice(i + 1).trim();
    });
    return out;
  }
  function validMxPattern(p) {
    var host = p.indexOf('*.') === 0 ? p.slice(2) : p;
    return !isIp(host) && validDomain(host);
  }
  // RFC 8461 section 4.1: "*." matches exactly one left-most label, never the bare parent.
  function mxMatches(pattern, host) {
    pattern = pattern.toLowerCase().replace(/\.$/, '');
    host = host.toLowerCase().replace(/\.$/, '');
    if (pattern.indexOf('*.') === 0) {
      var suffix = pattern.slice(1); // ".example.com"
      var label = host.slice(0, host.length - suffix.length);
      return host.length > suffix.length && host.slice(-suffix.length) === suffix && label.length > 0 && label.indexOf('.') === -1;
    }
    return pattern === host;
  }
  function parsePolicy(text) {
    var p = { version: null, mode: null, mx: [], maxAge: null, maxAgeRaw: null, unknown: [], problems: [] };
    var lines = String(text).replace(/^﻿/, '').split(/\r?\n/);
    lines.forEach(function (raw, n) {
      var line = raw.trim();
      if (!line) return;
      var i = line.indexOf(':');
      if (i < 1) { p.problems.push('Line ' + (n + 1) + ' is not "key: value": ' + line.slice(0, 60)); return; }
      var k = line.slice(0, i).trim().toLowerCase(), v = line.slice(i + 1).trim();
      if (k === 'version') { if (p.version !== null) p.problems.push('"version" appears more than once.'); p.version = v; }
      else if (k === 'mode') { if (p.mode !== null) p.problems.push('"mode" appears more than once.'); p.mode = v.toLowerCase(); }
      else if (k === 'mx') p.mx.push(v.toLowerCase().replace(/\.$/, ''));
      else if (k === 'max_age') { if (p.maxAgeRaw !== null) p.problems.push('"max_age" appears more than once.'); p.maxAgeRaw = v; p.maxAge = /^\d+$/.test(v) ? parseInt(v, 10) : NaN; }
      else p.unknown.push(k);
    });
    return p;
  }
  function human(sec) {
    if (sec >= 86400 * 365) return (sec / (86400 * 365)).toFixed(sec % (86400 * 365) ? 2 : 0) + ' year(s)';
    if (sec >= 86400) return (sec / 86400).toFixed(sec % 86400 ? 1 : 0) + ' day(s)';
    if (sec >= 3600) return (sec / 3600).toFixed(sec % 3600 ? 1 : 0) + ' hour(s)';
    return sec + ' second(s)';
  }

  function validatePolicy(p, mx) {
    var c = [];
    var add = function (level, text) { c.push({ level: level, text: text }); };
    p.problems.forEach(function (t) { add('fail', t); });
    if (p.version === null) add('fail', 'Missing "version" line; it must be "version: STSv1".');
    else if (p.version !== 'STSv1') add('fail', 'Unsupported version "' + p.version + '"; it must be exactly STSv1 (case-sensitive).');
    else add('pass', 'version: STSv1.');

    if (p.mode === null) add('fail', 'Missing "mode" line; use enforce, testing or none.');
    else if (['enforce', 'testing', 'none'].indexOf(p.mode) < 0) add('fail', 'Invalid mode "' + p.mode + '"; it must be enforce, testing or none.');
    else if (p.mode === 'enforce') add('pass', 'mode: enforce. Senders refuse to deliver if TLS or the certificate check fails.');
    else if (p.mode === 'testing') add('warn', 'mode: testing. Failures are only reported (via TLS-RPT), mail is still delivered. Move to enforce once reports are clean.');
    else add('info', 'mode: none. The policy is effectively off (used to retire MTA-STS: publish it with a short-lived id change and wait for max_age).');

    if (p.maxAgeRaw === null) add('fail', 'Missing "max_age" line (seconds the policy may be cached).');
    else if (isNaN(p.maxAge)) add('fail', 'max_age must be a whole number of seconds, found "' + p.maxAgeRaw + '".');
    else if (p.maxAge > MAX_AGE_MAX) add('warn', 'max_age ' + p.maxAge + ' is above ' + MAX_AGE_MAX + ' seconds (1 year), the maximum RFC 8461 allows; senders may reject the policy.');
    else if (p.maxAge < MAX_AGE_MIN && p.mode !== 'none') add('warn', 'max_age ' + p.maxAge + ' (' + human(p.maxAge) + ') is very short; use at least ' + MAX_AGE_MIN + ' (1 day), typically 604800 or more once in enforce.');
    else add('pass', 'max_age ' + p.maxAge + ' (' + human(p.maxAge) + ').');

    if (p.unknown.length) add('info', 'Unknown key(s) ignored by senders: ' + p.unknown.filter(function (k, i, a) { return a.indexOf(k) === i; }).join(', ') + '.');

    var validPatterns = [];
    if (!p.mx.length) {
      add(p.mode === 'none' ? 'info' : 'fail', p.mode === 'none' ? 'No mx lines (allowed with mode none).' : 'No "mx:" line; a policy needs at least one.');
    } else {
      p.mx.forEach(function (m) {
        if (validMxPattern(m)) validPatterns.push(m);
        else add('fail', 'mx pattern "' + m + '" is not a valid hostname or "*.hostname" wildcard.');
      });
      if (validPatterns.length) add('pass', validPatterns.length + ' valid mx line(s): ' + validPatterns.join(', ') + '.');
    }

    // Cross-check with the real MX records.
    if (mx === null) {
      add('info', 'MX hosts were not compared: the DNS lookup did not run or failed.');
    } else {
      var real = mx.map(function (r) { return r.host; }).filter(function (h, i, a) { return h !== '.' && a.indexOf(h) === i; });
      if (!real.length) add('warn', 'The domain publishes no usable MX hosts (none or null MX), so there is nothing to match the mx lines against.');
      else {
        var bad = p.mode === 'enforce' ? 'fail' : 'warn';
        var uncovered = real.filter(function (h) { return !validPatterns.some(function (pt) { return mxMatches(pt, h); }); });
        if (uncovered.length) add(bad, 'MX host(s) not matched by any mx line: ' + uncovered.join(', ') + '.' + (p.mode === 'enforce' ? ' In enforce mode senders will not deliver to them.' : ' They would be refused once you enforce.'));
        else add('pass', 'Every real MX host (' + real.join(', ') + ') matches an mx line.');
        var stale = validPatterns.filter(function (pt) { return !real.some(function (h) { return mxMatches(pt, h); }); });
        if (stale.length) add('warn', 'mx line(s) matching no current MX host: ' + stale.join(', ') + '. Remove them unless you are mid-migration.');
        else if (validPatterns.length) add('pass', 'Every mx line matches at least one real MX host.');
      }
    }
    return c;
  }

  function checkStsTxt(records) {
    var c = [];
    var add = function (level, text) { c.push({ level: level, text: text }); };
    var cand = records.filter(function (t) { return /^\s*v=STSv1/i.test(t); });
    if (!cand.length) { add('info', 'No MTA-STS TXT record at _mta-sts: senders do not apply MTA-STS to this domain (TLS to your MX hosts is opportunistic and can be downgraded).'); return { checks: c, id: null, record: null }; }
    if (cand.length > 1) add('fail', cand.length + ' MTA-STS TXT records found; with more than one, senders treat the domain as having none. Keep a single record.');
    var t = parseTags(cand[0]);
    var id = t.id || null;
    if (t.v !== 'STSv1') add('fail', 'The version tag must be exactly "v=STSv1" (found "v=' + t.v + '").');
    if (!id) add('fail', 'Missing id tag; it signals policy changes (1-32 letters/digits).');
    else if (!/^[A-Za-z0-9]{1,32}$/.test(id)) add('fail', 'id "' + id + '" must be 1 to 32 letters or digits only.');
    else if (t.v === 'STSv1' && cand.length === 1) add('pass', 'MTA-STS TXT record is valid (id ' + id + ').');
    return { checks: c, id: id, record: cand[0] };
  }
  function checkRptTxt(records) {
    var c = [];
    var add = function (level, text) { c.push({ level: level, text: text }); };
    var cand = records.filter(function (t) { return /^\s*v=TLSRPTv1/i.test(t); });
    if (!cand.length) { add('info', 'No TLS-RPT TXT record at _smtp._tls: you will not receive reports on TLS failures (including MTA-STS validation errors).'); return { checks: c, rua: [], record: null }; }
    if (cand.length > 1) add('fail', cand.length + ' TLS-RPT TXT records found; keep a single record.');
    var t = parseTags(cand[0]);
    var rua = [];
    if (t.v !== 'TLSRPTv1') add('fail', 'The version tag must be exactly "v=TLSRPTv1".');
    if (!t.rua) add('fail', 'Missing rua tag; it lists where reports are sent (mailto: or https:).');
    else {
      t.rua.split(',').map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (u) {
        rua.push(u);
        if (/^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$/i.test(u) || /^https:\/\/[^\s]+$/i.test(u)) return;
        add('fail', 'rua target "' + u + '" is not a valid mailto:address or https:// URI.');
      });
      if (rua.length && !c.some(function (x) { return x.level === 'fail'; })) add('pass', 'TLS-RPT record is valid: reports go to ' + rua.join(', ') + '.');
    }
    return { checks: c, rua: rua, record: cand[0] };
  }

  // ---- Rendering helpers ----
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function renderChecks(box, checks) {
    var ul = el('ul', 'checks');
    var labels = { pass: 'ok', warn: 'warn', fail: 'fail', info: 'note' };
    var order = { fail: 0, warn: 1, info: 2, pass: 3 };
    checks.slice().sort(function (a, b) { return order[a.level] - order[b.level]; }).forEach(function (c) {
      var li = el('li');
      li.append(el('span', 'chk ' + c.level, labels[c.level]));
      li.append(el('span', null, c.text));
      ul.append(li);
    });
    box.append(ul);
  }
  function worstOf(checks) {
    return checks.some(function (c) { return c.level === 'fail'; }) ? 'fail' : checks.some(function (c) { return c.level === 'warn'; }) ? 'warn' : 'ok';
  }
  function recordBlock(title, value) {
    var d = el('div', 'rec-block');
    d.append(el('div', 'preview-label', title));
    d.append(el('div', 'preview', value || 'not published'));
    return d;
  }
  function siblingLinks(domain) {
    var wrap = el('p', 'provider');
    wrap.append('Also check ' + domain + ': ');
    [['mx', 'MX'], ['ssl', 'SSL/TLS'], ['dnssec', 'DNSSEC'], ['dmarc', 'DMARC'], ['spf', 'SPF'], ['dkim', 'DKIM'], ['caa', 'CAA']].forEach(function (t, i) {
      if (i) wrap.append(' · ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      wrap.append(a);
    });
    return wrap;
  }
  function copyButton(getText) {
    var b = el('button', 'btn quiet', 'Copy');
    b.type = 'button';
    b.addEventListener('click', function () {
      var done = function (ok) { b.textContent = ok ? 'Copied' : 'Copy failed: select and copy by hand'; setTimeout(function () { b.textContent = 'Copy'; }, 2000); };
      try { navigator.clipboard.writeText(getText()).then(function () { done(true); }, function () { done(false); }); } catch (e) { done(false); }
    });
    return b;
  }

  // ---- Lookup flow ----
  var domainInput = $('domainInput'), checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }
  var lookup = null; // {domain, mx, stsId, rua}
  var polSection = $('policySection');

  function renderError(domain, msg) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', domain ? 'Error checking ' + domain : 'Error'));
    s.append(el('p', null, msg));
    box.append(s);
  }
  function setLoading(on) {
    checkBtn.disabled = on;
    btnText.textContent = on ? 'Checking' : 'Check MTA-STS';
    btnLoader.hidden = !on;
    btnLoader.className = on ? 'loader' : '';
  }

  function renderDns(domain, sts, rpt, mx) {
    var box = views.records;
    box.replaceChildren();
    var checks = sts.checks.concat(rpt.checks);
    var real = mx.filter(function (r) { return r.host !== '.'; });
    if (!mx.length) checks.push({ level: 'warn', text: 'No MX records: the domain does not receive mail by MX, so MTA-STS has nothing to protect.' });
    else if (!real.length) checks.push({ level: 'info', text: 'Null MX (RFC 7505): the domain does not accept mail; MTA-STS is not needed.' });
    else checks.push({ level: 'pass', text: real.length + ' MX host(s) found: ' + real.map(function (r) { return r.host; }).join(', ') + '.' });
    if (sts.record && !real.length) checks.push({ level: 'warn', text: 'An MTA-STS record is published but the domain has no usable MX hosts.' });

    var state = el('div', 'state ' + worstOf(checks));
    state.append(el('h2', 'state-title', 'MTA-STS and TLS-RPT for'));
    state.append(el('span', 'badge-domain', domain));
    box.append(state);

    var recs = el('div', 'rec-grid');
    recs.append(recordBlock('_mta-sts.' + domain + ' TXT', sts.record));
    recs.append(recordBlock('_smtp._tls.' + domain + ' TXT', rpt.record));
    recs.append(recordBlock('MX records (priority host)', real.length ? mx.map(function (r) { return r.pref + ' ' + r.host; }).join('\n') : (mx.length ? '0 . (null MX)' : 'none')));
    box.append(recs);
    renderChecks(box, checks);
    box.append(siblingLinks(domain));
  }

  async function performLookup() {
    var domain = normalizeDomain(domainInput.value);
    if (!domain) { lookup = null; setView('error'); renderError('', 'Please enter a domain name'); return; }
    if (!validDomain(domain)) { lookup = null; setView('error'); renderError(domain, 'That is not a valid domain name.'); return; }
    domainInput.value = domain;
    setLoading(true);
    try {
      var r = await Promise.all([txtRecords('_mta-sts.' + domain), txtRecords('_smtp._tls.' + domain), mxHosts(domain)]);
      var sts = checkStsTxt(r[0]), rpt = checkRptTxt(r[1]);
      lookup = { domain: domain, mx: r[2], stsId: sts.id, rua: rpt.rua };
      renderDns(domain, sts, rpt, r[2]);
      setView('records');
      showPolicyHelp(domain);
    } catch (err) {
      lookup = null;
      renderError(domain, err.message || 'Unknown error');
      setView('error');
    } finally {
      setLoading(false);
    }
  }
  checkBtn.addEventListener('click', performLookup);
  domainInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') performLookup(); });

  // ---- Policy: curl command + paste validator ----
  var curlBox = $('curlBox'), polInput = $('policyInput'), polOut = $('policyResult'), polBtn = $('validatePolicyBtn');
  var polUrl = $('policyLink');
  function policyUrl(domain) { return 'https://mta-sts.' + domain + '/.well-known/mta-sts.txt'; }
  function showPolicyHelp(domain) {
    // Re-check here, right before the URL is built: only a plain hostname may reach href.
    if (!/^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i.test(domain)) return;
    var url = policyUrl(domain);
    curlBox.textContent = 'curl -si ' + url;
    $('curlHint').hidden = true;
    polUrl.href = url;
    polUrl.textContent = url;
    polSection.querySelectorAll('[data-needs-domain]').forEach(function (n) { n.hidden = false; });
  }
  async function validatePasted() {
    polOut.replaceChildren();
    var text = polInput.value;
    if (!text.trim()) { polOut.append(el('p', 'field-error visible', 'Paste the policy text first.')); return; }
    var domain = lookup ? lookup.domain : null;
    var mx = lookup ? lookup.mx : null;
    var typed = normalizeDomain(domainInput.value);
    if (validDomain(typed) && (!lookup || lookup.domain !== typed)) {
      polBtn.disabled = true;
      try { mx = await mxHosts(typed); domain = typed; } catch (e) { mx = null; }
      polBtn.disabled = false;
    }
    var p = parsePolicy(text);
    var checks = validatePolicy(p, mx);
    var state = el('div', 'state ' + worstOf(checks));
    state.append(el('h2', 'state-title', 'Policy check'));
    if (domain) state.append(el('span', 'badge-domain', 'MX compared against ' + domain));
    polOut.append(state);
    renderChecks(polOut, checks);
  }
  polBtn.addEventListener('click', validatePasted);

  // ---- Generator ----
  var gMode = $('genMode'), gAge = $('genAge'), gMx = $('genMx'), gId = $('genId'), gRua = $('genRua'), gErr = $('genError');
  var oPolicy = $('outPolicy'), oSts = $('outSts'), oRpt = $('outRpt'), gHint = $('genAgeHint'), gLoadHint = $('loadMxHint');

  function stamp() {
    var d = new Date(), p = function (n) { return ('0' + n).slice(-2); };
    return String(d.getUTCFullYear()) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds());
  }
  function showError(msg) { gErr.textContent = msg; gErr.classList.toggle('visible', !!msg); }
  function genDomain() { var d = normalizeDomain(domainInput.value); return validDomain(d) ? d : 'example.com'; }

  function updateGen() {
    var errors = [];
    var mode = gMode.value;
    var age = gAge.value.trim();
    var ageN = /^\d+$/.test(age) ? parseInt(age, 10) : NaN;
    if (isNaN(ageN)) { errors.push('max_age must be a whole number of seconds.'); gHint.textContent = ''; }
    else {
      gHint.textContent = human(ageN);
      if (ageN > MAX_AGE_MAX) errors.push('max_age above ' + MAX_AGE_MAX + ' seconds (1 year) is not allowed.');
      else if (ageN < MAX_AGE_MIN && mode !== 'none') errors.push('max_age below ' + MAX_AGE_MIN + ' seconds (1 day) is too short to be useful.');
    }
    var patterns = gMx.value.split(/\r?\n/).map(function (s) { return s.trim().toLowerCase().replace(/\.$/, ''); }).filter(Boolean);
    var badP = patterns.filter(function (p) { return !validMxPattern(p); });
    if (badP.length) errors.push('Invalid mx pattern(s): ' + badP.join(', ') + ' (use hostnames, optionally "*.host").');
    if (!patterns.length && mode !== 'none') errors.push('Add at least one mx host.');
    var id = gId.value.trim();
    if (!/^[A-Za-z0-9]{1,32}$/.test(id)) errors.push('id must be 1 to 32 letters or digits.');
    var ruas = gRua.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    var badR = ruas.filter(function (u) { return !(/^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$/i.test(u) || /^https:\/\/[^\s]+$/i.test(u)); });
    if (badR.length) errors.push('Invalid rua target(s): ' + badR.join(', ') + ' (use mailto:you@example.com or https://...).');
    showError(errors.join(' '));

    var domain = genDomain();
    var lines = ['version: STSv1', 'mode: ' + mode];
    patterns.forEach(function (p) { lines.push('mx: ' + p); });
    lines.push('max_age: ' + (isNaN(ageN) ? '[seconds]' : ageN));
    oPolicy.textContent = lines.join('\n') + '\n';
    oSts.textContent = '_mta-sts.' + domain + '. IN TXT "v=STSv1; id=' + (id || '[id]') + '"';
    oRpt.textContent = ruas.length ? '_smtp._tls.' + domain + '. IN TXT "v=TLSRPTv1; rua=' + ruas.join(',') + '"' : '; enter a report address (rua) to generate the TLS-RPT record';
    $('policyWhere').textContent = 'Serve the policy at ' + policyUrl(domain) + ' over HTTPS with a valid certificate for mta-sts.' + domain + ' and Content-Type text/plain, with no redirect.';
  }
  [gMode, gAge, gMx, gId, gRua].forEach(function (n) { n.addEventListener('input', updateGen); });
  domainInput.addEventListener('input', updateGen);
  $('newIdBtn').addEventListener('click', function () { gId.value = stamp(); updateGen(); });
  $('loadMxBtn').addEventListener('click', function () {
    var hosts = lookup ? lookup.mx.filter(function (r) { return r.host !== '.'; }).map(function (r) { return r.host; }).filter(function (h, i, a) { return a.indexOf(h) === i; }) : [];
    if (!hosts.length) {
      gLoadHint.textContent = lookup ? 'The last lookup found no usable MX hosts.' : 'Run a lookup above first.';
      gLoadHint.classList.add('visible');
      return;
    }
    gLoadHint.classList.remove('visible');
    gMx.value = hosts.join('\n');
    updateGen();
  });
  $('loadRuaBtn').addEventListener('click', function () {
    if (lookup && lookup.rua.length) { gRua.value = lookup.rua.join(','); updateGen(); }
    else { gLoadHint.textContent = lookup ? 'The last lookup found no TLS-RPT rua.' : 'Run a lookup above first.'; gLoadHint.classList.add('visible'); }
  });
  [['copyPolicy', oPolicy], ['copySts', oSts], ['copyRpt', oRpt]].forEach(function (x) {
    $(x[0]).replaceWith(copyButton(function () { return x[1].textContent; }));
  });
  gId.value = stamp();
  updateGen();

  setView('placeholder');
  var param = new URLSearchParams(window.location.search).get('domain');
  if (param) { domainInput.value = param; performLookup(); }

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
})();
