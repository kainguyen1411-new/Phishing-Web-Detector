// Phishing web detector backend. Zero dependencies, needs Node 18 or newer.
// Start:  node server.js     Open: http://localhost:3000
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const PORT = Number(process.env.PORT) || 3000;
const PT_USER = process.env.PT_USER || "anonymous";
const PT_KEY = process.env.PHISHTANK_KEY || "";
const GSB_KEY = process.env.GSB_KEY || "";
const DATA_DIR = path.join(__dirname, "data");
const PT_REFRESH = 6 * 3600e3;   // PhishTank limits downloads, so refresh gently
const OP_REFRESH = 1 * 3600e3;
const RETRY_AFTER = 30 * 60e3;   // after a failed download, try again in 30 minutes

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- feed store ----------
const store = {
  phishtank: { urls: new Map(), hosts: new Map(), count: 0, updated: null, ok: false, error: null },
  openphish: { urls: new Map(), hosts: new Map(), count: 0, updated: null, ok: false, error: null },
};

const retryTimers = {};
function retryLater(name, fn) {
  clearTimeout(retryTimers[name]);
  retryTimers[name] = setTimeout(fn, RETRY_AFTER);
  retryTimers[name].unref();
  log(name + ": will retry in " + RETRY_AFTER / 60000 + " minutes");
}

function normalize(raw) {
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "http://" + raw);
    const host = u.hostname.toLowerCase().replace(/^www\./, "");
    let p = u.pathname.replace(/\/+$/, "");
    return { host, key: host + p + u.search };
  } catch (e) { return null; }
}

function build(name, entries) {
  const urls = new Map(), hosts = new Map();
  for (const e of entries) {
    const n = normalize(e.url);
    if (!n) continue;
    urls.set(n.key, e);
    if (!hosts.has(n.host)) hosts.set(n.host, e);
  }
  Object.assign(store[name], { urls, hosts, count: urls.size, updated: new Date().toISOString(), ok: true, error: null });
}

async function download(url, headers) {
  const res = await fetch(url, { headers: Object.assign({ "User-Agent": "phishtank/" + PT_USER }, headers), signal: AbortSignal.timeout(120000) });
  if (!res.ok) throw new Error("HTTP " + res.status);
  let buf = Buffer.from(await res.arrayBuffer());
  if (buf[0] === 0x1f && buf[1] === 0x8b) buf = zlib.gunzipSync(buf);
  return buf.toString("utf8");
}

async function refreshPhishTank() {
  const cache = path.join(DATA_DIR, "phishtank.json");
  try {
    const base = "http://data.phishtank.com/data/" + (PT_KEY ? PT_KEY + "/" : "");
    const text = await download(base + "online-valid.json.gz");
    fs.writeFileSync(cache, text);
    build("phishtank", JSON.parse(text).map(r => ({ url: r.url, target: r.target, detail: r.phish_detail_url })));
    clearTimeout(retryTimers.phishtank);
    log("PhishTank loaded:", store.phishtank.count);
  } catch (e) {
    store.phishtank.error = e.message;
    log("PhishTank download failed:", e.message);
    retryLater("phishtank", refreshPhishTank);
    if (!store.phishtank.ok && fs.existsSync(cache)) {
      try {
        build("phishtank", JSON.parse(fs.readFileSync(cache, "utf8")).map(r => ({ url: r.url, target: r.target, detail: r.phish_detail_url })));
        store.phishtank.error = e.message + " (using cached copy)";
        log("PhishTank loaded from cache:", store.phishtank.count);
      } catch (_) {}
    }
  }
}

async function refreshOpenPhish() {
  const cache = path.join(DATA_DIR, "openphish.txt");
  const parse = t => t.split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(url => ({ url }));
  try {
    const text = await download("https://openphish.com/feed.txt");
    fs.writeFileSync(cache, text);
    build("openphish", parse(text));
    clearTimeout(retryTimers.openphish);
    log("OpenPhish loaded:", store.openphish.count);
  } catch (e) {
    store.openphish.error = e.message;
    log("OpenPhish download failed:", e.message);
    retryLater("openphish", refreshOpenPhish);
    if (!store.openphish.ok && fs.existsSync(cache)) {
      build("openphish", parse(fs.readFileSync(cache, "utf8")));
      store.openphish.error = e.message + " (using cached copy)";
    }
  }
}

async function googleLookup(url) {
  const res = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(GSB_KEY), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(8000),
    body: JSON.stringify({
      client: { clientId: "phishing-web-detector", clientVersion: "1.0.0" },
      threatInfo: {
        threatTypes: ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    }),
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  const j = await res.json();
  return (j.matches || []).map(m => m.threatType);
}

// ---------- lookup ----------
async function check(rawUrl) {
  const n = normalize(rawUrl);
  if (!n) return null;
  const matches = [];
  const sources = {};
  for (const name of ["phishtank", "openphish"]) {
    const s = store[name];
    sources[name] = { ok: s.ok, count: s.count, updated: s.updated, error: s.error };
    const exact = s.urls.get(n.key);
    if (exact) matches.push({ source: name, type: "exact", target: exact.target || null, detail: exact.detail || null });
    else {
      const h = s.hosts.get(n.host);
      if (h) matches.push({ source: name, type: "host", listedUrl: h.url, target: h.target || null, detail: h.detail || null });
    }
  }
  if (GSB_KEY) {
    try {
      const types = await googleLookup(rawUrl);
      sources.google = { ok: true };
      if (types.length) matches.push({ source: "google", type: "exact", threats: types });
    } catch (e) { sources.google = { ok: false, error: e.message }; }
  }
  return { url: rawUrl, host: n.host, listed: matches.some(m => m.type === "exact"), hostListed: matches.some(m => m.type === "host"), matches, sources };
}

// ---------- http ----------
const hits = new Map();
setInterval(() => hits.clear(), 60000).unref();
function limited(ip) { const c = (hits.get(ip) || 0) + 1; hits.set(ip, c); return c > 40; }

function send(res, code, body, type) {
  res.writeHead(code, { "Content-Type": type || "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".ico": "image/x-icon", ".woff2": "font/woff2" };
const PUBLIC = path.join(__dirname, "public");
function serveStatic(res, pathname) {
  let file;
  try { file = path.join(PUBLIC, decodeURIComponent(pathname === "/" ? "/index.html" : pathname)); } catch (e) { return false; }
  if (!file.startsWith(PUBLIC + path.sep)) return false;
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return false;
  send(res, 200, fs.readFileSync(file), MIME[path.extname(file).toLowerCase()] || "application/octet-stream");
  return true;
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://localhost");
  if (req.method === "GET" && u.pathname === "/api/status") {
    const out = {};
    for (const k of Object.keys(store)) out[k] = { ok: store[k].ok, count: store[k].count, updated: store[k].updated, error: store[k].error };
    out.google = { enabled: !!GSB_KEY };
    return send(res, 200, out);
  }
  if (req.method === "GET" && u.pathname === "/api/check") {
    if (limited(req.socket.remoteAddress)) return send(res, 429, { error: "Too many requests. Try again in a minute." });
    const raw = (u.searchParams.get("url") || "").trim();
    if (!raw || raw.length > 2048) return send(res, 400, { error: "Provide a url of up to 2048 characters." });
    try {
      const r = await check(raw);
      return r ? send(res, 200, r) : send(res, 400, { error: "That is not a valid link." });
    } catch (e) { return send(res, 500, { error: "Lookup failed." }); }
  }
  if (req.method === "GET" && !u.pathname.startsWith("/api/") && serveStatic(res, u.pathname)) return;
  send(res, 404, { error: "Not found" });
});

function log(...a) { console.log(new Date().toISOString(), ...a); }

server.listen(PORT, () => {
  log("Phishing web detector running at http://localhost:" + PORT);
  if (!GSB_KEY) log("Google Safe Browsing disabled (set GSB_KEY to enable).");
  refreshPhishTank(); refreshOpenPhish();
  setInterval(refreshPhishTank, PT_REFRESH).unref();
  setInterval(refreshOpenPhish, OP_REFRESH).unref();
});