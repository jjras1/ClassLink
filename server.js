// Minimal server-side web proxy. Requires Node 18+ (global fetch).
// Fetches a page on the visitor's behalf and rewrites its links so
// navigation keeps going through /proxy?url=...
//
// Not covered: JavaScript-driven navigation, form submissions, cookies/logins,
// srcset, url() inside CSS. Rammerhead and Ultraviolet handle those by
// rewriting JS in the browser; see the notes in the reply.

const express = require('express');
const cheerio = require('cheerio');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');
const { Readable } = require('stream');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

// Password gate for /proxy (HTTP Basic auth). Set PROXY_PASSWORD (and optionally
// PROXY_USER) as environment variables. On Vercel the proxy refuses to run
// without a password, so it can never be left open by accident.
const PROXY_USER = process.env.PROXY_USER || 'user';
const PROXY_PASSWORD = process.env.PROXY_PASSWORD;

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireLogin(req, res, next) {
  if (!PROXY_PASSWORD) {
    if (process.env.VERCEL) {
      return res.status(503).send('Set PROXY_PASSWORD in your Vercel environment variables.');
    }
    return next(); // local testing only
  }
  const [scheme, encoded] = (req.get('authorization') || '').split(' ');
  if (scheme === 'Basic' && encoded) {
    const [user, ...rest] = Buffer.from(encoded, 'base64').toString().split(':');
    if (safeEqual(user, PROXY_USER) && safeEqual(rest.join(':'), PROXY_PASSWORD)) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Proxy"').status(401).send('Login required.');
}

// Refuse addresses on private/internal networks (SSRF protection).
// Basic check: a hardened deployment should also pin the resolved IP
// for the actual connection to avoid DNS rebinding.
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  const v6 = ip.toLowerCase();
  if (v6.startsWith('::ffff:')) return isPrivateIp(v6.slice(7));
  return v6 === '::1' || v6 === '::' || v6.startsWith('fc') || v6.startsWith('fd') || v6.startsWith('fe80');
}

async function assertPublic(url) {
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (addrs.some((a) => isPrivateIp(a.address))) throw new Error('private address');
}

// Turn any link into one that goes back through this proxy.
function toProxy(value, base) {
  if (!value || value.startsWith('#') || /^(data|javascript|mailto|tel|blob):/i.test(value)) return value;
  try {
    const abs = new URL(value, base);
    if (!/^https?:$/.test(abs.protocol)) return value;
    return '/proxy?url=' + encodeURIComponent(abs.href);
  } catch {
    return value;
  }
}

app.get('/proxy', requireLogin, async (req, res) => {
  let target;
  try {
    target = new URL(req.query.url);
    if (!/^https?:$/.test(target.protocol)) throw new Error('protocol');
    await assertPublic(target);
  } catch {
    return res.status(400).send('That address cannot be loaded.');
  }

  let upstream;
  try {
    upstream = await fetch(target, {
      redirect: 'manual', // follow redirects ourselves so each hop is re-checked
      signal: AbortSignal.timeout(15000),
      headers: {
        'user-agent': req.get('user-agent') || 'Mozilla/5.0',
        accept: req.get('accept') || '*/*',
        'accept-language': req.get('accept-language') || 'en-US,en;q=0.9',
      },
    });
  } catch {
    return res.status(502).send('The site did not respond.');
  }

  const location = upstream.headers.get('location');
  if (upstream.status >= 300 && upstream.status < 400 && location) {
    return res.redirect(toProxy(location, target));
  }

  // Only the content type is forwarded, so the site's own CSP and
  // X-Frame-Options headers are dropped.
  const type = upstream.headers.get('content-type') || 'application/octet-stream';
  res.status(upstream.status).set('content-type', type);

  if (!upstream.body) return res.end();
  if (!type.includes('text/html')) return Readable.fromWeb(upstream.body).pipe(res);

  const $ = cheerio.load(await upstream.text());

  const baseHref = $('base[href]').attr('href');
  const base = baseHref ? new URL(baseHref, target) : target;
  $('base').remove();
  $('meta[http-equiv="refresh" i]').remove();

  const targets = {
    href: 'a, area, link',
    src: 'img, script, iframe, source, video, audio, embed',
  };
  for (const [attr, selector] of Object.entries(targets)) {
    $(selector).each((_, el) => {
      const v = $(el).attr(attr);
      if (v) $(el).attr(attr, toProxy(v, base));
    });
  }

  res.send($.html());
});

// Vercel imports the exported app; running `npm start` locally still works.
module.exports = app;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Proxy running at http://localhost:${PORT}`));
}
