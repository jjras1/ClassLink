const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { promisify } = require('util');
const { WebSocketServer } = require('ws');
const scrypt = promisify(crypto.scrypt);
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, 'data'), PUB = path.join(__dirname, 'public');
fs.mkdirSync(DATA, { recursive: true });

const readJSON = f => { try { return JSON.parse(fs.readFileSync(path.join(DATA, f))); } catch { return null; } };
let users = readJSON('users.json') || {};
let rooms = readJSON('rooms.json') || ['general', 'random'];
const msgs = {};
try {
  for (const l of fs.readFileSync(path.join(DATA, 'messages.jsonl'), 'utf8').split('\n')) {
    if (!l) continue;
    const m = JSON.parse(l);
    (msgs[m.room] ??= []).push(m);
    if (msgs[m.room].length > 200) msgs[m.room].shift();
  }
} catch {}

let dirty = false;
const save = () => {
  if (!dirty) return;
  dirty = false;
  for (const [f, d] of [['users.json', users], ['rooms.json', rooms]]) {
    const p = path.join(DATA, f);
    fs.writeFileSync(p + '.tmp', JSON.stringify(d));
    fs.renameSync(p + '.tmp', p);
  }
};
setInterval(save, 2000);
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { save(); process.exit(); });

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml' };
const server = http.createServer((q, r) => {
  let p = decodeURIComponent(q.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const f = path.join(PUB, p);
  if (!f.startsWith(PUB + path.sep)) { r.writeHead(403); return r.end(); }
  fs.readFile(f, (e, d) => {
    if (e) { r.writeHead(404); return r.end('Not found'); }
    r.writeHead(200, { 'Content-Type': (MIME[path.extname(f)] || 'application/octet-stream') + '; charset=utf-8' });
    r.end(d);
  });
});

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 8192 });
const online = new Map();
const send = (w, o) => w.readyState === 1 && w.send(JSON.stringify(o));
const bcast = o => { for (const [w, s] of online) if (s.name) send(w, o); };
const presence = () => bcast({ t: 'online', users: [...new Set([...online.values()].map(s => s.name).filter(Boolean))] });
const sha = s => crypto.createHash('sha256').update(s).digest('hex');

wss.on('connection', w => {
  const s = { name: null, hits: [], fails: 0 };
  online.set(w, s);
  w.alive = true;
  w.on('pong', () => (w.alive = true));
  const login = u => { s.name = u.name; send(w, { t: 'init', name: u.name, rooms }); presence(); };

  w.on('message', async raw => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }
    const now = Date.now();
    s.hits = s.hits.filter(x => now - x < 5000);
    if (s.hits.push(now) > 8) return send(w, { t: 'err', m: 'Slow down a little.' });
    try {
      if (m.t === 'auth') {
        if (s.fails >= 10) return w.close();
        const n = String(m.name || ''), pw = String(m.pass || ''), k = n.toLowerCase();
        let u = users[k];
        if (m.mode === 'register') {
          if (!/^\w{3,16}$/.test(n) || pw.length < 6 || pw.length > 100)
            return send(w, { t: 'err', m: 'Use a 3-16 character username (letters, numbers, _) and a password of 6+ characters.' });
          if (u) return send(w, { t: 'err', m: 'That username is taken.' });
          const salt = crypto.randomBytes(16).toString('hex');
          const hash = (await scrypt(pw, salt, 32)).toString('hex');
          if (users[k]) return send(w, { t: 'err', m: 'That username is taken.' });
          u = users[k] = { name: n, salt, hash, tokens: [] };
        } else if (!u || !crypto.timingSafeEqual(await scrypt(pw, u.salt, 32), Buffer.from(u.hash, 'hex'))) {
          s.fails++;
          return send(w, { t: 'err', m: 'Wrong username or password.' });
        }
        const tok = crypto.randomBytes(24).toString('hex');
        u.tokens = [...u.tokens.slice(-4), sha(tok)];
        dirty = true;
        send(w, { t: 'token', name: u.name, token: tok });
        return login(u);
      }
      if (m.t === 'resume') {
        const u = users[String(m.name || '').toLowerCase()];
        if (u && u.tokens.includes(sha(String(m.token || '')))) return login(u);
        return send(w, { t: 'logout' });
      }
      if (!s.name) return;
      if (m.t === 'history' && rooms.includes(m.room)) return send(w, { t: 'history', room: m.room, msgs: msgs[m.room] || [] });
      if (m.t === 'msg') {
        const text = String(m.text || '').trim().slice(0, 2000);
        if (!text || !rooms.includes(m.room)) return;
        const msg = { id: crypto.randomUUID(), room: m.room, user: s.name, text, ts: now };
        const list = (msgs[m.room] ??= []);
        list.push(msg);
        if (list.length > 200) list.shift();
        fs.appendFile(path.join(DATA, 'messages.jsonl'), JSON.stringify(msg) + '\n', () => {});
        return bcast({ t: 'msg', m: msg });
      }
      if (m.t === 'newroom') {
        const n = String(m.name || '').toLowerCase().trim().replace(/\s+/g, '-');
        if (!/^[a-z0-9-]{2,24}$/.test(n)) return send(w, { t: 'err', m: 'Room names use 2-24 letters, numbers or dashes.' });
        if (rooms.includes(n)) return send(w, { t: 'err', m: 'That room already exists.' });
        if (rooms.length >= 100) return send(w, { t: 'err', m: 'Room limit reached.' });
        rooms.push(n);
        dirty = true;
        bcast({ t: 'rooms', rooms });
      }
    } catch (e) { console.error(e); }
  });
  w.on('close', () => { online.delete(w); presence(); });
});

setInterval(() => {
  for (const w of wss.clients) { if (!w.alive) { w.terminate(); continue; } w.alive = false; w.ping(); }
}, 30000);

server.listen(PORT, () => console.log('Commons running on port ' + PORT));
