'use strict';
// Secure portfolio server: sessions, host-only content API, validated uploads, live updates (SSE). No npm dependencies.
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
try { process.loadEnvFile(path.join(__dirname, '.env')); } catch {}
const PORT = +process.env.PORT || 3000, PROD = process.env.NODE_ENV === 'production', PROXY = process.env.TRUST_PROXY === '1';
const HOST = (process.env.OWNER_EMAIL || '').trim().toLowerCase();
const DIR = path.join(process.env.DATA_DIR || path.join(__dirname, 'data')), UP = path.join(DIR, 'uploads');
fs.mkdirSync(UP, { recursive: true });
const db = new DatabaseSync(path.join(DIR, 'app.db'));
db.exec(`create table if not exists users(id integer primary key, email text unique not null, pw text not null, role text not null default 'visitor');
create table if not exists sessions(h text primary key, uid integer not null, exp integer not null);
create table if not exists items(id integer primary key, kind text not null, data text not null);`);

const hash = p => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const check = (p, st) => { const [s, h] = st.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(p, Buffer.from(s, 'hex'), 64), Buffer.from(h, 'hex')); };
const DUMMY = hash('x');
if (HOST && process.env.OWNER_PASSWORD) { // the only way to become host: server-side env config
  db.prepare(`insert into users(email,pw,role) values(?,?,'host') on conflict(email) do update set pw=excluded.pw, role='host'`).run(HOST, hash(process.env.OWNER_PASSWORD));
  db.prepare(`update users set role='visitor' where role='host' and email<>?`).run(HOST);
} else if (!db.prepare(`select 1 from users where role='host'`).get()) console.warn('No host account yet: set OWNER_EMAIL and OWNER_PASSWORD in .env');
if (!db.prepare('select 1 from items').get() && fs.existsSync(path.join(__dirname, 'seed.json'))) {
  const sd = JSON.parse(fs.readFileSync(path.join(__dirname, 'seed.json')));
  for (const k of ['projects', 'certs']) for (const o of sd[k]) db.prepare('insert into items(kind,data) values(?,?)').run(k, JSON.stringify(o));
}

const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const mkSession = uid => { const t = crypto.randomBytes(32).toString('hex'); db.prepare('insert into sessions values(?,?,?)').run(sha(t), uid, Date.now() + 7 * 864e5); return t; };
const cookie = (v, age) => `sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${PROD ? '; Secure' : ''}`;
function who(req) {
  const m = /(?:^|; )sid=([a-f0-9]{64})/.exec(req.headers.cookie || ''); if (!m) return null;
  const h = sha(m[1]), r = db.prepare('select u.id,u.email,u.role,s.exp from sessions s join users u on u.id=s.uid where s.h=?').get(h);
  return r && r.exp > Date.now() ? { ...r, h } : null;
}
const tries = new Map();
const over = ip => { const n = Date.now(), a = (tries.get(ip) || []).filter(t => n - t < 6e5); a.push(n); tries.set(ip, a); return a.length > 10; };

const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" };
const send = (res, c, o, h = {}) => { const html = typeof o === 'string'; res.writeHead(c, { 'Content-Type': html ? 'text/html; charset=utf-8' : 'application/json', 'Cache-Control': 'no-store', ...SEC, ...h }); res.end(html ? o : JSON.stringify(o)); };
const body = req => new Promise((ok, no) => { const b = []; let n = 0;
  req.on('data', c => { n += c.length; if (n > 5e6) { no('Request too large.'); req.destroy(); } else b.push(c); });
  req.on('end', () => { try { ok(JSON.parse(Buffer.concat(b).toString() || '{}')); } catch { no('Invalid request.'); } }); });

const MIME = { png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', pdf: 'application/pdf' };
const SIG = [['png', [0x89, 0x50, 0x4e, 0x47]], ['jpg', [0xff, 0xd8, 0xff]], ['gif', [0x47, 0x49, 0x46, 0x38]], ['pdf', [0x25, 0x50, 0x44, 0x46]]];
function saveUpload(d, allowPdf) { // type is decided from file bytes, never from the name
  const m = /^data:[\w/+.-]+;base64,([A-Za-z0-9+/=]+)$/.exec(d || ''); if (!m) throw 'Invalid file.';
  const b = Buffer.from(m[1], 'base64'); if (b.length > 3e6) throw 'File too large (max 3 MB).';
  let e = (SIG.find(([, s]) => s.every((x, i) => b[i] === x)) || [])[0];
  if (!e && b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') e = 'webp';
  if (!e || (e === 'pdf' && !allowPdf)) throw allowPdf ? 'Only PNG, JPG, GIF, WebP or PDF files are allowed.' : 'Only PNG, JPG, GIF or WebP images are allowed.';
  const n = crypto.randomBytes(12).toString('hex') + '.' + e; fs.writeFileSync(path.join(UP, n), b); return n;
}
const rmFile = f => { if (f && /^[a-f0-9]{24}\.\w+$/.test(f)) fs.rmSync(path.join(UP, f), { force: true }); };
const KEYS = { projects: ['title', 'cat', 'short', 'full', 'tech', 'url', 'gh', 'img', 'status', 'featured', 'role', 'year', 'feat'], certs: ['name', 'org', 'date', 'desc', 'cid', 'url', 'img', 'tech'] };
function clean(kind, x) {
  const o = {};
  for (const k of KEYS[kind]) {
    let v = x[k]; if (k === 'featured') v = !!v; else {
      v = String(v ?? '').trim().slice(0, ['full', 'feat', 'desc'].includes(k) ? 3000 : 300);
      if (['url', 'gh', 'img'].includes(k) && v && !/^https?:\/\//i.test(v)) throw 'Links must start with http:// or https://';
    } o[k] = v;
  }
  if (!o[kind === 'projects' ? 'title' : 'name']) throw 'A title is required.'; return o;
}
const all = () => db.prepare('select id,kind,data from items order by id').all().map(r => ({ id: r.id, kind: r.kind, ...JSON.parse(r.data) }));
const live = new Set(), ping = () => live.forEach(r => r.write('data: update\n\n'));
const page = f => fs.readFileSync(path.join(__dirname, f), 'utf8');

http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, 'http://x').pathname, s = who(req), M = req.method;
    const ip = (PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;
    if (M !== 'GET' && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return send(res, 403, { error: 'Forbidden.' });
    if (M === 'GET' && p === '/') return send(res, 200, page(s ? 'private/index.html' : 'public/login.html'));
    if (M === 'POST' && p === '/api/login') {
      if (over(ip)) return send(res, 429, { error: 'Too many attempts. Please try again in a few minutes.' });
      const b = await body(req), r = db.prepare('select * from users where email=?').get(String(b.email || '').trim().toLowerCase());
      if (!(check(String(b.password || ''), r ? r.pw : DUMMY) && r)) return send(res, 401, { error: 'Invalid email or password.' });
      return send(res, 200, { role: r.role }, { 'Set-Cookie': cookie(mkSession(r.id), 604800) });
    }
    if (M === 'POST' && p === '/api/signup') { // always creates a plain visitor; host email is reserved
      if (over(ip)) return send(res, 429, { error: 'Too many attempts. Please try again in a few minutes.' });
      const b = await body(req), e = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
      if (!/^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/.test(e) || e.length > 120) return send(res, 400, { error: 'Enter a valid email address.' });
      if (pw.length < 8 || pw.length > 128) return send(res, 400, { error: 'Password must be 8 to 128 characters.' });
      if (e === HOST || db.prepare('select 1 from users where email=?').get(e)) return send(res, 409, { error: 'This email cannot be registered. Try logging in.' });
      const id = db.prepare(`insert into users(email,pw,role) values(?,?,'visitor')`).run(e, hash(pw)).lastInsertRowid;
      return send(res, 200, { role: 'visitor' }, { 'Set-Cookie': cookie(mkSession(Number(id)), 604800) });
    }
    if (M === 'POST' && p === '/api/logout') { if (s) db.prepare('delete from sessions where h=?').run(s.h); return send(res, 200, { ok: 1 }, { 'Set-Cookie': cookie('', 0) }); }
    if (!s) return send(res, 401, { error: 'Sign in required.' });
    if (p === '/api/me') return send(res, 200, { email: s.email, role: s.role });
    if (p === '/api/content') { const a = all(); return send(res, 200, { projects: a.filter(x => x.kind === 'projects'), certs: a.filter(x => x.kind === 'certs') }); }
    if (p === '/api/events') { res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', ...SEC }); res.write('retry: 3000\n\n'); live.add(res); req.on('close', () => live.delete(res)); return; }
    if (p.startsWith('/uploads/')) {
      const n = path.basename(p), e = n.split('.').pop(), f = path.join(UP, n);
      if (!MIME[e] || !fs.existsSync(f)) return send(res, 404, { error: 'Not found.' });
      res.writeHead(200, { 'Content-Type': MIME[e], 'Cache-Control': 'private, max-age=3600', ...SEC }); return res.end(fs.readFileSync(f));
    }
    const m = /^\/api\/(projects|certs)(?:\/(\d+))?$/.exec(p);
    if (m) { // every write is authorised here, on the server
      if (s.role !== 'host') return send(res, 403, { error: 'Host access required.' });
      const kind = m[1], id = m[2] && +m[2], old = id && db.prepare('select data from items where id=? and kind=?').get(id, kind);
      if (M === 'POST' && !id) { const b = await body(req), o = clean(kind, b); if (b.upload) o.file = saveUpload(b.upload, kind === 'certs');
        db.prepare('insert into items(kind,data) values(?,?)').run(kind, JSON.stringify(o)); ping(); return send(res, 201, { ok: 1 }); }
      if (id && !old) return send(res, 404, { error: 'Not found.' });
      if (M === 'PUT' && id) { const b = await body(req), prev = JSON.parse(old.data), o = clean(kind, b); o.file = prev.file;
        if (b.upload) { o.file = saveUpload(b.upload, kind === 'certs'); rmFile(prev.file); }
        db.prepare('update items set data=? where id=?').run(JSON.stringify(o), id); ping(); return send(res, 200, { ok: 1 }); }
      if (M === 'DELETE' && id) { rmFile(JSON.parse(old.data).file); db.prepare('delete from items where id=?').run(id); ping(); return send(res, 200, { ok: 1 }); }
    }
    send(res, 404, { error: 'Not found.' });
  } catch (e) { send(res, typeof e === 'string' ? 400 : 500, { error: typeof e === 'string' ? e : 'Server error.' }); if (typeof e !== 'string') console.error(e); }
}).listen(PORT, () => console.log(`Portfolio running at http://localhost:${PORT}`));
