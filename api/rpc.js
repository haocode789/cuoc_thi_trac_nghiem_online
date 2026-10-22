// API duy nhất cho hệ thống thi. Token Turso lấy từ biến môi trường trên Vercel, không nằm trong mã nguồn.
const { createClient } = require('@libsql/client');
const crypto = require('crypto');

const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
const SECRET = process.env.SECRET;
const PASS = 70;
const hmac = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const E = m => Object.assign(new Error(m), { user: true });
const q = async (sql, args = []) => (await db.execute({ sql, args })).rows.map(r => ({ ...r }));
const j = (s, d) => { try { return JSON.parse(s) ?? d } catch (e) { return d } };

const wait = ms => new Promise(r => setTimeout(r, ms));
const getS = async k => (await q('SELECT v FROM settings WHERE k=?', [k]))[0]?.v;
const setS = (k, v) => q('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', [k, v]);
const hashPw = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 32).toString('hex') };
const chkPw = (p, h) => { const [s, x] = String(h || '').split(':'); if (!s || !x) return false; const y = crypto.scryptSync(String(p), s, 32), z = Buffer.from(x, 'hex'); return z.length === y.length && crypto.timingSafeEqual(y, z) };
const admUser = async () => (await getS('admin_user')) || process.env.ADMIN_USER || 'admin';
const admOk = async (u, p) => {
  const sp = await getS('admin_pw');
  if (sp) return u === (await admUser()) && chkPw(p, sp);
  return !!process.env.ADMIN_PASS && u === (process.env.ADMIN_USER || 'admin') && p === process.env.ADMIN_PASS;
};

let ready;
const init = () => ready || (ready = (async () => {
  await db.batch([
    'CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY AUTOINCREMENT,q TEXT,o TEXT,a INTEGER,subj TEXT,lvl TEXT)',
    "CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,mode TEXT,dur INTEGER,cnt INTEGER,t1 INTEGER,t2 INTEGER,status TEXT,st INTEGER,en INTEGER)",
    "CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,eid INTEGER,name TEXT,unit TEXT,phone TEXT,qids TEXT,ans TEXT DEFAULT '{}',deadline INTEGER,done INTEGER DEFAULT 0,score REAL,ok INTEGER,sub INTEGER)",
    'CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,cccd TEXT UNIQUE,name TEXT,unit TEXT,phone TEXT,pw TEXT,created INTEGER)',
    'CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT)'
  ]);
  await db.execute('ALTER TABLE attempts ADD COLUMN uid INTEGER').catch(() => {});
  await db.execute('DROP INDEX IF EXISTS ux_att').catch(() => {});
  await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS ux_att2 ON attempts(eid,uid)').catch(() => {});
})().catch(e => { ready = null; throw e }));

const adminTok = () => { const x = Date.now() + 12 * 3600e3; return x + '.' + hmac('adm' + x) };
const isAdmin = req => { const [x, s] = String(req.headers.authorization || '').replace('Bearer ', '').split('.'); return x && s && +x > Date.now() && s === hmac('adm' + x) };
const userTok = id => { const x = Date.now() + 30 * 864e5; return 'U.' + id + '.' + x + '.' + hmac('usr' + id + '.' + x) };
const userId = req => { const [t, id, x, s] = String(req.headers.authorization || '').replace('Bearer ', '').split('.'); return t === 'U' && +x > Date.now() && s === hmac('usr' + id + '.' + x) ? +id : 0 };
const getExam = async id => { const e = (await q('SELECT * FROM exams WHERE id=?', [id]))[0]; if (!e) throw E('Không tìm thấy kỳ thi'); return e };
const eff = (a, e) => e.mode === 'live' ? e.en : a.deadline;

async function grade(id) {
  const a = (await q('SELECT * FROM attempts WHERE id=?', [id]))[0];
  if (!a || a.done) return a;
  const ids = j(a.qids, []), ans = j(a.ans, {});
  const qs = ids.length ? await q(`SELECT id,a FROM questions WHERE id IN (${ids.map(() => '?').join(',')})`, ids) : [];
  const key = Object.fromEntries(qs.map(x => [x.id, x.a]));
  const right = ids.filter((id, i) => ans[i] === key[id]).length;
  const score = ids.length ? Math.round(right / ids.length * 1000) / 10 : 0;
  await q('UPDATE attempts SET done=1,score=?,ok=?,sub=? WHERE id=?', [score, score >= PASS ? 1 : 0, Date.now(), id]);
  return { ...a, done: 1, score, ok: score >= PASS ? 1 : 0 };
}
async function sweep() {
  const now = Date.now();
  const rows = await q('SELECT a.id,a.deadline,e.mode,e.en FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.done=0 AND a.qids IS NOT NULL');
  for (const r of rows) if (now >= (r.mode === 'live' ? r.en : r.deadline)) await grade(r.id);
}
const pick = async n => (await q('SELECT id FROM questions ORDER BY RANDOM() LIMIT ?', [n])).map(x => x.id);
async function mine(b) {
  if (!b.aid || b.tok !== hmac('att' + b.aid)) throw E('Phiên thi không hợp lệ');
  const a = (await q('SELECT * FROM attempts WHERE id=?', [b.aid]))[0];
  if (!a) throw E('Không tìm thấy bài thi');
  return a;
}

const H = {
  async login(b) {
    if (await admOk(b.u, b.p)) return { token: adminTok() };
    await wait(700);
    throw E('Sai tên đăng nhập hoặc mật khẩu');
  },
  async theme() { return j(await getS('theme'), {}) },
  async reg(b) {
    const cccd = String(b.cccd || '').replace(/\s/g, ''), name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').replace(/[\s.\-]/g, '').slice(0, 20), pw = String(b.pw || '');
    if (!/^\d{12}$/.test(cccd)) throw E('Số căn cước công dân phải gồm đúng 12 chữ số');
    if (!name) throw E('Vui lòng nhập họ và tên');
    if (phone && !/^\+?\d{9,12}$/.test(phone)) throw E('Số điện thoại không hợp lệ');
    if (pw.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    try {
      const r = await db.execute({ sql: 'INSERT INTO users(cccd,name,unit,phone,pw,created) VALUES(?,?,?,?,?,?)', args: [cccd, name, unit, phone, hashPw(pw), Date.now()] });
      return { token: userTok(Number(r.lastInsertRowid)) };
    } catch (e) { if (/UNIQUE|constraint/i.test(e.message)) throw E('Số căn cước này đã được đăng ký, vui lòng đăng nhập'); throw e }
  },
  async ulogin(b) {
    const u = (await q('SELECT id,pw FROM users WHERE cccd=?', [String(b.cccd || '').trim()]))[0];
    if (u && chkPw(b.pw, u.pw)) return { token: userTok(u.id) };
    await wait(700); throw E('Sai số căn cước hoặc mật khẩu');
  },
  async me(b) { return (await q('SELECT cccd,name,unit,phone FROM users WHERE id=?', [b.uid]))[0] || (() => { throw E('Tài khoản không tồn tại') })() },
  async mset(b) {
    const name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').replace(/[\s.\-]/g, '').slice(0, 20);
    if (!name) throw E('Vui lòng nhập họ và tên');
    if (phone && !/^\+?\d{9,12}$/.test(phone)) throw E('Số điện thoại không hợp lệ');
    await q('UPDATE users SET name=?,unit=?,phone=? WHERE id=?', [name, unit, phone, b.uid]); return { ok: 1 };
  },
  async mpw(b) {
    const u = (await q('SELECT pw FROM users WHERE id=?', [b.uid]))[0];
    if (!u || !chkPw(b.old, u.pw)) { await wait(500); throw E('Mật khẩu hiện tại không đúng') }
    if (String(b.np || '').length < 6) throw E('Mật khẩu mới tối thiểu 6 ký tự');
    await q('UPDATE users SET pw=? WHERE id=?', [hashPw(String(b.np)), b.uid]); return { ok: 1 };
  },
  async myex(b) {
    await sweep();
    return (await q('SELECT a.id aid,a.done,a.score,a.ok,a.sub,e.id eid,e.name,e.mode,e.status,e.en,a.qids IS NOT NULL st FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.uid=? ORDER BY a.rowid DESC', [b.uid])).map(r => ({ ...r, tok: hmac('att' + r.aid) }));
  },
  async exams() {
    const n = Date.now();
    return q("SELECT id,name,mode,dur,cnt,status,en FROM exams WHERE (mode='free' AND status='open' AND (t1 IS NULL OR t1<=?) AND (t2 IS NULL OR t2>=?)) OR (mode='live' AND (status='waiting' OR (status='running' AND en>?))) ORDER BY id DESC", [n, n, n]);
  },
  async join(b) {
    const u = (await q('SELECT * FROM users WHERE id=?', [b.uid]))[0];
    if (!u) throw E('Tài khoản không tồn tại');
    const e = await getExam(b.eid), now = Date.now();
    if (!(await q('SELECT 1 x FROM questions LIMIT 1')).length) throw E('Ngân hàng câu hỏi đang trống, vui lòng liên hệ quản trị');
    if (e.mode === 'free' && (e.status !== 'open' || (e.t1 && now < e.t1) || (e.t2 && now > e.t2))) throw E('Kỳ thi hiện chưa mở hoặc đã đóng');
    if (e.mode === 'live' && (e.status === 'ended' || (e.status === 'running' && now >= e.en))) throw E('Kỳ thi đã kết thúc');
    const prev = (await q('SELECT id,done FROM attempts WHERE eid=? AND uid=?', [e.id, u.id]))[0];
    if (prev) { if (prev.done) throw E('Bạn đã nộp bài kỳ thi này'); return { aid: prev.id, tok: hmac('att' + prev.id) }; }
    const id = crypto.randomUUID();
    const ids = e.mode === 'free' || e.status === 'running' ? await pick(e.cnt) : null;
    await q('INSERT INTO attempts(id,eid,name,unit,phone,qids,deadline,uid) VALUES(?,?,?,?,?,?,?,?)', [id, e.id, u.name, u.unit, u.phone || u.cccd, ids && JSON.stringify(ids), e.mode === 'free' ? now + e.dur * 60000 : null, u.id]);
    return { aid: id, tok: hmac('att' + id) };
  },
  async state(b) {
    let a = await mine(b); const e = await getExam(a.eid), now = Date.now();
    const res = x => ({ s: 'done', score: x.score, ok: x.ok, exam: e.name });
    if (a.done) return res(a);
    if (e.mode === 'live') {
      if (e.status === 'waiting') return { s: 'wait', exam: e.name, n: (await q('SELECT COUNT(*) c FROM attempts WHERE eid=?', [e.id]))[0].c };
      if (e.status === 'ended' && !a.qids) return { s: 'ended', exam: e.name };
      if (!a.qids) { await q('UPDATE attempts SET qids=? WHERE id=? AND qids IS NULL', [JSON.stringify(await pick(e.cnt)), a.id]); a = (await q('SELECT * FROM attempts WHERE id=?', [a.id]))[0]; }
    }
    const dl = eff(a, e);
    if (now >= dl) return res(await grade(a.id));
    if (b.light) return { s: 'run', now, dl };
    const ids = j(a.qids, []);
    const rows = ids.length ? await q(`SELECT id,q,o FROM questions WHERE id IN (${ids.map(() => '?').join(',')})`, ids) : [];
    const by = Object.fromEntries(rows.map(r => [r.id, r]));
    return { s: 'run', exam: e.name, now, dl, ans: j(a.ans, {}), qs: ids.map(i => by[i]).filter(Boolean).map(r => ({ id: r.id, q: r.q, o: j(r.o, []) })) };
  },
  async answer(b) {
    const a = await mine(b), e = await getExam(a.eid);
    if (a.done || Date.now() >= eff(a, e)) return { ok: 0 };
    const ans = j(a.ans, {}); ans[+b.i] = +b.v;
    await q('UPDATE attempts SET ans=? WHERE id=?', [JSON.stringify(ans), a.id]);
    return { ok: 1 };
  },
  async submit(b) { const a = await mine(b); if (!a.qids) throw E('Kỳ thi chưa bắt đầu'); const r = await grade(a.id); return { score: r.score, ok: r.ok }; },

  // quản trị
  async ainfo() { return { u: await admUser() } },
  async apw(b) {
    const cu = await admUser(), nu = String(b.nu || '').trim().slice(0, 40) || cu, np = String(b.np || '');
    if (!(await admOk(cu, b.old))) { await wait(500); throw E('Mật khẩu hiện tại không đúng') }
    if (np.length < 6) throw E('Mật khẩu mới tối thiểu 6 ký tự');
    await setS('admin_user', nu); await setS('admin_pw', hashPw(np)); return { ok: 1, u: nu };
  },
  async thset(b) {
    const t = b.t || {}, c = v => /^#[0-9a-f]{6}$/i.test(v), n = (v, a, z, d) => { v = parseFloat(v); return Number.isFinite(v) ? Math.min(z, Math.max(a, v)) : d }, im = v => /^(data:image\/|https?:\/\/)/.test(v) ? String(v) : '';
    const o = { menu: c(t.menu) ? t.menu : '#0a2a6e', acc: c(t.acc) ? t.acc : '#1a5fe0', bg: c(t.bg) ? t.bg : '#f3f6fc', ff: String(t.ff || '').slice(0, 120).replace(/[;{}<>]/g, ''), fs: n(t.fs, 12, 20, 14), r: n(t.r, 0, 28, 12), hz: n(t.hz, 1, 1.15, 1.04), zoom: t.zoom ? 1 : 0, logo: im(t.logo), hero: im(t.hero) };
    const s = JSON.stringify(o); if (s.length > 2e6) throw E('Ảnh quá lớn, vui lòng chọn ảnh nhỏ hơn');
    await setS('theme', s); return { ok: 1 };
  },
  async dash() {
    await sweep();
    const c = async s => (await q(s))[0].c;
    return { run: await c("SELECT COUNT(*) c FROM exams WHERE status IN ('open','running','waiting')"), att: await c('SELECT COUNT(*) c FROM attempts'), qn: await c('SELECT COUNT(*) c FROM questions'), done: await c('SELECT COUNT(*) c FROM attempts WHERE done=1'), pass: await c('SELECT COUNT(*) c FROM attempts WHERE ok=1'), avg: (await q('SELECT AVG(score) v FROM attempts WHERE done=1'))[0].v };
  },
  async ql() { return (await q('SELECT * FROM questions ORDER BY id DESC')).map(r => ({ ...r, o: j(r.o, []) })); },
  async qs(b) {
    const o = JSON.stringify((b.o || []).slice(0, 4).map(String));
    if (!b.q || (b.o || []).length < 2) throw E('Thiếu nội dung câu hỏi hoặc đáp án');
    if (b.id) await q('UPDATE questions SET q=?,o=?,a=?,subj=?,lvl=? WHERE id=?', [b.q, o, +b.a, b.subj, b.lvl, b.id]);
    else await q('INSERT INTO questions(q,o,a,subj,lvl) VALUES(?,?,?,?,?)', [b.q, o, +b.a, b.subj, b.lvl]);
    return { ok: 1 };
  },
  async qd(b) { await q('DELETE FROM questions WHERE id=?', [b.id]); return { ok: 1 }; },
  async el() {
    return q('SELECT e.*,(SELECT COUNT(*) FROM attempts WHERE eid=e.id) n FROM exams e ORDER BY id DESC');
  },
  async es(b) {
    if (!b.name) throw E('Vui lòng nhập tên kỳ thi');
    const live = b.mode === 'live';
    await q('INSERT INTO exams(name,mode,dur,cnt,t1,t2,status) VALUES(?,?,?,?,?,?,?)', [b.name, live ? 'live' : 'free', Math.max(1, +b.dur || 30), Math.max(1, +b.cnt || 10), b.t1 || null, b.t2 || null, live ? 'waiting' : 'open']);
    return { ok: 1 };
  },
  async ed(b) { await q('DELETE FROM attempts WHERE eid=?', [b.id]); await q('DELETE FROM exams WHERE id=?', [b.id]); return { ok: 1 }; },
  async start(b) {
    const e = await getExam(b.id), now = Date.now();
    if (e.mode === 'live' && !(await q('SELECT 1 x FROM questions LIMIT 1')).length) throw E('Ngân hàng câu hỏi đang trống');
    if (e.mode === 'live') await q("UPDATE exams SET status='running',st=?,en=? WHERE id=?", [now, now + e.dur * 60000, e.id]);
    else await q("UPDATE exams SET status='open' WHERE id=?", [e.id]);
    return { ok: 1 };
  },
  async end(b) {
    const e = await getExam(b.id);
    if (e.mode === 'live') await q("UPDATE exams SET status='ended',en=? WHERE id=?", [Date.now(), e.id]);
    else await q("UPDATE exams SET status='closed' WHERE id=?", [e.id]);
    await sweep(); return { ok: 1 };
  },
  async ext(b) {
    const e = await getExam(b.id), m = Math.min(120, Math.max(1, +b.m || 5));
    if (e.mode !== 'live' || e.status !== 'running') throw E('Chỉ gia hạn được kỳ thi đồng loạt đang diễn ra');
    await q('UPDATE exams SET en=en+? WHERE id=?', [m * 60000, e.id]); return { ok: 1 };
  },
  async qi(b) {
    const L = (Array.isArray(b.list) ? b.list : []).slice(0, 500).map(x => ({ q: String(x.q || '').trim(), o: (x.o || []).map(s => String(s).trim()).filter(Boolean).slice(0, 4), a: +x.a, s: x.s || 'Pháp luật', l: x.l || 'Trung bình' })).filter(x => x.q && x.o.length >= 2 && x.a >= 0 && x.a < x.o.length);
    if (!L.length) throw E('Không có câu hỏi hợp lệ để nhập');
    await db.batch(L.map(x => ({ sql: 'INSERT INTO questions(q,o,a,subj,lvl) VALUES(?,?,?,?,?)', args: [x.q, JSON.stringify(x.o), x.a, x.s, x.l] })));
    return { ok: 1, n: L.length };
  },
  async mon(b) {
    await sweep();
    const e = await getExam(b.id);
    const rows = await q('SELECT id,name,unit,phone,qids,ans,done,score,ok FROM attempts WHERE eid=? ORDER BY name', [e.id]);
    return { e, at: rows.map(r => ({ id: r.id, name: r.name, unit: r.unit, phone: r.phone, total: j(r.qids, []).length, got: Object.keys(j(r.ans, {})).length, done: r.done, score: r.score, ok: r.ok })) };
  },
  async res() {
    await sweep();
    return q('SELECT a.name,a.unit,a.phone,a.score,a.ok,a.sub,e.name exam FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.done=1 ORDER BY a.sub DESC');
  }
};
const ADM = new Set(['dash', 'ql', 'qs', 'qd', 'el', 'es', 'ed', 'start', 'end', 'mon', 'res', 'ext', 'qi', 'ainfo', 'apw', 'thset']);
const USR = new Set(['join', 'me', 'mset', 'mpw', 'myex']);

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return res.status(405).json({ e: 'Method not allowed' });
    if (!SECRET) throw E('Máy chủ chưa cấu hình biến môi trường SECRET');
    await init();
    const b = req.body || {}, f = H[b.a];
    if (!f) return res.status(400).json({ e: 'Yêu cầu không hợp lệ' });
    if (ADM.has(b.a) && !isAdmin(req)) return res.status(401).json({ e: 'Cần đăng nhập quản trị' });
    if (USR.has(b.a)) { b.uid = userId(req); if (!b.uid) return res.status(401).json({ e: 'Vui lòng đăng nhập' }) }
    res.status(200).json(await f(b));
  } catch (e) {
    console.error(e);
    res.status(e.user ? 400 : 500).json({ e: e.user ? e.message : 'Lỗi máy chủ' });
  }
};
