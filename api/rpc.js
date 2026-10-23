// API duy nhất cho hệ thống thi. Token Turso lấy từ biến môi trường trên Vercel, không nằm trong mã nguồn.
const { createClient } = require('@libsql/client');
const crypto = require('crypto');

const db = createClient({ url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN });
let SECRET;
const PASS = 70;
const hmac = s => crypto.createHmac('sha256', SECRET).update(s).digest('hex');
const E = m => Object.assign(new Error(m), { user: true });
const q = async (sql, args = []) => (await db.execute({ sql, args })).rows.map(r => ({ ...r }));
const j = (s, d) => { try { return JSON.parse(s) ?? d } catch (e) { return d } };

let ready;
const init = () => ready || (ready = db.batch([
  'CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY AUTOINCREMENT,q TEXT,o TEXT,a INTEGER,subj TEXT,lvl TEXT)',
  "CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,mode TEXT,dur INTEGER,cnt INTEGER,t1 INTEGER,t2 INTEGER,status TEXT,st INTEGER,en INTEGER)",
  "CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,eid INTEGER,name TEXT,unit TEXT,phone TEXT,qids TEXT,ans TEXT DEFAULT '{}',deadline INTEGER,done INTEGER DEFAULT 0,score REAL,ok INTEGER,sub INTEGER)",
  'CREATE TABLE IF NOT EXISTS cfg(k TEXT PRIMARY KEY,v TEXT)',
  'CREATE TABLE IF NOT EXISTS users(cccd TEXT PRIMARY KEY,name TEXT,unit TEXT,phone TEXT,pw TEXT,created INTEGER)'
]).then(async () => {
  for (const x of ['ALTER TABLE attempts ADD COLUMN cccd TEXT', 'DROP INDEX IF EXISTS ux_att', 'CREATE UNIQUE INDEX IF NOT EXISTS ux_att2 ON attempts(eid,cccd)']) await db.execute(x).catch(() => {});
  if (!(await cfg('secret'))) await db.execute({ sql: "INSERT OR IGNORE INTO cfg(k,v) VALUES('secret',?)", args: [crypto.randomBytes(32).toString('hex')] });
  SECRET = await cfg('secret');
}).catch(e => { ready = null; throw e }));

const cfg = async k => (await q('SELECT v FROM cfg WHERE k=?', [k]))[0]?.v ?? null;
const cset = (k, v) => q('INSERT INTO cfg(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', [k, v]);
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y) };
const hashPw = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 32).toString('hex') };
const checkPw = (p, st) => { const [s, h] = String(st || '').split(':'); return !!(s && h) && same(h, crypto.scryptSync(p, s, 32).toString('hex')) };
const gf = async k => String((await cfg('f:' + k)) || '0,0').split(',').map(Number);
const locked = async k => { const [, t] = await gf(k); if (t > Date.now()) throw E('Nhập sai quá nhiều lần, vui lòng thử lại sau 5 phút') };
const fail = async k => { const [n] = await gf(k), m = n + 1; await cset('f:' + k, m >= 5 ? '0,' + (Date.now() + 300000) : m + ',0'); await new Promise(r => setTimeout(r, 500)) };
const adminTok = async () => { const x = Date.now() + 12 * 3600e3; return x + '.' + hmac('adm' + x + await cfg('adm')) };
const isAdmin = async req => { const [x, s] = String(req.headers.authorization || '').replace('Bearer ', '').split('.'), h = await cfg('adm'); return !!(x && s && h && +x > Date.now() && same(s, hmac('adm' + x + h))) };
const utok = c => { const x = Date.now() + 30 * 864e5; return c + '.' + x + '.' + hmac('usr' + c + x) };
const uout = u => ({ ut: utok(u.cccd), cccd: u.cccd, name: u.name, unit: u.unit });
const uauth = async b => {
  const [c, x, s] = String(b.ut || '').split('.');
  if (!c || !s || +x < Date.now() || !same(s, hmac('usr' + c + x))) throw E('Vui lòng đăng nhập lại');
  const u = (await q('SELECT * FROM users WHERE cccd=?', [c]))[0];
  if (!u) throw E('Vui lòng đăng nhập lại');
  return u;
};
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
  async astat() { return { set: !!(await cfg('adm')) } },
  async setup(b) {
    if (await cfg('adm')) throw E('Tài khoản quản trị đã được thiết lập');
    const u = String(b.u || '').trim(), p = String(b.p || '');
    if (u.length < 3) throw E('Tên đăng nhập tối thiểu 3 ký tự');
    if (p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    await cset('admu', u); await cset('adm', hashPw(p));
    return { token: await adminTok() };
  },
  async login(b) {
    await locked('adm');
    const h = await cfg('adm');
    if (h && String(b.u || '').trim() === (await cfg('admu')) && checkPw(String(b.p || ''), h)) { await cset('f:adm', '0,0'); return { token: await adminTok() }; }
    await fail('adm'); throw E('Sai tên đăng nhập hoặc mật khẩu');
  },
  async chpw(b) {
    await locked('adm');
    const p = String(b.p || ''), u = String(b.u || '').trim();
    if (!checkPw(String(b.old || ''), await cfg('adm'))) { await fail('adm'); throw E('Mật khẩu hiện tại không đúng'); }
    if (p.length < 6) throw E('Mật khẩu mới tối thiểu 6 ký tự');
    if (u && u.length < 3) throw E('Tên đăng nhập tối thiểu 3 ký tự');
    await cset('adm', hashPw(p)); if (u) await cset('admu', u);
    return { token: await adminTok() };
  },
  async reg(b) {
    const cccd = String(b.cccd || '').trim(), name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').replace(/[\s.\-]/g, '').slice(0, 20), p = String(b.p || '');
    if (!/^\d{12}$/.test(cccd)) throw E('Số căn cước công dân phải gồm đúng 12 chữ số');
    if (!name) throw E('Vui lòng nhập họ và tên');
    if (p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    if (phone && !/^\+?\d{9,12}$/.test(phone)) throw E('Số điện thoại không hợp lệ');
    if ((await q('SELECT 1 x FROM users WHERE cccd=?', [cccd])).length) throw E('Số căn cước này đã có tài khoản, hãy đăng nhập');
    await q('INSERT INTO users(cccd,name,unit,phone,pw,created) VALUES(?,?,?,?,?,?)', [cccd, name, unit, phone, hashPw(p), Date.now()]);
    return uout({ cccd, name, unit });
  },
  async ulogin(b) {
    const c = String(b.cccd || '').trim(), k = 'u' + c; await locked(k);
    const u = (await q('SELECT * FROM users WHERE cccd=?', [c]))[0];
    if (!u || !checkPw(String(b.p || ''), u.pw)) { await fail(k); throw E('Sai số căn cước hoặc mật khẩu'); }
    await cset('f:' + k, '0,0'); return uout(u);
  },
  async theme() { return j(await cfg('theme'), {}) },
  async themeset(b) {
    const x = JSON.stringify(b.t && typeof b.t === 'object' ? b.t : {});
    if (x.length > 900000) throw E('Ảnh quá lớn, hãy chọn ảnh nhỏ hơn');
    await cset('theme', x); return { ok: 1 };
  },
  async ul() { return q('SELECT cccd,name,unit,phone,created FROM users ORDER BY created DESC') },
  async ures(b) { const c = String(b.cccd || ''); await q('UPDATE users SET pw=? WHERE cccd=?', [hashPw(c.slice(-6)), c]); return { ok: 1 } },
  async ud(b) { await q('DELETE FROM users WHERE cccd=?', [String(b.cccd || '')]); return { ok: 1 } },
  async exams() {
    const n = Date.now();
    return q("SELECT id,name,mode,dur,cnt,status,en FROM exams WHERE (mode='free' AND status='open' AND (t1 IS NULL OR t1<=?) AND (t2 IS NULL OR t2>=?)) OR (mode='live' AND (status='waiting' OR (status='running' AND en>?))) ORDER BY id DESC", [n, n, n]);
  },
  async join(b) {
    const u = await uauth(b), e = await getExam(b.eid), now = Date.now();
    if (e.mode === 'free' && (e.status !== 'open' || (e.t1 && now < e.t1) || (e.t2 && now > e.t2))) throw E('Kỳ thi hiện chưa mở hoặc đã đóng');
    if (e.mode === 'live' && (e.status === 'ended' || (e.status === 'running' && now >= e.en))) throw E('Kỳ thi đã kết thúc');
    if (!(await q('SELECT 1 x FROM questions LIMIT 1')).length) throw E('Ngân hàng câu hỏi đang trống, vui lòng liên hệ quản trị');
    const prev = (await q('SELECT id,done FROM attempts WHERE eid=? AND cccd=?', [e.id, u.cccd]))[0];
    if (prev) { if (prev.done) throw E('Bạn đã nộp bài kỳ thi này'); return { aid: prev.id, tok: hmac('att' + prev.id) }; }
    const id = crypto.randomUUID();
    const ids = e.mode === 'free' || e.status === 'running' ? await pick(e.cnt) : null;
    await q('INSERT INTO attempts(id,eid,name,unit,phone,cccd,qids,deadline) VALUES(?,?,?,?,?,?,?,?)', [id, e.id, u.name, u.unit, u.phone, u.cccd, ids && JSON.stringify(ids), e.mode === 'free' ? now + e.dur * 60000 : null]);
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
const ADM = new Set(['dash', 'ql', 'qs', 'qd', 'el', 'es', 'ed', 'start', 'end', 'mon', 'res', 'ext', 'qi', 'chpw', 'themeset', 'ul', 'ures', 'ud']);

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return res.status(405).json({ e: 'Method not allowed' });
    await init();
    const b = req.body || {}, f = H[b.a];
    if (!f) return res.status(400).json({ e: 'Yêu cầu không hợp lệ' });
    if (ADM.has(b.a) && !(await isAdmin(req))) return res.status(401).json({ e: 'Cần đăng nhập quản trị' });
    res.status(200).json(await f(b));
  } catch (e) {
    console.error(e);
    res.status(e.user ? 400 : 500).json({ e: e.user ? e.message : 'Lỗi máy chủ' });
  }
};
