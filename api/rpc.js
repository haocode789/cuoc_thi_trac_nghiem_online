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
  'CREATE TABLE IF NOT EXISTS users(cccd TEXT PRIMARY KEY,name TEXT,unit TEXT,phone TEXT,pw TEXT,created INTEGER)',
  'CREATE TABLE IF NOT EXISTS papers(id INTEGER PRIMARY KEY AUTOINCREMENT,eid INTEGER,no INTEGER,qids TEXT)'
]).then(async () => {
  for (const x of ['ALTER TABLE attempts ADD COLUMN cccd TEXT', 'DROP INDEX IF EXISTS ux_att', 'CREATE UNIQUE INDEX IF NOT EXISTS ux_att2 ON attempts(eid,cccd)', 'ALTER TABLE questions ADD COLUMN eid INTEGER', 'ALTER TABLE exams ADD COLUMN sm TEXT', 'ALTER TABLE exams ADD COLUMN ra INTEGER', 'ALTER TABLE exams ADD COLUMN rb INTEGER', 'ALTER TABLE exams ADD COLUMN sids TEXT', 'ALTER TABLE attempts ADD COLUMN st INTEGER', 'ALTER TABLE attempts ADD COLUMN rc INTEGER', 'ALTER TABLE attempts ADD COLUMN tt INTEGER', 'ALTER TABLE attempts ADD COLUMN pid INTEGER', 'ALTER TABLE exams ADD COLUMN pass INTEGER', 'CREATE INDEX IF NOT EXISTS ix_q ON questions(eid)',
    'INSERT INTO questions(q,o,a,subj,lvl,eid) SELECT x.q,x.o,x.a,x.subj,x.lvl,e.id FROM exams e JOIN questions x ON x.eid IS NULL WHERE e.sm IS NULL AND NOT EXISTS (SELECT 1 FROM questions y WHERE y.eid=e.id)',
    "UPDATE exams SET sm='random' WHERE sm IS NULL"]) await db.execute(x).catch(() => {});
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
  const e = await getExam(a.eid), okk = score >= (e.pass ?? PASS) ? 1 : 0;
  await q('UPDATE attempts SET done=1,score=?,ok=?,sub=?,rc=?,tt=? WHERE id=?', [score, okk, Math.min(Date.now(), eff(a, e) || Date.now()), right, ids.length, id]);
  return { ...a, done: 1, score, ok: okk };
}
async function sweep() {
  const now = Date.now();
  const rows = await q('SELECT a.id,a.deadline,e.mode,e.en FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.done=0 AND a.qids IS NOT NULL');
  for (const r of rows) if (now >= (r.mode === 'live' ? r.en : r.deadline)) await grade(r.id);
}
const assignPaper = async e => {
  const r = (await q('SELECT p.id,p.qids,(SELECT COUNT(*) FROM attempts a WHERE a.pid=p.id) u FROM papers p WHERE p.eid=? ORDER BY u, RANDOM() LIMIT 1', [e.id]))[0];
  return r ? { pid: r.id, ids: j(r.qids, []) } : null;
};
const getSet = async e => { if (e.sm === 'papers') { const p = await assignPaper(e); return { ids: p ? p.ids : [], pid: p ? p.pid : null }; } return { ids: await pickFor(e), pid: null }; };
const dropPapers = async eid => { await q('DELETE FROM papers WHERE eid=?', [eid]); await q("UPDATE exams SET sm='random' WHERE id=? AND sm='papers'", [eid]); };
const pickFor = async e => {
  const m = e.sm || 'random';
  if (m === 'papers') { const p = await assignPaper(e); return p ? p.ids : []; }
  if (m === 'random') return (await q('SELECT id FROM questions WHERE eid=? ORDER BY RANDOM() LIMIT ?', [e.id, e.cnt])).map(x => x.id);
  let ids = (await q('SELECT id FROM questions WHERE eid=? ORDER BY id', [e.id])).map(x => x.id);
  if (m === 'range') ids = ids.slice(Math.max(0, (+e.ra || 1) - 1), +e.rb || ids.length);
  else { const t = new Set(j(e.sids, [])); ids = ids.filter(i => t.has(i)); }
  for (let i = ids.length - 1; i > 0; i--) { const k = Math.floor(Math.random() * (i + 1)); [ids[i], ids[k]] = [ids[k], ids[i]]; }
  return ids;
};
async function mine(b) {
  if (!b.aid || b.tok !== hmac('att' + b.aid)) throw E('Phiên thi không hợp lệ');
  const a = (await q('SELECT * FROM attempts WHERE id=?', [b.aid]))[0];
  if (!a) throw E('Không tìm thấy bài thi');
  return a;
}

const busy = async eid => { await sweep(); if ((await q('SELECT 1 x FROM attempts WHERE done=0 AND qids IS NOT NULL AND eid=? LIMIT 1', [eid ?? -1])).length) throw E('Đang có thí sinh làm bài kỳ thi này, chưa thể xóa câu hỏi lúc này'); };

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
    const cccd = String(b.cccd || '').trim(), name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').trim().slice(0, 20), p = String(b.p || '');
    if (!/^\d{12}$/.test(cccd)) throw E('Số căn cước công dân phải gồm đúng 12 chữ số');
    if (!name) throw E('Vui lòng nhập họ và tên');
    if (p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
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
  async me(b) { const u = await uauth(b); return { cccd: u.cccd, name: u.name, unit: u.unit, phone: u.phone }; },
  async meset(b) {
    const u = await uauth(b), name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').trim().slice(0, 20);
    if (!name) throw E('Vui lòng nhập họ và tên');
    await q('UPDATE users SET name=?,unit=?,phone=? WHERE cccd=?', [name, unit, phone, u.cccd]);
    return { name, unit, phone };
  },
  async mepw(b) {
    const u = await uauth(b), k = 'u' + u.cccd, p = String(b.p || ''); await locked(k);
    if (!checkPw(String(b.old || ''), u.pw)) { await fail(k); throw E('Mật khẩu hiện tại không đúng'); }
    if (p.length < 6) throw E('Mật khẩu mới tối thiểu 6 ký tự');
    await q('UPDATE users SET pw=? WHERE cccd=?', [hashPw(p), u.cccd]); await cset('f:' + k, '0,0');
    return { ok: 1 };
  },
  async myres(b) {
    const u = await uauth(b); await sweep();
    return (await q('SELECT a.qids,a.done,a.score,a.ok,a.sub,e.name exam FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.cccd=? ORDER BY a.rowid DESC', [u.cccd])).map(r => { const total = j(r.qids, []).length; return { exam: r.exam, done: r.done, score: r.score, ok: r.ok, sub: r.sub, total, wait: !r.qids, right: r.done ? Math.round((r.score || 0) * total / 100) : 0 }; });
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
    if (!(await q('SELECT 1 x FROM questions WHERE eid=? LIMIT 1', [e.id])).length) throw E('Kỳ thi chưa có câu hỏi, vui lòng liên hệ quản trị');
    const prev = (await q('SELECT id,done FROM attempts WHERE eid=? AND cccd=?', [e.id, u.cccd]))[0];
    if (prev) { if (prev.done) throw E('Bạn đã nộp bài kỳ thi này'); return { aid: prev.id, tok: hmac('att' + prev.id) }; }
    const id = crypto.randomUUID();
    const set = e.mode === 'free' || e.status === 'running' ? await getSet(e) : null, ids = set && set.ids;
    if (ids && !ids.length) throw E('Kỳ thi chưa có câu hỏi, vui lòng liên hệ quản trị');
    await q('INSERT INTO attempts(id,eid,name,unit,phone,cccd,qids,deadline,pid,st) VALUES(?,?,?,?,?,?,?,?,?,?)', [id, e.id, u.name, u.unit, u.phone, u.cccd, ids && JSON.stringify(ids), e.mode === 'free' ? now + e.dur * 60000 : null, set ? set.pid : null, ids ? now : null]);
    return { aid: id, tok: hmac('att' + id) };
  },
  async state(b) {
    let a = await mine(b); const e = await getExam(a.eid), now = Date.now();
    const res = x => ({ s: 'done', score: x.score, ok: x.ok, exam: e.name });
    if (a.done) return res(a);
    if (e.mode === 'live') {
      if (e.status === 'waiting') return { s: 'wait', exam: e.name, n: (await q('SELECT COUNT(*) c FROM attempts WHERE eid=?', [e.id]))[0].c };
      if (e.status === 'ended' && !a.qids) return { s: 'ended', exam: e.name };
      if (!a.qids) { const set = await getSet(e); if (!set.ids.length) throw E('Kỳ thi chưa có câu hỏi'); await q('UPDATE attempts SET qids=?,pid=?,st=? WHERE id=? AND qids IS NULL', [JSON.stringify(set.ids), set.pid, Date.now(), a.id]); a = (await q('SELECT * FROM attempts WHERE id=?', [a.id]))[0]; }
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
  async ql(b) { return (await q('SELECT * FROM questions WHERE eid=? ORDER BY id', [+b.eid || 0])).map(r => ({ ...r, o: j(r.o, []) })); },
  async qs(b) {
    const o = JSON.stringify((b.o || []).slice(0, 4).map(String));
    if (!b.q || (b.o || []).length < 2) throw E('Thiếu nội dung câu hỏi hoặc đáp án');
    if (!(+b.a >= 0 && +b.a < Math.min(4, b.o.length))) throw E('Chưa chọn đáp án đúng hợp lệ');
    if (b.id) await q('UPDATE questions SET q=?,o=?,a=?,subj=?,lvl=? WHERE id=?', [b.q, o, +b.a, b.subj, b.lvl, b.id]);
    else { await getExam(b.eid); await q('INSERT INTO questions(q,o,a,subj,lvl,eid) VALUES(?,?,?,?,?,?)', [b.q, o, +b.a, b.subj, b.lvl, +b.eid]); }
    return { ok: 1 };
  },
  async qd(b) { const x = (await q('SELECT eid FROM questions WHERE id=?', [b.id]))[0]; await busy(x && x.eid); await q('DELETE FROM questions WHERE id=?', [b.id]); if (x && x.eid) await dropPapers(x.eid); return { ok: 1 }; },
  async qda(b) { await busy(+b.eid); await q('DELETE FROM questions WHERE eid=?', [+b.eid]); await dropPapers(+b.eid); return { ok: 1 }; },
  async qold() { return { n: (await q('SELECT COUNT(*) c FROM questions WHERE eid IS NULL'))[0].c }; },
  async qcp(b) {
    const e = await getExam(b.eid), old = b.from === 'old';
    if (!old) await getExam(b.from);
    const r = await db.execute({ sql: `INSERT INTO questions(q,o,a,subj,lvl,eid) SELECT q,o,a,subj,lvl,? FROM questions WHERE ${old ? 'eid IS NULL' : 'eid=?'} ORDER BY id`, args: old ? [e.id] : [e.id, +b.from] });
    return { n: r.rowsAffected };
  },
  async el() {
    return q('SELECT e.*,(SELECT COUNT(*) FROM attempts WHERE eid=e.id) n,(SELECT COUNT(*) FROM questions WHERE eid=e.id) qn,(SELECT COUNT(*) FROM papers WHERE eid=e.id) pn FROM exams e ORDER BY id DESC');
  },
  async es(b) {
    if (!b.name) throw E('Vui lòng nhập tên kỳ thi');
    const old = b.id ? await getExam(b.id) : null;
    const dur = Math.max(1, +b.dur || (old ? old.dur : 30)), cnt = Math.max(1, +b.cnt || (old ? old.cnt : 10)), t1 = b.t1 || null, t2 = b.t2 || null;
    const pass = b.pass === undefined || b.pass === null || b.pass === '' ? (old ? (old.pass ?? PASS) : PASS) : Math.min(100, Math.max(0, +b.pass || 0));
    if (old) {
      await q('UPDATE exams SET name=?,dur=?,cnt=?,t1=?,t2=?,pass=? WHERE id=?', [b.name, dur, cnt, t1, t2, pass, old.id]);
      await q('UPDATE attempts SET ok=(CASE WHEN score>=? THEN 1 ELSE 0 END) WHERE eid=? AND done=1', [pass, old.id]);
      return { ok: 1, id: old.id };
    }
    const live = b.mode === 'live';
    const r = await db.execute({ sql: 'INSERT INTO exams(name,mode,dur,cnt,t1,t2,status,sm,pass) VALUES(?,?,?,?,?,?,?,?,?)', args: [b.name, live ? 'live' : 'free', dur, cnt, t1, t2, live ? 'waiting' : 'open', 'random', pass] });
    return { ok: 1, id: Number(r.lastInsertRowid) };
  },
  async pgen(b) {
    const e = await getExam(b.id), n = Math.min(500, Math.max(1, +b.n || 0)), c = Math.max(1, +b.c || 0);
    if ((await q('SELECT 1 x FROM attempts WHERE eid=? LIMIT 1', [e.id])).length) throw E('Kỳ thi đã có thí sinh tham gia, không thể tạo lại bộ đề');
    const pool = (await q('SELECT id FROM questions WHERE eid=?', [e.id])).map(x => x.id);
    if (!pool.length) throw E('Kỳ thi chưa có câu hỏi');
    if (c > pool.length) throw E('Mỗi bộ đề cần ' + c + ' câu nhưng kỳ thi chỉ có ' + pool.length + ' câu');
    const rows = [];
    for (let i = 1; i <= n; i++) { const a = pool.slice(); for (let k = a.length - 1; k > 0; k--) { const r = Math.floor(Math.random() * (k + 1)); [a[k], a[r]] = [a[r], a[k]]; } rows.push({ sql: 'INSERT INTO papers(eid,no,qids) VALUES(?,?,?)', args: [e.id, i, JSON.stringify(a.slice(0, c))] }); }
    await db.batch([{ sql: 'DELETE FROM papers WHERE eid=?', args: [e.id] }, ...rows, { sql: "UPDATE exams SET sm='papers',cnt=? WHERE id=?", args: [c, e.id] }]);
    return { ok: 1, n };
  },
  async pl(b) { return (await q('SELECT p.id,p.no,p.qids,(SELECT COUNT(*) FROM attempts a WHERE a.pid=p.id) u FROM papers p WHERE p.eid=? ORDER BY p.no', [+b.eid])).map(x => ({ id: x.id, no: x.no, c: j(x.qids, []).length, u: x.u })); },
  async pd(b) {
    const p = (await q('SELECT * FROM papers WHERE id=?', [b.id]))[0]; if (!p) throw E('Không tìm thấy bộ đề');
    const ids = j(p.qids, []), rows = ids.length ? await q(`SELECT id,q,o,a FROM questions WHERE id IN (${ids.map(() => '?').join(',')})`, ids) : [];
    const by = Object.fromEntries(rows.map(r => [r.id, r]));
    return { no: p.no, qs: ids.map(i => by[i]).filter(Boolean).map(r => ({ id: r.id, q: r.q, o: j(r.o, []), a: r.a })) };
  },
  async esel(b) {
    const e = await getExam(b.id), sm = ['random', 'range', 'manual', 'papers'].includes(b.sm) ? b.sm : 'random';
    if (sm === 'papers' && !(await q('SELECT 1 x FROM papers WHERE eid=? LIMIT 1', [e.id])).length) throw E('Hãy bấm "Tạo bộ đề" trước');
    const ids = (Array.isArray(b.sids) ? b.sids : []).map(Number).filter(Number.isInteger);
    const ra = Math.max(1, +b.ra || 1), rb = Math.max(ra, +b.rb || ra);
    await q('UPDATE exams SET sm=?,cnt=?,ra=?,rb=?,sids=? WHERE id=?', [sm, Math.max(1, +b.cnt || e.cnt), ra, rb, JSON.stringify(ids), e.id]);
    return { ok: 1 };
  },
  async ed(b) { await q('DELETE FROM papers WHERE eid=?', [b.id]); await q('DELETE FROM questions WHERE eid=?', [b.id]); await q('DELETE FROM attempts WHERE eid=?', [b.id]); await q('DELETE FROM exams WHERE id=?', [b.id]); return { ok: 1 }; },
  async start(b) {
    const e = await getExam(b.id), now = Date.now();
    if (e.mode === 'live' && !(await pickFor(e)).length) throw E('Kỳ thi chưa có câu hỏi, hãy thêm câu hỏi trước khi bắt đầu');
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
    const eid = (await getExam(b.eid)).id;
    if (b.replace) await busy(eid);
    await db.batch([...(b.replace ? [{ sql: 'DELETE FROM questions WHERE eid=?', args: [eid] }] : []), ...L.map(x => ({ sql: 'INSERT INTO questions(q,o,a,subj,lvl,eid) VALUES(?,?,?,?,?,?)', args: [x.q, JSON.stringify(x.o), x.a, x.s, x.l, eid] }))]);
    if (b.replace) await dropPapers(eid);
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
    return q('SELECT a.name,a.unit,a.phone,a.cccd,a.score,a.ok,a.sub,a.st,a.rc,a.tt,e.id eid,e.name exam,e.pass FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.done=1 ORDER BY a.sub DESC');
  }
};
const ADM = new Set(['dash', 'ql', 'qs', 'qd', 'el', 'es', 'ed', 'start', 'end', 'mon', 'res', 'ext', 'qi', 'qda', 'pgen', 'pl', 'pd', 'esel', 'qcp', 'qold', 'chpw', 'themeset', 'ul', 'ures', 'ud']);

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
