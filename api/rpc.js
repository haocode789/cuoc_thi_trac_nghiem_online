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

const SCHEMA = 8;
const IMGK = ['logo', 'hero', 'banner', 'menubg', 'loginbg'];
const HOT = new Set(['adm', 'admu', 'secret', 'subu', 'subpw']);   // cấu hình ít đổi: giữ trong bộ nhớ, không hỏi DB mỗi request
const CC = new Map();
const cfg = async k => {
  if (HOT.has(k)) { const c = CC.get(k); if (c && Date.now() - c.t < 30000) return c.v; }
  const v = (await q('SELECT v FROM cfg WHERE k=?', [k]))[0]?.v ?? null;
  if (HOT.has(k)) CC.set(k, { v, t: Date.now() });
  return v;
};
const cset = async (k, v) => {
  await q('INSERT INTO cfg(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', [k, v]);
  if (HOT.has(k)) CC.set(k, { v, t: Date.now() });
};

const DDL = [
  'CREATE TABLE IF NOT EXISTS questions(id INTEGER PRIMARY KEY AUTOINCREMENT,q TEXT,o TEXT,a INTEGER,subj TEXT,lvl TEXT)',
  "CREATE TABLE IF NOT EXISTS exams(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,mode TEXT,dur INTEGER,cnt INTEGER,t1 INTEGER,t2 INTEGER,status TEXT,st INTEGER,en INTEGER)",
  "CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,eid INTEGER,name TEXT,unit TEXT,phone TEXT,qids TEXT,ans TEXT DEFAULT '{}',deadline INTEGER,done INTEGER DEFAULT 0,score REAL,ok INTEGER,sub INTEGER)",
  'CREATE TABLE IF NOT EXISTS cfg(k TEXT PRIMARY KEY,v TEXT)', 'CREATE TABLE IF NOT EXISTS fails(k TEXT PRIMARY KEY,n INTEGER,t INTEGER)', 'CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY AUTOINCREMENT,cccd TEXT,fr TEXT,body TEXT,at INTEGER,rd INTEGER DEFAULT 0,nm TEXT,v INTEGER DEFAULT 0)', 'CREATE INDEX IF NOT EXISTS ix_msg ON msgs(cccd)',
  'CREATE TABLE IF NOT EXISTS users(cccd TEXT PRIMARY KEY,name TEXT,unit TEXT,phone TEXT,pw TEXT,created INTEGER)',
  'CREATE TABLE IF NOT EXISTS papers(id INTEGER PRIMARY KEY AUTOINCREMENT,eid INTEGER,no INTEGER,qids TEXT)'
];
const MIG = [
  'ALTER TABLE attempts ADD COLUMN cccd TEXT', 'DROP INDEX IF EXISTS ux_att', 'DROP INDEX IF EXISTS ux_att2',
  'ALTER TABLE questions ADD COLUMN eid INTEGER', 'ALTER TABLE exams ADD COLUMN sm TEXT', 'ALTER TABLE exams ADD COLUMN ra INTEGER', 'ALTER TABLE exams ADD COLUMN rb INTEGER', 'ALTER TABLE exams ADD COLUMN sids TEXT',
  'ALTER TABLE attempts ADD COLUMN st INTEGER', 'ALTER TABLE attempts ADD COLUMN rc INTEGER', 'ALTER TABLE attempts ADD COLUMN tt INTEGER', 'ALTER TABLE attempts ADD COLUMN pid INTEGER',
  'ALTER TABLE exams ADD COLUMN pass INTEGER', 'ALTER TABLE exams ADD COLUMN cr INTEGER', 'ALTER TABLE exams ADD COLUMN up INTEGER',
  // v4: chế độ thi, số lần tham gia, quy chế thi
  'ALTER TABLE exams ADD COLUMN ow TEXT', 'ALTER TABLE exams ADD COLUMN gm TEXT', 'ALTER TABLE exams ADD COLUMN maxa INTEGER', 'ALTER TABLE exams ADD COLUMN rules TEXT', 'ALTER TABLE exams ADD COLUMN sr INTEGER',
  'ALTER TABLE attempts ADD COLUMN n INTEGER DEFAULT 1', 'UPDATE attempts SET n=1 WHERE n IS NULL',
  'CREATE UNIQUE INDEX IF NOT EXISTS ux_att3 ON attempts(eid,cccd,n)',
  'CREATE INDEX IF NOT EXISTS ix_q ON questions(eid)', 'CREATE INDEX IF NOT EXISTS ix_a_c ON attempts(cccd)', 'CREATE INDEX IF NOT EXISTS ix_a_e ON attempts(eid)', 'CREATE INDEX IF NOT EXISTS ix_p ON papers(eid)',
  'INSERT INTO questions(q,o,a,subj,lvl,eid) SELECT x.q,x.o,x.a,x.subj,x.lvl,e.id FROM exams e JOIN questions x ON x.eid IS NULL WHERE e.sm IS NULL AND NOT EXISTS (SELECT 1 FROM questions y WHERE y.eid=e.id)',
  "UPDATE exams SET sm='random' WHERE sm IS NULL"
];
const SQ = "SELECT k,v FROM cfg WHERE k IN ('schema','secret','adm','admu')";
async function migrate() {
  await db.batch(DDL);
  for (const x of MIG) await db.execute(x).catch(() => {});
  await db.execute({ sql: "INSERT OR IGNORE INTO cfg(k,v) VALUES('secret',?)", args: [crypto.randomBytes(32).toString('hex')] });
  await db.execute({ sql: "INSERT INTO cfg(k,v) VALUES('schema',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", args: [String(SCHEMA)] });
}
let ready;
// Khởi động nguội chỉ tốn 1 truy vấn (trước đây ~25 câu lệnh tuần tự). Migration chỉ chạy khi nâng phiên bản schema.
const init = () => ready || (ready = (async () => {
  let rows = null;
  try { rows = await q(SQ); } catch (e) {}
  if (!rows || !rows.some(r => r.k === 'schema' && +r.v === SCHEMA)) { await migrate(); rows = await q(SQ); }
  for (const r of rows) if (HOT.has(r.k)) CC.set(r.k, { v: r.v, t: Date.now() });
  SECRET = rows.find(r => r.k === 'secret')?.v;
})().catch(e => { ready = null; throw e }));
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y) };
const hashPw = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 32).toString('hex') };
const checkPw = (p, st) => { const [s, h] = String(st || '').split(':'); return !!(s && h) && same(h, crypto.scryptSync(p, s, 32).toString('hex')) };
// ===== Giới hạn đăng nhập / đăng ký (chống dò mật khẩu, chống spam ghi DB) =====
// - Đếm TRƯỚC khi kiểm tra mật khẩu bằng một câu lệnh SQL nguyên tử nên gửi song song cũng không vượt được giới hạn.
// - Khóa theo (tài khoản + IP): người lạ nhập sai không khóa được người dùng thật ở mạng khác.
// - Thêm trần theo IP (net số lần sai) và trần theo tài khoản (chống dò từ nhiều IP).
const WIN = 300000, IP_LIM = 100, ACC_IP_LIM = 5, ACC_LIM = 30, REG_LIM = 100, MSG_IP_LIM = 30;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const hit = async (k, win) => {
  const now = Date.now();
  await q('INSERT INTO fails(k,n,t) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN t<? THEN 1 ELSE n+1 END, t=CASE WHEN t<? THEN ? ELSE t END', [k, now, now - win, now - win, now]);
  if (Math.random() < 0.02) await q('DELETE FROM fails WHERE t<?', [now - 3600000]).catch(() => {});
  const r = await q('SELECT n FROM fails WHERE k=?', [k]);
  return r.length ? +r[0].n : 1;
};
const attempt = async (b, acct, real) => {   // real = tài khoản có thật (chỉ khi đó mới tạo khóa theo tài khoản toàn cục)
  const ip = String(b._ip || '?'), ks = ['i:' + ip, 'a:' + acct + '|' + ip], lim = [IP_LIM, ACC_IP_LIM, ACC_LIM];
  if (real) ks.push('g:' + acct);
  for (let i = 0; i < ks.length; i++) if (await hit(ks[i], WIN) > lim[i]) { await sleep(300); throw E('Nhập sai quá nhiều lần, vui lòng thử lại sau 5 phút'); }
  return ks;
};
const ok = async ks => {   // đăng nhập đúng: xóa bộ đếm tài khoản+IP, hoàn lại 1 lượt ở bộ đếm IP/toàn cục
  await q('DELETE FROM fails WHERE k=?', [ks[1]]);
  await q('UPDATE fails SET n=MAX(n-1,0) WHERE k IN (?,?)', [ks[0], ks[2] || ks[0]]);
};
const adminTok = async () => { const x = Date.now() + 12 * 3600e3; return x + '.' + hmac('adm' + x + await cfg('adm')) };
const isAdmin = async req => { const [x, s] = String(req.headers.authorization || '').replace('Bearer ', '').split('.'), h = await cfg('adm'); return !!(x && s && h && +x > Date.now() && same(s, hmac('adm' + x + h))) };
const subTok = async () => { const x = Date.now() + 12 * 3600e3; return 'sub.' + x + '.' + hmac('sub' + x + await cfg('subpw')); };
const role = async req => {
  if (await isAdmin(req)) return 'admin';
  const [t, x, s] = String(req.headers.authorization || '').replace('Bearer ', '').split('.'), h = await cfg('subpw');
  return t === 'sub' && x && s && h && +x > Date.now() && same(s, hmac('sub' + x + h)) ? 'sub' : null;
};
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
const maxA = e => Math.max(1, +e.maxa || 1);
const isOpen = (e, now) => e.mode === 'free' ? (e.status === 'open' && (!e.t1 || now >= e.t1) && (!e.t2 || now <= e.t2)) : (e.status === 'waiting' || (e.status === 'running' && now < e.en));
// Chế độ 1: xếp hạng theo số câu đúng (nhiều hơn → trên), bằng nhau thì thời gian hoàn thành ngắn hơn → trên.
const dur = r => (r.st && r.sub >= r.st) ? r.sub - r.st : 9e15;
const cmp = (a, b) => ((b.rc ?? -1) - (a.rc ?? -1)) || (dur(a) - dur(b));
function rankOf(rows) {   // mỗi tài khoản tính một lần với lần làm tốt nhất
  const best = new Map();
  for (const r of rows) { const c = best.get(r.cccd); if (!c || cmp(r, c) < 0) best.set(r.cccd, r); }
  const L = [...best.values()].sort(cmp), rk = new Map(), byC = new Map(); let pos = 0;
  L.forEach((r, i) => { if (!i || cmp(L[i - 1], r) !== 0) pos = i + 1; rk.set(r.id, pos); byC.set(r.cccd, pos); });
  return { rk, byC, total: L.length };
}
const ranksFor = async eid => rankOf(await q('SELECT id,cccd,rc,st,sub FROM attempts WHERE eid=? AND done=1', [eid]));

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
let lastSweep = 0;
async function sweep(force) {
  const now = Date.now();
  if (!force && now - lastSweep < 4000) return;
  lastSweep = now;
  const rows = await q('SELECT a.id,a.deadline,e.mode,e.en FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.done=0 AND a.qids IS NOT NULL');
  const due = rows.filter(r => now >= (r.mode === 'live' ? r.en : r.deadline));
  for (let i = 0; i < due.length; i += 8) await Promise.all(due.slice(i, i + 8).map(r => grade(r.id)));
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

const busy = async eid => { await sweep(true); if ((await q('SELECT 1 x FROM attempts WHERE done=0 AND qids IS NOT NULL AND eid=? LIMIT 1', [eid ?? -1])).length) throw E('Đang có thí sinh làm bài kỳ thi này, chưa thể xóa câu hỏi lúc này'); };

async function mexF(u) {
  const now = Date.now();
  const [ex, at] = await Promise.all([
    q("SELECT id,name,mode,dur,cnt,status,en,sm,ra,rb,sids,t1,t2,gm,maxa,rules,(SELECT COUNT(*) FROM questions WHERE eid=exams.id) qn FROM exams WHERE (mode='free' AND status='open' AND (t1 IS NULL OR t1<=?) AND (t2 IS NULL OR t2>=?)) OR (mode='live' AND (status='waiting' OR (status='running' AND en>?))) OR id IN (SELECT eid FROM attempts WHERE cccd=?) ORDER BY id DESC", [now, now, now, u.cccd]),
    q('SELECT eid,done,score,ok,rc,tt,n,st,sub,(qids IS NULL) wq FROM attempts WHERE cccd=? ORDER BY n', [u.cccd])
  ]);
  const by = {}; for (const a of at) (by[a.eid] ||= []).push(a);
  return ex.map(e => {
    const m = e.sm || 'random', qn = e.qn, A = by[e.id] || [], last = A[A.length - 1], dn = A.filter(a => a.done), mx = maxA(e), open = isOpen(e, now);
    const nq = m === 'papers' ? e.cnt : m === 'range' ? Math.max(0, Math.min(+e.rb || qn, qn) - (+e.ra || 1) + 1) : m === 'manual' ? j(e.sids, []).length : Math.min(e.cnt, qn);
    const best = dn.slice().sort(cmp)[0], ui = !last ? 'none' : last.done ? 'done' : 'doing';
    return { id: e.id, name: e.name, mode: e.mode, dur: e.dur, status: e.status, nq, st: ui, wt: ui === 'doing' && !!last.wq, gm: e.gm === 'rank' ? 'rank' : 'pass', mx, na: dn.length, open, again: ui === 'done' && open && dn.length < mx, rules: e.rules || '', ok: dn.some(a => a.ok) ? 1 : 0, rc: best ? best.rc : null, tt: best ? best.tt : null, score: best ? best.score : null };
  });
}
async function myresF(u) {
  await sweep();
  const rows = await q('SELECT a.id,a.eid,a.qids,a.done,a.score,a.ok,a.sub,a.st,a.rc,a.tt,a.n,e.name exam,e.gm,e.pass,e.sr FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.cccd=? ORDER BY a.rowid DESC', [u.cccd]);
  const ids = [...new Set(rows.filter(r => r.done && r.gm === 'rank' && r.sr !== 0).map(r => r.eid))];
  const rm = Object.fromEntries(await Promise.all(ids.map(async eid => [eid, await ranksFor(eid)])));
  return rows.map(r => {
    const total = r.tt ?? j(r.qids, []).length, rk = r.done && r.gm === 'rank' && r.sr !== 0 ? (rm[r.eid].rk.get(r.id) ?? null) : null, pm = r.gm !== 'rank';
    return { exam: r.exam, n: r.n || 1, gm: r.gm === 'rank' ? 'rank' : 'pass', done: r.done, score: r.score, ok: r.ok, sub: r.sub, total, wait: !r.qids, right: r.done ? (r.rc ?? Math.round((r.score || 0) * total / 100)) : 0, sr: r.sr === 0 ? 0 : 1, dur: r.done && dur(r) < 9e15 ? dur(r) : null, rk, rt: rk ? rm[r.eid].total : null, pass: r.pass ?? PASS };
  });
}

const H = {
  async astat() { return { set: !!(await cfg('adm')) } },
  async setup(b) {
    if (await cfg('adm')) throw E('Tài khoản quản trị đã được thiết lập');
    const SK = process.env.SETUP_KEY;
    if (!SK) throw E('Chưa cấu hình biến môi trường SETUP_KEY trên Vercel nên chưa thể thiết lập tài khoản quản trị');
    const ksS = await attempt(b, 'setup', true);
    if (!same(String(b.k || ''), SK)) { await sleep(500); throw E('Mã thiết lập không đúng'); }
    await ok(ksS);
    const u = String(b.u || '').trim(), p = String(b.p || '');
    if (u.length < 3) throw E('Tên đăng nhập tối thiểu 3 ký tự');
    if (p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    await cset('admu', u); await cset('adm', hashPw(p));
    return { token: await adminTok() };
  },
  async login(b) {
    const ks = await attempt(b, 'adm', true);
    const h = await cfg('adm');
    if (h && String(b.u || '').trim() === (await cfg('admu')) && checkPw(String(b.p || ''), h)) { await ok(ks); return { token: await adminTok() }; }
    await sleep(500); throw E('Sai tên đăng nhập hoặc mật khẩu');
  },
  async subget() { return { u: (await cfg('subu')) || null }; },
  async subset(b) {   // chỉ quản trị viên chính
    const u = String(b.u || '').trim().slice(0, 40), p = String(b.p || ''), cur = await cfg('subu');
    if (u.length < 3) throw E('Tên đăng nhập tối thiểu 3 ký tự');
    if (/^\d{6,20}$/.test(u)) throw E('Tên đăng nhập không được là dãy số giống số CCCD');
    if (u === (await cfg('admu'))) throw E('Trùng tên đăng nhập quản trị chính');
    if (!cur && p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    if (p && p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    await cset('subu', u); if (p) await cset('subpw', hashPw(p));
    return { ok: 1 };
  },
  async subdel() { await cset('subu', ''); await cset('subpw', ''); return { ok: 1 }; },
  async xreset(b) {   // đặt lại cuộc thi: xóa toàn bộ bài làm, đưa kỳ thi về trạng thái ban đầu
    const e = await getExam(b.id);
    await q('DELETE FROM attempts WHERE eid=?', [e.id]);
    if (e.mode === 'live') await q("UPDATE exams SET status='waiting',st=NULL,en=NULL WHERE id=?", [e.id]);
    return { ok: 1 };
  },
  async rdel(b) {     // xóa kết quả tùy chọn
    const ids = (Array.isArray(b.ids) ? b.ids : []).map(String).slice(0, 500);
    if (!ids.length) return { n: 0 };
    const r = await db.execute({ sql: 'DELETE FROM attempts WHERE id IN (' + ids.map(() => '?').join(',') + ')', args: ids });
    return { n: r.rowsAffected };
  },
  async chpw(b) {
    const ks = await attempt(b, 'adm', true);
    const p = String(b.p || ''), u = String(b.u || '').trim();
    if (!checkPw(String(b.old || ''), await cfg('adm'))) { await sleep(500); throw E('Mật khẩu hiện tại không đúng'); }
    await ok(ks);
    if (p.length < 6) throw E('Mật khẩu mới tối thiểu 6 ký tự');
    if (u && u.length < 3) throw E('Tên đăng nhập tối thiểu 3 ký tự');
    await cset('adm', hashPw(p)); if (u) await cset('admu', u);
    return { token: await adminTok() };
  },
  async reg(b) {
    if (await hit('r:' + String(b._ip || '?'), 600000) > REG_LIM) throw E('Đăng ký quá nhiều lần từ cùng một mạng, vui lòng thử lại sau ít phút');
    const cccd = String(b.cccd || '').trim(), name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').trim().slice(0, 20), p = String(b.p || '');
    if (!/^\d{12}$/.test(cccd)) throw E('Số căn cước công dân phải gồm đúng 12 chữ số');
    if (!name) throw E('Vui lòng nhập họ và tên');
    if (p.length < 6) throw E('Mật khẩu tối thiểu 6 ký tự');
    if ((await q('SELECT 1 x FROM users WHERE cccd=?', [cccd])).length) throw E('Số căn cước này đã có tài khoản, hãy đăng nhập');
    await q('INSERT INTO users(cccd,name,unit,phone,pw,created) VALUES(?,?,?,?,?,?)', [cccd, name, unit, phone, hashPw(p), Date.now()]);
    return uout({ cccd, name, unit });
  },
  async signin(b) {   // một cổng đăng nhập chung: thí sinh (CCCD) hoặc quản trị viên
    const id = String(b.u || '').trim().slice(0, 60), p = String(b.p || '');
    if (!id || !p) throw E('Vui lòng nhập tài khoản và mật khẩu');
    const u = /^\d{6,20}$/.test(id) ? (await q('SELECT * FROM users WHERE cccd=?', [id]))[0] : null;
    const admu = await cfg('admu'), subu = await cfg('subu'), real = !!u || id === admu || (!!id && id === subu);
    const ks = await attempt(b, u ? 'u' + id : id === admu ? 'adm' : id === subu ? 'sub' : 'x:' + id, real);
    if (u) {
      if (!checkPw(p, u.pw)) { await sleep(500); throw E('Sai tài khoản hoặc mật khẩu'); }
      await ok(ks); return { role: 'user', ...uout(u) };
    }
    if (id === admu) {
      const h = await cfg('adm');
      if (h && checkPw(p, h)) { await ok(ks); return { role: 'admin', token: await adminTok() }; }
      await sleep(500);
    } else if (id && id === subu) {
      const h = await cfg('subpw');
      if (h && checkPw(p, h)) { await ok(ks); return { role: 'sub', token: await subTok() }; }
      await sleep(500);
    } else await new Promise(x => setTimeout(x, 500));
    throw E('Sai tài khoản hoặc mật khẩu');
  },
  async ulogin(b) {
    const c = String(b.cccd || '').trim().slice(0, 60);
    const u = (await q('SELECT * FROM users WHERE cccd=?', [c]))[0], ks = await attempt(b, 'u' + c, !!u);
    if (!u || !checkPw(String(b.p || ''), u.pw)) { await sleep(500); throw E('Sai số căn cước hoặc mật khẩu'); }
    await ok(ks); return uout(u);
  },
  async theme(b) {
    const v = (await cfg('thv')) || '0';
    if (b && b.v && String(b.v) === v) return { same: 1, v };   // máy khách đã có bản mới nhất
    const [t, ...im] = await Promise.all([cfg('theme'), ...IMGK.map(k => cfg('timg:' + k))]);
    const o = j(t, {}); IMGK.forEach((k, i) => { if (im[i]) o[k] = im[i]; });
    return { v, t: o };
  },
  async themeset(b) {   // phần chữ/màu nhỏ lưu riêng; ảnh chỉ ghi khi có thay đổi → lưu rất nhanh
    const t = { ...(b.t && typeof b.t === 'object' ? b.t : {}) }, im = { ...(b.img && typeof b.img === 'object' ? b.img : {}) };
    if (!b.reset) {
      const old = j(await cfg('theme'), {});   // di chuyển ảnh cũ (lưu chung) sang khóa riêng
      for (const k of IMGK) if (old[k] && im[k] === undefined) im[k] = old[k];
    }
    for (const k of IMGK) { if (typeof t[k] === 'string' && t[k] && im[k] === undefined) im[k] = t[k]; delete t[k]; }
    const x = JSON.stringify(t);
    if (x.length > 300000) throw E('Nội dung quá dài');
    const w = [cset('theme', x)];
    for (const k of IMGK) {
      if (b.reset || im[k] === '') w.push(cset('timg:' + k, ''));
      else if (typeof im[k] === 'string') { if (im[k].length > 1500000) throw E('Ảnh quá lớn, hãy chọn ảnh nhỏ hơn'); w.push(cset('timg:' + k, im[k])); }
    }
    const v = String(Date.now()); w.push(cset('thv', v));
    await Promise.all(w); return { ok: 1, v };
  },
  // ===== Tin nhắn hỗ trợ: thí sinh <-> quản trị viên chính =====
  async msend(b) {   // công khai: thí sinh đã đăng nhập (ut) hoặc người chưa đăng nhập (họ tên + CCCD, đánh dấu v=0)
    if (await hit('m:' + String(b._ip || '?'), 600000) > MSG_IP_LIM) throw E('Bạn gửi quá nhiều tin nhắn, vui lòng thử lại sau ít phút');
    const text = String(b.text || '').trim().slice(0, 1000);
    if (!text) throw E('Vui lòng nhập nội dung tin nhắn');
    let cccd, name, v = 0;
    if (b.ut) { const u = await uauth(b); cccd = u.cccd; name = u.name; v = 1; }
    else {
      cccd = String(b.cccd || '').trim(); name = String(b.name || '').trim().slice(0, 80);
      if (!/^\d{12}$/.test(cccd)) throw E('Số căn cước công dân phải gồm đúng 12 chữ số');
      if (!name) throw E('Vui lòng nhập họ và tên');
    }
    if (await hit('mc:' + cccd, 3600000) > 10) throw E('Bạn đã gửi nhiều tin nhắn, vui lòng chờ quản trị viên trả lời');
    await q("INSERT INTO msgs(cccd,fr,body,at,rd,nm,v) VALUES(?,'u',?,?,0,?,?)", [cccd, text, Date.now(), name, v]);
    return { ok: 1 };
  },
  async mlist(b) {   // thí sinh xem hội thoại của chính tài khoản mình (peek: chỉ đếm tin chưa đọc)
    const u = await uauth(b);
    const unread = +(await q("SELECT COUNT(*) c FROM msgs WHERE cccd=? AND fr='a' AND rd=0", [u.cccd]))[0].c;
    if (b.peek) return { unread };
    const items = await q('SELECT id,fr,body,at FROM msgs WHERE cccd=? ORDER BY id DESC LIMIT 100', [u.cccd]); items.reverse();
    await q("UPDATE msgs SET rd=1 WHERE cccd=? AND fr='a' AND rd=0", [u.cccd]);
    return { items, unread: 0 };
  },
  async mthreads() {
    const g = await q("SELECT cccd, MAX(id) lid, SUM(CASE WHEN fr='u' AND rd=0 THEN 1 ELSE 0 END) unread FROM msgs GROUP BY cccd ORDER BY lid DESC LIMIT 200");
    if (!g.length) return [];
    const ids = g.map(x => x.lid);
    const ls = await q("SELECT m.id,m.fr,m.body,m.at,COALESCE(u.name,(SELECT nm FROM msgs WHERE cccd=m.cccd AND fr='u' ORDER BY id DESC LIMIT 1)) name FROM msgs m LEFT JOIN users u ON u.cccd=m.cccd WHERE m.id IN (" + ids.map(() => '?').join(',') + ')', ids);
    const by = new Map(ls.map(x => [+x.id, x]));
    return g.map(x => { const l = by.get(+x.lid) || {}; return { cccd: x.cccd, unread: +x.unread || 0, last: String(l.body || '').slice(0, 120), fr: l.fr, at: l.at, name: l.name || '' }; });
  },
  async mthread(b) {
    const c = String(b.cccd || '').trim().slice(0, 20);
    const items = await q('SELECT id,fr,body,at,v FROM msgs WHERE cccd=? ORDER BY id DESC LIMIT 200', [c]); items.reverse();
    await q("UPDATE msgs SET rd=1 WHERE cccd=? AND fr='u' AND rd=0", [c]);
    const u = (await q('SELECT name,unit,phone FROM users WHERE cccd=?', [c]))[0];
    const nm = u ? u.name : ((await q("SELECT nm FROM msgs WHERE cccd=? AND fr='u' ORDER BY id DESC LIMIT 1", [c]))[0] || {}).nm;
    return { items, name: nm || '', unit: u ? u.unit : '', phone: u ? u.phone : '', acct: !!u };
  },
  async mreply(b) {
    const c = String(b.cccd || '').trim(), text = String(b.text || '').trim().slice(0, 1000);
    if (!/^\d{12}$/.test(c)) throw E('Số căn cước công dân không hợp lệ');
    if (!text) throw E('Vui lòng nhập nội dung trả lời');
    if (!(await q('SELECT 1 x FROM msgs WHERE cccd=? LIMIT 1', [c])).length) throw E('Không tìm thấy cuộc trò chuyện này');
    await q("INSERT INTO msgs(cccd,fr,body,at,rd,v) VALUES(?,'a',?,?,0,1)", [c, text, Date.now()]);
    return { ok: 1 };
  },
  async mdel(b) { await q('DELETE FROM msgs WHERE cccd=?', [String(b.cccd || '').trim().slice(0, 20)]); return { ok: 1 }; },
  async mcount() { return { n: +(await q("SELECT COUNT(*) c FROM msgs WHERE fr='u' AND rd=0"))[0].c }; },
  async mex(b) { return mexF(await uauth(b)); },
  async pre(b) {   // nạp trước mọi mục của thí sinh bằng 1 request
    const u = await uauth(b);
    const [mex, news, myres] = await Promise.all([mexF(u), cfg('news').then(x => j(x, [])), myresF(u)]);
    return { mex, news, myres, me: { cccd: u.cccd, name: u.name, unit: u.unit, phone: u.phone } };
  },
  async news() { return j(await cfg('news'), []); },
  async newsset(b) {
    const L = (Array.isArray(b.l) ? b.l : []).slice(0, 30).map(x => ({ t: String(x.t || '').trim().slice(0, 120), c: String(x.c || '').trim().slice(0, 400), d: String(x.d || '').trim().slice(0, 20) })).filter(x => x.t);
    await cset('news', JSON.stringify(L)); return { ok: 1 };
  },
  async me(b) { const u = await uauth(b); return { cccd: u.cccd, name: u.name, unit: u.unit, phone: u.phone }; },
  async meset(b) {
    const u = await uauth(b), name = String(b.name || '').trim().slice(0, 80), unit = String(b.unit || '').trim().slice(0, 80), phone = String(b.phone || '').trim().slice(0, 20);
    if (!name) throw E('Vui lòng nhập họ và tên');
    await q('UPDATE users SET name=?,unit=?,phone=? WHERE cccd=?', [name, unit, phone, u.cccd]);
    return { name, unit, phone };
  },
  async mepw(b) {
    const u = await uauth(b), p = String(b.p || ''), ks = await attempt(b, 'u' + u.cccd, true);
    if (!checkPw(String(b.old || ''), u.pw)) { await sleep(500); throw E('Mật khẩu hiện tại không đúng'); }
    if (p.length < 6) throw E('Mật khẩu mới tối thiểu 6 ký tự');
    await q('UPDATE users SET pw=? WHERE cccd=?', [hashPw(p), u.cccd]); await ok(ks);
    return { ok: 1 };
  },
  async myres(b) { return myresF(await uauth(b)); },
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
    const A = await q('SELECT id,done,n FROM attempts WHERE eid=? AND cccd=? ORDER BY n DESC', [e.id, u.cccd]), last = A[0];
    const reply = async id => { const tok = hmac('att' + id); let st = null; try { st = await H.state({ aid: id, tok }); } catch (x) {} return { aid: id, tok, st }; };
    if (last && !last.done) return reply(last.id);
    const mx = maxA(e);
    if (A.length >= mx) throw E(mx === 1 ? 'Bạn đã nộp bài kỳ thi này' : 'Bạn đã sử dụng hết ' + mx + ' lần tham gia kỳ thi này');
    const id = crypto.randomUUID();
    const set = e.mode === 'free' || e.status === 'running' ? await getSet(e) : null, ids = set && set.ids;
    if (ids && !ids.length) throw E('Kỳ thi chưa có câu hỏi, vui lòng liên hệ quản trị');
    try {
      await q('INSERT INTO attempts(id,eid,name,unit,phone,cccd,qids,deadline,pid,st,n) VALUES(?,?,?,?,?,?,?,?,?,?,?)', [id, e.id, u.name, u.unit, u.phone, u.cccd, ids && JSON.stringify(ids), e.mode === 'free' ? now + e.dur * 60000 : null, set ? set.pid : null, ids ? now : null, A.length + 1]);
    } catch (x) {   // bấm hai lần liên tiếp: dùng lại lượt vừa tạo
      const r = (await q('SELECT id FROM attempts WHERE eid=? AND cccd=? ORDER BY n DESC LIMIT 1', [e.id, u.cccd]))[0];
      if (r) return reply(r.id); throw x;
    }
    return reply(id);
  },
  async state(b) {
    let a = await mine(b); const e = await getExam(a.eid), now = Date.now();
    const res = async x => {
      x = (await q('SELECT * FROM attempts WHERE id=?', [x.id]))[0] || x;
      const gm = e.gm === 'rank' ? 'rank' : 'pass', mx = maxA(e), sr = e.sr === 0 ? 0 : 1;
      const [nr, R] = await Promise.all([q('SELECT COUNT(*) c FROM attempts WHERE eid=? AND cccd=? AND done=1', [e.id, a.cccd]), gm === 'rank' && sr ? ranksFor(e.id) : null]);
      const na = nr[0].c, d = dur(x);
      return { s: 'done', score: x.score, ok: x.ok, exam: e.name, eid: e.id, gm, n: x.n || 1, na, mx, again: isOpen(e, Date.now()) && na < mx, pass: e.pass ?? PASS, sr, rc: x.rc ?? Math.round((x.score || 0) * (x.tt || 0) / 100), tt: x.tt, dur: d < 9e15 ? d : null, rk: R ? (R.byC.get(a.cccd) ?? null) : null, rt: R ? R.total : null };
    };
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
    return { s: 'run', exam: e.name, eid: e.id, rules: e.rules || '', now, dl, ans: j(a.ans, {}), qs: ids.map(i => by[i]).filter(Boolean).map(r => ({ id: r.id, q: r.q, o: j(r.o, []) })) };
  },
  async answer(b) {   // 1 câu lệnh, ghi nguyên tử từng câu (không ghi đè lẫn nhau khi bấm nhanh)
    if (!b.aid || b.tok !== hmac('att' + b.aid)) throw E('Phiên thi không hợp lệ');
    const i = +b.i, v = +b.v;
    if (!(Number.isInteger(i) && i >= 0 && i < 1000 && Number.isInteger(v) && v >= 0 && v < 4)) return { ok: 0 };
    const r = await db.execute({ sql: `UPDATE attempts SET ans=json_set(COALESCE(ans,'{}'),'$."${i}"',?) WHERE id=? AND done=0 AND (SELECT CASE WHEN e.mode='live' THEN e.en ELSE attempts.deadline END FROM exams e WHERE e.id=attempts.eid)>?`, args: [v, b.aid, Date.now()] });
    return { ok: r.rowsAffected ? 1 : 0 };
  },
  async submit(b) { const a = await mine(b); if (!a.qids) throw E('Kỳ thi chưa bắt đầu'); const r = await grade(a.id); return { score: r.score, ok: r.ok }; },

  // quản trị
  async dash() {
    await sweep();
    const c = async s => (await q(s))[0].c;
    return { run: await c("SELECT COUNT(*) c FROM exams WHERE status IN ('open','running','waiting')"), att: await c('SELECT COUNT(*) c FROM attempts'), qn: await c('SELECT COUNT(*) c FROM questions'), ne: await c('SELECT COUNT(*) c FROM exams'), nu: await c('SELECT COUNT(*) c FROM users'), done: await c('SELECT COUNT(*) c FROM attempts WHERE done=1'), pass: await c('SELECT COUNT(*) c FROM attempts WHERE ok=1'), avg: (await q('SELECT AVG(score) v FROM attempts WHERE done=1'))[0].v };
  },
  async ql(b) { return (await q('SELECT * FROM questions WHERE eid=? ORDER BY id', [+b.eid || 0])).map(r => ({ ...r, o: j(r.o, []) })); },
  async qs(b) {
    const o = JSON.stringify((b.o || []).slice(0, 4).map(String));
    if (!b.q || (b.o || []).length < 2) throw E('Thiếu nội dung câu hỏi hoặc đáp án');
    const ai = b.ai ?? b.a;   // đáp án đúng (client gửi ở khóa 'ai' để không trùng khóa 'a' = tên hành động)
    if (!(+ai >= 0 && +ai < Math.min(4, b.o.length))) throw E('Chưa chọn đáp án đúng hợp lệ');
    if (b.id) await q('UPDATE questions SET q=?,o=?,a=?,subj=?,lvl=? WHERE id=?', [b.q, o, +ai, b.subj, b.lvl, b.id]);
    else { await getExam(b.eid); await q('INSERT INTO questions(q,o,a,subj,lvl,eid) VALUES(?,?,?,?,?,?)', [b.q, o, +ai, b.subj, b.lvl, +b.eid]); }
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
    return q('SELECT e.*,(SELECT COUNT(*) FROM attempts WHERE eid=e.id) n,(SELECT COUNT(*) FROM attempts WHERE eid=e.id AND done=1) dn,(SELECT COUNT(*) FROM questions WHERE eid=e.id) qn,(SELECT COUNT(*) FROM papers WHERE eid=e.id) pn FROM exams e ORDER BY id DESC');
  },
  async es(b) {
    if (!b.name) throw E('Vui lòng nhập tên kỳ thi');
    const old = b.id ? await getExam(b.id) : null;
    const dur = Math.max(1, +b.dur || (old ? old.dur : 30)), cnt = Math.max(1, +b.cnt || (old ? old.cnt : 10)), t1 = b.t1 || null, t2 = b.t2 || null;
    const pass = b.pass === undefined || b.pass === null || b.pass === '' ? (old ? (old.pass ?? PASS) : PASS) : Math.min(100, Math.max(0, +b.pass || 0));
    const gm = b.gm === 'rank' || b.gm === 'pass' ? b.gm : (old ? (old.gm === 'rank' ? 'rank' : 'pass') : 'pass');
    const maxa = b.maxa === undefined || b.maxa === null || b.maxa === '' ? (old ? maxA(old) : 1) : Math.min(99, Math.max(1, Math.floor(+b.maxa) || 1));
    const rules = b.rules === undefined || b.rules === null ? (old ? old.rules || '' : '') : String(b.rules).slice(0, 8000);
    const sr = b.sr === undefined || b.sr === null || b.sr === '' ? (old ? (old.sr === 0 ? 0 : 1) : 1) : (String(b.sr) === '0' ? 0 : 1);
    if (old) {
      await q('UPDATE exams SET name=?,dur=?,cnt=?,t1=?,t2=?,pass=?,gm=?,maxa=?,rules=?,sr=?,up=? WHERE id=?', [b.name, dur, cnt, t1, t2, pass, gm, maxa, rules, sr, Date.now(), old.id]);
      await q('UPDATE attempts SET ok=(CASE WHEN score>=? THEN 1 ELSE 0 END) WHERE eid=? AND done=1', [pass, old.id]);
      return { ok: 1, id: old.id };
    }
    const live = b.mode === 'live';
    const r = await db.execute({ sql: 'INSERT INTO exams(name,mode,dur,cnt,t1,t2,status,sm,pass,cr,up,gm,maxa,rules,sr,ow) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', args: [b.name, live ? 'live' : 'free', dur, cnt, t1, t2, live ? 'waiting' : 'open', 'random', pass, Date.now(), Date.now(), gm, maxa, rules, sr, b._rl === 'sub' ? 'sub' : 'admin'] });
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
  async stats(b) {
    const days = [7, 14, 30].includes(+b.days) ? +b.days : 7, off = 7 * 3600e3, today = Math.floor((Date.now() + off) / 864e5), k0 = today - days + 1, from = k0 * 864e5 - off;
    const rows = await q(b.eid ? 'SELECT st,cccd FROM attempts WHERE st>=? AND eid=?' : 'SELECT st,cccd FROM attempts WHERE st>=?', b.eid ? [from, +b.eid] : [from]);
    const out = Array.from({ length: days }, (_, i) => ({ k: k0 + i, j: 0, s: new Set() }));
    for (const r of rows) { const o = out[Math.floor((r.st + off) / 864e5) - k0]; if (o) { o.j++; o.s.add(r.cccd); } }
    return out.map(o => { const d = new Date(o.k * 864e5); return { d: String(d.getUTCDate()).padStart(2, '0') + '/' + String(d.getUTCMonth() + 1).padStart(2, '0'), j: o.j, p: o.s.size }; });
  },
  async act() {
    const ev = [];
    for (const r of await q('SELECT a.name,a.st,a.sub,a.done,e.name exam FROM attempts a JOIN exams e ON e.id=a.eid ORDER BY COALESCE(a.sub,a.st) DESC LIMIT 12')) {
      if (r.done && r.sub) ev.push({ k: 'done', t: 'Thí sinh ' + r.name + ' nộp bài thi', s: r.exam, at: r.sub });
      if (r.st) ev.push({ k: 'start', t: 'Thí sinh ' + r.name + ' bắt đầu làm bài', s: r.exam, at: r.st });
    }
    for (const r of await q('SELECT name,cr FROM exams WHERE cr IS NOT NULL ORDER BY cr DESC LIMIT 5')) ev.push({ k: 'new', t: 'Tạo kỳ thi "' + r.name + '"', s: '', at: r.cr });
    return ev.sort((a, b) => b.at - a.at).slice(0, 8);
  },
  async edup(b) {
    const e = await getExam(b.id), now = Date.now(), live = e.mode === 'live';
    const r = await db.execute({ sql: 'INSERT INTO exams(name,mode,dur,cnt,t1,t2,status,sm,ra,rb,pass,cr,up,gm,maxa,rules,sr,ow) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', args: [e.name + ' (bản sao)', e.mode, e.dur, e.cnt, e.t1, e.t2, live ? 'waiting' : 'open', e.sm === 'papers' ? 'random' : (e.sm || 'random'), e.ra ?? null, e.rb ?? null, e.pass ?? PASS, now, now, e.gm === 'rank' ? 'rank' : 'pass', maxA(e), e.rules || '', e.sr === 0 ? 0 : 1, b._rl === 'sub' ? 'sub' : 'admin'] });
    const nid = Number(r.lastInsertRowid), old = (await q('SELECT id FROM questions WHERE eid=? ORDER BY id', [e.id])).map(x => x.id);
    if (old.length) {
      await db.execute({ sql: 'INSERT INTO questions(q,o,a,subj,lvl,eid) SELECT q,o,a,subj,lvl,? FROM questions WHERE eid=? ORDER BY id', args: [nid, e.id] });
      if (e.sm === 'manual') { const nw = (await q('SELECT id FROM questions WHERE eid=? ORDER BY id', [nid])).map(x => x.id), mp = new Map(old.map((o, i) => [o, nw[i]])); await q('UPDATE exams SET sids=? WHERE id=?', [JSON.stringify(j(e.sids, []).map(i => mp.get(i)).filter(Boolean)), nid]); }
    }
    return { ok: 1, id: nid };
  },
  async esel(b) {
    const e = await getExam(b.id), sm = ['random', 'range', 'manual', 'papers'].includes(b.sm) ? b.sm : 'random';
    if (sm === 'papers' && !(await q('SELECT 1 x FROM papers WHERE eid=? LIMIT 1', [e.id])).length) throw E('Hãy bấm "Tạo bộ đề" trước');
    const ids = (Array.isArray(b.sids) ? b.sids : []).map(Number).filter(Number.isInteger);
    const ra = Math.max(1, +b.ra || 1), rb = Math.max(ra, +b.rb || ra);
    await q('UPDATE exams SET sm=?,cnt=?,ra=?,rb=?,sids=?,up=? WHERE id=?', [sm, Math.max(1, +b.cnt || e.cnt), ra, rb, JSON.stringify(ids), Date.now(), e.id]);
    return { ok: 1 };
  },
  async ed(b) { await q('DELETE FROM papers WHERE eid=?', [b.id]); await q('DELETE FROM questions WHERE eid=?', [b.id]); await q('DELETE FROM attempts WHERE eid=?', [b.id]); await q('DELETE FROM exams WHERE id=?', [b.id]); return { ok: 1 }; },
  async start(b) {
    const e = await getExam(b.id), now = Date.now();
    if (e.mode === 'live' && !(await pickFor(e)).length) throw E('Kỳ thi chưa có câu hỏi, hãy thêm câu hỏi trước khi bắt đầu');
    if (e.mode === 'live') await q("UPDATE exams SET status='running',st=?,en=? WHERE id=?", [now, now + e.dur * 60000, e.id]);
    else await q("UPDATE exams SET status='open',t1=?,t2=CASE WHEN t2 IS NOT NULL AND t2<=? THEN NULL ELSE t2 END WHERE id=?", [now, now, e.id]);   // bắt đầu ngay, bỏ qua giờ hẹn mở
    return { ok: 1 };
  },
  async end(b) {
    const e = await getExam(b.id);
    if (e.mode === 'live') await q("UPDATE exams SET status='ended',en=? WHERE id=?", [Date.now(), e.id]);
    else await q("UPDATE exams SET status='closed' WHERE id=?", [e.id]);
    await sweep(true); return { ok: 1 };
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
    const rows = await q('SELECT id,cccd,n,name,unit,phone,qids,ans,done,score,ok,rc,tt FROM attempts WHERE eid=? ORDER BY name,n', [e.id]);
    return { e, at: rows.map(r => ({ id: r.id, n: r.n || 1, cccd: r.cccd, name: r.name, unit: r.unit, phone: r.phone, total: j(r.qids, []).length, got: Object.keys(j(r.ans, {})).length, done: r.done, rc: r.rc ?? (r.done ? Math.round((r.score || 0) * j(r.qids, []).length / 100) : null), tt: r.tt ?? j(r.qids, []).length, ok: r.ok })) };
  },
  async res() {
    await sweep();
    const rows = await q('SELECT a.id,a.name,a.unit,a.phone,a.cccd,a.score,a.ok,a.sub,a.st,a.rc,a.tt,a.n,e.id eid,e.name exam,e.pass,e.gm FROM attempts a JOIN exams e ON e.id=a.eid WHERE a.done=1 ORDER BY a.sub DESC');
    const by = {}; for (const r of rows) if (r.gm === 'rank') (by[r.eid] ||= []).push(r);
    const rm = {}; for (const k in by) rm[k] = rankOf(by[k]);
    return rows.map(r => ({ ...r, gm: r.gm === 'rank' ? 'rank' : 'pass', n: r.n || 1, rk: r.gm === 'rank' ? (rm[r.eid].rk.get(r.id) ?? null) : null }));
  }
};
const ADM = new Set(['dash', 'ql', 'qs', 'qd', 'el', 'es', 'ed', 'start', 'end', 'mon', 'res', 'ext', 'qi', 'qda', 'newsset', 'stats', 'act', 'edup', 'pgen', 'pl', 'pd', 'esel', 'qcp', 'qold', 'chpw', 'themeset', 'ul', 'ures', 'ud', 'subget', 'subset', 'subdel', 'xreset', 'rdel', 'mthreads', 'mthread', 'mreply', 'mdel', 'mcount']);
const MAIN = new Set(['chpw', 'themeset', 'subget', 'subset', 'subdel', 'xreset', 'rdel', 'ures', 'ud', 'mthreads', 'mthread', 'mreply', 'mdel', 'mcount']);   // tài khoản phụ không được dùng


// Tài khoản quản trị phụ chỉ được XEM và CHỈNH SỬA kỳ thi (cùng câu hỏi, đáp án) do chính tài khoản phụ tạo (exams.ow = 'sub').
const qEid = async id => { const x = (await q('SELECT eid FROM questions WHERE id=?', [id]))[0]; return x ? x.eid : null; };
const OWN = {   // hành động → các cách lấy mã kỳ thi bị tác động (đều phải thuộc tài khoản phụ)
  es: [b => b.id || 'new'], ed: [b => b.id], start: [b => b.id], end: [b => b.id], ext: [b => b.id], esel: [b => b.id], pgen: [b => b.id],
  qi: [b => b.eid], qda: [b => b.eid], ql: [b => b.eid], edup: [b => b.id],
  qcp: [b => b.eid, b => b.from === 'old' ? 0 : b.from],      // nguồn sao chép cũng phải là kỳ thi của mình; ngân hàng cũ thì không
  qs: [async b => b.id ? qEid(b.id) : b.eid], qd: [async b => qEid(b.id)],
  pd: [async b => (await q('SELECT eid FROM papers WHERE id=?', [b.id]))[0]?.eid],
  qold: [() => 0]                                              // ngân hàng câu hỏi cũ: chỉ admin chính
};
const ownGuard = async b => {
  for (const f of OWN[b.a] || []) {
    const eid = await f(b); if (eid === 'new') continue;
    const e = eid ? (await q('SELECT ow FROM exams WHERE id=?', [+eid]))[0] : null;
    if (!e || e.ow !== 'sub') throw Object.assign(new Error('Tài khoản quản trị phụ chỉ được xem và chỉnh sửa kỳ thi do chính tài khoản mình tạo'), { forbid: true });
  }
};
// IP máy khách: ưu tiên header do Vercel đặt (client không giả mạo được)
const clientIp = req => String(req.headers['x-vercel-forwarded-for'] || req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0] || (req.socket && req.socket.remoteAddress) || '?').split(',')[0].trim().slice(0, 64);

module.exports = async (req, res) => {
  try {
    if (req.method !== 'POST') return res.status(405).json({ e: 'Method not allowed' });
    await init();
    const b = req.body || {}, f = H[b.a];
    if (!f) return res.status(400).json({ e: 'Yêu cầu không hợp lệ' });
    b._ip = clientIp(req); b._rl = null;   // luôn do máy chủ đặt, bỏ qua giá trị client gửi lên
    if (ADM.has(b.a)) {
      const rl = await role(req);
      if (!rl) return res.status(401).json({ e: 'Cần đăng nhập quản trị' });
      if (MAIN.has(b.a) && rl !== 'admin') return res.status(403).json({ e: 'Chức năng này chỉ dành cho quản trị viên chính' });
      if (rl === 'sub') await ownGuard(b);
      b._rl = rl;
    }
    res.status(200).json(await f(b));
  } catch (e) {
    console.error(e);
    res.status(e.forbid ? 403 : e.user ? 400 : 500).json({ e: e.user || e.forbid ? e.message : 'Lỗi máy chủ' });
  }
};
