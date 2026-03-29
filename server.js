const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'db.json');

function loadDB() {
  if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: [], keys: [],
      plans: [{ id: 1, name: 'COMPRE SEU PAINEL', duration: 0, keyType: 'lifetime', maxKeys: 1000, price: 'R$ 9,90', active: true }],
      settings: { keyPrefix: 'KEY', keySegments: 2, segmentLength: 8 }
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'hwid_secret_2025',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 86400000 }
}));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'gerasHUBsystem';

function generateKey(prefix, segments, segLen) {
  const p = (prefix || 'KEY').toUpperCase().replace(/[^A-Z0-9]/g, '') || 'KEY';
  const parts = [];
  for (let i = 0; i < (segments || 2); i++) {
    parts.push(crypto.randomBytes(Math.ceil((segLen || 8) / 2)).toString('hex').toUpperCase().slice(0, segLen || 8));
  }
  return p + '-' + parts.join('-');
}

function getKeyExpiry(keyType) {
  if (keyType === 'lifetime') return null;
  const d = new Date();
  if (keyType === 'daily')   d.setDate(d.getDate() + 1);
  if (keyType === 'weekly')  d.setDate(d.getDate() + 7);
  if (keyType === 'monthly') d.setMonth(d.getMonth() + 1);
  return d.toISOString();
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/paineladmDOtheGERAS', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, msg: 'Preencha todos os campos.' });
  if (username.length < 3) return res.json({ ok: false, msg: 'Nome muito curto.' });
  if (password.length < 6) return res.json({ ok: false, msg: 'Senha muito curta (min 6).' });
  const db = loadDB();
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.json({ ok: false, msg: 'Usuario ja existe.' });
  const hash = await bcrypt.hash(password, 10);
  db.users.push({ id: Date.now(), username, password: hash, plan: null, planExpiry: null, maxKeys: 0, keyPrefix: 'KEY', keySegments: 2, segmentLength: 8, createdAt: new Date().toISOString() });
  saveDB(db);
  res.json({ ok: true, msg: 'Conta criada!' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.json({ ok: false, msg: 'Usuario nao encontrado.' });
  if (!await bcrypt.compare(password, user.password)) return res.json({ ok: false, msg: 'Senha incorreta.' });
  req.session.userId = user.id;
  res.json({ ok: true, username: user.username });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ ok: false });
  const now = new Date();
  const expired = user.planExpiry && new Date(user.planExpiry) < now;
  const userKeys = db.keys.filter(k => k.userId === user.id);
  res.json({ ok: true, username: user.username, plan: expired ? null : user.plan, planExpiry: user.planExpiry, planIsLifetime: !user.planExpiry && !!user.plan, expired, maxKeys: expired ? 0 : user.maxKeys, keysGenerated: userKeys.length, keys: userKeys, keyPrefix: user.keyPrefix || 'KEY', keySegments: user.keySegments || 2, segmentLength: user.segmentLength || 8 });
});

app.get('/api/plans', (req, res) => {
  const db = loadDB();
  res.json({ plans: db.plans.filter(p => p.active) });
});

app.post('/api/user/prefix', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false, msg: 'Nao autenticado.' });
  const { keyPrefix, keySegments, segmentLength } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ ok: false, msg: 'Usuario nao encontrado.' });
  if (!user.plan) return res.json({ ok: false, msg: 'Voce precisa de um plano.' });
  user.keyPrefix = (keyPrefix || 'KEY').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10) || 'KEY';
  user.keySegments = Math.min(Math.max(Number(keySegments) || 2, 1), 4);
  user.segmentLength = Math.min(Math.max(Number(segmentLength) || 8, 4), 12);
  saveDB(db);
  res.json({ ok: true, msg: 'Prefixo salvo!', preview: generateKey(user.keyPrefix, user.keySegments, user.segmentLength) });
});

// ── GERAR KEY — HWID opcional, vincula na primeira validação ──
app.post('/api/generate', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false, msg: 'Nao autenticado.' });
  const { keyType, hwid } = req.body;
  const validTypes = ['daily', 'weekly', 'monthly', 'lifetime'];
  if (!validTypes.includes(keyType)) return res.json({ ok: false, msg: 'Tipo de key invalido.' });

  // HWID agora é opcional — se vier, salva; se não vier, fica vazio e vincula na primeira validação
  const cleanHwid = hwid ? hwid.trim().toUpperCase().replace(/[^A-Z0-9\-_]/g, '').slice(0, 64) : '';

  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ ok: false, msg: 'Usuario nao encontrado.' });
  const planExpired = user.planExpiry && new Date(user.planExpiry) < new Date();
  if (!user.plan || planExpired) return res.json({ ok: false, msg: 'NOPLAN' });
  const userKeys = db.keys.filter(k => k.userId === user.id);
  if (userKeys.length >= user.maxKeys) return res.json({ ok: false, msg: 'Limite de ' + user.maxKeys + ' keys atingido.' });
  const key = generateKey(user.keyPrefix || 'KEY', user.keySegments || 2, user.segmentLength || 8);
  const keyExpiry = getKeyExpiry(keyType);
  const isLifetime = keyType === 'lifetime';
  db.keys.push({ id: Date.now(), userId: user.id, username: user.username, key, hwid: cleanHwid, keyType, keyExpiry, isLifetime, createdAt: new Date().toISOString() });
  saveDB(db);
  res.json({ ok: true, key, hwid: cleanHwid, keyType, keyExpiry, isLifetime });
});

// ── VALIDAR KEY — vincula HWID automaticamente na primeira vez ──
function validateKeyLogic(key, hwid, db) {
  if (!key) return { valid: false, reason: 'key obrigatoria.' };
  const entry = db.keys.find(k => k.key === key.trim().toUpperCase());
  if (!entry) return { valid: false, reason: 'Key nao encontrada.' };

  const incomingHwid = hwid ? hwid.trim().toUpperCase().replace(/[^A-Z0-9\-_]/g, '').slice(0, 64) : '';

  // Se a key não tem HWID vinculado, vincula agora com o HWID do script
  if (!entry.hwid || entry.hwid === '') {
    entry.hwid = incomingHwid;
    saveDB(db);
  } else {
    // Já tem HWID vinculado — compara
    if (incomingHwid && entry.hwid !== incomingHwid) {
      return { valid: false, reason: 'HWID nao corresponde.' };
    }
  }

  if (!entry.isLifetime && entry.keyExpiry && new Date(entry.keyExpiry) < new Date()) {
    return { valid: false, reason: 'Key expirada.', expiredAt: entry.keyExpiry };
  }

  return { valid: true, username: entry.username, keyType: entry.keyType, keyExpiry: entry.keyExpiry, isLifetime: entry.isLifetime, hwid: entry.hwid };
}

app.post('/api/validate', (req, res) => {
  const { key, hwid } = req.body;
  const db = loadDB();
  res.json(validateKeyLogic(key, hwid, db));
});

app.get('/api/validate', (req, res) => {
  const { key, hwid } = req.query;
  const db = loadDB();
  res.json(validateKeyLogic(key, hwid, db));
});

// ── ADMIN ────────────────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) { req.session.isAdmin = true; return res.json({ ok: true }); }
  res.json({ ok: false, msg: 'Senha incorreta.' });
});

app.post('/api/admin/logout', (req, res) => { req.session.isAdmin = false; res.json({ ok: true }); });

function adminAuth(req, res, next) {
  if (!req.session.isAdmin) return res.json({ ok: false, msg: 'Nao autorizado.' });
  next();
}

app.get('/api/admin/data', adminAuth, (req, res) => {
  const db = loadDB();
  res.json({ ok: true, users: db.users.map(u => ({ ...u, password: undefined })), keys: db.keys, plans: db.plans, settings: db.settings });
});

app.post('/api/admin/user/plan', adminAuth, (req, res) => {
  const { userId, planId } = req.body;
  const db = loadDB();
  const user = db.users.find(u => u.id === Number(userId));
  if (!user) return res.json({ ok: false, msg: 'Usuario nao encontrado.' });
  if (planId === 'remove') {
    user.plan = null; user.planExpiry = null; user.maxKeys = 0;
    saveDB(db); return res.json({ ok: true, msg: 'Plano removido.' });
  }
  const plan = db.plans.find(p => p.id === Number(planId));
  if (!plan) return res.json({ ok: false, msg: 'Plano nao encontrado.' });
  let expiry = null;
  if (plan.keyType !== 'lifetime' && plan.duration > 0) {
    expiry = new Date(); expiry.setDate(expiry.getDate() + plan.duration); expiry = expiry.toISOString();
  }
  user.plan = plan.name; user.planExpiry = expiry; user.maxKeys = plan.maxKeys;
  saveDB(db);
  res.json({ ok: true, msg: 'Plano ' + plan.name + ' atribuido.' });
});

app.post('/api/admin/plan/save', adminAuth, (req, res) => {
  const { id, name, duration, keyType, maxKeys, price, active } = req.body;
  const db = loadDB();
  if (id) {
    const plan = db.plans.find(p => p.id === Number(id));
    if (!plan) return res.json({ ok: false, msg: 'Plano nao encontrado.' });
    plan.name = name; plan.duration = Number(duration); plan.keyType = keyType || 'lifetime';
    plan.maxKeys = Number(maxKeys); plan.price = price; plan.active = active !== false;
  } else {
    db.plans.push({ id: Date.now(), name, duration: Number(duration), keyType: keyType || 'lifetime', maxKeys: Number(maxKeys), price, active: true });
  }
  saveDB(db); res.json({ ok: true, msg: 'Plano salvo.' });
});

app.post('/api/admin/plan/delete', adminAuth, (req, res) => {
  const db = loadDB(); db.plans = db.plans.filter(p => p.id !== Number(req.body.id));
  saveDB(db); res.json({ ok: true, msg: 'Plano deletado.' });
});

app.post('/api/admin/key/delete', adminAuth, (req, res) => {
  const db = loadDB(); db.keys = db.keys.filter(k => k.id !== Number(req.body.id));
  saveDB(db); res.json({ ok: true, msg: 'Key deletada.' });
});

app.post('/api/admin/key/reset-hwid', adminAuth, (req, res) => {
  const { id, newHwid } = req.body;
  const db = loadDB();
  const key = db.keys.find(k => k.id === Number(id));
  if (!key) return res.json({ ok: false, msg: 'Key nao encontrada.' });
  key.hwid = (newHwid || '').trim().toUpperCase().replace(/[^A-Z0-9\-_]/g, '').slice(0, 64) || key.hwid;
  saveDB(db);
  res.json({ ok: true, msg: 'HWID atualizado.', hwid: key.hwid });
});

app.post('/api/admin/settings', adminAuth, (req, res) => {
  const { keyPrefix, keySegments, segmentLength } = req.body;
  const db = loadDB();
  if (!db.settings) db.settings = {};
  db.settings.keyPrefix = (keyPrefix || 'KEY').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 10) || 'KEY';
  db.settings.keySegments = Math.min(Math.max(Number(keySegments) || 2, 1), 6);
  db.settings.segmentLength = Math.min(Math.max(Number(segmentLength) || 8, 4), 16);
  saveDB(db);
  res.json({ ok: true, msg: 'Configuracoes salvas!', preview: generateKey(db.settings.keyPrefix, db.settings.keySegments, db.settings.segmentLength) });
});

app.get('/api/admin/settings', adminAuth, (req, res) => {
  const db = loadDB();
  res.json({ ok: true, settings: db.settings || { keyPrefix: 'KEY', keySegments: 2, segmentLength: 8 } });
});

app.use((req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log('Servidor na porta ' + PORT);
  console.log('ADMIN_PASSWORD: ' + (ADMIN_PASSWORD ? '✓ definida (' + ADMIN_PASSWORD.length + ' chars)' : '✗ VAZIA'));
});
