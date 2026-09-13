/*
 * Lexi Loader - Reseller Panel Backend & Web UI (Build F1 Edition)
 * Fully updated with F1 feature-action handshake, glowing gaming UI, emojis,
 * and strict owner-only loader control.
 */

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = path.join(__dirname, "database.json");

app.disable("x-powered-by");
app.use((req,res,next)=>{
  res.setHeader("Cache-Control","no-store");
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Referrer-Policy","no-referrer");
  res.setHeader("Permissions-Policy","camera=(), microphone=(), geolocation=()");
  if (process.env.NODE_ENV === "production") res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  next();
});
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

app.use((req, res, next) => {
  const supplied = String(req.headers["x-request-id"] || "").trim();
  const requestId = /^[A-Za-z0-9._:-]{8,80}$/.test(supplied) ? supplied : randomId("req");
  req.requestId = requestId;
  res.setHeader("X-Request-ID", requestId);
  next();
});

const DEFAULT_SESSION_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const ALLOWED_SESSION_HOURS = [24, 168];
const RESET_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_RESET_ATTEMPTS = 3;
const MAX_PANEL_DEVICE_RESETS = 3;
function resetWindowForRole(role) {
  if (role === ROLE.ADMIN) return 7 * 24 * 60 * 60 * 1000;
  if (role === ROLE.RESELLER) return 30 * 24 * 60 * 60 * 1000;
  return 24 * 60 * 60 * 1000;
}
function resetWindowLabel(role) {
  if (role === ROLE.ADMIN) return "7 days";
  if (role === ROLE.RESELLER) return "30 days";
  return "24 hours";
}
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_FAILURES = 10;
const MAX_KEY_QUANTITY = 1000;
const MAX_DEVICE_LIMIT = 9999;
const LOADER_SESSION_TTL_MS = 30 * 60 * 1000;
const LOADER_API_VERSION = 1;
const DEFAULT_LOADER_VERSION = "F1.0";
const DEFAULT_TARGET_PACKAGE = "com.pubg.imobile";

const ROLE = Object.freeze({ OWNER: "owner", ADMIN: "admin", RESELLER: "reseller" });
const STATUS = Object.freeze({ ACTIVE: "active", BLOCKED: "blocked", DELETED: "deleted" });
const KEY_STATUS = Object.freeze({ ACTIVE: "active", BLOCKED: "blocked", EXPIRED: "expired", DELETED: "deleted" });

const PRICING = Object.freeze({
  "3h":  { label: "3 Hour", hours: 3,   price: 10 },
  "1d":  { label: "1 Day",   hours: 24,  price: 100 },
  "3d":  { label: "3 Days",  hours: 72,  price: 200 },
  "7d":  { label: "7 Days",  hours: 168, price: 350 },
  "15d": { label: "15 Days", hours: 360, price: 500 },
  "30d": { label: "30 Days", hours: 720, price: 750 },
  "60d": { label: "60 Days", hours: 1440, price: 1000 }
});

function now() { return new Date().toISOString(); }
function randomId(prefix) { return `${prefix}_${crypto.randomBytes(10).toString("hex")}`; }
function randomToken(bytes = 32) { return crypto.randomBytes(bytes).toString("hex"); }
function normalizeUsername(value) { return String(value || "").trim().toLowerCase(); }
function normalizeCode(value) { return String(value || "").trim().toUpperCase(); }
function sanitizeString(value, max = 200) { return String(value ?? "").trim().slice(0, max); }
function clientIp(req) { return String(req.ip || req.socket.remoteAddress || "unknown"); }

function parseCookies(req) {
  const raw = String(req.headers.cookie || "");
  const out = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = decodeURIComponent(part.slice(i + 1).trim());
    if (k) out[k] = v;
  }
  return out;
}

function setSessionCookie(res, token, maxAgeMs) {
  const maxAge = Math.max(1, Math.floor(maxAgeMs / 1000));
  res.setHeader("Set-Cookie", `lexi_session=${encodeURIComponent(token)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV === "production" ? "; Secure" : ""}`);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "lexi_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash).split("$");
    if (parts.length !== 3 || parts[0] !== "scrypt") return false;
    const [, salt, expected] = parts;
    const actual = crypto.scryptSync(String(password), salt, 64).toString("hex");
    return safeEqual(actual, expected);
  } catch {
    return false;
  }
}

function initialDatabase() {
  return {
    version: 5,
    settings: {
      loaderStatus: true,
      maintenanceMsg: "Loader is temporarily under maintenance.",
      panelName: "Lexi Loader F1",
      supportLink: "",
      ipGeoLockEnabled: false,
      sessionTimeoutHours: 24,
      resetLimit: 3,
      resetWindowHours: 24,
      systemOnline: true,
      onlineMessage: "System is online.",
      appNotice: "",
      appNoticeType: "info",
      appNoticeEnabled: false,
      loaderApiVersion: LOADER_API_VERSION,
      loaderVersion: DEFAULT_LOADER_VERSION,
      loaderMinimumVersion: DEFAULT_LOADER_VERSION,
      loaderTargetPackage: DEFAULT_TARGET_PACKAGE,
      loaderUpdateUrl: "",
      loaderUpdateSha256: "",
      loaderUpdateSize: 0,
      loaderUpdateRequired: false,
      loaderUpdateNotes: "",
      loaderFeatures: { BT: true, AIM: true, ESP: true, IPAD_VIEW: true },
      loaderFileManifests: [],
      createdAt: now(),
      updatedAt: now()
    },
    pricing: { ...PRICING },
    users: [], referrals: [], keys: [], devices: [], transactions: [], auditLogs: [], sessions: [], rateLimits: []
  };
}

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const db = initialDatabase();
    atomicWrite(db);
    return db;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    const db = JSON.parse(raw);
    const base = initialDatabase();
    return {
      ...base, ...db,
      settings: { ...base.settings, ...(db.settings || {}) },
      pricing: { ...base.pricing, ...(db.pricing || {}) },
      users: Array.isArray(db.users) ? db.users : [],
      referrals: Array.isArray(db.referrals) ? db.referrals : [],
      keys: Array.isArray(db.keys) ? db.keys : [],
      devices: Array.isArray(db.devices) ? db.devices : [],
      transactions: Array.isArray(db.transactions) ? db.transactions : [],
      auditLogs: Array.isArray(db.auditLogs) ? db.auditLogs : [],
      sessions: Array.isArray(db.sessions) ? db.sessions : [],
      loaderSessions: Array.isArray(db.loaderSessions) ? db.loaderSessions : [],
      rateLimits: Array.isArray(db.rateLimits) ? db.rateLimits : []
    };
  } catch (err) {
    throw new Error(`database.json is invalid: ${err.message}`);
  }
}

function migrateDatabase() {
  db.version = 5;
  db.settings = db.settings || {};
  db.settings.loaderTargetPackage = DEFAULT_TARGET_PACKAGE;
  if (!Array.isArray(db.loaderSessions)) db.loaderSessions = [];
  db.pricing = { ...PRICING, ...(db.pricing || {}) };
  for (const u of db.users) {
    if (u.role === "user" || u.role === "normal" || u.role === "limited") u.role = ROLE.RESELLER;
    if (!u.registeredIp) u.registeredIp = null;
    if (!u.passwordResetAttempts) u.passwordResetAttempts = 0;
    if (!u.passwordResetWindowStartedAt) u.passwordResetWindowStartedAt = now();
    if (!Number.isInteger(u.usernameChangeCount)) u.usernameChangeCount = 0;
    if (!Number.isInteger(u.panelDeviceResetCount)) u.panelDeviceResetCount = 0;
    if (u.panelDeviceId === undefined) u.panelDeviceId = null;
  }
  for (const k of db.keys) {
    if (k.active_hack === undefined) k.active_hack = "ESP";
    if (k.hack_expiry === undefined) k.hack_expiry = null;
  }
}

function atomicWrite(db) {
  const tmp = `${DB_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}

let db = loadDb();
migrateDatabase();

function save() {
  db.settings.updatedAt = now();
  atomicWrite(db);
}

function publicUser(user) {
  return {
    id: user.id, username: user.username, role: user.role, status: user.status, parentId: user.parentId, balance: Number(user.balance || 0), createdAt: user.createdAt, lastLoginAt: user.lastLoginAt || null,
    reset: { used: Number(user.resetAttempts || 0), remaining: Math.max(0, MAX_RESET_ATTEMPTS - Number(user.resetAttempts || 0)), windowStartedAt: user.resetWindowStartedAt || null },
    panelDevice: { bound: Boolean(user.panelDeviceId), resetUsed: Number(user.panelDeviceResetCount || 0), resetRemaining: Math.max(0, MAX_PANEL_DEVICE_RESETS - Number(user.panelDeviceResetCount || 0)) }
  };
}

function findUserByUsername(username) { const normalized = normalizeUsername(username); return db.users.find(u => normalizeUsername(u.username) === normalized); }
function findUserById(id) { return db.users.find(u => u.id === id); }
function isActiveUser(user) { return !!user && user.status === STATUS.ACTIVE; }
function isDescendantOrSelf(targetUserId, actorUserId) {
  if (targetUserId === actorUserId) return true;
  let current = findUserById(targetUserId);
  const seen = new Set();
  while (current && current.parentId && !seen.has(current.id)) {
    seen.add(current.id);
    if (current.parentId === actorUserId) return true;
    current = findUserById(current.parentId);
  }
  return false;
}
function canManageUser(actor, target) {
  if (!actor || !target) return false;
  if (actor.role === ROLE.OWNER) return actor.id !== target.id;
  if (actor.role === ROLE.ADMIN) return target.role === ROLE.RESELLER && isDescendantOrSelf(target.id, actor.id) && target.id !== actor.id;
  return false;
}
function canViewUser(actor, target) {
  if (!actor || !target) return false;
  if (actor.role === ROLE.OWNER) return true;
  if (actor.role === ROLE.ADMIN) return target.id === actor.id || isDescendantOrSelf(target.id, actor.id);
  return target.id === actor.id;
}
function canManageKey(actor, key) {
  if (!actor || !key) return false;
  if (actor.role === ROLE.OWNER) return true;
  if (key.creatorId === actor.id) return true;
  if (actor.role === ROLE.ADMIN) {
    const creator = findUserById(key.creatorId);
    return !!creator && isDescendantOrSelf(creator.id, actor.id);
  }
  return false;
}
function keyStatus(key) {
  if (key.status === KEY_STATUS.DELETED) return KEY_STATUS.DELETED;
  if (key.status === KEY_STATUS.BLOCKED) return KEY_STATUS.BLOCKED;
  if (key.startedAt && key.expiryAt && Date.now() >= Date.parse(key.expiryAt)) return KEY_STATUS.EXPIRED;
  return KEY_STATUS.ACTIVE;
}
function publicKey(key) {
  const devices = db.devices.filter(d => d.keyId === key.id);
  return {
    id: key.id, key: key.key, creatorId: key.creatorId, creatorUsername: findUserById(key.creatorId)?.username || null, duration: key.duration, durationLabel: key.durationLabel, deviceLimit: key.deviceLimit, quantityBatchId: key.batchId || null, createdAt: key.createdAt, startedAt: key.startedAt || null, expiryAt: key.expiryAt || null, activated: !!key.startedAt, hwid: devices[0]?.hwid || null, status: keyStatus(key), gamePackage: key.gamePackage || "", ipLock: key.ipLock || null, geoLock: key.geoLock || null, devicesUsed: devices.length, active_hack: key.active_hack || "ESP", hack_expiry: key.hack_expiry || null,
    devices: devices.map(d => ({ id: d.id, hwid: d.hwid, deviceName: d.deviceName || "", ip: d.ip || "", firstSeenAt: d.firstSeenAt, lastSeenAt: d.lastSeenAt })), deletedAt: key.deletedAt || null
  };
}

function audit(actor, action, targetType, targetId, details = {}) {
  db.auditLogs.push({ id: randomId("audit"), actorId: actor?.id || "system", actorUsername: actor?.username || "system", action, targetType, targetId: targetId || null, ip: details.ip || null, details: details.details || {}, createdAt: now() });
  if (db.auditLogs.length > 10000) db.auditLogs.splice(0, db.auditLogs.length - 10000);
}
function transaction(actor, type, amount, before, after, targetUserId, details = {}) {
  db.transactions.push({ id: randomId("txn"), type, amount: Number(amount), balanceBefore: Number(before), balanceAfter: Number(after), actorId: actor?.id || "system", actorUsername: actor?.username || "system", targetUserId, details, createdAt: now() });
}

function cleanRateLimits() {
  const cutoff = Date.now() - Math.max(LOGIN_WINDOW_MS, RESET_WINDOW_MS);
  db.rateLimits = db.rateLimits.filter(x => Date.parse(x.updatedAt || x.createdAt || 0) >= cutoff);
}
function failedLoginCount(ip, username) {
  cleanRateLimits();
  const row = db.rateLimits.find(x => x.type === "login" && x.ip === ip && x.username === username);
  if (!row) return 0;
  if (Date.now() - Date.parse(row.windowStartedAt) > LOGIN_WINDOW_MS) return 0;
  return Number(row.failures || 0);
}
function registerFailedLogin(ip, username) {
  cleanRateLimits();
  let row = db.rateLimits.find(x => x.type === "login" && x.ip === ip && x.username === username);
  if (!row || Date.now() - Date.parse(row.windowStartedAt) > LOGIN_WINDOW_MS) {
    row = { id: randomId("rate"), type: "login", ip, username, failures: 0, windowStartedAt: now(), createdAt: now(), updatedAt: now() };
    db.rateLimits.push(row);
  }
  row.failures += 1; row.updatedAt = now(); save(); return row.failures;
}
function clearFailedLogin(ip, username) {
  db.rateLimits = db.rateLimits.filter(x => !(x.type === "login" && x.ip === ip && x.username === username));
  save();
}

function createSession(user, req, rememberMe = false, supportSession = false, sessionTimeoutHours = null) {
  const token = randomToken(32);
  const created = Date.now();
  const configuredHours = Number(sessionTimeoutHours || db.settings?.sessionTimeoutHours || 24);
  const timeoutHours = ALLOWED_SESSION_HOURS.includes(configuredHours) ? configuredHours : 24;
  const inactivityMs = timeoutHours * 60 * 60 * 1000;
  const maxAge = user.role === ROLE.OWNER ? 36500 * 24 * 60 * 60 * 1000 : (rememberMe ? 30 * 24 * 60 * 60 * 1000 : inactivityMs);

  db.sessions.push({ id: randomId("session"), token, userId: user.id, createdAt: new Date(created).toISOString(), lastActivityAt: new Date(created).toISOString(), expiresAt: new Date(created + maxAge).toISOString(), ip: clientIp(req), userAgent: String(req.headers["user-agent"] || "").slice(0, 300), rememberMe: !!rememberMe, supportSession: !!supportSession, timeoutHours });
  return token;
}

function getSession(req) {
  const header = String(req.headers.authorization || "");
  let token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) token = parseCookies(req).lexi_session || "";
  if (!token) return null;

  const session = db.sessions.find(s => safeEqual(s.token, token));
  if (!session) return null;
  if (Date.now() >= Date.parse(session.expiresAt)) {
    db.sessions = db.sessions.filter(s => s.id !== session.id); save(); return null;
  }
  const user = findUserById(session.userId);
  if (!isActiveUser(user)) return null;
  return { session, user };
}

function auth(req, res, next) {
  const result = getSession(req);
  if (!result) return res.status(401).json({ success: false, message: "Authentication required." });
  req.user = result.user; req.session = result.session; next();
}
function requireRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ success: false, message: "Permission denied." });
    next();
  };
}

function ensureOwner() {
  if (db.users.length > 0) return;
  const ownerPassword = process.env.LEXI_OWNER_PASSWORD || "lexi_owner_secure";
  const owner = { id: randomId("usr"), username: process.env.LEXI_OWNER_USERNAME || "owner", passwordHash: hashPassword(ownerPassword), role: ROLE.OWNER, status: STATUS.ACTIVE, parentId: null, balance: 0, resetAttempts: 0, resetWindowStartedAt: now(), passwordResetAttempts: 0, passwordResetWindowStartedAt: now(), createdAt: now(), lastLoginAt: null };
  db.users.push(owner);
  audit(owner, "OWNER_INITIALIZED", "user", owner.id, { details: { username: owner.username } });
  save();
}
ensureOwner();

/* ---------- APIs ---------- */
app.get("/api/health", (req, res) => { res.json({ success: true, service: "Lexi Loader Backend F1", version: db.version, time: now() }); });

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const rememberMe = Boolean(req.body.rememberMe);
  const requestedSessionHours = Number(req.body.sessionTimeoutHours || 24);
  const sessionTimeoutHours = ALLOWED_SESSION_HOURS.includes(requestedSessionHours) ? requestedSessionHours : 24;
  const ip = clientIp(req);

  if (!username || !password) return res.status(400).json({ success: false, message: "Username and password are required." });
  if (failedLoginCount(ip, username) >= MAX_LOGIN_FAILURES) return res.status(429).json({ success: false, message: "Too many failed login attempts. Please try again later." });

  const user = findUserByUsername(username);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    registerFailedLogin(ip, username);
    return res.status(401).json({ success: false, message: "Invalid username or password." });
  }
  if (user.status !== STATUS.ACTIVE) return res.status(403).json({ success: false, message: user.status === STATUS.BLOCKED ? "This account is blocked." : "This account is unavailable." });

  const panelDeviceId = sanitizeString(req.body.deviceId || "", 160);
  if (user.role !== ROLE.OWNER) {
    const deviceMismatch = Boolean(user.panelDeviceId && panelDeviceId && user.panelDeviceId !== panelDeviceId);
    const ipMismatch = Boolean(user.panelIp && user.panelIp !== ip);
    if (deviceMismatch || ipMismatch) {
      return res.status(403).json({ success: false, code: "DEVICE_LIMIT_REACHED", message: "Device Limit Reached", resetAvailable: Number(user.panelDeviceResetCount || 0) < MAX_PANEL_DEVICE_RESETS, resetRemaining: Math.max(0, MAX_PANEL_DEVICE_RESETS - Number(user.panelDeviceResetCount || 0)) });
    }
    if (!user.panelDeviceId && panelDeviceId) user.panelDeviceId = panelDeviceId;
    if (!user.panelIp) user.panelIp = ip;
    db.sessions = db.sessions.filter(s => s.userId !== user.id);
  }

  clearFailedLogin(ip, username);
  user.lastLoginAt = now();
  const token = createSession(user, req, rememberMe, false, sessionTimeoutHours);
  const sessionMaxAge = user.role === ROLE.OWNER ? 36500 * 24 * 60 * 60 * 1000 : (rememberMe ? 30 * 24 * 60 * 60 * 1000 : sessionTimeoutHours * 60 * 60 * 1000);
  setSessionCookie(res, token, sessionMaxAge);
  audit(user, "LOGIN", "user", user.id, { ip, details: { rememberMe } });
  save();
  res.json({ success: true, token, user: publicUser(user), session: { timeoutHours: user.role === ROLE.OWNER ? null : (rememberMe ? 720 : sessionTimeoutHours), rememberMe } });
});

app.post("/api/auth/logout", auth, (req, res) => {
  db.sessions = db.sessions.filter(s => s.id !== req.session.id);
  clearSessionCookie(res);
  audit(req.user, "LOGOUT", "user", req.user.id, { ip: clientIp(req) });
  save(); res.json({ success: true, message: "Logged out successfully." });
});

app.get("/api/auth/me", auth, (req, res) => { res.json({ success: true, user: publicUser(req.user) }); });

app.post("/api/auth/register", (req, res) => {
  const username = normalizeUsername(req.body.username); const password = String(req.body.password || ""); const referralCode = normalizeCode(req.body.referralCode); const ip = clientIp(req);
  if (!validUsername(username)) return res.status(400).json({ success: false, message: "Invalid username." });
  if (!validPassword(password)) return res.status(400).json({ success: false, message: "Invalid password." });
  if (!referralCode) return res.status(400).json({ success: false, message: "Referral code required." });
  if (findUserByUsername(username)) return res.status(409).json({ success: false, message: "Username exists." });
  const referral = db.referrals.find(r => normalizeCode(r.code) === referralCode);
  if (!referral || referral.status !== STATUS.ACTIVE) return res.status(400).json({ success: false, message: "Invalid code." });
  if (referral.expiresAt && Date.now() >= Date.parse(referral.expiresAt)) { referral.status = STATUS.BLOCKED; save(); return res.status(400).json({ success: false, message: "Code expired." }); }
  const creator = findUserById(referral.creatorId);
  if (!creator || creator.status !== STATUS.ACTIVE) return res.status(400).json({ success: false, message: "Referral owner unavailable." });
  const assignedRole = normalizeRole(referral.role);
  if (creator.role === ROLE.ADMIN && assignedRole !== ROLE.RESELLER) return res.status(400).json({ success: false, message: "Invalid role." });
  if (creator.role === ROLE.RESELLER) return res.status(400).json({ success: false, message: "Resellers cannot refer." });

  const user = { id: randomId("usr"), username, passwordHash: hashPassword(password), role: assignedRole, status: STATUS.ACTIVE, parentId: creator.id, balance: Number(referral.startingBalance || 0), resetAttempts: 0, resetWindowStartedAt: now(), passwordResetAttempts: 0, passwordResetWindowStartedAt: now(), createdAt: now(), lastLoginAt: null, registeredIp: ip, panelIp: null };
  db.users.push(user); referral.usedCount = Number(referral.usedCount || 0) + 1;
  if (user.balance > 0) transaction(creator, "REFERRAL_STARTING_BALANCE", user.balance, 0, user.balance, user.id, { referralId: referral.id, code: referral.code, role: user.role });
  audit(creator, "REGISTER_USER", "user", user.id, { ip, details: { referralId: referral.id, referralCode: referral.code, role: user.role } });
  save(); res.status(201).json({ success: true, message: "Account created successfully.", user: publicUser(user) });
});

app.post("/api/auth/reset-device", (req, res) => {
  const username = normalizeUsername(req.body.username); const password = String(req.body.password || ""); const deviceId = sanitizeString(req.body.deviceId || "", 160); const ip = clientIp(req);
  if (!username || !password || !deviceId) return res.status(400).json({ success: false, code: "INVALID_REQUEST", message: "All fields required." });
  const user = findUserByUsername(username);
  if (!user || !verifyPassword(password, user.passwordHash)) return res.status(401).json({ success: false, code: "RESET_FAILED", message: "Invalid credentials." });
  if (user.status !== STATUS.ACTIVE) return res.status(403).json({ success: false, code: "RESET_FAILED", message: "Account blocked." });
  if (user.role !== ROLE.OWNER && Number(user.panelDeviceResetCount || 0) >= MAX_PANEL_DEVICE_RESETS) return res.status(429).json({ success: false, code: "RESET_LIMIT_REACHED", message: "Limit reached." });
  const oldDeviceId = user.panelDeviceId || null; user.panelDeviceId = deviceId; user.panelIp = ip; user.panelDeviceResetCount = Number(user.panelDeviceResetCount || 0) + 1;
  db.sessions = db.sessions.filter(x => x.userId !== user.id);
  audit(user, "RESET_PANEL_DEVICE", "user", user.id, { ip, details: { oldDeviceId: oldDeviceId ? oldDeviceId.slice(0, 12) : null, newDeviceId: deviceId.slice(0, 12), used: user.panelDeviceResetCount, remaining: MAX_PANEL_DEVICE_RESETS - user.panelDeviceResetCount } });
  save(); res.json({ success: true, message: "Device reset successfully.", reset: { used: user.panelDeviceResetCount, remaining: Math.max(0, MAX_PANEL_DEVICE_RESETS - user.panelDeviceResetCount) } });
});

app.post("/api/auth/reset-password", (req, res) => {
  const username = normalizeUsername(req.body.username); const newPassword = String(req.body.newPassword || ""); const ip = clientIp(req);
  const user = findUserByUsername(username);
  if (!user || user.status !== STATUS.ACTIVE) return res.status(404).json({ success: false, message: "Account not found." });
  if (!validPassword(newPassword)) return res.status(400).json({ success: false, message: "Invalid password." });
  const started = Date.parse(user.passwordResetWindowStartedAt || 0); const resetWindowMs = resetWindowForRole(user.role);
  if (!user.passwordResetWindowStartedAt || Date.now() - started >= resetWindowMs) { user.passwordResetAttempts = 0; user.passwordResetWindowStartedAt = now(); }
  if (user.role !== ROLE.OWNER && Number(user.passwordResetAttempts || 0) >= MAX_RESET_ATTEMPTS) return res.status(429).json({ success: false, message: "Limit reached." });
  if (user.role !== ROLE.OWNER) user.passwordResetAttempts = Number(user.passwordResetAttempts || 0) + 1;
  user.passwordHash = hashPassword(newPassword); db.sessions = db.sessions.filter(x => x.userId !== user.id);
  audit(user, "PASSWORD_RESET", "user", user.id, { ip, details: { remaining: Math.max(0, MAX_RESET_ATTEMPTS - user.passwordResetAttempts) } });
  save(); res.json({ success: true, message: "Password reset successfully.", remaining: Math.max(0, MAX_RESET_ATTEMPTS - user.passwordResetAttempts) });
});

app.post("/api/auth/change-password", auth, (req, res) => {
  const newPassword = String(req.body.newPassword || "");
  if (!validPassword(newPassword)) return res.status(400).json({ success: false, message: "Invalid password." });
  req.user.passwordHash = hashPassword(newPassword);
  db.sessions = db.sessions.filter(s => s.userId !== req.user.id || s.id === req.session.id);
  audit(req.user, "PASSWORD_CHANGED", "user", req.user.id, { ip: clientIp(req) }); save();
  res.json({ success: true, message: "Password changed successfully." });
});

/* ---------- Referrals & Users & Keys ---------- */
app.post("/api/referrals/create", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const startingBalance = Number(req.body.startingBalance ?? 0); const expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt).toISOString() : null;
  let target = req.user; const requestedTargetId = sanitizeString(req.body.userId || "", 80);
  if (requestedTargetId) { target = findUserById(requestedTargetId); if (!target || (!canManageUser(req.user, target) && target.id !== req.user.id)) return res.status(403).json({ success: false, message: "Denied." }); }
  if (target.role === ROLE.OWNER && req.user.role !== ROLE.OWNER) return res.status(403).json({ success: false, message: "Denied." });
  if (target.role === ROLE.RESELLER) return res.status(403).json({ success: false, message: "Denied." });
  let role = normalizeRole(req.body.role); if (target.role === ROLE.ADMIN) role = ROLE.RESELLER; if (target.role === ROLE.OWNER && ![ROLE.OWNER, ROLE.ADMIN, ROLE.RESELLER].includes(role)) role = ROLE.RESELLER;
  let code = ""; do { code = normalizeCode(`LEXI-${crypto.randomBytes(5).toString("hex").toUpperCase()}`); } while (db.referrals.some(r => normalizeCode(r.code) === code));
  const referral = { id: randomId("ref"), code, creatorId: target.id, role, startingBalance, usageLimit: 0, usedCount: 0, status: STATUS.ACTIVE, expiresAt, createdAt: now() };
  db.referrals.push(referral); audit(req.user, "CREATE_REFERRAL", "referral", referral.id, { ip: clientIp(req), details: { code, targetId: target.id, role, startingBalance } }); save();
  res.status(201).json({ success: true, referral });
});
app.get("/api/referrals", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const rows = db.referrals.filter(r => req.user.role === ROLE.OWNER ? true : r.creatorId === req.user.id);
  res.json({ success: true, referrals: rows.map(r => ({ ...r, creatorUsername: findUserById(r.creatorId)?.username || null })) });
});
app.get("/api/referrals/:id", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id);
  if (!referral) return res.status(404).json({ success: false, message: "Not found." });
  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) return res.status(403).json({ success: false, message: "Denied." });
  res.json({ success: true, referral: { ...referral, creatorUsername: findUserById(referral.creatorId)?.username || null } });
});
app.post("/api/referrals/:id/balance", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id); if (!referral) return res.status(404).json({ success:false, message:"Not found." });
  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) return res.status(403).json({ success:false, message:"Denied." });
  const target = findUserById(referral.creatorId); const amount = Number(req.body.amount); const mode = String(req.body.mode || "set").toLowerCase();
  if (!target) return res.status(404).json({ success:false, message:"Not found." });
  if (!Number.isFinite(amount) || amount < 0) return res.status(400).json({ success:false, message:"Invalid amount." });
  const before = Number(target.balance || 0); let after = amount;
  if (mode === "add") after = before + amount; else if (mode === "subtract") after = Math.max(0, before - amount);
  target.balance = after; audit(req.user, "UPDATE_REFERRAL_CREATOR_BALANCE", "user", target.id, { ip: clientIp(req), details:{ referralId: referral.id, mode, amount, before, after } }); save();
  res.json({ success:true, balance:after, user:{ id:target.id, username:target.username, balance:after } });
});
app.post("/api/referrals/:id/toggle", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id); if (!referral) return res.status(404).json({ success: false, message: "Not found." });
  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) return res.status(403).json({ success: false, message: "Denied." });
  referral.status = referral.status === STATUS.ACTIVE ? STATUS.BLOCKED : STATUS.ACTIVE; audit(req.user, "TOGGLE_REFERRAL", "referral", referral.id, { ip: clientIp(req), details: { status: referral.status } }); save();
  res.json({ success: true, referral });
});
app.delete("/api/referrals/:id", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id); if (!referral) return res.status(404).json({ success:false, message:"Not found." });
  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) return res.status(403).json({ success:false, message:"Denied." });
  referral.status = STATUS.DELETED; audit(req.user, "DELETE_REFERRAL", "referral", referral.id, { ip: clientIp(req) }); save();
  res.json({ success:true, message:"Deleted." });
});

app.get("/api/users", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const q = sanitizeString(req.query.search, 80).toLowerCase(); const role = String(req.query.role || "all").toLowerCase(); const status = String(req.query.status || "all").toLowerCase();
  let rows = db.users.filter(u => canViewUser(req.user, u));
  if (q) rows = rows.filter(u => u.username.toLowerCase().includes(q) || u.id.toLowerCase().includes(q));
  if (role !== "all") rows = rows.filter(u => u.role === role); if (status !== "all") rows = rows.filter(u => u.status === status);
  res.json({ success: true, users: rows.map(publicUser), total: rows.length });
});
app.get("/api/users/:id", auth, (req, res) => {
  const target = findUserById(req.params.id); if (!target || !canViewUser(req.user, target)) return res.status(404).json({ success: false, message: "Not found." });
  const keys = db.keys.filter(k => k.creatorId === target.id).map(publicKey);
  res.json({ success: true, user: publicUser(target), keys });
});
app.post("/api/users/create", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const username = normalizeUsername(req.body.username); const password = String(req.body.password || ""); const role = normalizeRole(req.body.role); const balance = Number(req.body.balance ?? 0);
  if (!validUsername(username) || !validPassword(password)) return res.status(400).json({ success: false, message: "Invalid." });
  if (findUserByUsername(username)) return res.status(409).json({ success: false, message: "Exists." });
  if (!Number.isFinite(balance) || balance < 0) return res.status(400).json({ success: false, message: "Invalid balance." });
  if (req.user.role === ROLE.ADMIN && role !== ROLE.RESELLER) return res.status(403).json({ success: false, message: "Denied." });
  const user = { id: randomId("usr"), username, passwordHash: hashPassword(password), role: req.user.role === ROLE.ADMIN ? ROLE.RESELLER : role, status: STATUS.ACTIVE, parentId: req.user.id, balance, resetAttempts: 0, resetWindowStartedAt: now(), passwordResetAttempts: 0, passwordResetWindowStartedAt: now(), createdAt: now(), lastLoginAt: null, registeredIp: null };
  db.users.push(user); if (balance > 0) transaction(req.user, "USER_BALANCE_ASSIGNMENT", balance, 0, balance, user.id, {});
  audit(req.user, "CREATE_USER", "user", user.id, { ip: clientIp(req), details: { role: user.role, balance } }); save();
  res.status(201).json({ success: true, message: "Created.", user: publicUser(user) });
});
app.post("/api/users/:id/balance", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const target = findUserById(req.params.id); const amount = Number(req.body.amount); const mode = String(req.body.mode || "set").toLowerCase();
  if (!target || !canManageUser(req.user, target)) return res.status(404).json({ success: false, message: "Not found or denied." });
  if (target.role === ROLE.OWNER) return res.status(403).json({ success: false, message: "Denied." });
  if (!Number.isFinite(amount) || amount < 0) return res.status(400).json({ success: false, message: "Invalid." });
  const before = Number(target.balance || 0); let after;
  if (mode === "add") after = before + amount; else if (mode === "subtract") { after = before - amount; if (after < 0) return res.status(400).json({ success: false, message: "Negative." }); } else if (mode === "set") after = amount;
  target.balance = Number(after.toFixed(2)); transaction(req.user, "BALANCE_CHANGE", after - before, before, after, target.id, { mode }); audit(req.user, "CHANGE_BALANCE", "user", target.id, { ip: clientIp(req), details: { mode, amount, before, after } }); save();
  res.json({ success: true, user: publicUser(target) });
});
app.post("/api/users/:id/status", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const target = findUserById(req.params.id); if (!target || !canManageUser(req.user, target)) return res.status(404).json({ success: false, message: "Not found." });
  const status = String(req.body.status || "").toLowerCase(); if (![STATUS.ACTIVE, STATUS.BLOCKED, STATUS.DELETED].includes(status)) return res.status(400).json({ success: false, message: "Invalid." });
  if (target.role === ROLE.OWNER) return res.status(403).json({ success: false, message: "Denied." });
  target.status = status; if (status !== STATUS.ACTIVE) db.sessions = db.sessions.filter(s => s.userId !== target.id);
  audit(req.user, "CHANGE_USER_STATUS", "user", target.id, { ip: clientIp(req), details: { status } }); save();
  res.json({ success: true, user: publicUser(target) });
});

/* ---------- Keys API ---------- */
function getCreatorKeyScope(actor) {
  if (actor.role === ROLE.OWNER) return () => true;
  if (actor.role === ROLE.ADMIN) { return k => { const creator = findUserById(k.creatorId); return !!creator && isDescendantOrSelf(creator.id, actor.id); }; }
  return k => k.creatorId === actor.id;
}
app.get("/api/keys", auth, (req, res) => {
  const q = sanitizeString(req.query.search, 120).toLowerCase(); const status = String(req.query.status || "all").toLowerCase(); const scope = getCreatorKeyScope(req.user);
  let rows = db.keys.filter(scope);
  if (q) rows = rows.filter(k => { const devices = db.devices.filter(d => d.keyId === k.id); return ( k.key.toLowerCase().includes(q) || k.id.toLowerCase().includes(q) || devices.some(d => String(d.hwid || "").toLowerCase().includes(q)) ); });
  if (status !== "all") rows = rows.filter(k => keyStatus(k) === status);
  res.json({ success: true, keys: rows.map(publicKey), total: rows.length });
});
app.get("/api/keys/:id", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id); if (!key || !canManageKey(req.user, key)) return res.status(404).json({ success: false, message: "Not found." });
  res.json({ success: true, key: publicKey(key) });
});
function durationKeyLabel(duration, durationLabel) {
  const d = String(duration || "").toLowerCase();
  if (/^\d+h$/.test(d)) return d.toUpperCase();
  if (/^\d+d$/.test(d)) return d.toUpperCase();
  const match = String(durationLabel || "").match(/(\d+)\s*(hour|hours|day|days)/i);
  if (match) return Number(match[1]) + (match[2].toLowerCase().startsWith("h") ? "H" : "D");
  return "CUSTOM";
}
function generateLicenseKey(prefix = "Lexi-F1", duration = "", durationLabel = "") {
  const cleanPrefix = String(prefix || "Lexi-F1").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 20) || "Lexi-F1";
  const length = 15 + crypto.randomInt(6);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let tail = "";
  for (let i = 0; i < length; i++) tail += alphabet[crypto.randomInt(alphabet.length)];
  return `${cleanPrefix}_${durationKeyLabel(duration, durationLabel)}_${tail}`;
}
function ensureUniqueKey(prefix, duration, durationLabel) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const key = generateLicenseKey(prefix, duration, durationLabel);
    if (!db.keys.some(k => k.key === key)) return key;
  }
  throw new Error("Unable to generate unique key.");
}
app.post("/api/keys/generate", auth, (req, res) => {
  const duration = String(req.body.duration || "").toLowerCase(); const deviceLimit = Number(req.body.deviceLimit ?? 1); const quantity = Number(req.body.quantity ?? 1); const customKey = sanitizeString(req.body.customKey || "", 100); const gamePackage = sanitizeString(req.body.gamePackage || "", 150);
  if (customKey && ![ROLE.OWNER, ROLE.ADMIN].includes(req.user.role)) return res.status(403).json({ success: false, message: "Denied." });
  let durationHours = null; let durationLabel = "Custom"; let basePrice = 0;
  if (db.pricing[duration]) { 
    durationHours = Number(db.pricing[duration].hours); 
    durationLabel = db.pricing[duration].label; 
    basePrice = Number(db.pricing[duration].price); 
  } else {
    durationHours = Number(req.body.customHours || 24); 
    durationLabel = sanitizeString(req.body.customLabel || `${durationHours} Hours`, 50); 
    basePrice = req.user.role === ROLE.OWNER ? Number(req.body.customPrice || 0) : 0;
  }
  const totalPrice = Number((basePrice * quantity).toFixed(2)); const beforeBalance = Number(req.user.balance || 0);
  if (req.user.role !== ROLE.OWNER && beforeBalance < totalPrice) return res.status(402).json({ success: false, code: "INSUFFICIENT_BALANCE", message: "Insufficient balance." });

  const batchId = randomId("batch"); const createdAt = Date.now(); const generated = [];
  for (let i = 0; i < quantity; i++) {
    const key = { id: randomId("key"), key: customKey || ensureUniqueKey("Lexi-F1", duration, durationLabel), creatorId: req.user.id, batchId, duration, durationHours, durationLabel, basePrice, deviceLimit, gamePackage, status: KEY_STATUS.ACTIVE, createdAt: new Date(createdAt).toISOString(), startedAt: null, expiryAt: null, active_hack: "ESP", hack_expiry: null, deletedAt: null };
    db.keys.push(key); generated.push(publicKey(key));
  }
  if (req.user.role !== ROLE.OWNER && totalPrice > 0) {
    const afterBalance = Number((beforeBalance - totalPrice).toFixed(2)); req.user.balance = afterBalance;
    transaction(req.user, "KEY_GENERATION", -totalPrice, beforeBalance, afterBalance, req.user.id, { batchId, quantity });
  }
  audit(req.user, "GENERATE_KEYS", "batch", batchId, { ip: clientIp(req), details: { quantity, duration, deviceLimit, totalPrice } }); save();
  res.status(201).json({ success: true, message: `${quantity} key(s) generated.`, batchId, keys: generated });
});
app.post("/api/keys/:id/reset", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id); if (!key || !canManageKey(req.user, key)) return res.status(404).json({ success: false, message: "Not found." });
  db.devices = db.devices.filter(d => d.keyId !== key.id);
  audit(req.user, "RESET_KEY_DEVICES", "key", key.id, { ip: clientIp(req) }); save();
  res.json({ success: true, message: "Reset.", key: publicKey(key) });
});
app.post("/api/keys/:id/status", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id); if (!key || !canManageKey(req.user, key)) return res.status(404).json({ success: false, message: "Not found." });
  const status = String(req.body.status || "").toLowerCase();
  key.status = status; key.deletedAt = status === KEY_STATUS.DELETED ? now() : null; if (status === KEY_STATUS.DELETED) db.devices = db.devices.filter(d => d.keyId !== key.id);
  audit(req.user, "CHANGE_KEY_STATUS", "key", key.id, { ip: clientIp(req), details: { status } }); save(); res.json({ success: true, key: publicKey(key) });
});

/* ---------- F1 LOADER ENDPOINTS ---------- */
function loaderResponse(res, status, code, message, extra = {}) {
  return res.status(status).json({ success: false, code, message, requestId: res.req.requestId, ...extra });
}
function loaderSuccess(res, extra = {}) {
  return res.json({ success: true, requestId: res.req.requestId, ...extra });
}
function hashLoaderToken(token) { return crypto.createHash("sha256").update(String(token)).digest("hex"); }
function normalizeVersion(v) { return String(v || "0.0.0").trim().replace(/^v/i, ""); }

// 1. Standard Loader Login / Verify endpoint for Key + HWID
app.post("/api/loader/verify", (req, res) => {
  const licenseKey = sanitizeString(req.body.key, 150);
  const hwid = sanitizeString(req.body.hwid, 300);
  const packageName = sanitizeString(req.body.packageName || db.settings.loaderTargetPackage || DEFAULT_TARGET_PACKAGE, 200);
  const ip = clientIp(req);

  if (!db.settings.loaderStatus || db.settings.systemOnline === false) {
    return loaderResponse(res, 530, "LOADER_DISABLED", db.settings.maintenanceMsg || "Loader is under maintenance.");
  }
  if (!licenseKey || !hwid) {
    return loaderResponse(res, 400, "INVALID_REQUEST", "Key and HWID are required.");
  }

  const key = db.keys.find(k => k.key === licenseKey);
  if (!key || key.status === KEY_STATUS.DELETED) {
    return loaderResponse(res, 404, "KEY_NOT_FOUND", "Invalid License Key!");
  }
  const status = keyStatus(key);
  if (status === KEY_STATUS.BLOCKED) return loaderResponse(res, 403, "KEY_BLOCKED", "License Key Blocked!");
  if (status === KEY_STATUS.EXPIRED) return loaderResponse(res, 403, "KEY_EXPIRED", "License Key Expired!");

  // Activate / Start expiry timer if first time used
  let devices = db.devices.filter(d => d.keyId === key.id);
  let device = devices.find(d => safeEqual(d.hwid, hwid));
  const firstActivation = !key.startedAt;

  if (!device) {
    if (devices.length >= Number(key.deviceLimit || 1)) {
      return loaderResponse(res, 403, "DEVICE_LIMIT_REACHED", "Device limit reached for this key!");
    }
    if (firstActivation) {
      const startedMs = Date.now();
      key.startedAt = new Date(startedMs).toISOString();
      key.expiryAt = new Date(startedMs + Number(key.durationHours || 24) * 60 * 60 * 1000).toISOString();
    }
    device = { id: randomId("dev"), keyId: key.id, hwid, deviceName: "Android Device", ip, firstSeenAt: now(), lastSeenAt: now() };
    db.devices.push(device);
  } else {
    if (firstActivation) {
      const startedMs = Date.now();
      key.startedAt = new Date(startedMs).toISOString();
      key.expiryAt = new Date(startedMs + Number(key.durationHours || 24) * 60 * 60 * 1000).toISOString();
    }
    device.lastSeenAt = now();
    device.ip = ip;
  }

  const expiryEpoch = key.expiryAt ? Math.floor(Date.parse(key.expiryAt) / 1000) : 0;
  save();

  // Returns expiry epoch as expected by AuthManager.java verifyKey
  return res.json({
    success: true,
    expiry: expiryEpoch,
    status: "SUCCESS",
    message: "Login Successful"
  });
});

// 2. F1 Feature Action Endpoint (/api/feature_action) requested by PostLaunchActivity
app.post("/api/loader/feature_action", (req, res) => {
  const hwid = sanitizeString(req.body.hwid, 300);
  const selectedFeature = sanitizeString(req.body.selected_feature, 50).toUpperCase(); // AIM, BT, ESP

  if (!db.settings.loaderStatus || db.settings.systemOnline === false) {
    return res.status(403).json({ success: false, reason: db.settings.maintenanceMsg || "Loader is under maintenance." });
  }

  // Find bound device or key
  const device = db.devices.find(d => safeEqual(d.hwid, hwid));
  if (!device) {
    return res.status(403).json({ success: false, reason: "Device authorization not found. Please log in again." });
  }
  const key = db.keys.find(k => k.id === device.keyId);
  if (!key || keyStatus(key) !== KEY_STATUS.ACTIVE) {
    return res.status(403).json({ success: false, reason: "License key is invalid or expired." });
  }

  // Update active feature in record
  key.active_hack = ["AIM", "BT", "ESP"].includes(selectedFeature) ? selectedFeature : "ESP";
  save();

  // Returns dynamic prefix text as requested ("Lexi Loader" or customized by Owner)
  const prefixText = sanitizeString(db.settings.panelName || "Lexi Loader", 50);
  return res.json({
    success: true,
    status: "SUCCESS",
    prefix_text: prefixText,
    selected_feature: key.active_hack
  });
});

app.get("/api/loader/config", (req, res) => loaderSuccess(res, { loader: { enabled: db.settings.loaderStatus, targetPackage: db.settings.loaderTargetPackage || DEFAULT_TARGET_PACKAGE }, pricing: db.pricing }));
app.get("/api/loader/version", (req, res) => loaderSuccess(res, { version: { currentVersion: db.settings.loaderVersion || DEFAULT_LOADER_VERSION } }));

/* ---------- Owner-Only Loader Control Endpoints ---------- */
app.post("/api/owner/loader-settings", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const b = req.body || {};
  if (b.loaderStatus !== undefined) db.settings.loaderStatus = Boolean(b.loaderStatus);
  if (b.maintenanceMsg !== undefined) db.settings.maintenanceMsg = sanitizeString(b.maintenanceMsg, 1000);
  if (b.panelName !== undefined) db.settings.panelName = sanitizeString(b.panelName, 50);
  if (b.loaderVersion !== undefined) db.settings.loaderVersion = normalizeVersion(b.loaderVersion);
  if (b.loaderTargetPackage !== undefined) db.settings.loaderTargetPackage = sanitizeString(b.loaderTargetPackage, 200);
  
  audit(req.user, "UPDATE_LOADER_SETTINGS", "settings", "global", { ip: clientIp(req), details: { panelName: db.settings.panelName, loaderStatus: db.settings.loaderStatus } });
  save();
  return res.json({ success: true, message: "Loader settings updated successfully.", settings: db.settings });
});

/* ---------- Dashboard, Activity, Settings ---------- */
app.get("/api/dashboard", auth, (req, res) => {
  const scope = getCreatorKeyScope(req.user); const visibleKeys = db.keys.filter(scope); const visibleUsers = db.users.filter(u => canViewUser(req.user, u));
  const counts = { activeKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.ACTIVE).length, expiredKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.EXPIRED).length, blockedKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.BLOCKED).length, users: visibleUsers.length };
  res.json({ success: true, user: publicUser(req.user), stats: { ...counts, balance: Number(req.user.balance || 0), totalVisibleBalance: visibleUsers.reduce((sum, u) => sum + Number(u.balance || 0), 0) }, settings: { loaderStatus: db.settings.loaderStatus, maintenanceMsg: db.settings.maintenanceMsg, panelName: db.settings.panelName } });
});
app.get("/api/activity", auth, (req, res) => {
  let rows = [...db.auditLogs];
  res.json({ success: true, logs: rows.reverse().slice(0, 100) });
});
app.get("/api/transactions", auth, (req, res) => {
  let rows = [...db.transactions];
  res.json({ success: true, transactions: rows.reverse().slice(0, 100) });
});
app.get("/api/settings", auth, (req, res) => {
  res.json({ success: true, settings: db.settings, role: req.user.role });
});
app.post("/api/settings/update", auth, requireRoles(ROLE.OWNER), (req, res) => {
  if (req.body.panelName) db.settings.panelName = sanitizeString(req.body.panelName, 50);
  save();
  res.json({ success: true, settings: db.settings });
});
app.get("/api/pricing", auth, (req, res) => { res.json({ success: true, pricing: db.pricing }); });

app.post("/api/owner/enter-user/:id", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const target = findUserById(req.params.id); if (!target || target.id === req.user.id) return res.status(404).json({ success: false, message: "Not found." });
  const token = createSession(target, req, false, true); audit(req.user, "OWNER_ENTER_USER_PANEL", "user", target.id, { ip: clientIp(req) }); save();
  res.json({ success: true, token, user: publicUser(target) });
});

/* ---------- Web panel HTML with Gaming Vibe & Glowing Neon UI ---------- */
const PANEL_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Lexi Loader F1 Panel</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
:root{--bg:#07090e;--panel:#10141f;--panel2:#161c2d;--line:rgba(0, 229, 255, 0.15);--text:#f0f4f8;--muted:#8b9bb4;--accent:#00e5ff;--accent-glow:rgba(0, 229, 255, 0.35);--danger:#ff4757;--ok:#2ed573;--sidebar:260px;--shadow:0 10px 30px rgba(0,0,0,0.7), 0 0 20px rgba(0, 229, 255, 0.08)}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px 'Plus Jakarta Sans',system-ui,sans-serif}
button,input,select,textarea{font:inherit}
button{cursor:pointer; transition:all 0.25s ease}
.hidden{display:none!important}
#app{min-height:100vh}
.brand{font-size:24px;font-weight:800;letter-spacing:-0.5px;text-shadow:0 0 10px rgba(0,229,255,0.4)}
.brand span{background:linear-gradient(135deg,#00e5ff,#ff9100);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.muted,small{color:var(--muted)}
.app-shell{min-height:100vh}
.sidebar{position:fixed;left:0;top:0;bottom:0;width:var(--sidebar);background:rgba(10,14,23,0.95);backdrop-filter:blur(12px);border-right:1px solid var(--line);padding:24px 16px;z-index:50;display:flex;flex-direction:column;box-shadow:5px 0 25px rgba(0,0,0,0.5)}
.side-user{padding:16px;margin:20px 0 16px;background:var(--panel2);border:1px solid var(--line);border-radius:14px;box-shadow:inset 0 1px 0 rgba(255,255,255,0.05), 0 0 15px rgba(0,229,255,0.05)}
.side-nav{display:grid;gap:8px}
.navbtn{width:100%;text-align:left;background:transparent;color:#94a3b8;border:1px solid transparent;border-radius:10px;padding:12px 14px;font-weight:500;display:flex;align-items:center;gap:10px}
.navbtn:hover,.navbtn.active{background:rgba(0,229,255,0.1);color:var(--accent);border-color:rgba(0,229,255,0.3);box-shadow:0 0 12px rgba(0,229,255,0.15)}
.side-bottom{margin-top:auto;display:grid;gap:8px}
.main{margin-left:var(--sidebar);min-height:100vh}
.topbar{height:76px;padding:0 28px;border-bottom:1px solid var(--line);background:rgba(10,14,23,0.85);backdrop-filter:blur(12px);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:30}
.side-overlay{display:none}
.mobile-menu{display:none}
.layout{max-width:1450px;margin:auto;padding:28px}
.page-head{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px}
.page-head h1{margin:0 0 6px;font-size:32px;font-weight:700;letter-spacing:-0.5px;text-shadow:0 0 15px rgba(0,229,255,0.2)}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}
.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:var(--shadow);position:relative;overflow:hidden;transition:all 0.3s ease}
.card:hover{border-color:rgba(0,229,255,0.4);box-shadow:0 15px 40px rgba(0,0,0,0.8), 0 0 25px rgba(0, 229, 255, 0.15)}
.card::before{content:"";position:absolute;top:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,#00e5ff,transparent);pointer-events:none}
.stat .label{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:1px}
.stat b{display:block;font-size:32px;margin-top:10px;font-weight:800;color:#fff;text-shadow:0 0 10px rgba(0,229,255,0.3)}
.toolbar{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:12px;margin-bottom:16px}
.table-wrap{overflow:auto}
.table{width:100%;border-collapse:separate;border-spacing:0;min-width:920px}
.table th,.table td{padding:14px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}
.table th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:12px;letter-spacing:0.5px}
.table tbody tr:hover{background:rgba(0,229,255,0.03)}
.badge{display:inline-block;padding:5px 12px;border-radius:99px;background:#161c2d;font-size:12px;font-weight:600;border:1px solid var(--line)}
.badge.ok{color:#2ed573;background:rgba(46,213,115,0.1);border-color:rgba(46,213,115,0.3);box-shadow:0 0 8px rgba(46,213,115,0.2)}
.badge.bad{color:#ff4757;background:rgba(255,71,87,0.1);border-color:rgba(255,71,87,0.3);box-shadow:0 0 8px rgba(255,71,87,0.2)}
.actions{display:flex;flex-wrap:wrap;gap:8px}
.primary,.action,.danger{padding:11px 18px;border-radius:10px;border:1px solid transparent;font-weight:600;display:inline-flex;align-items:center;gap:8px}
.primary{background:linear-gradient(135deg,#00e5ff,#0083b0);color:#000;box-shadow:0 4px 15px rgba(0,229,255,0.3)}
.primary:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(0,229,255,0.5);filter:brightness(1.1)}
.action{background:var(--panel2);color:var(--text);border-color:var(--line)}
.action:hover{background:#1e263d;border-color:var(--accent)}
.danger{background:rgba(255,71,87,0.1);color:#ff4757;border-color:rgba(255,71,87,0.3)}
.danger:hover{background:rgba(255,71,87,0.2);box-shadow:0 0 10px rgba(255,71,87,0.2)}
.full{width:100%}
.field{margin:16px 0}
.field label{display:block;margin-bottom:8px;color:#94a3b8;font-weight:500;font-size:13px;letter-spacing:0.3px}
input,select,textarea{width:100%;background:#07090e;color:var(--text);border:1px solid var(--line);border-radius:10px;padding:13px 14px;outline:none;transition:all 0.25s}
input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 12px rgba(0,229,255,0.25)}
.row{display:flex;gap:10px;align-items:center}
.wrap{flex-wrap:wrap}
.empty{text-align:center;padding:50px;color:var(--muted);font-style:italic}
.key{font-family:'Courier New',Courier,monospace;font-size:13px;background:rgba(0,229,255,0.06);padding:4px 8px;border-radius:6px;color:#00e5ff;border:1px solid rgba(0,229,255,0.2)}
.login-wrap{min-height:100vh;display:grid;place-items:center;padding:20px;background:radial-gradient(circle at top, #101935 0%, #07090e 100%)}
.login{width:min(440px,100%);background:rgba(16,20,31,0.75);backdrop-filter:blur(20px);border:1px solid rgba(0,229,255,0.25);border-radius:20px;padding:36px;box-shadow:0 25px 50px rgba(0,0,0,0.9), 0 0 35px rgba(0,229,255,0.12)}
.error{color:#ff4757;background:rgba(255,71,87,0.1);border:1px solid rgba(255,71,87,0.3);padding:12px;border-radius:10px;margin:12px 0;font-weight:500}
.flash{margin-bottom:16px;padding:14px 18px;border-radius:10px;font-weight:600;border:1px solid;display:flex;align-items:center;gap:10px}
.flash.success{color:#2ed573;background:rgba(46,213,115,0.1);border-color:rgba(46,213,115,0.3)}
.flash.error{color:#ff4757;background:rgba(255,71,87,0.1);border-color:rgba(255,71,87,0.3)}
.toast{position:fixed;right:24px;bottom:24px;background:var(--panel2);border:1px solid var(--accent);color:#fff;padding:14px 20px;border-radius:12px;z-index:100;box-shadow:0 10px 30px rgba(0,0,0,0.8), 0 0 15px rgba(0,229,255,0.3);font-weight:600}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.85);backdrop-filter:blur(6px);display:grid;place-items:center;padding:20px;z-index:90}
.modal{width:min(650px,100%);max-height:90vh;overflow:auto;background:var(--panel);border:1px solid rgba(0,229,255,0.3);border-radius:20px;padding:28px;box-shadow:0 25px 60px rgba(0,0,0,0.9), 0 0 30px rgba(0,229,255,0.15)}
.modal h2{margin-top:0;font-size:24px;margin-bottom:16px;color:#00e5ff}
.password-wrap{position:relative}
.password-wrap input{padding-right:48px}
.eye-btn{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:36px;height:36px;border:0;background:transparent;color:#71717a;padding:0;display:grid;place-items:center}
.eye-btn:hover{color:var(--text)}
.eye-btn svg{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:2}
.setting-row{display:flex;justify-content:space-between;gap:16px;align-items:center;padding:16px 0;border-bottom:1px solid var(--line)}
.switch{position:relative;width:52px;height:28px}
.switch input{display:none}
.switch span{position:absolute;inset:0;background:#1e263d;border-radius:99px;transition:0.3s;border:1px solid var(--line)}
.switch span:after{content:"";position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:0.3s;box-shadow:0 2px 5px rgba(0,0,0,0.3)}
.switch input:checked+span{background:var(--ok);border-color:var(--ok);box-shadow:0 0 10px rgba(46,213,115,0.4)}
.switch input:checked+span:after{transform:translateX(24px)}
@media(max-width:900px){:root{--sidebar:0px}.sidebar{display:none}.sidebar.open{display:flex;width:280px;box-shadow:20px 0 60px rgba(0,0,0,0.9)}.side-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(3px);z-index:40}.side-overlay.open{display:block}.main{margin-left:0}.mobile-menu{display:inline-flex;padding:8px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.grid2{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr 1fr}.toolbar input{grid-column:1/-1}.topbar{padding:0 20px}}
@media(max-width:550px){.layout{padding:16px}.grid{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr}}
</style>
</head>
<body>
<div id="app"></div><div id="toast" class="toast hidden"></div>
<script>
let token=localStorage.getItem('lexi_token')||'';let ownerToken=localStorage.getItem('lexi_owner_token')||'';let currentUser=null;function getPanelDeviceId(){let id=localStorage.getItem('lexi_panel_device_id');if(!id){id='panel-'+Math.random().toString(36).substring(2)+Date.now().toString(36);localStorage.setItem('lexi_panel_device_id',id)}return id}let pricing={};let currentPage='dashboard';window.__panelFlash=null;window.__generatedKeys=null;let booting=false;
function esc(v){return String(v??'').replace(/[&<>'"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[m]))}
function setFlash(message,type='success'){window.__panelFlash={message,type};window.__panelFlashPage=currentPage;const html='<div class="flash '+(type==='error'?'error':'success')+'">'+esc(message)+'</div>';const a=document.getElementById('flashArea');if(a)a.innerHTML=html;}
function consumeFlash(){const f=window.__panelFlash;if(!f)return '';window.__panelFlash=null;return '<div class="flash '+(f.type==='error'?'error':'success')+'">'+esc(f.message)+'</div>'}
function toast(msg){const e=document.getElementById('toast');if(!e)return;e.textContent=msg;e.classList.remove('hidden');clearTimeout(window.__toast);window.__toast=setTimeout(()=>e.classList.add('hidden'),2800)}
async function api(url,opt={}){opt.credentials='same-origin';opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});if(token)opt.headers.Authorization='Bearer '+token;let r;try{r=await fetch(url,opt)}catch(e){throw new Error('Network error. Check connection.')};let d={};try{d=await r.json()}catch{}if(!r.ok){const e=new Error(d.message||'Request failed');e.status=r.status;throw e}return d}
function eyeSvg(open){return open?'<svg viewBox="0 0 24 24"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"></path><circle cx="12" cy="12" r="2.5"></circle></svg>':'<svg viewBox="0 0 24 24"><path d="M3 3l18 18"></path><path d="M10.6 6.2A11.7 11.7 0 0 1 12 6c6.5 0 10 6 10 6a18.8 18.8 0 0 1-3.1 3.8"></path><path d="M6.2 6.2C3.5 8.1 2 12 2 12s3.5 6 10 6c1.2 0 2.3-.2 3.3-.6"></path></svg>'}function togglePassword(id,btn){const el=document.getElementById(id);if(!el)return;const show=el.type==='password';el.type=show?'text':'password';if(btn)btn.innerHTML=eyeSvg(show)}

function renderLogin(){const f=consumeFlash();document.getElementById('app').innerHTML='<div class="login-wrap"><div class="login"><div id="loginFlash">'+f+'</div><div class="brand">⚡ Lexi <span>Loader F1</span></div><p class="muted">Secure Gaming Admin & Reseller Portal</p><form onsubmit="login(event)"><div class="field"><label>👤 Username</label><input id="loginUser" placeholder="Enter your username" autocomplete="username" required></div><div class="field"><label>🔑 Password</label><div class="password-wrap"><input id="loginPass" type="password" placeholder="Enter your password" autocomplete="current-password" required><button type="button" class="eye-btn" onclick="togglePassword(\'loginPass\',this)"><span class="eye-icon"></span></button></div></div><div id="loginErr" class="error hidden"></div><button class="primary full" style="margin-top:14px" type="submit">🚀 SIGN IN</button></form><button class="action full" style="margin-top:12px" onclick="renderRegister()">📝 Create Reseller Account</button></div></div>';initEyeButtons()}
async function login(e){e.preventDefault();const er=document.getElementById('loginErr');er.classList.add('hidden');try{const r=await fetch('/api/auth/login',{credentials:'same-origin',method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('loginUser').value,password:document.getElementById('loginPass').value,deviceId:getPanelDeviceId()})});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.message||'Login failed.');token=d.token;localStorage.setItem('lexi_token',token);currentUser=d.user;await shell();await page('dashboard')}catch(x){er.textContent=x?.message||'Login failed.';er.classList.remove('hidden')}}

function renderRegister(){document.getElementById('app').innerHTML='<div class="login-wrap"><div class="login"><div class="brand">⚡ Lexi <span>Loader F1</span></div><p class="muted">Register New Reseller Account</p><form onsubmit="registerAccount(event)"><div class="field"><label>👤 Username</label><input id="regUser" placeholder="Choose a username" required></div><div class="field"><label>🔑 Password</label><div class="password-wrap"><input id="regPass" type="password" placeholder="Choose a password" required><button type="button" class="eye-btn" onclick="togglePassword(\'regPass\',this)"><span class="eye-icon"></span></button></div></div><div class="field"><label>🎟️ Referral Code</label><input id="regRef" placeholder="Enter referral code" required></div><div id="regErr" class="error hidden"></div><button class="primary full" type="submit">✨ CREATE ACCOUNT</button></form><button class="action full" style="margin-top:12px" onclick="renderLogin()">🔙 Back to Login</button></div></div>';initEyeButtons()}
async function registerAccount(e){e.preventDefault();const er=document.getElementById('regErr');er.classList.add('hidden');try{const r=await fetch('/api/auth/register',{credentials:'same-origin',method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('regUser').value,password:document.getElementById('regPass').value,referralCode:document.getElementById('regRef').value})});const d=await r.json();if(!r.ok)throw new Error(d.message||'Registration failed');alert('Account created successfully!');renderLogin()}catch(x){er.textContent=x.message;er.classList.remove('hidden')}}

function navItem(id,label,icon){return '<button data-page="'+esc(id)+'" class="navbtn '+(currentPage===id?'active':'')+'" onclick="page(\''+id+'\')"><span>'+icon+'</span> '+label+'</button>'}
function sidebar(){let owner=currentUser.role==='owner',admin=currentUser.role==='admin';let items=navItem('dashboard','Dashboard','📊')+navItem('generateKeys','Generate Keys','🔑')+navItem('manageKeys','Manage Keys','🛡️');if(owner)items+=navItem('users','Users','👥');if(owner||admin)items+=navItem('referrals','Referrals','🎟️')+navItem('transactions','Transactions','💰')+navItem('activity','Activity','⚡');if(owner)items+=navItem('loader','Loader Control','⚙️');items+=navItem('settings','Settings','🔧');return '<div id="sideOverlay" class="side-overlay" onclick="closeSideMenu()"></div><aside id="sidebar" class="sidebar" onclick="event.stopPropagation()"><div class="brand">⚡ Lexi <span>Loader</span></div><div class="side-user"><b>👤 '+esc(currentUser.username)+'</b><div class="muted" style="margin-top:5px">⭐ '+esc(currentUser.role.toUpperCase())+'</div><div style="margin-top:7px">💰 Balance: ₹'+Number(currentUser.balance||0).toFixed(2)+'</div></div><div class="side-nav">'+items+'</div><div class="side-bottom"><button class="action full" onclick="logout()">🚪 Logout</button></div></aside>'}
function toggleSideMenu(){document.getElementById('sidebar')?.classList.toggle('open');document.getElementById('sideOverlay')?.classList.toggle('open')}function closeSideMenu(){document.getElementById('sidebar')?.classList.remove('open');document.getElementById('sideOverlay')?.classList.remove('open')}
async function shell(){document.getElementById('app').innerHTML='<div class="app-shell">'+sidebar()+'<section class="main"><header class="topbar"><div class="row"><button class="action mobile-menu" onclick="toggleSideMenu()">☰ Menu</button><div><b>⭐ '+esc(currentUser.role.toUpperCase())+'</b><div class="muted">👤 '+esc(currentUser.username)+'</div></div></div></header><main class="layout"><div id="flashArea">'+consumeFlash()+'</div><div id="content"></div></main></section></div>'}

async function boot(){if(booting)return;booting=true;try{if(!token){renderLogin();return}const m=await api('/api/auth/me');currentUser=m.user;await shell();await page(currentPage,{push:false})}catch(e){localStorage.removeItem('lexi_token');token='';currentUser=null;renderLogin()}finally{booting=false}}
async function page(name,opts={}){currentPage=name;closeSideMenu();document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('active',b.dataset.page===name));if(!currentUser)return;if(name==='dashboard')return dashboard();if(name==='generateKeys')return generateKeysPage();if(name==='manageKeys')return keysPage();if(name==='users'&&currentUser.role==='owner')return usersPage();if(name==='referrals')return referralsPage();if(name==='transactions')return transactionsPage();if(name==='activity')return activityPage();if(name==='loader'&&currentUser.role==='owner')return loaderPage();if(name==='settings')return settingsPage();return dashboard()}

function stat(label,value,icon){return '<div class="card stat"><div class="label">'+icon+' '+esc(label)+'</div><b>'+esc(value)+'</b></div>'}
async function dashboard(){try{const d=await api('/api/dashboard');const s=d.stats||{};document.getElementById('content').innerHTML='<div class="page-head"><div><h1>📊 Dashboard Overview</h1><div class="muted">License and reseller statistics</div></div><button class="primary" onclick="page(\'generateKeys\')">⚡ Generate Keys</button></div><div class="grid">'+stat('Active Keys',s.activeKeys||0,'🟢')+stat('Expired Keys',s.expiredKeys||0,'⏰')+stat('Blocked Keys',s.blockedKeys||0,'⛔')+stat('Total Users',s.users||0,'👥')+'</div><div class="grid2" style="margin-top:16px">'+stat('Account Balance','₹'+Number(s.balance||0).toFixed(2),'💰')+stat('Loader Status',d.settings?.loaderStatus?'ONLINE 🟢':'MAINTENANCE 🔴','⚙️')+'</div>'}catch(e){toast(e.message)}}

async function generateKeysPage(){try{pricing=(await api('/api/pricing')).pricing||{};document.getElementById('content').innerHTML=consumeFlash()+'<div class="page-head"><div><h1>🔑 Generate License Keys</h1><div class="muted">Create custom duration keys instantly</div></div></div><div class="grid2"><div class="card"><h3>⚡ Quick Generator</h3><div class="field"><label>Duration</label><select id="genDuration">'+Object.keys(pricing).map(k=>'<option value="'+esc(k)+'">'+esc(pricing[k].label)+' — ₹'+Number(pricing[k].price).toFixed(2)+'</option>').join('')+'</select></div><div class="field"><label>Max Devices / HWID Lock</label><input id="genDevices" type="number" min="1" value="1"></div><div class="field"><label>Quantity</label><input id="genCount" type="number" min="1" max="100" value="1"></div><div id="genErr" class="error hidden"></div><button class="primary full" onclick="generateSave()">🚀 Generate Keys</button></div><div class="card" id="generatedResultBox"><h3>📋 Recent Batch Output</h3><p class="muted">Generated keys will appear here for easy copying.</p></div></div>'}catch(e){toast(e.message)}}

async function generateSave(){const er=document.getElementById('genErr');try{const duration=document.getElementById('genDuration').value;const body={duration,deviceLimit:Number(document.getElementById('genDevices').value),quantity:Number(document.getElementById('genCount').value)};const d=await api('/api/keys/generate',{method:'POST',body:JSON.stringify(body)});toast('Keys generated successfully!');let keys=d.keys||[];document.getElementById('generatedResultBox').innerHTML='<h3 style="color:var(--ok)">✅ Generated Keys ('+keys.length+')</h3>'+keys.map(k=>'<div style="margin:10px 0;padding:8px;background:var(--panel2);border-radius:8px" class="row"><b class="key">'+esc(k.key)+'</b><button class="action" onclick="copyText(\''+esc(k.key)+'\')">📋 Copy</button></div>').join('');await dashboard()}catch(e){er.textContent=e.message;er.classList.remove('hidden')}}

async function keysPage(){try{const d=await api('/api/keys');window.__keys=d.keys||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>🛡️ Manage License Keys</h1><div class="muted">View and control active licenses & HWID locks</div></div></div><div class="card"><div class="toolbar"><input id="keySearch" placeholder="Search license or HWID..." oninput="renderKeys()"><select id="keyStatus" onchange="renderKeys()"><option value="all">All Status</option><option value="active">Active</option><option value="blocked">Blocked</option><option value="expired">Expired</option></select><div></div><button class="primary" onclick="loadKeys()">🔄 Refresh</button></div><div id="keysTable"></div></div>';renderKeys()}catch(e){toast(e.message)}}

function renderKeys(){let q=(document.getElementById('keySearch')?.value||'').toLowerCase(),st=document.getElementById('keyStatus')?.value||'all';let rows=(window.__keys||[]).filter(k=>{let ok=!q||String(k.key).toLowerCase().includes(q)||String(k.hwid||'').toLowerCase().includes(q);let ss=st==='all'||k.status===st;return ok&&ss});const el=document.getElementById('keysTable');if(!el)return;if(!rows.length){el.innerHTML='<div class="empty">No license keys found.</div>';return}el.innerHTML='<div class="table-wrap"><table class="table"><thead><tr><th>License Key</th><th>Status</th><th>Duration</th><th>Devices</th><th>Expiry</th><th>Actions</th></tr></thead><tbody>'+rows.map(k=>'<tr><td><b class="key">'+esc(k.key)+'</b></td><td><span class="badge '+(k.status==='active'?'ok':'bad')+'">'+esc(k.status)+'</span></td><td>'+esc(k.durationLabel||k.duration||'')+'</td><td>'+((k.devices||[]).length)+' / '+Number(k.deviceLimit||1)+'</td><td>'+esc(k.expiryAt?new Date(k.expiryAt).toLocaleString():'Not Started')+'</td><td><div class="actions"><button class="action" onclick="keyAction(\''+esc(k.id)+'\',\'reset\')">🔄 Reset</button><button class="danger" onclick="keyAction(\''+esc(k.id)+'\',\'block\')">⛔ Block</button></div></td></tr>').join('')+'</tbody></table></div>'}

async function loadKeys(){try{const d=await api('/api/keys');window.__keys=d.keys||[];renderKeys();toast('Keys refreshed')}catch(e){toast(e.message)}}
async function keyAction(id,action){try{if(action==='reset'){await api('/api/keys/'+encodeURIComponent(id)+'/reset',{method:'POST'});toast('Devices unbound successfully')}else{let status=action==='block'?'blocked':'active';await api('/api/keys/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status})});toast('Key status updated')}loadKeys()}catch(e){toast(e.message)}}

async function usersPage(){if(currentUser.role!=='owner')return dashboard();try{const d=await api('/api/users');window.__users=d.users||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>👥 User & Reseller Management</h1><div class="muted">Create and oversee resellers</div></div><button class="primary" onclick="createUserModal()">➕ Add User</button></div><div class="card"><div id="usersTable"></div></div>';renderUsers()}catch(e){toast(e.message)}}

function renderUsers(){const rows=window.__users||[];const el=document.getElementById('usersTable');if(!el)return;el.innerHTML='<div class="table-wrap"><table class="table"><thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Balance</th><th>Created</th><th>Actions</th></tr></thead><tbody>'+(rows.length?rows.map(u=>'<tr><td><b>'+esc(u.username)+'</b></td><td>'+esc(u.role)+'</td><td><span class="badge '+(u.status==='active'?'ok':'bad')+'">'+esc(u.status)+'</span></td><td>₹'+Number(u.balance||0).toFixed(2)+'</td><td>'+esc(new Date(u.createdAt).toLocaleDateString())+'</td><td><button class="action" onclick="balanceModal(\''+esc(u.id)+'\')">💰 Balance</button></td></tr>').join(''):'<tr><td colspan="6" class="empty">No users found.</td></tr>')+'</tbody></table></div>'}

function createUserModal(){modal('<h2>➕ Create New Reseller</h2><div class="field"><label>Username</label><input id="newUser"></div><div class="field"><label>Password</label><input id="newPass" type="password"></div><div class="field"><label>Role</label><select id="newRole"><option value="reseller">Reseller</option><option value="admin">Admin</option></select></div><div class="field"><label>Starting Balance (₹)</label><input id="newBal" type="number" value="0"></div><button class="primary full" onclick="createUserSave()">Create User</button>')}
async function createUserSave(){try{await api('/api/users/create',{method:'POST',body:JSON.stringify({username:document.getElementById('newUser').value,password:document.getElementById('newPass').value,role:document.getElementById('newRole').value,balance:Number(document.getElementById('newBal').value||0)})});closeModal();toast('User created successfully');usersPage()}catch(e){toast(e.message)}}

function balanceModal(id){modal('<h2>💰 Adjust User Balance</h2><div class="field"><label>Amount (₹)</label><input id="balAmount" type="number" value="0"></div><div class="field"><label>Mode</label><select id="balMode"><option value="add">Add</option><option value="subtract">Subtract</option><option value="set">Set Exact</option></select></div><button class="primary full" onclick="saveBalance(\''+esc(id)+'\')">Save Balance</button>')}
async function saveBalance(id){try{await api('/api/users/'+encodeURIComponent(id)+'/balance',{method:'POST',body:JSON.stringify({amount:Number(document.getElementById('balAmount').value),mode:document.getElementById('balMode').value})});closeModal();toast('Balance updated successfully');usersPage()}catch(e){toast(e.message)}}

async function referralsPage(){try{const d=await api('/api/referrals');const rows=d.referrals||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>🎟️ Referral Codes</h1><div class="muted">Manage invite codes for new resellers</div></div><button class="primary" onclick="createReferralModal()">➕ Generate Referral</button></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Code</th><th>Role</th><th>Used Count</th><th>Status</th></tr></thead><tbody>'+(rows.length?rows.map(r=>'<tr><td><b class="key">'+esc(r.code)+'</b></td><td>'+esc(r.role)+'</td><td>'+Number(r.usedCount||0)+'</td><td><span class="badge '+(r.status==='active'?'ok':'bad')+'">'+esc(r.status)+'</span></td></tr>').join(''):'<tr><td colspan="4" class="empty">No referral codes.</td></tr>')+'</tbody></table></div></div>'}catch(e){toast(e.message)}}

function createReferralModal(){modal('<h2>Generate Referral Code</h2><div class="field"><label>Role for New User</label><select id="refRole"><option value="reseller">Reseller</option></select></div><div class="field"><label>Starting Balance (₹)</label><input id="refBal" type="number" value="0"></div><button class="primary full" onclick="saveReferral()">Generate Code</button>')}
async function saveReferral(){try{await api('/api/referrals/create',{method:'POST',body:JSON.stringify({role:document.getElementById('refRole').value,startingBalance:Number(document.getElementById('refBal').value||0)})});closeModal();toast('Referral created');referralsPage()}catch(e){toast(e.message)}}

async function transactionsPage(){try{const d=await api('/api/transactions');const rows=d.transactions||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>💰 Transaction History</h1><div class="muted">Balance changes and key generation audit logs</div></div></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Type</th><th>Amount</th><th>Before</th><th>After</th></tr></thead><tbody>'+(rows.length?rows.map(t=>'<tr><td>'+esc(new Date(t.createdAt).toLocaleString())+'</td><td>'+esc(t.type)+'</td><td>₹'+Number(t.amount||0).toFixed(2)+'</td><td>₹'+Number(t.balanceBefore||0).toFixed(2)+'</td><td>₹'+Number(t.balanceAfter||0).toFixed(2)+'</td></tr>').join(''):'<tr><td colspan="5" class="empty">No transactions yet.</td></tr>')+'</tbody></table></div></div>'}catch(e){toast(e.message)}}

async function activityPage(){try{const d=await api('/api/activity');const rows=d.logs||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>⚡ Activity & Audit Logs</h1><div class="muted">System activity trail</div></div></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target ID</th></tr></thead><tbody>'+(rows.length?rows.map(x=>'<tr><td>'+esc(new Date(x.createdAt).toLocaleString())+'</td><td>'+esc(x.actorUsername)+'</td><td>'+esc(x.action)+'</td><td>'+esc(x.targetId||'-')+'</td></tr>').join(''):'<tr><td colspan="4" class="empty">No activity logged.</td></tr>')+'</tbody></table></div></div>'}catch(e){toast(e.message)}}

async function loaderPage(){try{const d=await api('/api/dashboard');document.getElementById('content').innerHTML='<div class="page-head"><div><h1>⚙️ Loader Control (Owner Only)</h1><div class="muted">Control Loader verification status and server handshake prefix</div></div></div><div class="card"><h3>Loader Verification Switch</h3><div class="setting-row"><div><b>Global Loader Status</b><small>Turn ON or OFF verification for all loaders</small></div><label class="switch"><input id="ldEnabled" type="checkbox" '+(d.settings?.loaderStatus?'checked':'')+'><span></span></label></div><div class="field" style="margin-top:16px"><label>Maintenance / Error Message</label><textarea id="ldMsg" rows="3">'+esc(d.settings?.maintenanceMsg||'')+'</textarea></div><div class="field"><label>Panel / Loader Prefix Name (Top Left Text)</label><input id="ldPanelName" value="'+esc(d.settings?.panelName||'Lexi Loader')+'" placeholder="Lexi Loader"></div><button class="primary" style="margin-top:16px" onclick="saveLoaderAdmin()">💾 Save Loader Settings</button></div>'}catch(e){toast(e.message)}}
async function saveLoaderAdmin(){try{await api('/api/owner/loader-settings',{method:'POST',body:JSON.stringify({loaderStatus:document.getElementById('ldEnabled').checked,maintenanceMsg:document.getElementById('ldMsg').value,panelName:document.getElementById('ldPanelName').value})});toast('Loader settings saved successfully!')}catch(e){toast(e.message)}}

async function settingsPage(){try{const d=await api('/api/settings');document.getElementById('content').innerHTML='<div class="page-head"><div><h1>🔧 Account Settings</h1><div class="muted">Manage your security and password</div></div></div><div class="card"><h3>🔒 Change Password</h3><div class="field"><label>New Password</label><input id="newPass" type="password"></div><button class="primary" onclick="changePassword()">Update Password</button></div>'}catch(e){toast(e.message)}}
async function changePassword(){try{await api('/api/auth/change-password',{method:'POST',body:JSON.stringify({newPassword:document.getElementById('newPass').value})});toast('Password updated successfully')}catch(e){toast(e.message)}}

function modal(html){closeModal();const d=document.createElement('div');d.id='modal';d.className='modal-bg';d.innerHTML='<div class="modal">'+html+'</div>';document.body.appendChild(d)}function closeModal(){document.getElementById('modal')?.remove()}
async function logout(){localStorage.removeItem('lexi_token');token='';currentUser=null;renderLogin()}
window.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});function initEyeButtons(){}
(async()=>{if(location.pathname.toLowerCase()==='/register'){renderRegister();return}await boot()})();
</script></body></html>`;

app.get("/", (req, res) => res.type("html").send(PANEL_HTML));
app.get(/^\/Login$/i, (req, res) => res.type("html").send(PANEL_HTML));
app.get("/panel", (req, res) => res.redirect(302, "/Dashboard"));
app.get(/^\/Register$/i, (req, res) => res.type("html").send(PANEL_HTML));
app.get(/^\/(Dashboard|Generate-Keys|Manage-Keys|Users|Referrals|Transactions|Activity|Settings|Loader)(?:\/.*)?$/i, (req, res) => res.type("html").send(PANEL_HTML));

/* ---------- Error Handling ---------- */
app.use("/api", (req, res) => { res.status(404).json({ success: false, message: "API endpoint not found." }); });
app.use((err, req, res, next) => { console.error(err); if (res.headersSent) return next(err); res.status(500).json({ success: false, message: "Internal server error." }); });

app.listen(PORT, () => {
  console.log(`Lexi Loader F1 Backend running on port ${PORT}`);
  console.log(`Database: ${DB_FILE}`);
});
