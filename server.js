/*
 * Lexi Loader - Reseller Panel Backend
 * GitHub-ready single-file backend foundation.
 *
 * Requirements locked in this build:
 * - OWNER > ADMIN > RESELLER
 * - Server-authoritative permissions
 * - Referral-based registration
 * - Balance-aware key generation
 * - Duration + quantity
 * - User/key search and filters
 * - 3 password/device reset attempts per rolling 24h window
 * - 1 Day / 7 Days fixed session timeout
 * - Audit logs and balance transactions
 * - Loader ON/OFF + maintenance message
 * - Optional IP/Geo lock fields
 * - Atomic JSON database writes
 *
 * Install:
 *   npm install express
 *
 * Run:
 *   node server.js
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

const ROLE = Object.freeze({
  OWNER: "owner",
  ADMIN: "admin",
  RESELLER: "reseller"
});

const STATUS = Object.freeze({
  ACTIVE: "active",
  BLOCKED: "blocked",
  DELETED: "deleted"
});

const KEY_STATUS = Object.freeze({
  ACTIVE: "active",
  BLOCKED: "blocked",
  EXPIRED: "expired",
  DELETED: "deleted"
});

const PRICING = Object.freeze({
  "3h":  { label: "3 Hour", hours: 3,   price: 10 },
  "1d":  { label: "1 Day",   hours: 24,  price: 100 },
  "3d":  { label: "3 Days",  hours: 72,  price: 200 },
  "7d":  { label: "7 Days",  hours: 168, price: 350 },
  "15d": { label: "15 Days", hours: 360, price: 500 },
  "30d": { label: "30 Days", hours: 720, price: 750 },
  "60d": { label: "60 Days", hours: 1440, price: 1000 }
});

function now() {
  return new Date().toISOString();
}

function randomId(prefix) {
  return `${prefix}_${crypto.randomBytes(10).toString("hex")}`;
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeCode(value) {
  return String(value || "").trim().toUpperCase();
}

function sanitizeString(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

function clientIp(req) {
  return String(req.ip || req.socket.remoteAddress || "unknown");
}

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

/* Password hashing with Node's built-in scrypt; no password package required. */
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
    version: 2,
    settings: {
      loaderStatus: true,
      maintenanceMsg: "Loader is temporarily under maintenance.",
      panelName: "Lexi Loader",
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
      createdAt: now(),
      updatedAt: now()
    },
    pricing: { ...PRICING },
    users: [],
    referrals: [],
    keys: [],
    devices: [],
    transactions: [],
    auditLogs: [],
    sessions: [],
    rateLimits: []
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
      ...base,
      ...db,
      settings: { ...base.settings, ...(db.settings || {}) },
      pricing: { ...base.pricing, ...(db.pricing || {}) },
      users: Array.isArray(db.users) ? db.users : [],
      referrals: Array.isArray(db.referrals) ? db.referrals : [],
      keys: Array.isArray(db.keys) ? db.keys : [],
      devices: Array.isArray(db.devices) ? db.devices : [],
      transactions: Array.isArray(db.transactions) ? db.transactions : [],
      auditLogs: Array.isArray(db.auditLogs) ? db.auditLogs : [],
      sessions: Array.isArray(db.sessions) ? db.sessions : [],
      rateLimits: Array.isArray(db.rateLimits) ? db.rateLimits : []
    };
  } catch (err) {
    throw new Error(`database.json is invalid: ${err.message}`);
  }
}

function migrateDatabase() {
  db.version = 3;
  db.settings = db.settings || {};
  if (db.settings.maintenanceMessage !== undefined && db.settings.maintenanceMsg === undefined) db.settings.maintenanceMsg = db.settings.maintenanceMessage;
  if (db.settings.supportUrl !== undefined && db.settings.supportLink === undefined) db.settings.supportLink = db.settings.supportUrl;
  if (db.settings.optionalIpLock !== undefined && db.settings.ipGeoLockEnabled === undefined) db.settings.ipGeoLockEnabled = Boolean(db.settings.optionalIpLock);
  if (db.settings.sessionTimeoutHours === undefined) db.settings.sessionTimeoutHours = 24;
  if (db.settings.resetLimit === undefined) db.settings.resetLimit = 3;
  if (db.settings.resetWindowHours === undefined) db.settings.resetWindowHours = 24;
  if (db.settings.systemOnline === undefined) db.settings.systemOnline = true;
  if (db.settings.onlineMessage === undefined) db.settings.onlineMessage = "System is online.";
  if (db.settings.appNotice === undefined) db.settings.appNotice = "";
  if (db.settings.appNoticeType === undefined) db.settings.appNoticeType = "info";
  if (db.settings.appNoticeEnabled === undefined) db.settings.appNoticeEnabled = false;
  db.pricing = { ...PRICING, ...(db.pricing || {}) };
  db.users = Array.isArray(db.users) ? db.users : [];
  db.referrals = Array.isArray(db.referrals) ? db.referrals : [];
  db.keys = Array.isArray(db.keys) ? db.keys : [];
  db.devices = Array.isArray(db.devices) ? db.devices : [];
  db.transactions = Array.isArray(db.transactions) ? db.transactions : [];
  db.auditLogs = Array.isArray(db.auditLogs) ? db.auditLogs : [];
  db.sessions = Array.isArray(db.sessions) ? db.sessions : [];
  db.rateLimits = Array.isArray(db.rateLimits) ? db.rateLimits : [];
  for (const u of db.users) {
    if (u.role === "user" || u.role === "normal" || u.role === "limited") u.role = ROLE.RESELLER;
    if (!u.registeredIp) u.registeredIp = null;
    if (!u.passwordResetAttempts) u.passwordResetAttempts = 0;
    if (!u.passwordResetWindowStartedAt) u.passwordResetWindowStartedAt = now();
    if (!Number.isInteger(u.usernameChangeCount)) u.usernameChangeCount = 0;
    if (!Number.isInteger(u.panelDeviceResetCount)) u.panelDeviceResetCount = 0;
    if (u.panelDeviceId === undefined) u.panelDeviceId = null;
  }

  /* Existing keys were created with an expiry timestamp. Preserve them as already-started. */
  for (const k of db.keys) {
    if (k.startedAt === undefined) {
      if (k.expiryAt && k.durationHours) {
        const expiryMs = Date.parse(k.expiryAt);
        const durationMs = Number(k.durationHours) * 60 * 60 * 1000;
        k.startedAt = Number.isFinite(expiryMs) ? new Date(expiryMs - durationMs).toISOString() : null;
      } else {
        k.startedAt = null;
      }
    }
    if (k.expiryAt === undefined) k.expiryAt = null;
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
    id: user.id,
    username: user.username,
    role: user.role,
    status: user.status,
    parentId: user.parentId,
    balance: Number(user.balance || 0),
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null,
    reset: {
      used: Number(user.resetAttempts || 0),
      remaining: Math.max(0, MAX_RESET_ATTEMPTS - Number(user.resetAttempts || 0)),
      windowStartedAt: user.resetWindowStartedAt || null
    },
    panelDevice: {
      bound: Boolean(user.panelDeviceId),
      resetUsed: Number(user.panelDeviceResetCount || 0),
      resetRemaining: Math.max(0, MAX_PANEL_DEVICE_RESETS - Number(user.panelDeviceResetCount || 0))
    }
  };
}

function findUserByUsername(username) {
  const normalized = normalizeUsername(username);
  return db.users.find(u => normalizeUsername(u.username) === normalized);
}

function findUserById(id) {
  return db.users.find(u => u.id === id);
}

function isActiveUser(user) {
  return !!user && user.status === STATUS.ACTIVE;
}

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
  if (actor.role === ROLE.ADMIN) {
    return target.role === ROLE.RESELLER && isDescendantOrSelf(target.id, actor.id) && target.id !== actor.id;
  }
  return false;
}

function canViewUser(actor, target) {
  if (!actor || !target) return false;
  if (actor.role === ROLE.OWNER) return true;
  if (actor.role === ROLE.ADMIN) {
    return target.id === actor.id || isDescendantOrSelf(target.id, actor.id);
  }
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
    id: key.id,
    key: key.key,
    creatorId: key.creatorId,
    creatorUsername: findUserById(key.creatorId)?.username || null,
    duration: key.duration,
    durationLabel: key.durationLabel,
    deviceLimit: key.deviceLimit,
    quantityBatchId: key.batchId || null,
    createdAt: key.createdAt,
    startedAt: key.startedAt || null,
    expiryAt: key.expiryAt || null,
    activated: !!key.startedAt,
    hwid: devices[0]?.hwid || null,
    status: keyStatus(key),
    gamePackage: key.gamePackage || "",
    ipLock: key.ipLock || null,
    geoLock: key.geoLock || null,
    devicesUsed: devices.length,
    devices: devices.map(d => ({
      id: d.id,
      hwid: d.hwid,
      deviceName: d.deviceName || "",
      ip: d.ip || "",
      firstSeenAt: d.firstSeenAt,
      lastSeenAt: d.lastSeenAt
    })),
    deletedAt: key.deletedAt || null
  };
}

function audit(actor, action, targetType, targetId, details = {}) {
  db.auditLogs.push({
    id: randomId("audit"),
    actorId: actor?.id || "system",
    actorUsername: actor?.username || "system",
    action,
    targetType,
    targetId: targetId || null,
    ip: details.ip || null,
    details: details.details || {},
    createdAt: now()
  });

  if (db.auditLogs.length > 10000) {
    db.auditLogs.splice(0, db.auditLogs.length - 10000);
  }
}

function transaction(actor, type, amount, before, after, targetUserId, details = {}) {
  db.transactions.push({
    id: randomId("txn"),
    type,
    amount: Number(amount),
    balanceBefore: Number(before),
    balanceAfter: Number(after),
    actorId: actor?.id || "system",
    actorUsername: actor?.username || "system",
    targetUserId,
    details,
    createdAt: now()
  });
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
    row = {
      id: randomId("rate"),
      type: "login",
      ip,
      username,
      failures: 0,
      windowStartedAt: now(),
      createdAt: now(),
      updatedAt: now()
    };
    db.rateLimits.push(row);
  }
  row.failures += 1;
  row.updatedAt = now();
  save();
  return row.failures;
}

function clearFailedLogin(ip, username) {
  db.rateLimits = db.rateLimits.filter(
    x => !(x.type === "login" && x.ip === ip && x.username === username)
  );
  save();
}

function createSession(user, req, rememberMe = false, supportSession = false, sessionTimeoutHours = null) {
  const token = randomToken(32);
  const created = Date.now();
  const configuredHours = Number(sessionTimeoutHours || db.settings?.sessionTimeoutHours || 24);
  const timeoutHours = ALLOWED_SESSION_HOURS.includes(configuredHours) ? configuredHours : 24;
  const inactivityMs = timeoutHours * 60 * 60 * 1000;
  const maxAge = user.role === ROLE.OWNER ? 36500 * 24 * 60 * 60 * 1000 : (rememberMe ? 30 * 24 * 60 * 60 * 1000 : inactivityMs);

  db.sessions.push({
    id: randomId("session"),
    token,
    userId: user.id,
    createdAt: new Date(created).toISOString(),
    lastActivityAt: new Date(created).toISOString(),
    expiresAt: new Date(created + maxAge).toISOString(),
    ip: clientIp(req),
    userAgent: String(req.headers["user-agent"] || "").slice(0, 300),
    rememberMe: !!rememberMe,
    supportSession: !!supportSession,
    timeoutHours
  });

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
    db.sessions = db.sessions.filter(s => s.id !== session.id);
    save();
    return null;
  }

  const user = findUserById(session.userId);
  if (!isActiveUser(user)) return null;

  /* Fixed session timeout: selected 1 Day / 7 Days is measured from login time. */
  if (Date.now() >= Date.parse(session.expiresAt)) {
    db.sessions = db.sessions.filter(s => s.id !== session.id);
    save();
    return null;
  }

  return { session, user };
}

function auth(req, res, next) {
  const result = getSession(req);
  if (!result) {
    return res.status(401).json({ success: false, message: "Authentication required." });
  }
  req.user = result.user;
  req.session = result.session;
  next();
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: "Permission denied." });
    }
    next();
  };
}

function resetWindow(user) {
  if (!user.resetWindowStartedAt || Date.now() - Date.parse(user.resetWindowStartedAt) >= RESET_WINDOW_MS) {
    user.resetAttempts = 0;
    user.resetWindowStartedAt = now();
  }
}

function consumeResetAttempt(user) {
  resetWindow(user);
  if (Number(user.resetAttempts || 0) >= MAX_RESET_ATTEMPTS) return false;
  user.resetAttempts = Number(user.resetAttempts || 0) + 1;
  save();
  return true;
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.-]{3,32}$/.test(username);
}

function validPassword(password) {
  return typeof password === "string" && password.length >= 6 && password.length <= 128;
}

function normalizeRole(role) {
  const value = String(role || "").toLowerCase();
  if (value === ROLE.OWNER) return ROLE.OWNER;
  if (value === ROLE.ADMIN) return ROLE.ADMIN;
  if (value === ROLE.RESELLER || value === "user" || value === "normal" || value === "limited") return ROLE.RESELLER;
  return ROLE.RESELLER;
}

function randomKeyTail() {
  const length = 15 + crypto.randomInt(11);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  let out = "";
  for (let i = 0; i < length; i++) {
    const useNumber = crypto.randomInt(100) < 25;
    const chars = useNumber ? numbers : alphabet;
    out += chars[crypto.randomInt(chars.length)];
  }
  return out;
}

function durationKeyLabel(duration, durationLabel) {
  const d = String(duration || "").toLowerCase();
  if (/^\d+h$/.test(d)) return d.toUpperCase();
  if (/^\d+d$/.test(d)) return d.toUpperCase();
  const match = String(durationLabel || "").match(/(\d+)\s*(hour|hours|day|days)/i);
  if (match) return Number(match[1]) + (match[2].toLowerCase().startsWith("h") ? "H" : "D");
  return "CUSTOM";
}

function generateLicenseKey(prefix = "Lexi-Loader", duration = "", durationLabel = "") {
  const cleanPrefix = String(prefix || "Lexi-Loader")
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, 20) || "Lexi-Loader";
  return `${cleanPrefix}_${durationKeyLabel(duration, durationLabel)}_${randomKeyTail()}`;
}

function ensureUniqueKey(prefix, duration, durationLabel) {
  let key;
  do {
    key = generateLicenseKey(prefix, duration, durationLabel);
  } while (db.keys.some(k => k.key === key));
  return key;
}

function getCreatorKeyScope(actor) {
  if (actor.role === ROLE.OWNER) return () => true;
  if (actor.role === ROLE.ADMIN) {
    return k => {
      const creator = findUserById(k.creatorId);
      return !!creator && isDescendantOrSelf(creator.id, actor.id);
    };
  }
  return k => k.creatorId === actor.id;
}

/* Initialize an owner if the database has no users. */
function ensureOwner() {
  if (db.users.length > 0) return;

  const ownerPassword = process.env.LEXI_OWNER_PASSWORD || "change-this-owner-password";
  const owner = {
    id: randomId("usr"),
    username: process.env.LEXI_OWNER_USERNAME || "owner",
    passwordHash: hashPassword(ownerPassword),
    role: ROLE.OWNER,
    status: STATUS.ACTIVE,
    parentId: null,
    balance: 0,
    resetAttempts: 0,
    resetWindowStartedAt: now(),
    passwordResetAttempts: 0,
    passwordResetWindowStartedAt: now(),
    createdAt: now(),
    lastLoginAt: null
  };

  db.users.push(owner);
  audit(owner, "OWNER_INITIALIZED", "user", owner.id, {
    details: { username: owner.username }
  });
  save();

  console.warn(
    `[Lexi Loader] Initial owner created: ${owner.username}. ` +
    `Set LEXI_OWNER_PASSWORD in production and change this password immediately.`
  );
}

ensureOwner();

/* ---------- Health ---------- */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "Lexi Loader Backend",
    version: db.version,
    time: now()
  });
});

/* ---------- Authentication ---------- */

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const rememberMe = Boolean(req.body.rememberMe);
  const requestedSessionHours = Number(req.body.sessionTimeoutHours || 24);
  const sessionTimeoutHours = ALLOWED_SESSION_HOURS.includes(requestedSessionHours) ? requestedSessionHours : 24;
  const ip = clientIp(req);

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required." });
  }

  if (failedLoginCount(ip, username) >= MAX_LOGIN_FAILURES) {
    return res.status(429).json({
      success: false,
      message: "Too many failed login attempts. Please try again later."
    });
  }

  const user = findUserByUsername(username);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    registerFailedLogin(ip, username);
    return res.status(401).json({ success: false, message: "Invalid username or password." });
  }

  if (user.status !== STATUS.ACTIVE) {
    return res.status(403).json({
      success: false,
      message: user.status === STATUS.BLOCKED ? "This account is blocked." : "This account is unavailable."
    });
  }

  const panelDeviceId = sanitizeString(req.body.deviceId || "", 160);
  if (user.role !== ROLE.OWNER) {
    const deviceMismatch = Boolean(user.panelDeviceId && panelDeviceId && user.panelDeviceId !== panelDeviceId);
    const ipMismatch = Boolean(user.panelIp && user.panelIp !== ip);
    if (deviceMismatch || ipMismatch) {
      return res.status(403).json({
        success: false,
        code: "DEVICE_LIMIT_REACHED",
        message: "Device Limit Reached",
        resetAvailable: Number(user.panelDeviceResetCount || 0) < MAX_PANEL_DEVICE_RESETS,
        resetRemaining: Math.max(0, MAX_PANEL_DEVICE_RESETS - Number(user.panelDeviceResetCount || 0))
      });
    }
    if (!user.panelDeviceId && panelDeviceId) user.panelDeviceId = panelDeviceId;
    if (!user.panelIp) user.panelIp = ip;
  }

  clearFailedLogin(ip, username);

  user.lastLoginAt = now();
  const token = createSession(user, req, rememberMe, false, sessionTimeoutHours);
  const sessionMaxAge = user.role === ROLE.OWNER ? 36500 * 24 * 60 * 60 * 1000 : (rememberMe ? 30 * 24 * 60 * 60 * 1000 : sessionTimeoutHours * 60 * 60 * 1000);
  setSessionCookie(res, token, sessionMaxAge);

  audit(user, "LOGIN", "user", user.id, {
    ip,
    details: { rememberMe }
  });
  save();

  res.json({
    success: true,
    token,
    user: publicUser(user),
    session: {
      timeoutHours: user.role === ROLE.OWNER ? null : (rememberMe ? 720 : sessionTimeoutHours),
      rememberMe
    }
  });
});

app.post("/api/auth/logout", auth, (req, res) => {
  db.sessions = db.sessions.filter(s => s.id !== req.session.id);
  clearSessionCookie(res);
  audit(req.user, "LOGOUT", "user", req.user.id, { ip: clientIp(req) });
  save();
  res.json({ success: true, message: "Logged out successfully." });
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json({ success: true, user: publicUser(req.user) });
});

/* ---------- Registration via referral ---------- */

app.post("/api/auth/register", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const referralCode = normalizeCode(req.body.referralCode);
  const ip = clientIp(req);

  if (!validUsername(username)) {
    return res.status(400).json({
      success: false,
      message: "Username must be 3-32 characters and contain only letters, numbers, dot, dash or underscore."
    });
  }

  if (!validPassword(password)) {
    return res.status(400).json({
      success: false,
      message: "Password must be between 6 and 128 characters."
    });
  }

  if (!referralCode) {
    return res.status(400).json({ success: false, message: "Referral code is required." });
  }

  if (findUserByUsername(username)) {
    return res.status(409).json({ success: false, message: "Username already exists." });
  }

  const referral = db.referrals.find(r => normalizeCode(r.code) === referralCode);
  if (!referral || referral.status !== STATUS.ACTIVE) {
    return res.status(400).json({ success: false, message: "Invalid or inactive referral code." });
  }

  if (referral.expiresAt && Date.now() >= Date.parse(referral.expiresAt)) {
    referral.status = STATUS.BLOCKED;
    save();
    return res.status(400).json({ success: false, message: "Referral code has expired." });
  }


  const creator = findUserById(referral.creatorId);
  if (!creator || creator.status !== STATUS.ACTIVE) {
    return res.status(400).json({ success: false, message: "Referral owner is unavailable." });
  }

  const assignedRole = normalizeRole(referral.role);
  if (creator.role === ROLE.ADMIN && assignedRole !== ROLE.RESELLER) {
    return res.status(400).json({ success: false, message: "This referral can only create a Reseller account." });
  }
  if (creator.role === ROLE.RESELLER) {
    return res.status(400).json({ success: false, message: "Resellers cannot create referral registrations." });
  }

  const user = {
    id: randomId("usr"),
    username,
    passwordHash: hashPassword(password),
    role: assignedRole,
    status: STATUS.ACTIVE,
    parentId: creator.id,
    balance: Number(referral.startingBalance || 0),
    resetAttempts: 0,
    resetWindowStartedAt: now(),
    passwordResetAttempts: 0,
    passwordResetWindowStartedAt: now(),
    createdAt: now(),
    lastLoginAt: null,
    registeredIp: ip,
    panelIp: null
  };

  db.users.push(user);
  referral.usedCount = Number(referral.usedCount || 0) + 1;

  if (user.balance > 0) {
    transaction(creator, "REFERRAL_STARTING_BALANCE", user.balance, 0, user.balance, user.id, {
      referralId: referral.id,
      code: referral.code,
      role: user.role
    });
  }

  audit(creator, "REGISTER_USER", "user", user.id, {
    ip,
    details: { referralId: referral.id, referralCode: referral.code, role: user.role }
  });
  save();

  res.status(201).json({
    success: true,
    message: "Account created successfully.",
    user: publicUser(user)
  });
});

/* ---------- Password / device reset ---------- */

app.post("/api/auth/reset-device", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const deviceId = sanitizeString(req.body.deviceId || "", 160);
  const ip = clientIp(req);

  if (!username || !password || !deviceId) {
    return res.status(400).json({ success: false, code: "INVALID_REQUEST", message: "Username, password and device information are required." });
  }

  const user = findUserByUsername(username);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ success: false, code: "RESET_FAILED", message: "Invalid username or password." });
  }
  if (user.status !== STATUS.ACTIVE) {
    return res.status(403).json({ success: false, code: "RESET_FAILED", message: "This account is blocked." });
  }

  if (user.role !== ROLE.OWNER && Number(user.panelDeviceResetCount || 0) >= MAX_PANEL_DEVICE_RESETS) {
    return res.status(429).json({ success: false, code: "RESET_LIMIT_REACHED", message: "Panel device reset limit reached. Maximum 3 resets are allowed." });
  }

  const oldDeviceId = user.panelDeviceId || null;
  user.panelDeviceId = deviceId;
  user.panelIp = ip;
  user.panelDeviceResetCount = Number(user.panelDeviceResetCount || 0) + 1;
  db.sessions = db.sessions.filter(x => x.userId !== user.id);

  audit(user, "RESET_PANEL_DEVICE", "user", user.id, {
    ip,
    details: { oldDeviceId: oldDeviceId ? oldDeviceId.slice(0, 12) : null, newDeviceId: deviceId.slice(0, 12), used: user.panelDeviceResetCount, remaining: MAX_PANEL_DEVICE_RESETS - user.panelDeviceResetCount }
  });
  save();

  res.json({
    success: true,
    message: "Device reset successfully. This device is now authorized.",
    reset: { used: user.panelDeviceResetCount, remaining: Math.max(0, MAX_PANEL_DEVICE_RESETS - user.panelDeviceResetCount) }
  });
});

/* ---------- Password reset ---------- */
app.post("/api/auth/reset-password", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const newPassword = String(req.body.newPassword || "");
  const ip = clientIp(req);
  const user = findUserByUsername(username);
  if (!user || user.status !== STATUS.ACTIVE) return res.status(404).json({ success: false, message: "Account not found or unavailable." });
  if (!validPassword(newPassword)) return res.status(400).json({ success: false, message: "Password must be between 6 and 128 characters." });

  const started = Date.parse(user.passwordResetWindowStartedAt || 0);
  const resetWindowMs = resetWindowForRole(user.role);
  if (!user.passwordResetWindowStartedAt || Date.now() - started >= resetWindowMs) {
    user.passwordResetAttempts = 0;
    user.passwordResetWindowStartedAt = now();
  }
  if (user.role !== ROLE.OWNER && Number(user.passwordResetAttempts || 0) >= MAX_RESET_ATTEMPTS) return res.status(429).json({ success: false, message: "Password reset limit reached. Try again after the " + resetWindowLabel(user.role) + " window." });
  if (user.role !== ROLE.OWNER) user.passwordResetAttempts = Number(user.passwordResetAttempts || 0) + 1;
  user.passwordHash = hashPassword(newPassword);
  db.sessions = db.sessions.filter(x => x.userId !== user.id);
  audit(user, "PASSWORD_RESET", "user", user.id, { ip, details: { remaining: Math.max(0, MAX_RESET_ATTEMPTS - user.passwordResetAttempts) } });
  save();
  res.json({ success: true, message: "Password reset successfully.", remaining: Math.max(0, MAX_RESET_ATTEMPTS - user.passwordResetAttempts) });
});

app.get("/api/auth/reset-status", (req, res) => {
  const user = findUserByUsername(normalizeUsername(req.query.username));
  if (!user) return res.status(404).json({ success: false, message: "Account not found." });
  const started = Date.parse(user.passwordResetWindowStartedAt || 0);
  const resetWindowMs = resetWindowForRole(user.role);
  if (!user.passwordResetWindowStartedAt || Date.now() - started >= resetWindowMs) return res.json({ success: true, used: 0, remaining: MAX_RESET_ATTEMPTS, window: resetWindowLabel(user.role) });
  const used = Number(user.passwordResetAttempts || 0);
  res.json({ success: true, used, remaining: Math.max(0, MAX_RESET_ATTEMPTS - used), windowStartedAt: user.passwordResetWindowStartedAt, window: resetWindowLabel(user.role) });
});

/* ---------- Authenticated password change ---------- */
app.post("/api/auth/change-password", auth, (req, res) => {
  const newPassword = String(req.body.newPassword || "");
  if (!validPassword(newPassword)) return res.status(400).json({ success: false, message: "Password must be between 6 and 128 characters." });
  req.user.passwordHash = hashPassword(newPassword);
  const currentSessionId = req.session.id;
  db.sessions = db.sessions.filter(s => s.userId !== req.user.id || s.id === currentSessionId);
  audit(req.user, "PASSWORD_CHANGED", "user", req.user.id, { ip: clientIp(req) });
  save();
  res.json({ success: true, message: "Password changed successfully." });
});

/* ---------- Referrals ---------- */

app.post("/api/referrals/create", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const startingBalance = Number(req.body.startingBalance ?? 0);
  const usageLimit = 0; // Referrals are unlimited; usage limit is no longer configurable.
  const expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt).toISOString() : null;
  const requestedRole = normalizeRole(req.body.role);

  let target = req.user;
  const requestedTargetId = sanitizeString(req.body.userId || "", 80);
  if (requestedTargetId) {
    target = findUserById(requestedTargetId);
    if (!target || (!canManageUser(req.user, target) && target.id !== req.user.id)) {
      return res.status(403).json({ success: false, message: "You cannot create a referral for this account." });
    }
  }

  if (target.role === ROLE.OWNER && req.user.role !== ROLE.OWNER) {
    return res.status(403).json({ success: false, message: "Permission denied." });
  }

  if (target.role === ROLE.RESELLER) {
    return res.status(403).json({ success: false, message: "Resellers cannot create referral codes." });
  }

  let role = requestedRole;
  if (target.role === ROLE.ADMIN) role = ROLE.RESELLER;
  if (target.role === ROLE.OWNER && ![ROLE.OWNER, ROLE.ADMIN, ROLE.RESELLER].includes(role)) {
    role = ROLE.RESELLER;
  }

  if (req.user.role === ROLE.ADMIN && role !== ROLE.RESELLER) {
    return res.status(403).json({ success: false, message: "Admins can create only Reseller referral codes." });
  }

  if (req.user.role !== ROLE.OWNER && (!Number.isFinite(startingBalance) || startingBalance < 3000 || startingBalance > 50000)) {
    return res.status(400).json({ success: false, message: "Starting balance must be between ₹3,000 and ₹50,000." });
  }
  if (req.user.role === ROLE.OWNER && (!Number.isFinite(startingBalance) || startingBalance < 0)) {
    return res.status(400).json({ success: false, message: "Invalid starting balance." });
  }
  if (expiresAt && !Number.isFinite(Date.parse(expiresAt))) {
    return res.status(400).json({ success: false, message: "Invalid expiry date." });
  }

  let code = "";
  do {
    code = normalizeCode(`LEXI-${crypto.randomBytes(5).toString("hex").toUpperCase()}`);
  } while (db.referrals.some(r => normalizeCode(r.code) === code));

  const referral = {
    id: randomId("ref"),
    code,
    creatorId: target.id,
    role,
    startingBalance,
    usageLimit,
    usedCount: 0,
    status: STATUS.ACTIVE,
    expiresAt,
    createdAt: now()
  };

  db.referrals.push(referral);
  audit(req.user, "CREATE_REFERRAL", "referral", referral.id, {
    ip: clientIp(req),
    details: {
      code,
      targetId: target.id,
      role,
      startingBalance,
      usageLimit: 0,
      expiresAt
    }
  });
  save();

  res.status(201).json({ success: true, referral });
});

app.get("/api/referrals", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const requestedUserId = sanitizeString(req.query.userId || "", 80);
  if (requestedUserId) {
    const target = findUserById(requestedUserId);
    if (!target || !canViewUser(req.user, target)) return res.status(404).json({ success: false, message: "User not found or permission denied." });
  }
  const rows = db.referrals.filter(r => {
    if (requestedUserId) return r.creatorId === requestedUserId;
    return req.user.role === ROLE.OWNER ? true : r.creatorId === req.user.id;
  });

  res.json({
    success: true,
    referrals: rows.map(r => ({
      ...r,
      creatorUsername: findUserById(r.creatorId)?.username || null
    }))
  });
});

app.get("/api/referrals/:id", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id);
  if (!referral) return res.status(404).json({ success: false, message: "Referral not found." });
  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) {
    return res.status(403).json({ success: false, message: "Permission denied." });
  }
  res.json({ success: true, referral: { ...referral, creatorUsername: findUserById(referral.creatorId)?.username || null } });
});

app.post("/api/referrals/:id/toggle", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id);
  if (!referral) return res.status(404).json({ success: false, message: "Referral not found." });

  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) {
    return res.status(403).json({ success: false, message: "Permission denied." });
  }

  referral.status = referral.status === STATUS.ACTIVE ? STATUS.BLOCKED : STATUS.ACTIVE;
  audit(req.user, "TOGGLE_REFERRAL", "referral", referral.id, {
    ip: clientIp(req),
    details: { status: referral.status }
  });
  save();

  res.json({ success: true, referral });
});

app.delete("/api/referrals/:id", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const referral = db.referrals.find(r => r.id === req.params.id);
  if (!referral) return res.status(404).json({ success:false, message:"Referral not found." });
  if (req.user.role !== ROLE.OWNER && referral.creatorId !== req.user.id) return res.status(403).json({ success:false, message:"Permission denied." });
  referral.status = STATUS.DELETED;
  audit(req.user, "DELETE_REFERRAL", "referral", referral.id, { ip: clientIp(req) });
  save();
  res.json({ success:true, message:"Referral deleted successfully." });
});

/* ---------- Users ---------- */

app.get("/api/users", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const q = sanitizeString(req.query.search, 80).toLowerCase();
  const role = String(req.query.role || "all").toLowerCase();
  const status = String(req.query.status || "all").toLowerCase();

  let rows = db.users.filter(u => canViewUser(req.user, u));

  if (q) {
    rows = rows.filter(u =>
      u.username.toLowerCase().includes(q) ||
      u.id.toLowerCase().includes(q)
    );
  }

  if (role !== "all") rows = rows.filter(u => u.role === role);
  if (status !== "all") rows = rows.filter(u => u.status === status);

  res.json({
    success: true,
    users: rows.map(publicUser),
    total: rows.length
  });
});

app.get("/api/users/:id", auth, (req, res) => {
  const target = findUserById(req.params.id);
  if (!target || !canViewUser(req.user, target)) {
    return res.status(404).json({ success: false, message: "User not found." });
  }

  const keys = db.keys
    .filter(k => k.creatorId === target.id)
    .map(publicKey);

  res.json({
    success: true,
    user: publicUser(target),
    keys
  });
});

app.post("/api/users/create", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const role = normalizeRole(req.body.role);
  const balance = Number(req.body.balance ?? 0);

  if (!validUsername(username) || !validPassword(password)) {
    return res.status(400).json({ success: false, message: "Invalid username or password." });
  }

  if (findUserByUsername(username)) {
    return res.status(409).json({ success: false, message: "Username already exists." });
  }

  if (!Number.isFinite(balance) || balance < 0) {
    return res.status(400).json({ success: false, message: "Invalid balance." });
  }

  if (req.user.role === ROLE.ADMIN && role !== ROLE.RESELLER) {
    return res.status(403).json({
      success: false,
      message: "Admins can create only Reseller users."
    });
  }

  const user = {
    id: randomId("usr"),
    username,
    passwordHash: hashPassword(password),
    role: req.user.role === ROLE.ADMIN ? ROLE.RESELLER : role,
    status: STATUS.ACTIVE,
    parentId: req.user.id,
    balance,
    resetAttempts: 0,
    resetWindowStartedAt: now(),
    passwordResetAttempts: 0,
    passwordResetWindowStartedAt: now(),
    createdAt: now(),
    lastLoginAt: null,
    registeredIp: null
  };

  db.users.push(user);

  if (balance > 0) {
    transaction(req.user, "USER_BALANCE_ASSIGNMENT", balance, 0, balance, user.id, {});
  }

  audit(req.user, "CREATE_USER", "user", user.id, {
    ip: clientIp(req),
    details: { role: user.role, balance }
  });
  save();

  res.status(201).json({
    success: true,
    message: "User created successfully.",
    user: publicUser(user)
  });
});

app.post("/api/users/:id/balance", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const target = findUserById(req.params.id);
  const amount = Number(req.body.amount);
  const mode = String(req.body.mode || "set").toLowerCase();

  if (!target || !canManageUser(req.user, target)) {
    return res.status(404).json({ success: false, message: "User not found or permission denied." });
  }

  if (target.role === ROLE.OWNER) {
    return res.status(403).json({ success: false, message: "Owner balance cannot be modified through this endpoint." });
  }

  if (!Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ success: false, message: "Invalid amount." });
  }

  const before = Number(target.balance || 0);
  let after;

  if (mode === "add") after = before + amount;
  else if (mode === "subtract") {
    after = before - amount;
    if (after < 0) {
      return res.status(400).json({ success: false, message: "Balance cannot become negative." });
    }
  } else if (mode === "set") after = amount;
  else {
    return res.status(400).json({ success: false, message: "Mode must be add, subtract or set." });
  }

  target.balance = Number(after.toFixed(2));

  transaction(req.user, "BALANCE_CHANGE", after - before, before, after, target.id, { mode });
  audit(req.user, "CHANGE_BALANCE", "user", target.id, {
    ip: clientIp(req),
    details: { mode, amount, before, after }
  });
  save();

  res.json({ success: true, user: publicUser(target) });
});

app.post("/api/users/:id/status", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const target = findUserById(req.params.id);
  if (!target || !canManageUser(req.user, target)) {
    return res.status(404).json({ success: false, message: "User not found or permission denied." });
  }

  const status = String(req.body.status || "").toLowerCase();
  if (![STATUS.ACTIVE, STATUS.BLOCKED, STATUS.DELETED].includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid status." });
  }

  if (target.role === ROLE.OWNER) {
    return res.status(403).json({ success: false, message: "Owner cannot be changed by this endpoint." });
  }

  target.status = status;

  if (status !== STATUS.ACTIVE) {
    db.sessions = db.sessions.filter(s => s.userId !== target.id);
  }

  audit(req.user, "CHANGE_USER_STATUS", "user", target.id, {
    ip: clientIp(req),
    details: { status }
  });
  save();

  res.json({ success: true, user: publicUser(target) });
});

app.delete("/api/users/:id", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN), (req, res) => {
  const target = findUserById(req.params.id);
  if (!target || !canManageUser(req.user, target)) return res.status(404).json({ success: false, message: "User not found or permission denied." });
  if (target.role === ROLE.OWNER) return res.status(403).json({ success: false, message: "Owner cannot be deleted here." });
  target.status = STATUS.DELETED;
  db.sessions = db.sessions.filter(x => x.userId !== target.id);
  audit(req.user, "DELETE_USER", "user", target.id, { ip: clientIp(req), details: { username: target.username } });
  save();
  res.json({ success: true, message: "User deleted." });
});

app.post("/api/users/:id/impersonate", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const target = findUserById(req.params.id);
  if (!target || target.id === req.user.id) {
    return res.status(404).json({ success: false, message: "User not found." });
  }

  if (target.status !== STATUS.ACTIVE) {
    return res.status(403).json({ success: false, message: "Target account is not active." });
  }

  /*
   * Owner receives a separate short-lived support session.
   * The original owner session remains valid and is not replaced.
   */
  const token = createSession(target, req, false, true);
  setSessionCookie(res, token, DEFAULT_SESSION_TIMEOUT_MS);

  audit(req.user, "OWNER_ENTER_USER_PANEL", "user", target.id, {
    ip: clientIp(req),
    details: { supportSession: true }
  });
  save();

  res.json({
    success: true,
    token,
    user: publicUser(target),
    supportSession: true,
    expiresInHours: 24
  });
});

/* ---------- Keys ---------- */

app.get("/api/keys", auth, (req, res) => {
  const q = sanitizeString(req.query.search, 120).toLowerCase();
  const status = String(req.query.status || "all").toLowerCase();
  const scope = getCreatorKeyScope(req.user);

  let rows = db.keys.filter(scope);

  if (q) {
    rows = rows.filter(k => {
      const devices = db.devices.filter(d => d.keyId === k.id);
      return (
        k.key.toLowerCase().includes(q) ||
        k.id.toLowerCase().includes(q) ||
        devices.some(d => String(d.hwid || "").toLowerCase().includes(q))
      );
    });
  }

  if (status !== "all") {
    rows = rows.filter(k => keyStatus(k) === status);
  }

  res.json({
    success: true,
    keys: rows.map(publicKey),
    total: rows.length
  });
});

app.get("/api/keys/:id", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id);
  if (!key || !canManageKey(req.user, key)) {
    return res.status(404).json({ success: false, message: "Key not found." });
  }

  res.json({ success: true, key: publicKey(key) });
});

app.post("/api/keys/generate", auth, (req, res) => {
  const duration = String(req.body.duration || "").toLowerCase();
  const deviceLimit = Number(req.body.deviceLimit ?? 1);
  const quantity = Number(req.body.quantity ?? 1);
  const customKey = sanitizeString(req.body.customKey || "", 100);
  const gamePackage = sanitizeString(req.body.gamePackage || "", 150);

  if (customKey && ![ROLE.OWNER, ROLE.ADMIN].includes(req.user.role)) {
    return res.status(403).json({ success: false, message: "Custom key is available only to Owner/Admin." });
  }
  if (customKey && quantity !== 1) {
    return res.status(400).json({ success: false, message: "Custom key can generate only 1 key at a time." });
  }
  if (customKey && !/^[a-zA-Z0-9_-]{1,100}$/.test(customKey)) {
    return res.status(400).json({ success: false, message: "Custom key may contain only letters, numbers, hyphen and underscore." });
  }
  const customPrice = req.body.customPrice === undefined || req.body.customPrice === null
    ? null
    : Number(req.body.customPrice);

  if (!db.pricing[duration] && ![ROLE.OWNER, ROLE.ADMIN].includes(req.user.role)) {
    return res.status(400).json({ success: false, message: "Invalid duration." });
  }

  if (!Number.isInteger(deviceLimit) || deviceLimit < 1 || (req.user.role !== ROLE.OWNER && deviceLimit > MAX_DEVICE_LIMIT)) {
    return res.status(400).json({ success: false, message: `Device limit must be 1-${MAX_DEVICE_LIMIT}.` });
  }

  if (!Number.isInteger(quantity) || quantity < 1 || (req.user.role !== ROLE.OWNER && quantity > MAX_KEY_QUANTITY)) {
    return res.status(400).json({ success: false, message: `Key count must be 1-${MAX_KEY_QUANTITY}.` });
  }

  let durationHours = null;
  let durationLabel = "Custom";
  let basePrice = 0;

  if (db.pricing[duration]) {
    durationHours = Number(db.pricing[duration].hours);
    durationLabel = db.pricing[duration].label;
    basePrice = Number(db.pricing[duration].price);
  } else {
    if (![ROLE.OWNER, ROLE.ADMIN].includes(req.user.role)) {
      return res.status(403).json({ success: false, message: "Custom duration is available only to Owner/Admin." });
    }
    durationHours = Number(req.body.customHours);
    durationLabel = sanitizeString(req.body.customLabel || `${durationHours} Hours`, 50);
    basePrice = req.user.role === ROLE.OWNER ? (customPrice === null ? 0 : customPrice) : 0;

    if (!Number.isFinite(durationHours) || durationHours <= 0 || (req.user.role !== ROLE.OWNER && durationHours > 87600)) {
      return res.status(400).json({ success: false, message: "Invalid custom duration." });
    }
    if (!Number.isFinite(basePrice) || basePrice < 0) {
      return res.status(400).json({ success: false, message: "Invalid custom price." });
    }
  }

  if (req.user.role === ROLE.ADMIN && customPrice !== null) {
    return res.status(400).json({ success: false, message: "Custom price is not available in Admin panel." });
  }

  const totalPrice = Number((basePrice * quantity).toFixed(2));
  const beforeBalance = Number(req.user.balance || 0);

  /* Owner is unlimited; all other roles must have enough balance. */
  if (req.user.role !== ROLE.OWNER && beforeBalance < totalPrice) {
    return res.status(402).json({
      success: false,
      code: "INSUFFICIENT_BALANCE",
      message: "Insufficient balance for key generation.",
      required: totalPrice,
      available: beforeBalance,
      shortfall: Number((totalPrice - beforeBalance).toFixed(2))
    });
  }

  /*
   * All checks happen before mutating keys.
   * This prevents partial generation if balance is insufficient.
   */
  const batchId = randomId("batch");
  const createdAt = Date.now();

  const generated = [];

  for (let i = 0; i < quantity; i++) {
    const key = {
      id: randomId("key"),
      key: customKey || ensureUniqueKey("LexiLoader", duration, durationLabel),
      creatorId: req.user.id,
      batchId,
      duration,
      durationHours,
      durationLabel,
      basePrice,
      deviceLimit,
      gamePackage,
      status: KEY_STATUS.ACTIVE,
      createdAt: new Date(createdAt).toISOString(),
      startedAt: null,
      expiryAt: null,
      ipLock: db.settings.ipGeoLockEnabled && req.body.ipLock ? sanitizeString(req.body.ipLock, 100) : null,
      geoLock: db.settings.ipGeoLockEnabled && req.body.geoLock ? sanitizeString(req.body.geoLock, 100) : null,
      deletedAt: null
    };

    db.keys.push(key);
    generated.push(publicKey(key));
  }

  if (req.user.role !== ROLE.OWNER && totalPrice > 0) {
    const afterBalance = Number((beforeBalance - totalPrice).toFixed(2));
    req.user.balance = afterBalance;

    transaction(req.user, "KEY_GENERATION", -totalPrice, beforeBalance, afterBalance, req.user.id, {
      batchId,
      quantity,
      duration,
      deviceLimit,
      unitPrice: basePrice
    });
  }

  audit(req.user, "GENERATE_KEYS", "batch", batchId, {
    ip: clientIp(req),
    details: {
      quantity,
      duration,
      deviceLimit,
      totalPrice,
      ownerUnlimited: req.user.role === ROLE.OWNER
    }
  });

  save();

  res.status(201).json({
    success: true,
    message: `${quantity} key(s) generated successfully.`,
    batchId,
    pricing: {
      unitPrice: basePrice,
      quantity,
      totalPrice,
      balanceBefore: beforeBalance,
      balanceAfter: req.user.role === ROLE.OWNER ? beforeBalance : req.user.balance
    },
    keys: generated
  });
});

app.post("/api/keys/:id/update", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id);
  if (!key || !canManageKey(req.user, key)) return res.status(404).json({ success:false, message:"Key not found or permission denied." });
  const nextKey = sanitizeString(req.body.key || key.key, 100).trim();
  if (!nextKey || !/^[A-Za-z0-9_-]+$/.test(nextKey)) return res.status(400).json({success:false,message:"License key may contain only letters, numbers, hyphen and underscore."});
  if (db.keys.some(k => k.id !== key.id && k.key === nextKey)) return res.status(409).json({success:false,message:"License key already exists."});
  const deviceLimit = Number(req.body.deviceLimit ?? key.deviceLimit);
  if (!Number.isInteger(deviceLimit) || deviceLimit < 1 || deviceLimit > 9999) return res.status(400).json({success:false,message:"Invalid device limit."});
  const status = String(req.body.status || key.status || "active").toLowerCase();
  if (![KEY_STATUS.ACTIVE, KEY_STATUS.BLOCKED, KEY_STATUS.DELETED].includes(status)) return res.status(400).json({success:false,message:"Invalid key status."});
  key.key=nextKey; key.deviceLimit=deviceLimit; key.gamePackage=sanitizeString(req.body.gamePackage ?? key.gamePackage ?? "",200); key.ipLock=sanitizeString(req.body.ipLock ?? key.ipLock ?? "",120); key.geoLock=sanitizeString(req.body.geoLock ?? key.geoLock ?? "",120); key.status=status;
  audit(req.user,"UPDATE_KEY","key",key.id,{ip:clientIp(req),details:{key:key.key,deviceLimit:key.deviceLimit,status:key.status}}); save();
  res.json({success:true,message:"Key updated successfully.",key:publicKey(key)});
});

app.post("/api/keys/:id/reset", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id);
  if (!key || !canManageKey(req.user, key)) {
    return res.status(404).json({ success: false, message: "Key not found or permission denied." });
  }

  const before = db.devices.length;
  db.devices = db.devices.filter(d => d.keyId !== key.id);
  const removed = before - db.devices.length;

  audit(req.user, "RESET_KEY_DEVICES", "key", key.id, {
    ip: clientIp(req),
    details: { removedDevices: removed }
  });
  save();

  res.json({
    success: true,
    message: "Key device bindings reset.",
    removedDevices: removed,
    key: publicKey(key)
  });
});

app.post("/api/keys/:id/status", auth, (req, res) => {
  const key = db.keys.find(k => k.id === req.params.id);
  if (!key || !canManageKey(req.user, key)) {
    return res.status(404).json({ success: false, message: "Key not found or permission denied." });
  }

  const status = String(req.body.status || "").toLowerCase();

  if (![KEY_STATUS.ACTIVE, KEY_STATUS.BLOCKED, KEY_STATUS.DELETED].includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid key status." });
  }

  if (status === KEY_STATUS.ACTIVE && keyStatus(key) === KEY_STATUS.EXPIRED) {
    return res.status(400).json({ success: false, message: "Expired key cannot be reactivated." });
  }

  key.status = status;
  key.deletedAt = status === KEY_STATUS.DELETED ? now() : null;

  if (status === KEY_STATUS.DELETED) {
    db.devices = db.devices.filter(d => d.keyId !== key.id);
  }

  audit(req.user, "CHANGE_KEY_STATUS", "key", key.id, {
    ip: clientIp(req),
    details: { status }
  });
  save();

  res.json({ success: true, key: publicKey(key) });
});

/* ---------- Loader ---------- */

app.get("/api/loader/config", (req, res) => {
  res.json({
    success: true,
    loader: {
      enabled: Boolean(db.settings.loaderStatus) && db.settings.systemOnline !== false,
      systemOnline: db.settings.systemOnline !== false,
      maintenanceMessage: db.settings.maintenanceMsg,
      panelName: db.settings.panelName,
      appNoticeEnabled: Boolean(db.settings.appNoticeEnabled),
      appNotice: db.settings.appNotice || "",
      appNoticeType: db.settings.appNoticeType || "info"
    },
    pricing: db.pricing
  });
});

app.post("/api/owner/loader-settings", auth, requireRoles(ROLE.OWNER), (req, res) => {
  if (req.body.loaderStatus !== undefined) {
    db.settings.loaderStatus = Boolean(req.body.loaderStatus);
  }

  if (req.body.maintenanceMsg !== undefined) {
    db.settings.maintenanceMsg = sanitizeString(req.body.maintenanceMsg, 1000);
  }

  if (req.body.panelName !== undefined) {
    db.settings.panelName = sanitizeString(req.body.panelName, 100);
  }

  if (req.body.ipGeoLockEnabled !== undefined) {
    db.settings.ipGeoLockEnabled = Boolean(req.body.ipGeoLockEnabled);
  }

  audit(req.user, "UPDATE_LOADER_SETTINGS", "settings", "global", {
    ip: clientIp(req),
    details: {
      loaderStatus: db.settings.loaderStatus,
      ipGeoLockEnabled: db.settings.ipGeoLockEnabled
    }
  });
  save();

  res.json({
    success: true,
    settings: {
      loaderStatus: db.settings.loaderStatus,
      maintenanceMsg: db.settings.maintenanceMsg,
      panelName: db.settings.panelName,
      ipGeoLockEnabled: db.settings.ipGeoLockEnabled
    }
  });
});

app.post("/api/loader/verify", (req, res) => {
  const licenseKey = sanitizeString(req.body.key, 150);
  const hwid = sanitizeString(req.body.hwid, 300);
  const deviceName = sanitizeString(req.body.deviceName, 150);
  const ip = clientIp(req);

  if (!db.settings.loaderStatus || db.settings.systemOnline === false) {
    return res.status(503).json({
      success: false,
      code: "LOADER_DISABLED",
      message: db.settings.maintenanceMsg
    });
  }

  if (!licenseKey || !hwid) {
    return res.status(400).json({
      success: false,
      code: "INVALID_REQUEST",
      message: "License key and HWID are required."
    });
  }

  const key = db.keys.find(k => k.key === licenseKey);
  if (!key || key.status === KEY_STATUS.DELETED) {
    return res.status(404).json({
      success: false,
      code: "KEY_NOT_FOUND",
      message: "License key not found."
    });
  }

  const status = keyStatus(key);

  if (status === KEY_STATUS.BLOCKED) {
    return res.status(403).json({ success: false, code: "KEY_BLOCKED", message: "License key is blocked." });
  }

  if (status === KEY_STATUS.EXPIRED) {
    return res.status(403).json({ success: false, code: "KEY_EXPIRED", message: "License key has expired." });
  }

  if (key.ipLock && key.ipLock !== ip) {
    return res.status(403).json({ success: false, code: "IP_LOCKED", message: "IP does not match this license." });
  }

  if (key.geoLock) {
    /*
     * Geo-lock requires a trusted geo service or proxy header in production.
     * This backend stores the lock but does not pretend to know a country
     * from an untrusted client header.
     */
    const country = String(req.headers["x-country-code"] || "").toUpperCase();
    if (!country || country !== String(key.geoLock).toUpperCase()) {
      return res.status(403).json({ success: false, code: "GEO_LOCKED", message: "Location does not match this license." });
    }
  }

  const devices = db.devices.filter(d => d.keyId === key.id);
  let device = devices.find(d => safeEqual(d.hwid, hwid));
  const firstActivation = !key.startedAt;

  if (!device) {
    if (devices.length >= Number(key.deviceLimit || 1)) {
      return res.status(403).json({
        success: false,
        code: "DEVICE_LIMIT_REACHED",
        message: "Device limit reached. Reset the key bindings before using another device."
      });
    }

    /* Timer starts only after this verification passes all checks. */
    if (firstActivation) {
      const startedMs = Date.now();
      key.startedAt = new Date(startedMs).toISOString();
      key.expiryAt = new Date(startedMs + Number(key.durationHours || 0) * 60 * 60 * 1000).toISOString();
    }

    device = {
      id: randomId("dev"),
      keyId: key.id,
      hwid,
      deviceName,
      ip,
      firstSeenAt: now(),
      lastSeenAt: now()
    };
    db.devices.push(device);
  } else {
    if (firstActivation) {
      const startedMs = Date.now();
      key.startedAt = new Date(startedMs).toISOString();
      key.expiryAt = new Date(startedMs + Number(key.durationHours || 0) * 60 * 60 * 1000).toISOString();
    }
    device.lastSeenAt = now();
    device.ip = ip;
    if (deviceName) device.deviceName = deviceName;
  }

  audit(null, "LOADER_VERIFY", "key", key.id, {
    ip,
    details: {
      hwid: hwid.slice(0, 12),
      deviceName,
      devicesUsed: db.devices.filter(d => d.keyId === key.id).length
    }
  });

  save();

  res.json({
    success: true,
    code: "VERIFIED",
    license: {
      key: key.key,
      startedAt: key.startedAt || null,
      expiryAt: key.expiryAt || null,
      durationHours: Number(key.durationHours || 0),
      deviceLimit: key.deviceLimit,
      devicesUsed: db.devices.filter(d => d.keyId === key.id).length
    },
    loader: {
      name: db.settings.panelName,
      enabled: true
    }
  });
});

/* ---------- Dashboard ---------- */

app.get("/api/dashboard", auth, (req, res) => {
  const scope = getCreatorKeyScope(req.user);
  const visibleKeys = db.keys.filter(scope);
  const visibleUsers = db.users.filter(u => canViewUser(req.user, u));

  const counts = {
    activeKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.ACTIVE).length,
    expiredKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.EXPIRED).length,
    blockedKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.BLOCKED).length,
    deletedKeys: visibleKeys.filter(k => keyStatus(k) === KEY_STATUS.DELETED).length,
    users: visibleUsers.length,
    admins: visibleUsers.filter(u => u.role === ROLE.ADMIN).length,
    resellers: visibleUsers.filter(u => u.role === ROLE.RESELLER).length
  };

  const ownTransactions = db.transactions.filter(t =>
    req.user.role === ROLE.OWNER
      ? true
      : t.actorId === req.user.id || t.targetUserId === req.user.id
  );

  res.json({
    success: true,
    user: publicUser(req.user),
    stats: {
      ...counts,
      balance: Number(req.user.balance || 0),
      totalVisibleBalance: visibleUsers.reduce((sum, u) => sum + Number(u.balance || 0), 0),
      referrals: db.referrals.filter(r => req.user.role === ROLE.OWNER || r.creatorId === req.user.id).length,
      transactions: ownTransactions.length
    },
    settings: {
      loaderStatus: db.settings.loaderStatus,
      maintenanceMsg: db.settings.maintenanceMsg,
      panelName: db.settings.panelName,
      ipGeoLockEnabled: db.settings.ipGeoLockEnabled
    }
  });
});

/* ---------- Owner-only audit/transactions ---------- */

app.get("/api/activity", auth, (req, res) => {
  let rows;
  if (req.user.role === ROLE.OWNER) {
    rows = [...db.auditLogs];
  } else {
    const visible = new Set(db.users.filter(u => u.id === req.user.id || (u.parentId === req.user.id && u.role === ROLE.RESELLER)).map(u => u.id));
    rows = db.auditLogs.filter(x => visible.has(x.actorId) || visible.has(x.targetId));
  }
  rows = rows.reverse().slice(0, 1000);
  res.json({ success: true, logs: rows });
});

app.get("/api/audit-logs", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const q = sanitizeString(req.query.search, 100).toLowerCase();
  let rows = [...db.auditLogs].reverse();

  if (q) {
    rows = rows.filter(x =>
      String(x.actorUsername).toLowerCase().includes(q) ||
      String(x.action).toLowerCase().includes(q) ||
      String(x.targetId || "").toLowerCase().includes(q)
    );
  }

  res.json({ success: true, logs: rows.slice(0, 1000) });
});

app.get("/api/transactions", auth, (req, res) => {
  let rows;
  if (req.user.role === ROLE.OWNER) {
    rows = [...db.transactions];
  } else {
    const visibleUsers = new Set(db.users.filter(u => u.id === req.user.id || (u.parentId === req.user.id && u.role === ROLE.RESELLER)).map(u => u.id));
    rows = db.transactions.filter(t => visibleUsers.has(t.actorId) || visibleUsers.has(t.targetUserId));
  }
  rows = rows.reverse().slice(0, 1000);
  res.json({ success: true, transactions: rows });
});


/* ---------- Settings / Pricing compatibility API ---------- */
app.get("/api/settings", auth, (req, res) => {
  if (req.user.role === ROLE.OWNER) return res.json({ success: true, settings: db.settings, role: req.user.role });
  res.json({ success: true, settings: { username: req.user.username, usernameChangeCount: Number(req.user.usernameChangeCount || 0), usernameChangeRemaining: req.user.role === ROLE.OWNER ? null : Math.max(0, 1 - Number(req.user.usernameChangeCount || 0)), passwordResetAttempts: Number(req.user.passwordResetAttempts || 0), passwordResetRemaining: req.user.role === ROLE.OWNER ? null : Math.max(0, MAX_RESET_ATTEMPTS - Number(req.user.passwordResetAttempts || 0)), passwordResetWindow: req.user.role === ROLE.OWNER ? "unlimited" : resetWindowLabel(req.user.role), theme: "local" }, role: req.user.role });
});

app.post("/api/profile/update", auth, (req, res) => {
  const username = normalizeUsername(req.body.username);
  if (!validUsername(username)) return res.status(400).json({ success: false, message: "Invalid username." });
  if (username !== req.user.username) {
    if (Number(req.user.usernameChangeCount || 0) >= 1) return res.status(429).json({ success: false, message: "Username can be changed only once." });
    if (findUserByUsername(username)) return res.status(409).json({ success: false, message: "Username already exists." });
    req.user.username = username;
    req.user.usernameChangeCount = Number(req.user.usernameChangeCount || 0) + 1;
    audit(req.user, "USERNAME_CHANGED", "user", req.user.id, { ip: clientIp(req), details: { username } });
    save();
  }
  res.json({ success: true, user: publicUser(req.user), usernameChangeRemaining: Math.max(0, 1 - Number(req.user.usernameChangeCount || 0)) });
});

app.post("/api/settings/update", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const allowed = [
    "panelName", "panelVersion", "supportLink", "sessionTimeoutHours",
    "resetLimit", "resetWindowHours", "ipGeoLockEnabled", "systemOnline", "onlineMessage", "appNotice", "appNoticeType", "appNoticeEnabled"
  ];
  for (const field of allowed) {
    if (req.body[field] === undefined) continue;
    if (["sessionTimeoutHours", "resetLimit", "resetWindowHours"].includes(field)) {
      const n = Number(req.body[field]);
      if (!Number.isFinite(n) || n <= 0) {
        return res.status(400).json({ success: false, message: `Invalid ${field}.` });
      }
      if (field === "sessionTimeoutHours" && ![24, 168].includes(Math.floor(n))) {
        return res.status(400).json({ success: false, message: "Session timeout must be 1 Day or 7 Days." });
      }
      db.settings[field] = Math.floor(n);
    } else if (["ipGeoLockEnabled", "systemOnline", "appNoticeEnabled"].includes(field)) {
      db.settings[field] = Boolean(req.body[field]);
    } else {
      db.settings[field] = sanitizeString(req.body[field], field === "supportLink" ? 500 : 150);
    }
  }
  audit(req.user, "UPDATE_SETTINGS", "settings", "global", {
    ip: clientIp(req), details: { fields: allowed.filter(x => req.body[x] !== undefined) }
  });
  save();
  res.json({ success: true, settings: db.settings });
});

app.post("/api/settings/loader", auth, requireRoles(ROLE.OWNER), (req, res) => {
  if (req.body.enabled !== undefined) db.settings.loaderStatus = Boolean(req.body.enabled);
  if (req.body.message !== undefined) db.settings.maintenanceMsg = sanitizeString(req.body.message, 1000);
  if (req.body.loaderStatus !== undefined) db.settings.loaderStatus = Boolean(req.body.loaderStatus);
  if (req.body.maintenanceMsg !== undefined) db.settings.maintenanceMsg = sanitizeString(req.body.maintenanceMsg, 1000);
  audit(req.user, "UPDATE_LOADER_SETTINGS", "settings", "global", {
    ip: clientIp(req), details: { loaderStatus: db.settings.loaderStatus }
  });
  save();
  res.json({ success: true, settings: db.settings });
});

app.get("/api/pricing", auth, requireRoles(ROLE.OWNER, ROLE.ADMIN, ROLE.RESELLER), (req, res) => {
  res.json({ success: true, pricing: db.pricing });
});

app.post("/api/pricing/update", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const incoming = req.body.pricing;
  if (!incoming || typeof incoming !== "object" || Array.isArray(incoming)) {
    return res.status(400).json({ success: false, message: "Invalid pricing object." });
  }
  const next = {};
  for (const key of Object.keys(PRICING)) {
    const row = incoming[key];
    if (!row) return res.status(400).json({ success: false, message: `Missing pricing plan ${key}.` });
    const hours = Number(row.hours);
    const price = Number(row.price);
    const label = sanitizeString(row.label || key, 60);
    if (!Number.isFinite(hours) || hours <= 0 || !Number.isFinite(price) || price < 0) {
      return res.status(400).json({ success: false, message: `Invalid pricing plan ${key}.` });
    }
    next[key] = { label, hours, price: Number(price.toFixed(2)) };
  }
  db.pricing = next;
  audit(req.user, "UPDATE_PRICING", "pricing", "global", { ip: clientIp(req), details: next });
  save();
  res.json({ success: true, pricing: db.pricing });
});

/* Owner enters another panel through a separate support session. */
app.post("/api/owner/enter-user/:id", auth, requireRoles(ROLE.OWNER), (req, res) => {
  const target = findUserById(req.params.id);
  if (!target || target.id === req.user.id) {
    return res.status(404).json({ success: false, message: "User not found." });
  }
  if (target.status !== STATUS.ACTIVE) {
    return res.status(403).json({ success: false, message: "Target account is not active." });
  }
  const token = createSession(target, req, false, true);
  audit(req.user, "OWNER_ENTER_USER_PANEL", "user", target.id, {
    ip: clientIp(req), details: { supportSession: true }
  });
  save();
  res.json({ success: true, token, user: publicUser(target), supportSession: true });
});

/* ---------- Web panel ---------- */
const PANEL_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Lexi Loader Panel</title>
<style>
:root{--bg:#07152f;--panel:#0d2144;--panel2:#102b55;--line:#21446f;--text:#f5f8ff;--muted:#9fb3d1;--accent:#f4cf70;--danger:#ef4b55;--ok:#20b96b;--blue:#1677ff;--sidebar:250px;--shadow:0 18px 50px rgba(0,0,0,.34)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px Inter,Arial,sans-serif}button,input,select,textarea{font:inherit}button{cursor:pointer}.hidden{display:none!important}#app{min-height:100vh}.brand{font-size:22px;font-weight:800}.brand span{color:var(--accent)}.muted,small{color:var(--muted)}
.app-shell{min-height:100vh}.sidebar{position:fixed;left:0;top:0;bottom:0;width:var(--sidebar);background:#0f131b;border-right:1px solid var(--line);padding:20px 14px;z-index:50;display:flex;flex-direction:column}.side-user{padding:15px 12px;margin:18px 0 12px;background:var(--panel);border:1px solid var(--line);border-radius:12px}.side-nav{display:grid;gap:6px}.navbtn{width:100%;text-align:left;background:transparent;color:#cfd5df;border:1px solid transparent;border-radius:9px;padding:11px 12px}.navbtn:hover,.navbtn.active{background:#1a202c;border-color:var(--line);color:#fff}.side-bottom{margin-top:auto;display:grid;gap:7px}.main{margin-left:var(--sidebar);min-height:100vh}.topbar{height:72px;padding:0 24px;border-bottom:1px solid var(--line);background:rgba(11,14,20,.94);backdrop-filter:blur(10px);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:30}.side-overlay{display:none}.mobile-menu{display:none}.layout{max-width:1450px;margin:auto;padding:24px}.page-head{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:20px}.page-head h1{margin:0 0 5px;font-size:28px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.grid2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:var(--shadow)}.stat .label{color:var(--muted)}.stat b{display:block;font-size:29px;margin-top:9px}.toolbar{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:9px;margin-bottom:14px}.table-wrap{overflow:auto}.table{width:100%;border-collapse:collapse;min-width:920px}.table th,.table td{padding:12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.table th{color:#aeb7c7}.status-active{color:#68cf98;font-weight:700}.status-blocked{color:#e66c74;font-weight:700}.bracket{background:#fff;color:#111;border:1px solid #d7dbe2;border-radius:9px;padding:11px}.list-box{display:grid;margin-top:5px}.list-box button{padding:10px;text-align:left;border:1px solid var(--line);background:var(--panel2);color:var(--text)}.badge{display:inline-block;padding:4px 9px;border-radius:99px;background:#29303b;font-size:12px}.badge.ok{color:#a9ebc6}.badge.bad{color:#ffb7bd}.actions{display:flex;flex-wrap:wrap;gap:6px}.primary,.action,.danger{padding:10px 14px;border-radius:9px;border:1px solid transparent}.primary{background:var(--accent);color:#151515;font-weight:750}.golden-btn{background:#f4cf70!important;color:#151515!important;border:1px solid #d7b24a!important;box-shadow:0 2px 0 rgba(215,178,74,.55),0 5px 14px rgba(0,0,0,.16);font-weight:750}.generate-btn{padding:10px 14px;border-radius:9px;border:1px solid #d7b24a!important;background:#18a968!important;color:#fff!important;box-shadow:0 2px 0 rgba(215,178,74,.55),0 5px 14px rgba(0,0,0,.18);font-weight:750;line-height:1.2;min-height:39px;display:inline-flex;align-items:center;justify-content:center}.manage-btn{background:#f4cf70!important;color:#151515!important;border-color:#f4cf70!important;font-weight:750}.modal-actions{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap}.action{background:#18345f;color:#fff;border-color:#2b5688}.danger{background:#d92f3b;color:#fff;border-color:#d92f3b;font-weight:750}.block-btn{background:#d92f3b!important;color:#fff!important;border-color:#d92f3b!important}.unblock-btn{background:#18a968!important;color:#fff!important;border-color:#18a968!important}.full{width:100%}.settings-actions{gap:16px;margin-top:2px;align-items:center}.owner-security-actions{display:flex;align-items:center;gap:16px;flex-wrap:wrap}.username-limit-row{margin-top:9px;padding-left:3px;justify-content:flex-start;gap:12px;flex-wrap:wrap}.username-save-btn{margin-left:4px}.field{margin:13px 0}.field label{display:block;margin-bottom:7px;color:#ccd3df}.field-input,input,select,textarea{width:100%;background:#081a38;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px;outline:none}.field-input:focus,input:focus,select:focus,textarea:focus{border-color:#657084}.row{display:flex;gap:9px;align-items:center}.wrap{flex-wrap:wrap}.empty{text-align:center;padding:40px;color:var(--muted)}.key{font-family:monospace;font-size:13px}.login-wrap{min-height:100vh;display:grid;place-items:center;padding:20px}.login{width:min(430px,100%);background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:30px;box-shadow:var(--shadow)}.error{color:#ffb4ba;background:#351d21;border:1px solid #63333a;padding:10px;border-radius:8px;margin:10px 0}.flash{margin-bottom:14px;padding:12px 15px;border-radius:9px;font-weight:700;border:1px solid}.flash.success{color:#63d493;background:#102a1d;border-color:#2f744b}.flash.error{color:#ff6f79;background:#35191e;border-color:#74343b}.toast{position:fixed;right:18px;bottom:18px;background:#202733;border:1px solid var(--line);padding:12px 15px;border-radius:9px;z-index:100}.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.76);display:grid;place-items:center;padding:18px;z-index:90}.modal{width:min(650px,100%);max-height:90vh;overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:15px;padding:20px}.modal h2{margin-top:0}.password-wrap{position:relative}.password-wrap input{padding-right:46px}.eye-btn{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:34px;height:34px;border:0;background:transparent;color:#b9c9e2;padding:0;display:grid;place-items:center}.eye-btn svg{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:2}.session-choice{display:flex;gap:10px;margin-top:8px}.session-option{flex:1;position:relative}.session-option input{position:absolute;opacity:0;pointer-events:none}.session-option label{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);cursor:pointer;color:var(--text)}.session-option input:checked+label{border-color:#3d8cff;box-shadow:0 0 0 2px rgba(61,140,255,.18);background:#12366b}.session-option label:after{content:"✓";font-weight:800;color:#7fb4ff;opacity:0}.session-option input:checked+label:after{opacity:1}.setting-row,.pricing-row{display:flex;justify-content:space-between;gap:15px;align-items:center;padding:13px 0;border-bottom:1px solid var(--line)}.settings-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.switch{position:relative;width:48px;height:26px}.switch input{display:none}.switch span{position:absolute;inset:0;background:#343b49;border-radius:99px}.switch span:after{content:"";position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}.switch input:checked+span{background:#5c8b6f}.switch input:checked+span:after{transform:translateX(22px)}
@media(max-width:900px){:root{--sidebar:0px}.sidebar{display:none}.sidebar.open{display:flex;width:270px;box-shadow:20px 0 60px rgba(0,0,0,.5)}.side-overlay{position:fixed;inset:0;background:rgba(0,0,0,.38);z-index:40}.side-overlay.open{display:block}.main{margin-left:0}.mobile-menu{display:inline-flex}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.settings-grid,.grid2{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr 1fr}.toolbar input{grid-column:1/-1}.topbar{padding:0 15px}}
@media(max-width:550px){.layout{padding:15px}.grid{grid-template-columns:1fr}.toolbar{grid-template-columns:1fr}.page-head{align-items:flex-start;flex-direction:column}.topbar{height:64px}.page-head h1{font-size:24px}.actions .action,.actions .danger{padding:8px 10px}}
 .session-timeout-heading{font-size:16px}.session-timeout-options .session-option label{font-size:8px!important;padding:9px 10px;justify-content:flex-start;gap:7px}.session-timeout-options .session-option label:after{font-size:10px;order:-1}</style></head><body><div id="app"></div><div id="toast" class="toast hidden"></div>
<script>
let token=localStorage.getItem('lexi_token')||'';let ownerToken=localStorage.getItem('lexi_owner_token')||'';let currentUser=null;function getPanelDeviceId(){let id=localStorage.getItem('lexi_panel_device_id');if(!id){id='panel-'+(crypto.randomUUID?crypto.randomUUID():Math.random().toString(36).slice(2)+Date.now().toString(36));localStorage.setItem('lexi_panel_device_id',id)}return id}let pricing={};let currentPage='dashboard';window.__panelFlash=null;window.__generatedKeys=null;let booting=false;
function esc(v){return String(v??'').replace(/[&<>'"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[m]))}
function setFlash(message,type='success'){window.__panelFlash={message,type};window.__panelFlashPage=currentPage;const html='<div class="flash '+(type==='error'?'error':'success')+'">'+esc(message)+'</div>';const a=document.getElementById('flashArea');if(a)a.innerHTML=html;const l=document.getElementById('loginFlash');if(l)l.innerHTML=html;}
function consumeFlash(){const f=window.__panelFlash;if(!f)return '';if(window.__panelFlashPage&&window.__panelFlashPage!==currentPage){window.__panelFlash=null;window.__panelFlashPage='';return '';}window.__panelFlash=null;window.__panelFlashPage='';return '<div class="flash '+(f.type==='error'?'error':'success')+'">'+esc(f.message)+'</div>'}
function keySuccessCard(keys,title='Key Generated Successfully'){if(!keys||!keys.length)return '';return '<div class="card" style="margin-bottom:14px;border-color:#2f744b"><h3 style="margin:0 0 10px;color:#63d493">'+esc(title)+'</h3>'+keys.map(k=>'<div style="padding:10px 0;border-bottom:1px solid var(--line)"><div class="row" style="justify-content:space-between;gap:8px"><b class="key">'+esc(k.key)+'</b><button class="action" onclick="copyText(\''+esc(k.key)+'\')">Copy</button></div><small>Duration: '+esc(k.durationLabel||k.duration||'')+' · Devices: '+Number(k.deviceLimit||1)+' · Status: '+esc(k.status||'active')+' · Expiry: '+esc(k.expiryAt?fmt(k.expiryAt):'Not Started')+'</small></div>').join('')+'</div>'}
function toast(msg){const e=document.getElementById('toast');if(!e)return;e.textContent=msg;e.classList.remove('hidden');clearTimeout(window.__toast);window.__toast=setTimeout(()=>e.classList.add('hidden'),2800)}
async function api(url,opt={}){opt.credentials='same-origin';opt.headers=Object.assign({'Content-Type':'application/json'},opt.headers||{});if(token)opt.headers.Authorization='Bearer '+token;let r;try{r=await fetch(url,opt)}catch(e){throw new Error('Network error. Check the server connection.')};let d={};try{d=await r.json()}catch{}if(!r.ok){const e=new Error(d.message||'Request failed');e.status=r.status;throw e}return d}
function initEyeButtons(){document.querySelectorAll('.eye-btn').forEach(b=>{if(!b.querySelector('svg'))b.innerHTML=eyeSvg(false)})}
function setToken(t){token=t||'';if(token)localStorage.setItem('lexi_token',token);else localStorage.removeItem('lexi_token')}
async function logout(){try{if(token)await api('/api/auth/logout',{method:'POST'})}catch{}localStorage.removeItem('lexi_token');localStorage.removeItem('lexi_owner_token');token='';ownerToken='';currentUser=null;renderLogin()}
function renderLogin(){const f=consumeFlash();document.getElementById('app').innerHTML='<div class="login-wrap"><div class="login"><div id="loginFlash">'+f+'</div><div class="brand">Lexi <span>Loader</span></div><p class="muted">Reseller Management Panel</p><form onsubmit="login(event)"><div class="field"><label>Username</label><input id="loginUser" autocomplete="username" required></div><div class="field"><label>Password</label><div class="password-wrap"><input id="loginPass" type="password" autocomplete="current-password" required><button type="button" class="eye-btn" onclick="togglePassword(\'loginPass\',this)"><span class="eye-icon"></span></button></div></div><div class="field"><label class="session-timeout-heading">Session Timeout</label><div class="session-choice session-timeout-options"><div class="session-option"><input id="session24" name="loginSessionTimeout" type="radio" value="24" checked><label for="session24">1 Day</label></div><div class="session-option"><input id="session168" name="loginSessionTimeout" type="radio" value="168"><label for="session168">7 Days</label></div></div></div><div id="loginErr" class="error hidden"></div><button class="primary full" style="margin-top:14px" type="submit">Sign in</button></form><button class="action full" style="margin-top:9px" onclick="renderRegister()">Register with Referral Code</button><button class="action full" style="margin-top:9px" onclick="resetPasswordModal()">Reset Password</button></div></div>'}
async function login(e){e.preventDefault();const er=document.getElementById('loginErr');const reset=null;er.classList.add('hidden');try{const r=await fetch('/api/auth/login',{credentials:'same-origin',method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('loginUser').value,password:document.getElementById('loginPass').value,rememberMe:false,sessionTimeoutHours:Number(document.querySelector('input[name=\"loginSessionTimeout\"]:checked')?.value||24),deviceId:getPanelDeviceId()})});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Object.assign(new Error(d.message||'Login failed. Please try again.'),{status:r.status,code:d.code,resetAvailable:d.resetAvailable,resetRemaining:d.resetRemaining});if(!d.token||!d.user)throw new Error('Login response was invalid. Please restart the server and try again.');setToken(d.token);currentUser=d.user;await shell();await page(currentPage)}catch(x){const msg=x?.message||'Login failed. Please try again.';er.textContent=msg;er.classList.remove('hidden');const rb=document.getElementById('loginResetDeviceBtn');if(rb)rb.remove();if(x?.code==='DEVICE_LIMIT_REACHED'&&x?.resetAvailable!==false){const b=document.createElement('button');b.id='loginResetDeviceBtn';b.className='primary full';b.style.marginTop='9px';b.textContent='Reset Device';b.onclick=resetPanelDeviceModal;er.insertAdjacentElement('afterend',b)}}}
function eyeSvg(open){return open?'<svg viewBox="0 0 24 24"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"></path><circle cx="12" cy="12" r="2.5"></circle></svg>':'<svg viewBox="0 0 24 24"><path d="M3 3l18 18"></path><path d="M10.6 6.2A11.7 11.7 0 0 1 12 6c6.5 0 10 6 10 6a18.8 18.8 0 0 1-3.1 3.8"></path><path d="M6.2 6.2C3.5 8.1 2 12 2 12s3.5 6 10 6c1.2 0 2.3-.2 3.3-.6"></path></svg>'}function togglePassword(id,btn){const el=document.getElementById(id);if(!el)return;const show=el.type==='password';el.type=show?'text':'password';if(btn)btn.innerHTML=eyeSvg(show)}
function resetPasswordModal(){modal('<h2>Reset Password</h2><p class="muted">Uses username and your new password. Maximum 3 resets per role window.</p><div class="field"><label>Username</label><input id="resetUser"></div><div class="field"><label>New Password</label><div class="password-wrap"><input id="resetNew" type="password" minlength="6"><button type="button" class="eye-btn" onclick="togglePassword(\'resetNew\',this)"><span class="eye-icon"></span></button></div></div><div id="resetErr" class="error hidden"></div><button class="primary" onclick="resetPasswordSave()">Reset Password</button> <button class="action" onclick="closeModal()">Cancel</button>')}
async function resetPasswordSave(){const er=document.getElementById('resetErr');try{await fetch('/api/auth/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('resetUser').value,newPassword:document.getElementById('resetNew').value})}).then(async r=>{const d=await r.json();if(!r.ok)throw new Error(d.message||'Reset failed');return d});closeModal();toast('Password reset successfully')}catch(e){er.textContent=e.message;er.classList.remove('hidden')}}
function navItem(id,label){return '<button data-page="'+esc(id)+'" class="navbtn '+(currentPage===id?'active':'')+'" onclick="page(\''+id+'\')">'+label+'</button>'}
const PAGE_PATHS={dashboard:'/Dashboard',generateKeys:'/Generate-Keys',manageKeys:'/Manage-Keys',keyManage:'/Manage-Key',users:'/Users',referrals:'/Referrals',transactions:'/Transactions',activity:'/Activity',audit:'/Audit-Logs',settings:'/Settings'};
const PATH_PAGES=Object.fromEntries(Object.entries(PAGE_PATHS).map(([k,v])=>[v.toLowerCase(),k]));
function pageFromPath(){const raw=location.pathname.replace(/\/+$/,'')||'/';const lower=raw.toLowerCase();if(lower==='/register')return null;return PATH_PAGES[lower]||'dashboard'}
function pagePath(name){return PAGE_PATHS[name]||'/Dashboard'}
function sidebar(){let owner=currentUser.role==='owner',admin=currentUser.role==='admin';let items=navItem('dashboard','Dashboard')+navItem('generateKeys','Generate Keys')+navItem('manageKeys','Manage Keys');if(owner)items+=navItem('users','Users');if(owner||admin)items+=navItem('referrals','Referrals');if(owner||admin)items+=navItem('transactions','Transactions')+navItem('activity','Activity');if(owner)items+=navItem('audit','Audit Logs')+navItem('settings','Settings');else items+=navItem('settings','Settings');return '<div id="sideOverlay" class="side-overlay" onclick="closeSideMenu()"></div><aside id="sidebar" class="sidebar" onclick="event.stopPropagation()"><div class="brand">Lexi <span>Loader</span></div><div class="side-user"><b>'+esc(currentUser.username)+'</b><div class="muted" style="margin-top:5px">'+esc(currentUser.role.toUpperCase())+'</div><div style="margin-top:7px">Balance: ₹'+Number(currentUser.balance||0).toFixed(2)+'</div></div><div class="side-nav">'+items+'</div><div class="side-bottom">'+(ownerToken&&owner?'<button class="primary full" onclick="returnOwner()">Return to Owner</button>':'')+'<button class="action full" onclick="logout()">Logout</button></div></aside>'}
function toggleSideMenu(){document.getElementById('sidebar')?.classList.toggle('open');document.getElementById('sideOverlay')?.classList.toggle('open')}function closeSideMenu(){document.getElementById('sidebar')?.classList.remove('open');document.getElementById('sideOverlay')?.classList.remove('open')}
async function shell(){document.getElementById('app').innerHTML='<div class="app-shell">'+sidebar()+'<section class="main"><header class="topbar"><div class="row"><button class="action mobile-menu" onclick="toggleSideMenu()">Menu</button><div><b>'+esc(currentUser.role.toUpperCase())+'</b><div class="muted">'+esc(currentUser.username)+'</div></div></div></header><main class="layout"><div id="flashArea">'+consumeFlash()+'</div><div id="content"></div></main></section></div>'}
async function boot(){if(booting)return;booting=true;try{if(!token){renderLogin();return}const m=await api('/api/auth/me');currentUser=m.user;currentPage=pageFromPath()||'dashboard';await shell();await page(currentPage,{push:false})}catch(e){if(e.status===401){localStorage.removeItem('lexi_token');token='';currentUser=null;renderLogin()}else{if(!currentUser){renderLogin()}else{await shell();document.getElementById('content').innerHTML='<div class="card"><h2>Connection problem</h2><p class="muted">Your session is still saved. Retry without logging out.</p><button class="primary" onclick="boot()">Retry</button></div>'}}}finally{booting=false}}
async function page(name,opts={}){const push=opts.push!==false;const changed=name!==currentPage;if(changed){window.__generatedKeys=null;window.__panelFlash=null;window.__panelFlashPage='';const fa=document.getElementById('flashArea');if(fa)fa.innerHTML='';}currentPage=name;localStorage.setItem('lexi_page',name);if(push&&location.pathname.toLowerCase()!==pagePath(name).toLowerCase())history.pushState({page:name},'',pagePath(name));closeSideMenu();document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('active',b.dataset.page===name));if(!currentUser)return;if(name==='dashboard')return dashboard();if(name==='generateKeys')return generateKeysPage();if(name==='manageKeys')return keysPage();if(name==='keyManage')return keyManagePage(opts.id);if(name==='users'&&currentUser.role==='owner')return usersPage();if(name==='referrals')return referralsPage();if(name==='transactions'&&(currentUser.role==='owner'||currentUser.role==='admin'))return transactionsPage();if(name==='activity'&&(currentUser.role==='owner'||currentUser.role==='admin'))return activityPage();if(name==='audit'&&currentUser.role==='owner')return auditPage();if(name==='settings')return settingsPage();return dashboard()}
window.addEventListener('popstate',()=>{if(!currentUser)return;page(pageFromPath()||'dashboard',{push:false})});
function stat(label,value){return '<div class="card stat"><div class="label">'+esc(label)+'</div><b>'+esc(value)+'</b></div>'}
async function dashboard(){try{const d=await api('/api/dashboard');const s=d.stats||{};document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Dashboard</h1><div class="muted">License and account overview</div></div><button class="primary" onclick="generateModal()">Generate Keys</button></div><div class="grid">'+stat('Active Keys',s.activeKeys||0)+stat('Expired Keys',s.expiredKeys||0)+stat('Blocked Keys',s.blockedKeys||0)+stat(currentUser.role==='owner'?'Users':'My Keys',s.users||s.activeKeys||0)+'</div><div class="grid2" style="margin-top:14px">'+stat('Balance','₹'+Number(s.balance||0).toFixed(2))+stat('Resellers',s.resellers||0)+'</div><div class="card" style="margin-top:14px"><h3>Loader Status</h3><p><span class="badge '+(d.settings?.loaderStatus?'ok':'bad')+'">'+(d.settings?.loaderStatus?'ONLINE':'MAINTENANCE')+'</span></p><p class="muted">'+esc(d.settings?.loaderStatus?'Loader verification is enabled.':(d.settings?.maintenanceMsg||'Loader disabled.'))+'</p></div><div class="card" style="margin-top:14px"><h3>Account Creation</h3><p class="muted">Exact account creation date and time</p><b>'+esc(fmt(currentUser.createdAt))+'</b></div>'}catch(e){toast(e.message)}}
async function generateKeysPage(){try{pricing=(await api('/api/pricing')).pricing||{};document.getElementById('content').innerHTML=consumeFlash()+keySuccessCard(window.__generatedKeys)+'<div class="page-head"><div><h1>Generate Keys</h1><div class="muted">Create license keys using your available balance and permitted duration.</div></div></div><div class="grid2"><div class="card"><h3>Key Generation</h3><p class="muted">Choose duration and quantity. Key timers start after first successful loader verification.</p><button class="primary" onclick="generateModal()">Generate Keys</button></div><div class="card"><h3>Manage Keys</h3><p class="muted">View, search and manage existing licenses and statuses.</p><button class="primary" onclick="page(\'manageKeys\')">Manage Keys</button></div></div>'}catch(e){setFlash('Generate Keys load failed: '+e.message,'error');renderFlashOnly()}}
async function keysPage(){try{const d=await api('/api/keys');pricing=(await api('/api/pricing')).pricing||{};document.getElementById('content').innerHTML=consumeFlash()+'<div class="page-head"><div><h1>Manage Keys</h1><div class="muted">Manage licenses and device bindings</div></div></div><div class="card"><div class="toolbar"><input id="keySearch" placeholder="Search license / HWID"><select id="keyStatus"><option value="all">All Status</option><option value="active">Active</option><option value="blocked">Blocked</option><option value="expired">Expired</option><option value="deleted">Deleted</option></select><select id="keyDevice"><option value="all">All Devices</option><option value="bound">Bound</option><option value="unbound">Unbound</option></select><button class="action" onclick="loadKeys()">Search</button></div><div id="keysTable"></div></div>';window.__keys=d.keys||[];renderKeys()}catch(e){setFlash('Failed: '+e.message,'error');renderFlashOnly()}}
function renderKeys(){let q=(document.getElementById('keySearch')?.value||'').toLowerCase(),st=document.getElementById('keyStatus')?.value||'all',dv=document.getElementById('keyDevice')?.value||'all';let rows=(window.__keys||[]).filter(k=>{let ok=!q||String(k.key).toLowerCase().includes(q)||String(k.hwid||'').toLowerCase().includes(q);let ss=st==='all'||k.status===st;let bound=Array.isArray(k.devices)&&k.devices.length>0;let dd=dv==='all'||(dv==='bound'?bound:!bound);return ok&&ss&&dd});if(!rows.length){document.getElementById('keysTable').innerHTML='<div class="empty">No keys found.</div>';return}document.getElementById('keysTable').innerHTML='<div class="table-wrap"><table class="table"><thead><tr><th>License</th><th>Status</th><th>Duration</th><th>Devices</th><th>Expiry</th><th>Creator</th><th>Actions</th></tr></thead><tbody>'+rows.map(k=>'<tr><td><b class="key">'+esc(k.key)+'</b><br><small>'+esc(k.hwid||'Unbound')+'</small></td><td><span class="badge '+(k.status==='active'?'ok':'bad')+'">'+esc(k.status)+'</span></td><td>'+esc(k.durationLabel||k.duration||'')+'</td><td>'+((k.devices||[]).length)+' / '+Number(k.deviceLimit||1)+'</td><td>'+esc(k.expiryAt?fmt(k.expiryAt):'Not Started')+'</td><td>'+esc(k.creatorUsername||k.creatorId||'')+'</td><td><div class="actions"><button class="action" onclick="keyAction(\''+esc(k.id)+'\',\'reset\')">Reset</button><button class="manage-btn" onclick="openKeyManage(\''+esc(k.id)+'\')">Manage</button></div></td></tr>').join('')+'</tbody></table></div>'}
async function loadKeys(){try{const d=await api('/api/keys');window.__keys=d.keys||[];renderKeys()}catch(e){toast(e.message)}}
async function keyAction(id,action){try{let url='/api/keys/'+encodeURIComponent(id);let opt={method:'POST'};if(action==='reset'){url+='/reset'}else{url+='/status';opt.body=JSON.stringify({status:action==='delete'?'deleted':(action==='block'?'blocked':'active')})}const d=await api(url,opt);if(action==='reset'){window.__generatedKeys=[d.key];setFlash('Device bindings reset successfully.','success')}else if(action==='delete'){setFlash('Key deleted successfully.','success')}else{setFlash('Key status updated successfully.','success')}await loadKeys()}catch(e){setFlash('Failed: '+e.message,'error');renderFlashOnly()}}
function renderFlashOnly(){const f=document.getElementById('flashArea');if(f)f.innerHTML=consumeFlash()}

function fmt(v){if(v===null||v===undefined||v==='')return '-';const d=new Date(v);if(Number.isNaN(d.getTime()))return String(v);return d.toLocaleString('en-IN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});}
async function copyText(v){try{await navigator.clipboard.writeText(v);toast('Copied')}catch{toast('Copy failed')}}
function generateModal(){let opts=Object.keys(pricing).map(k=>'<option value="'+esc(k)+'">'+esc(pricing[k].label)+' — ₹'+Number(pricing[k].price).toFixed(2)+'</option>').join('');let custom=['owner','admin'].includes(currentUser.role);let price=currentUser.role==='owner'?'<div class="field"><label>Custom Price</label><input id="customPrice" type="number" min="0" step="0.01" value="0"></div>':'';let customKeyField=custom?'<div class="field"><label>Custom Key</label><input id="customKey" type="text" value="" placeholder="Optional — e.g. Exl"></div>':'';modal('<h2>Generate Keys</h2><div class="field"><label id="durationHeading">Duration</label><select id="genDuration" onchange="customDurationToggle()">'+opts+(custom?'<option value="custom">Custom</option>':'')+'</select></div>'+customKeyField+'<div id="customFields" class="hidden"><div class="field"><label>Custom Duration (Hours)</label><input id="customHours" type="number" min="1" '+(currentUser.role==='owner'?'':'max="87600"')+' placeholder="Duration in hours"></div>'+price+'<div class="field"><label>Label</label><input id="customLabel" placeholder="Custom Key"></div></div><input id="genDevices" type="hidden" value="1"><div class="field"><label>Key Count</label><input id="genCount" type="number" min="1" '+(currentUser.role==='owner'?'':'max="1000"')+' value="1"></div><div id="genErr" class="error hidden"></div><span class="modal-actions"><button class="generate-btn" onclick="generateSave()">Generate</button><button class="action" onclick="closeModal()">Cancel</button></span>')}
function customDurationToggle(){const custom=document.getElementById('genDuration').value==='custom';document.getElementById('customFields').classList.toggle('hidden',!custom);document.getElementById('durationHeading').textContent=custom?'Custom Key':'Duration';}
async function generateSave(){const er=document.getElementById('genErr');try{const duration=document.getElementById('genDuration').value;const body={duration,deviceLimit:Number(document.getElementById('genDevices').value),quantity:Number(document.getElementById('genCount').value)};if(['owner','admin'].includes(currentUser.role)){const customKey=(document.getElementById('customKey')?.value||'').trim();if(customKey)body.customKey=customKey}if(duration==='custom'){body.customHours=Number(document.getElementById('customHours').value);body.customLabel=document.getElementById('customLabel').value;if(currentUser.role==='owner')body.customPrice=Number(document.getElementById('customPrice').value||0)}const d=await api('/api/keys/generate',{method:'POST',body:JSON.stringify(body)});closeModal();window.__generatedKeys=d.keys||[];window.__panelFlash=null;window.__panelFlashPage='';await page('generateKeys',{push:false})}catch(e){er.textContent=e.message;er.classList.remove('hidden');setFlash('Key generation failed: '+e.message,'error')}}

function openKeyManage(id){page('keyManage',{id});}
async function keyManagePage(id){try{const d=await api('/api/keys/'+encodeURIComponent(id));const k=d.key;document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Manage Key</h1><div class="muted">All key details and editable settings</div></div><button class="action" onclick="page(\'manageKeys\')">Back to Manage Keys</button></div><div class="card"><div class="field"><label>License Key</label><input id="mkKey" value="'+esc(k.key)+'"></div><div class="field"><label>Duration</label><div class="bracket">'+esc(k.durationLabel||k.duration||'-')+'</div></div><input id="mkDeviceLimit" type="hidden" value="'+Number(k.deviceLimit||1)+'"><div class="field"><label>Status</label><select id="mkStatus"><option value="active" '+(k.status==='active'?'selected':'')+'>Active</option><option value="blocked" '+(k.status==='blocked'?'selected':'')+'>Blocked</option><option value="deleted" '+(k.status==='deleted'?'selected':'')+'>Deleted</option></select></div><div class="field"><label>Game Package</label><input id="mkPackage" value="'+esc(k.gamePackage||'')+'"></div><div class="field"><label>IP Lock</label><input id="mkIp" value="'+esc(k.ipLock||'')+'"></div><div class="field"><label>Geo Lock</label><input id="mkGeo" value="'+esc(k.geoLock||'')+'"></div><div class="field"><label>Creator</label><div class="bracket">'+esc(k.creatorUsername||k.creatorId||'-')+'</div></div><div class="field"><label>HWID / Devices</label><div class="bracket">'+esc(k.hwid||'Unbound')+' · '+Number(k.devicesUsed||0)+' / '+Number(k.deviceLimit||1)+'</div></div><div class="field"><label>Created</label><div class="bracket">'+esc(fmt(k.createdAt))+'</div></div><div class="field"><label>Started</label><div class="bracket">'+esc(k.startedAt?fmt(k.startedAt):'Not Started')+'</div></div><div class="field"><label>Expiry</label><div class="bracket">'+esc(k.expiryAt?fmt(k.expiryAt):'Not Started')+'</div></div><div class="row wrap"><button class="primary" onclick="saveKeyManage(\''+esc(k.id)+'\')">Save Changes</button><button class="action" onclick="keyAction(\''+esc(k.id)+'\',\'reset\')">Reset Devices</button><button class="danger" onclick="deleteKeyFromManage(\''+esc(k.id)+'\')">Delete</button></div></div>'}catch(e){toast(e.message)}}
async function saveKeyManage(id){try{const d=await api('/api/keys/'+encodeURIComponent(id)+'/update',{method:'POST',body:JSON.stringify({key:document.getElementById('mkKey').value.trim(),deviceLimit:Number(document.getElementById('mkDeviceLimit').value),status:document.getElementById('mkStatus').value,gamePackage:document.getElementById('mkPackage').value.trim(),ipLock:document.getElementById('mkIp').value.trim(),geoLock:document.getElementById('mkGeo').value.trim()})});setFlash(d.message||'Key updated successfully.','success');keyManagePage(id)}catch(e){toast(e.message)}}
async function deleteKeyFromManage(id){if(!confirm('Delete this key?'))return;await keyAction(id,'delete');page('manageKeys')}
function userRow(u){const self=u.id===currentUser.id;let actions='';if(!self&&u.role!=='owner'){actions+='<button class="action" onclick="balanceModal(\''+esc(u.id)+'\')">Balance</button><button class="action" onclick="referralModal(\''+esc(u.id)+'\')">Referral</button><button class="action" onclick="toggleUser(\''+esc(u.id)+'\',\''+(u.status==='active'?'blocked':'active')+'\')">'+(u.status==='active'?'Block':'Unblock')+'</button>';if(currentUser.role==='owner')actions+='<button class="action" onclick="enterPanel(\''+esc(u.id)+'\')">Enter</button><button class="danger" onclick="toggleUser(\''+esc(u.id)+'\',\'deleted\')">Delete</button>'}else actions='<span class="muted">Current account</span>';return '<tr><td><b>'+esc(u.username)+'</b><br><small>'+esc(u.id)+'</small></td><td>'+esc(u.role)+'</td><td><span class="badge '+(u.status==='active'?'ok':'bad')+'">'+esc(u.status)+'</span></td><td>₹'+Number(u.balance||0).toFixed(2)+'</td><td>'+esc(fmt(u.createdAt))+'</td><td><div class="actions">'+actions+'</div></td></tr>'}
function createUserModal(){const owner=currentUser.role==='owner';modal('<h2>Create '+(owner?'Account':'Reseller')+'</h2><div class="field"><label>Username</label><input id="newUser" autocomplete="off"></div><div class="field"><label>Password</label><div class="password-wrap"><input id="newPass" type="password" autocomplete="new-password"><button type="button" class="eye-btn" onclick="togglePassword(\'newPass\',this)"><span class="eye-icon"></span></button></div></div>'+(owner?'<div class="field"><label>Role</label><select id="newRole"><option value="admin">Admin</option><option value="reseller">Reseller</option><option value="owner">Owner</option></select></div>':'<input id="newRole" type="hidden" value="reseller">')+'<div class="field"><label>Starting Balance</label><input id="newBal" type="number" min="0" step="0.01" value="0"></div><div id="createErr" class="error hidden"></div><button class="primary" onclick="createUserSave()">Create</button> <button class="action" onclick="closeModal()">Cancel</button>')}
async function createUserSave(){const er=document.getElementById('createErr');try{const d=await api('/api/users/create',{method:'POST',body:JSON.stringify({username:document.getElementById('newUser').value,password:document.getElementById('newPass').value,role:document.getElementById('newRole').value,balance:Number(document.getElementById('newBal').value||0)})});closeModal();toast('Account created');loadUsers()}catch(e){er.textContent=e.message;er.classList.remove('hidden')}}
async function toggleUser(id,status){if(!confirm(status==='deleted'?'Delete this account?':'Change account status?'))return;try{await api('/api/users/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status})});toast('Account updated');loadUsers()}catch(e){toast(e.message)}}
async function deleteUser(id){if(!confirm('Delete this account?'))return;try{await api('/api/users/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status:'deleted'})});toast('Account deleted');loadUsers()}catch(e){toast(e.message)}}
function balanceModal(id){modal('<h2>Adjust Balance</h2><div class="field"><label>Amount</label><input id="balAmount" type="number" step="0.01" value="0"></div><div class="field"><label>Mode</label><select id="balMode"><option value="add">Add</option><option value="subtract">Subtract</option><option value="set">Set</option></select></div><div id="balErr" class="error hidden"></div><button class="primary" onclick="saveBalance(\''+esc(id)+'\')">Save</button> <button class="action" onclick="closeModal()">Cancel</button>')}
async function saveBalance(id){const er=document.getElementById('balErr');try{await api('/api/users/'+encodeURIComponent(id)+'/balance',{method:'POST',body:JSON.stringify({amount:Number(document.getElementById('balAmount').value),mode:document.getElementById('balMode').value})});closeModal();toast('Balance updated');loadUsers()}catch(e){er.textContent=e.message;er.classList.remove('hidden')}}
async function referralModal(id){try{const d=await api('/api/referrals?userId='+encodeURIComponent(id));let r=(d.referrals||[]).find(x=>x.creatorId===id);if(!r){const c=await api('/api/referrals/create',{method:'POST',body:JSON.stringify({userId:id})});r=c.referral}const link=location.origin+'/register?ref='+encodeURIComponent(r.code);modal('<h2>Referral</h2><p>Owner: <b>'+esc(id)+'</b></p><div class="field"><label>Referral Code</label><input value="'+esc(r.code)+'" readonly></div><div class="field"><label>Referral Link</label><input value="'+esc(link)+'" readonly></div><button class="primary" onclick="copyText(\''+esc(r.code)+'\')">Copy Code</button> <button class="action" onclick="closeModal()">Close</button>')}catch(e){toast(e.message)}}
async function referralsPage(){try{const d=await api('/api/referrals');let rows=d.referrals||[];if(currentUser.role==='admin')rows=rows.filter(r=>r.creatorId===currentUser.id);document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Referrals</h1><div class="muted">Referral codes and referred user details</div></div><button class="primary" onclick="createReferralModal()">Create Referral</button></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Referral Code</th><th>Creator</th><th>Used</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead><tbody>'+(rows.length?rows.map(r=>'<tr><td><b>'+esc(r.code)+'</b></td><td>'+esc(r.creatorUsername||r.creatorId||'')+'</td><td>'+Number(r.usedCount||0)+'</td><td>'+esc(r.expiresAt?fmt(r.expiresAt):'Never')+'</td><td><span class="status-text '+(r.status==='active'?'status-active':'status-blocked')+'">'+esc(r.status)+'</span></td><td class="actions"><button class="action" onclick="manageReferral(\''+esc(r.id)+'\')">Manage</button><button class="danger" onclick="deleteReferral(\''+esc(r.id)+'\')">Delete</button></td></tr>').join(''):'<tr><td colspan="6" class="empty">No referrals yet.</td></tr>')+'</tbody></table></div></div>'}catch(e){setFlash('Referrals load failed: '+e.message,'error');renderFlashOnly()}}
async function manageReferral(id){try{const d=await api('/api/referrals/'+encodeURIComponent(id));const r=d.referral||d;const creatorId=r.creatorId;const ures=await api('/api/users/'+encodeURIComponent(creatorId));const u=ures.user;const canManage=u.id!==currentUser.id&&u.role!=='owner';modal('<h2>Manage</h2><div class="field"><label>Referral Code</label><div class="bracket">'+esc(r.code)+'</div></div><div class="field"><label>Creator</label><div class="bracket">'+esc(u.username||r.creatorUsername||creatorId)+'</div></div><div class="field"><label>Used</label><div class="bracket">'+Number(r.usedCount||0)+'</div></div><div class="field"><label>Expiry</label><div class="bracket">'+esc(r.expiresAt?fmt(r.expiresAt):'Never')+'</div></div><div class="field"><label>Referral Status</label><div class="bracket status-select"><span class="'+(r.status==='active'?'status-active':'status-blocked')+'">'+(r.status==='active'?'Active':'Block')+'</span></div><div class="row" style="margin-top:8px"><button class="action" onclick="toggleReferralFromManage(\''+esc(r.id)+'\')">'+(r.status==='active'?'Block':'Unblock')+'</button></div></div>'+(canManage?'<div class="field"><label>Balance</label><div class="row"><div class="bracket" style="flex:1">₹'+Number(u.balance||0).toFixed(2)+'</div><button class="action" onclick="editBalance(\''+esc(u.id)+'\')">Edit Balance</button></div></div><div class="field"><label>User Status</label><div class="bracket"><span class="'+(u.status==='active'?'status-active':'status-blocked')+'">'+(u.status==='active'?'Active':'Block')+'</span></div><div class="row" style="margin-top:8px"><button class="action" onclick="setResellerStatus(\''+esc(u.id)+'\',\''+(u.status==='active'?'blocked':'active')+'\')">'+(u.status==='active'?'Block':'Unblock')+'</button></div></div><div class="field"><label>Keys</label><div class="bracket">'+Number((u.keys||[]).length)+'</div></div><div class="field"><label>Last Activity</label><div class="bracket">'+esc(u.lastLoginAt?fmt(u.lastLoginAt):'No login yet')+'</div></div>':'')+'<button class="action" onclick="closeModal()">Close</button>')}catch(e){toast(e.message)}}
async function toggleReferralFromManage(id){try{await api('/api/referrals/'+encodeURIComponent(id)+'/toggle',{method:'POST'});closeModal();referralsPage()}catch(e){toast(e.message)}}
async function deleteReferral(id){if(!confirm('Delete this referral code?'))return;try{await api('/api/referrals/'+encodeURIComponent(id),{method:'DELETE'});closeModal();setFlash('Referral deleted successfully.','success');referralsPage()}catch(e){setFlash('Referral delete failed: '+e.message,'error');renderFlashOnly()}}

async function manageReseller(id){try{const d=await api('/api/users/'+encodeURIComponent(id));const u=d.user;modal('<h2>Manage Reseller</h2><div class="field"><label>Username</label><div class="bracket">'+esc(u.username)+'</div></div><div class="field"><label>Balance</label><div class="row"><div class="bracket" style="flex:1">₹'+Number(u.balance||0).toFixed(2)+'</div><button class="action" onclick="editBalance(\''+esc(u.id)+'\')">Edit</button></div></div><div class="field"><label>Status</label><div class="bracket status-select" onclick="statusListToggle()"><span class="'+(u.status==='active'?'status-active':'status-blocked')+'">'+(u.status==='active'?'Active':'Block')+'</span></div><div id="statusList" class="hidden list-box"><button onclick="setResellerStatus(\''+esc(u.id)+'\',\'active\')">Active</button><button onclick="setResellerStatus(\''+esc(u.id)+'\',\'blocked\')">Block</button></div></div><div class="field"><label>Keys</label><div class="bracket">'+u.keys.length+'</div></div><div class="field"><label>Last Activity</label><div class="bracket">'+esc(u.lastLoginAt?fmt(u.lastLoginAt):'No login yet')+'</div></div><button class="action" onclick="closeModal()">Close</button>')}catch(e){toast(e.message)}}
function statusListToggle(){document.getElementById('statusList')?.classList.toggle('hidden')}
async function setResellerStatus(id,status){try{await api('/api/users/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status})});closeModal();setFlash('Reseller status updated successfully.','success');referralsPage()}catch(e){setFlash('Failed: '+e.message,'error');renderFlashOnly()}}
async function editBalance(id){const amount=prompt('Enter new balance amount:');if(amount===null)return;const n=Number(amount);if(!Number.isFinite(n)||n<0){setFlash('Failed: invalid balance.','error');renderFlashOnly();return}try{await api('/api/users/'+encodeURIComponent(id)+'/balance',{method:'POST',body:JSON.stringify({mode:'set',amount:n})});closeModal();setFlash('Balance updated successfully.','success');referralsPage()}catch(e){setFlash('Failed: '+e.message,'error');renderFlashOnly()}}
async function deleteReseller(id){try{const d=await api('/api/users/'+encodeURIComponent(id));modal('<h2>Delete Reseller?</h2><p>Are you sure you want to delete <b>'+esc(d.user.username)+'</b>?</p><p class="muted">This action cannot be undone.</p><div class="row" style="justify-content:flex-end"><button class="action" onclick="closeModal()">Cancel</button><button class="danger" onclick="confirmDeleteReseller(\''+esc(id)+'\')">Confirm</button></div>')}catch(e){setFlash('Failed: '+e.message,'error');renderFlashOnly()}}
async function confirmDeleteReseller(id){try{await api('/api/users/'+encodeURIComponent(id),{method:'DELETE'});closeModal();setFlash('Reseller deleted successfully.','success');referralsPage()}catch(e){setFlash('Failed: '+e.message,'error');renderFlashOnly()}}

function createReferralModal(){const owner=currentUser.role==='owner';modal('<h2>Create Referral</h2><p class="muted">A unique code and registration link will be generated automatically.</p><div class="field"><label>New User Role</label><select id="refRole">'+(owner?'<option value="reseller">Reseller</option><option value="admin">Admin</option><option value="owner">Owner</option>':'<option value="reseller">Reseller</option>')+'</select></div><div class="field"><label>Starting Balance</label><input id="refBalance" type="number" '+(owner?'min="0"':'min="3000" max="50000"')+' step="1" value="'+(owner?'0':'3000')+'"></div><div class="field"><label>Expiry (optional)</label><input id="refExpiry" type="datetime-local"></div><div id="refErr" class="error hidden"></div><button class="primary" onclick="saveReferral()">Generate Code</button> <button class="action" onclick="closeModal()">Cancel</button>')}
async function saveReferral(){const er=document.getElementById('refErr');try{const d=await api('/api/referrals/create',{method:'POST',body:JSON.stringify({role:document.getElementById('refRole').value,startingBalance:Number(document.getElementById('refBalance').value||0),expiresAt:document.getElementById('refExpiry').value?new Date(document.getElementById('refExpiry').value).toISOString():null})});const link=location.origin+'/register?ref='+encodeURIComponent(d.referral.code);modal('<h2>Referral Created</h2><div class="field"><label>Referral Code</label><input value="'+esc(d.referral.code)+'" readonly></div><div class="field"><label>Registration Link</label><input value="'+esc(link)+'" readonly></div><button class="primary" onclick="copyText(\''+esc(d.referral.code)+'\')">Copy Code</button> <button class="action" onclick="closeModal();page(\'referrals\')">Done</button>')}catch(e){er.textContent=e.message;er.classList.remove('hidden');setFlash('Referral creation failed: '+e.message,'error')}}

async function toggleReferral(id){try{await api('/api/referrals/'+encodeURIComponent(id)+'/toggle',{method:'POST'});referralsPage()}catch(e){toast(e.message)}}
async function enterPanel(id){if(!confirm('Enter this account panel?'))return;try{const previous=token;const d=await api('/api/owner/enter-user/'+encodeURIComponent(id),{method:'POST'});ownerToken=previous;localStorage.setItem('lexi_owner_token',ownerToken);setToken(d.token);currentUser=d.user;await shell();await page('dashboard')}catch(e){toast(e.message)}}
async function returnOwner(){const t=localStorage.getItem('lexi_owner_token');if(!t){toast('Owner session not found');return}setToken(t);localStorage.removeItem('lexi_owner_token');ownerToken='';await boot()}
async function passwordModal(){modal('<h2>Change Password</h2><div class="field"><label>New Password</label><div class="password-wrap"><input id="newPassword" type="password" minlength="6"><button type="button" class="eye-btn" onclick="togglePassword(\'newPassword\',this)"><span class="eye-icon"></span></button></div></div><div id="pwErr" class="error hidden"></div><button class="primary" onclick="changePassword()">Save</button> <button class="action" onclick="closeModal()">Cancel</button>')}
function resetPanelDeviceModal(){modal('<h2>Reset Device</h2><p class="muted">Admin/Reseller only. Maximum 3 device resets.</p><div class="field"><label>Username</label><input id="resetDeviceUser" autocomplete="username"></div><div class="field"><label>Password</label><div class="password-wrap"><input id="resetDevicePass" type="password" autocomplete="current-password"><button type="button" class="eye-btn" onclick="togglePassword(\'resetDevicePass\',this)"><span class="eye-icon"></span></button></div></div><div id="resetDeviceErr" class="error hidden"></div><div class="row wrap settings-actions"><button class="primary" onclick="resetPanelDevice()">Reset Device</button><button class="action" onclick="closeModal()">Cancel</button></div>')}
async function resetPanelDevice(){const er=document.getElementById('resetDeviceErr');er.classList.add('hidden');try{const r=await fetch('/api/auth/reset-device',{credentials:'same-origin',method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('resetDeviceUser').value,password:document.getElementById('resetDevicePass').value,deviceId:getPanelDeviceId()})});const d=await r.json();if(!r.ok)throw new Error(d.message||'Device reset failed.');closeModal();const lb=document.getElementById('loginResetDeviceBtn');if(lb)lb.remove();const le=document.getElementById('loginErr');if(le){le.textContent='Device reset successfully. Please login again.';le.classList.remove('hidden')}toast('Device reset successfully')}catch(e){er.textContent=e.message;er.classList.remove('hidden')}}
async function changePassword(){const er=document.getElementById('pwErr');try{await api('/api/auth/change-password',{method:'POST',body:JSON.stringify({newPassword:document.getElementById('newPassword').value})});closeModal();toast('Password changed')}catch(e){er.textContent=e.message;er.classList.remove('hidden')}}
function applyTheme(){if(localStorage.getItem('lexi_theme')==='light'){document.documentElement.dataset.theme='light';document.documentElement.style.setProperty('--bg','#f4f6f9');document.documentElement.style.setProperty('--panel','#fff');document.documentElement.style.setProperty('--text','#151923');document.documentElement.style.setProperty('--muted','#687181');document.documentElement.style.setProperty('--line','#d8dde6')}else{document.documentElement.dataset.theme='';document.documentElement.style.cssText=''}}
function toggleTheme(){localStorage.setItem('lexi_theme',localStorage.getItem('lexi_theme')==='light'?'dark':'light');applyTheme()};function oldToggleTheme(){document.documentElement.dataset.theme=document.documentElement.dataset.theme==='light'?'':'light';if(document.documentElement.dataset.theme==='light'){document.documentElement.style.setProperty('--bg','#f4f6f9');document.documentElement.style.setProperty('--panel','#fff');document.documentElement.style.setProperty('--text','#151923');document.documentElement.style.setProperty('--muted','#687181');document.documentElement.style.setProperty('--line','#d8dde6')}else{document.documentElement.style.cssText=''}}
async function transactionsPage(){try{const d=await api('/api/transactions');const rows=d.transactions||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Transactions</h1><div class="muted">Balance and key-generation history</div></div></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Type</th><th>Actor</th><th>Amount</th><th>Before</th><th>After</th><th>Target</th></tr></thead><tbody>'+(rows.length?rows.map(t=>'<tr><td>'+esc(fmt(t.createdAt))+'</td><td>'+esc(t.type)+'</td><td>'+esc(t.actorUsername||t.actorId||'')+'</td><td>₹'+Number(t.amount||0).toFixed(2)+'</td><td>₹'+Number(t.balanceBefore||0).toFixed(2)+'</td><td>₹'+Number(t.balanceAfter||0).toFixed(2)+'</td><td>'+esc(t.targetUserId||'')+'</td></tr>').join(''):'<tr><td colspan="7" class="empty">No transactions yet.</td></tr>')+'</tbody></table></div></div>'}catch(e){toast(e.message)}}
async function auditPage(){try{const d=await api('/api/audit-logs');const rows=d.logs||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Audit Logs</h1><div class="muted">Owner security and activity trail</div></div></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th></tr></thead><tbody>'+(rows.length?rows.map(x=>'<tr><td>'+esc(fmt(x.createdAt))+'</td><td>'+esc(x.actorUsername||'system')+'</td><td>'+esc(x.action)+'</td><td>'+esc(x.targetId||'')+'</td><td>'+esc(x.ip||'')+'</td></tr>').join(''):'<tr><td colspan="5" class="empty">No audit logs yet.</td></tr>')+'</tbody></table></div></div>'}catch(e){toast(e.message)}}
async function settingsPage(){try{const d=await api('/api/settings');const s=d.settings||{};if(currentUser.role!=='owner'){document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Settings</h1><div class="muted">Account settings</div></div></div><div class="settings-grid"><div class="card"><h3>Username</h3><div class="field"><label>Current / New Username</label><input id="profileUsername" value="'+esc(s.username||currentUser.username)+'"></div><div class="row username-limit-row"><small>Username change remaining: '+Number(s.usernameChangeRemaining||0)+'</small><button class="primary username-save-btn" onclick="saveUsername()">Save Username</button></div></div><div class="card"><h3>Password Reset</h3><p class="muted">Password reset: 3 attempts per '+esc(s.passwordResetWindow||'window')+'.</p><div class="row wrap settings-actions"><button class="primary" onclick="resetPasswordModal()">Reset Password</button><button class="primary" onclick="resetPanelDeviceModal()">Reset Device</button></div></div><div class="card"><h3>Appearance</h3><button class="action" onclick="toggleTheme()">Toggle Dark / Light</button></div></div>';return}const p=await api('/api/pricing');pricing=p.pricing||{};document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Settings</h1><div class="muted">Owner global controls</div></div></div><div class="settings-grid"><div class="card"><h3>Security</h3><div class="setting-row"><div><b>IP / Geo Lock</b><small>Enable optional license lock fields</small></div><label class="switch"><input id="setGeo" type="checkbox" '+(s.ipGeoLockEnabled?'checked':'')+'><span></span></label></div><div class="field"><label>Session Timeout</label><div class="session-choice"><div class="session-option"><input id="setSession24" name="sessionTimeout" type="radio" value="24" '+(Number(s.sessionTimeoutHours||24)===24?'checked':'')+'><label for="setSession24">1 Day</label></div><div class="session-option"><input id="setSession168" name="sessionTimeout" type="radio" value="168" '+(Number(s.sessionTimeoutHours||24)===168?'checked':'')+'><label for="setSession168">7 Days</label></div></div></div><div class="owner-security-actions"><button class="primary golden-btn" onclick="saveSecurity()">Save Security</button><button class="primary golden-btn" onclick="passwordModal()">Change Password</button></div></div><div class="card"><h3>Panel</h3><div class="field"><label>Panel Name</label><input id="setName" value="'+esc(s.panelName||'')+'"></div><div class="field"><label>Support Link</label><input id="setSupport" value="'+esc(s.supportLink||'')+'"></div><button class="primary" onclick="savePanel()">Save Panel</button></div><div class="card"><h3>Pricing</h3><div id="priceEditor">'+Object.keys(pricing).map(k=>'<div class="pricing-row"><div><b>'+esc(pricing[k].label)+'</b><small>'+pricing[k].hours+' hours</small></div><input id="price_'+esc(k)+'" class="field-input" type="number" min="0" step="1" value="'+Number(pricing[k].price)+'" style="max-width:140px"></div>').join('')+'</div><button class="primary" onclick="savePricing()">Save Pricing</button></div><div class="card"><h3>Password Reset Limits</h3><p class="muted">Owner: Unlimited · Admin: 3 / 7 days · Reseller: 3 / 30 days</p></div><div class="card"><h3>Online</h3><div class="setting-row"><div><b>System Online</b><small>Turn loader/app verification on or off</small></div><label class="switch"><input id="sysOnline" type="checkbox" '+(s.systemOnline!==false?'checked':'')+'><span></span></label></div><div class="field"><label>Online / Offline Message</label><textarea id="onlineMsg" rows="4">'+esc(s.onlineMessage||'')+'</textarea></div><div class="setting-row"><div><b>Show Popup</b><small>Display owner message in loader/app</small></div><label class="switch"><input id="noticeEnabled" type="checkbox" '+(s.appNoticeEnabled?'checked':'')+'><span></span></label></div><div class="field"><label>Popup Message</label><textarea id="appNotice" rows="6">'+esc(s.appNotice||'')+'</textarea></div><div class="field"><label>Message Type</label><select id="noticeType"><option value="info" '+(s.appNoticeType==='info'?'selected':'')+'>Info</option><option value="update" '+(s.appNoticeType==='update'?'selected':'')+'>Update</option><option value="maintenance" '+(s.appNoticeType==='maintenance'?'selected':'')+'>Maintenance</option></select></div><button class="primary" onclick="saveOnline()">Save Online Settings</button></div></div>'}catch(e){toast(e.message)}}
async function saveUsername(){try{const d=await api('/api/profile/update',{method:'POST',body:JSON.stringify({username:document.getElementById('profileUsername').value})});currentUser=d.user;await shell();await page('settings');toast('Username saved')}catch(e){toast(e.message)}}
async function activityPage(){try{const d=await api('/api/activity');const rows=d.logs||[];document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Activity</h1><div class="muted">Your activity and your Resellers only</div></div></div><div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th></tr></thead><tbody>'+(rows.length?rows.map(x=>'<tr><td>'+esc(fmt(x.createdAt))+'</td><td>'+esc(x.actorUsername||'system')+'</td><td>'+esc(x.action)+'</td><td>'+esc(x.targetId||'')+'</td><td>'+esc(x.ip||'')+'</td></tr>').join(''):'<tr><td colspan="5" class="empty">No activity yet.</td></tr>')+'</tbody></table></div></div>'}catch(e){toast(e.message)}}
async function saveOnline(){try{await api('/api/settings/update',{method:'POST',body:JSON.stringify({systemOnline:document.getElementById('sysOnline').checked,onlineMessage:document.getElementById('onlineMsg').value,appNoticeEnabled:document.getElementById('noticeEnabled').checked,appNotice:document.getElementById('appNotice').value,appNoticeType:document.getElementById('noticeType').value})});toast('Online settings saved')}catch(e){toast(e.message)}}
async function saveLoader(){try{await api('/api/settings/loader',{method:'POST',body:JSON.stringify({enabled:document.getElementById('setLoader').checked,message:document.getElementById('setMsg').value})});toast('Loader settings saved')}catch(e){toast(e.message)}}
async function savePanel(){try{await api('/api/settings/update',{method:'POST',body:JSON.stringify({panelName:document.getElementById('setName').value,supportLink:document.getElementById('setSupport').value,sessionTimeoutHours:Number(document.querySelector('input[name=\"sessionTimeout\"]:checked')?.value||24)})});toast('Panel settings saved')}catch(e){toast(e.message)}}
async function saveSecurity(){try{await api('/api/settings/update',{method:'POST',body:JSON.stringify({ipGeoLockEnabled:document.getElementById('setGeo').checked,sessionTimeoutHours:Number(document.querySelector('input[name=\"sessionTimeout\"]:checked')?.value||24)})});toast('Security setting saved')}catch(e){toast(e.message)}}
async function savePricing(){try{const out={};for(const k of Object.keys(pricing))out[k]={label:pricing[k].label,hours:pricing[k].hours,price:Number(document.getElementById('price_'+k).value)};await api('/api/pricing/update',{method:'POST',body:JSON.stringify({pricing:out})});toast('Pricing saved')}catch(e){toast(e.message)}}
function modal(html){closeModal();const d=document.createElement('div');d.id='modal';d.className='modal-bg';d.innerHTML='<div class="modal">'+html+'</div>';document.body.appendChild(d)}function closeModal(){document.getElementById('modal')?.remove()}
function renderRegister(){const ref=new URLSearchParams(location.search).get('ref')||'';document.getElementById('app').innerHTML='<div class="login-wrap"><div class="login"><div class="brand">Lexi <span>Loader</span></div><p class="muted">Create Reseller account using referral</p><form onsubmit="registerAccount(event)"><div class="field"><label>Username</label><input id="regUser" autocomplete="username" required></div><div class="field"><label>Password</label><div class="password-wrap"><input id="regPass" type="password" autocomplete="new-password" required><button type="button" class="eye-btn" onclick="togglePassword(\'regPass\',this)"><span class="eye-icon"></span></button></div></div><div class="field"><label>Referral Code</label><input id="regRef" value="'+esc(ref)+'" placeholder="Enter referral code" autocomplete="off" required></div><div id="regErr" class="error hidden"></div><button class="primary full" type="submit">Create Reseller Account</button></form><button class="action full" style="margin-top:9px" onclick="location.href=\'/\'">Back to Login</button></div></div>'}

async function registerAccount(e){e.preventDefault();const er=document.getElementById('regErr');er.classList.add('hidden');try{const r=await fetch('/api/auth/register',{credentials:'same-origin',method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('regUser').value,password:document.getElementById('regPass').value,referralCode:document.getElementById('regRef').value})});const d=await r.json();if(!r.ok)throw new Error(d.message||'Registration failed');alert('Reseller account created successfully.');location.href='/'}catch(x){er.textContent=x.message;er.classList.remove('hidden')}}
window.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal()});new MutationObserver(()=>initEyeButtons()).observe(document.getElementById('app'),{childList:true,subtree:true});applyTheme();
(async()=>{if(location.pathname.toLowerCase()==='/register'){renderRegister();return}await boot()})();
function userActions(u){const can=u.id!==currentUser.id;return '<div class="actions">'+(can?'<button class="action" onclick="manageUser(\''+esc(u.id)+'\')">Manage</button>':'<span class="muted">Current account</span>')+(can?'<button class="danger" onclick="deleteUser(\''+esc(u.id)+'\')">Delete</button>':'')+'</div>'}
async function manageUser(id){try{const d=await api('/api/users/'+encodeURIComponent(id));const u=d.user;const isOwner=currentUser.role==='owner';const canEnter=isOwner&&u.id!==currentUser.id&&u.status==='active';modal('<h2>Manage</h2><div class="field"><label>Username</label><div class="bracket">'+esc(u.username)+'</div></div><div class="field"><label>Role</label><div class="bracket">'+esc(u.role)+'</div></div><div class="field"><label>Balance</label><div class="row"><div class="bracket" style="flex:1">₹'+Number(u.balance||0).toFixed(2)+'</div><button class="action" onclick="balanceModal(\''+esc(u.id)+'\')">Edit Balance</button></div></div><div class="field"><label>Status</label><div class="bracket"><span class="'+(u.status==='active'?'status-active':'status-blocked')+'">'+esc(u.status)+'</span></div><div class="row" style="margin-top:8px">'+(u.status==='active'?'<button class="block-btn" onclick="toggleUser(\''+esc(u.id)+'\',\''+(u.status==='active'?'blocked':'active')+'\')">Block</button>':'<button class="unblock-btn" onclick="toggleUser(\''+esc(u.id)+'\',\''+(u.status==='active'?'blocked':'active')+'\')">Unblock</button>')+'</div></div><div class="field"><label>Keys</label><div class="bracket">'+Number((u.keys||[]).length)+'</div></div><div class="field"><label>Last Activity</label><div class="bracket">'+esc(u.lastLoginAt?fmt(u.lastLoginAt):'Never')+'</div></div>'+(canEnter?'<button class="primary full" onclick="enterPanel(\''+esc(u.id)+'\')">Enter Panel</button>':'')+'<button class="danger full" style="margin-top:9px" onclick="deleteUserFromManage(\''+esc(u.id)+'\')">Delete</button><button class="action full" style="margin-top:9px" onclick="closeModal()">Close</button>')}catch(e){toast(e.message)}}
async function deleteUserFromManage(id){if(!confirm('Delete this account?'))return;try{await api('/api/users/'+encodeURIComponent(id)+'/status',{method:'POST',body:JSON.stringify({status:'deleted'})});closeModal();setFlash('Account deleted successfully.','success');usersPage()}catch(e){toast(e.message)}}

function renderUsers(){const rows=window.__users||[];const el=document.getElementById('usersTable');if(!el)return;el.innerHTML='<div class="table-wrap"><table class="table"><thead><tr><th>Username</th><th>User ID</th><th>Role</th><th>Status</th><th>Balance</th><th>Created</th><th>Last Activity</th><th>Actions</th></tr></thead><tbody>'+(rows.length?rows.map(u=>'<tr><td><b>'+esc(u.username)+'</b></td><td class="key">'+esc(u.id)+'</td><td>'+esc(u.role)+'</td><td class="status-'+esc(u.status)+'">'+esc(u.status)+'</td><td>₹'+Number(u.balance||0).toFixed(2)+'</td><td>'+esc(fmt(u.createdAt))+'</td><td>'+esc(u.lastLoginAt?fmt(u.lastLoginAt):'Never')+'</td><td>'+userActions(u)+'</td></tr>').join(''):'<tr><td colspan="8" class="empty">No users found.</td></tr>')+'</tbody></table></div>'}
async function loadUsers(){try{const q=encodeURIComponent(document.getElementById('userSearch')?.value||'');const role=encodeURIComponent(document.getElementById('userRole')?.value||'all');const status=encodeURIComponent(document.getElementById('userStatus')?.value||'all');const d=await api('/api/users?search='+q+'&role='+role+'&status='+status);window.__users=d.users||[];renderUsers()}catch(e){setFlash('Users load failed: '+e.message,'error');renderFlashOnly()}}
async function usersPage(){if(currentUser.role!=='owner')return dashboard();try{const d=await api('/api/users');document.getElementById('content').innerHTML='<div class="page-head"><div><h1>Users</h1><div class="muted">Owner-only user management</div></div><button class="primary" onclick="createUserModal()">New Registration</button></div><div class="card"><div class="toolbar"><input id="userSearch" placeholder="Search username / User ID"><select id="userRole"><option value="all">All Roles</option><option value="owner">Owner</option><option value="admin">Admin</option><option value="reseller">Reseller</option></select><select id="userStatus"><option value="all">All Status</option><option value="active">Active</option><option value="blocked">Blocked</option><option value="deleted">Deleted</option></select><button class="action" onclick="loadUsers()">Search</button></div><div id="usersTable"></div></div>';window.__users=d.users||[];renderUsers()}catch(e){setFlash('Users load failed: '+e.message,'error');renderFlashOnly()}}
;
</script></body></html>`;


app.get("/", (req, res) => res.type("html").send(PANEL_HTML));
app.get(/^\/Login$/i, (req, res) => res.type("html").send(PANEL_HTML));
app.get("/panel", (req, res) => res.redirect(302, "/Dashboard"));
app.get(/^\/Register$/i, (req, res) => res.type("html").send(PANEL_HTML));
app.get(/^\/(Dashboard|Generate-Keys|Manage-Keys|Manage-Key|Users|Referrals|Transactions|Activity|Audit-Logs|Settings|Online)(?:\/.*)?$/i, (req, res) => res.type("html").send(PANEL_HTML));

/* ---------- 404 / errors ---------- */

app.use("/api", (req, res) => {
  res.status(404).json({ success: false, message: "API endpoint not found." });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});

app.listen(PORT, () => {
  console.log(`Lexi Loader backend running on port ${PORT}`);
  console.log(`Database: ${DB_FILE}`);
});
