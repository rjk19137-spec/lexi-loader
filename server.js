const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const DB_FILE = path.join(__dirname, "database.json");

const SESSION_MS = 24 * 60 * 60 * 1000;
const RESET_WINDOW_MS = 24 * 60 * 60 * 1000;
const DEVICE_RESET_WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_RESET_ATTEMPTS = 3;
const MAX_DEVICE_RESETS = 3;
const PBKDF2_ITERATIONS = 210000;

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

function now() {
  return Date.now();
}

function iso(value) {
  return new Date(value || now()).toISOString();
}

function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function normalizeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, "");
}

function cleanString(value, max = 500) {
  return String(value ?? "").trim().slice(0, max);
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function createDatabase() {
  return {
    settings: {
      panelName: "Lexi Loader",
      panelVersion: "V4.5",
      loaderName: "Lexi Loader V4.5 AIM",
      loaderStatus: true,
      maintenanceMessage: "Loader is temporarily under maintenance.",
      supportUrl: "",
      theme: "dark",
      sessionTimeoutHours: 24,
      passwordResetLimit: 3,
      passwordResetWindowHours: 24,
      deviceResetLimit: 3,
      deviceResetWindowHours: 24,
      optionalIpLock: false,
      optionalGeoLock: false,
      serverCountry: "",
      serverRegion: ""
    },
    pricing: {
      "3h": { label: "3 Hours", hours: 3, price: 10 },
      "1d": { label: "1 Day", hours: 24, price: 100 },
      "3d": { label: "3 Days", hours: 72, price: 200 },
      "7d": { label: "7 Days", hours: 168, price: 350 },
      "15d": { label: "15 Days", hours: 360, price: 500 },
      "30d": { label: "30 Days", hours: 720, price: 750 },
      "60d": { label: "60 Days", hours: 1440, price: 1000 }
    },
    users: [],
    referrals: [],
    keys: [],
    devices: [],
    sessions: [],
    transactions: [],
    auditLogs: [],
    counters: {
      user: 0,
      referral: 0,
      key: 0,
      device: 0,
      transaction: 0,
      audit: 0,
      session: 0
    }
  };
}

function normalizeDatabase(db) {
  const base = createDatabase();
  const result = db && typeof db === "object" ? db : {};

  result.settings = {
    ...base.settings,
    ...(result.settings || {})
  };

  result.pricing = {
    ...base.pricing,
    ...(result.pricing || {})
  };

  const arrays = [
    "users",
    "referrals",
    "keys",
    "devices",
    "sessions",
    "transactions",
    "auditLogs"
  ];

  for (const name of arrays) {
    if (!Array.isArray(result[name])) {
      result[name] = [];
    }
  }

  result.counters = {
    ...base.counters,
    ...(result.counters || {})
  };

  return result;
}

function loadDatabase() {
  if (!fs.existsSync(DB_FILE)) {
    const fresh = createDatabase();
    fs.writeFileSync(DB_FILE, JSON.stringify(fresh, null, 2));
    return fresh;
  }

  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");
    return normalizeDatabase(JSON.parse(raw));
  } catch (error) {
    console.error("Database load error:", error.message);
    process.exit(1);
  }
}

let db = loadDatabase();

function saveDatabase() {
  const temp = `${DB_FILE}.tmp`;
  const data = JSON.stringify(db, null, 2);

  fs.writeFileSync(temp, data, "utf8");
  fs.renameSync(temp, DB_FILE);
}

function nextId(type, prefix) {
  db.counters[type] = safeNumber(db.counters[type], 0) + 1;
  return `${prefix}-${String(db.counters[type]).padStart(6, "0")}`;
}

function findUserById(id) {
  return db.users.find(u => u.id === id);
}

function findUserByUsername(username) {
  const name = normalizeUsername(username);
  return db.users.find(u => u.username === name);
}

function findKeyById(id) {
  return db.keys.find(k => k.id === id);
}

function findKeyByLicense(license) {
  const value = String(license || "").trim().toUpperCase();
  return db.keys.find(k => k.license === value);
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (forwarded) {
    return String(forwarded).split(",")[0].trim();
  }

  return String(
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  ).replace("::ffff:", "");
}

function getRequestInfo(req) {
  return {
    ip: getClientIp(req),
    userAgent: cleanString(req.headers["user-agent"], 300),
    country: cleanString(req.headers["x-country-code"], 20),
    region: cleanString(req.headers["x-region"], 100)
  };
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const derived = crypto
    .pbkdf2Sync(
      String(password),
      salt,
      PBKDF2_ITERATIONS,
      64,
      "sha512"
    )
    .toString("hex");

  return `pbkdf2$${PBKDF2_ITERATIONS}$${salt}$${derived}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 4 || parts[0] !== "pbkdf2") {
      return false;
    }

    const iterations = Number(parts[1]);
    const salt = parts[2];
    const expected = parts[3];

    if (!iterations || !salt || !expected) {
      return false;
    }

    const actual = crypto
      .pbkdf2Sync(
        String(password),
        salt,
        iterations,
        64,
        "sha512"
      )
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(actual, "utf8"),
      Buffer.from(expected, "utf8")
    );
  } catch {
    return false;
  }
}

function validPassword(password) {
  const value = String(password || "");

  return (
    value.length >= 8 &&
    value.length <= 128 &&
    /[A-Za-z]/.test(value) &&
    /\d/.test(value)
  );
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));

  if (aa.length !== bb.length) {
    return false;
  }

  return crypto.timingSafeEqual(aa, bb);
}

function sanitizeUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    username: user.username,
    role: user.role,
    status: user.status,
    balance: safeNumber(user.balance),
    parentId: user.parentId || null,
    referralCode: user.referralCode || null,
    createdAt: user.createdAt || null,
    lastLoginAt: user.lastLoginAt || null,
    lastLoginIp: user.lastLoginIp || null
  };
}

function sanitizeKey(key) {
  if (!key) {
    return null;
  }

  const devices = db.devices
    .filter(d => d.keyId === key.id)
    .map(d => ({
      id: d.id,
      hwid: d.hwid,
      deviceName: d.deviceName || "",
      boundAt: d.boundAt || null,
      lastSeenAt: d.lastSeenAt || null,
      ip: d.ip || null,
      country: d.country || null
    }));

  return {
    id: key.id,
    license: key.license,
    creatorId: key.creatorId,
    creatorUsername: key.creatorUsername,
    durationHours: key.durationHours,
    price: key.price,
    deviceLimit: key.deviceLimit,
    createdAt: key.createdAt,
    expiresAt: key.expiresAt,
    status: key.status,
    blockedAt: key.blockedAt || null,
    deletedAt: key.deletedAt || null,
    resetCount: key.resetCount || 0,
    resetWindowStartedAt: key.resetWindowStartedAt || null,
    devices
  };
}

function addAuditLog(actor, action, targetType, targetId, details = {}) {
  db.auditLogs.push({
    id: nextId("audit", "AUD"),
    actorId: actor?.id || null,
    actorUsername: actor?.username || "system",
    action,
    targetType,
    targetId: targetId || null,
    details,
    ip: actor?.ip || null,
    createdAt: iso()
  });
}

function addTransaction(user, type, amount, reason, meta = {}) {
  db.transactions.push({
    id: nextId("transaction", "TXN"),
    userId: user.id,
    username: user.username,
    type,
    amount: safeNumber(amount),
    reason: cleanString(reason, 300),
    balanceAfter: safeNumber(user.balance),
    meta,
    createdAt: iso()
  });
}

function hierarchyContains(parentId, userId) {
  if (!parentId || !userId) {
    return false;
  }

  let current = findUserById(userId);
  const visited = new Set();

  while (current && current.parentId && !visited.has(current.id)) {
    if (current.parentId === parentId) {
      return true;
    }

    visited.add(current.id);
    current = findUserById(current.parentId);
  }

  return false;
}

function roleRank(role) {
  if (role === "owner") return 3;
  if (role === "admin") return 2;
  if (role === "user") return 1;
  return 0;
}

function canManageUser(actor, target) {
  if (!actor || !target || actor.id === target.id) {
    return false;
  }

  if (actor.role === "owner") {
    return true;
  }

  if (actor.role === "admin") {
    return (
      target.role === "user" &&
      hierarchyContains(actor.id, target.id)
    );
  }

  return false;
}

function canManageKey(actor, key) {
  if (!actor || !key) {
    return false;
  }

  if (actor.role === "owner") {
    return true;
  }

  if (key.creatorId === actor.id) {
    return true;
  }

  return actor.role === "admin" &&
    hierarchyContains(actor.id, key.creatorId);
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "lexi-loader",
    time: iso(),
    loaderStatus: !!db.settings.loaderStatus
  });
});
function getBearerToken(req) {
  const header = String(req.headers.authorization || "");

  if (!header.toLowerCase().startsWith("bearer ")) {
    return "";
  }

  return header.slice(7).trim();
}

function getSessionByToken(token) {
  if (!token) {
    return null;
  }

  const session = db.sessions.find(
    s => s.token === token && !s.revokedAt
  );

  if (!session) {
    return null;
  }

  if (session.expiresAt <= now()) {
    session.revokedAt = iso();
    return null;
  }

  return session;
}

function getSessionUser(req) {
  const token = getBearerToken(req);
  const session = getSessionByToken(token);

  if (!session) {
    return null;
  }

  const user = findUserById(session.userId);

  if (!user || user.status !== "active") {
    return null;
  }

  return { user, session, token };
}

function createSession(user, req, actingAs = null) {
  const request = getRequestInfo(req);
  const token = randomToken(32);

  const session = {
    id: nextId("session", "SES"),
    token,
    userId: user.id,
    username: user.username,
    ip: request.ip,
    userAgent: request.userAgent,
    createdAt: iso(),
    expiresAt: iso(now() + SESSION_MS),
    revokedAt: null,
    ownerSessionId: actingAs || null
  };

  db.sessions.push(session);
  return session;
}

function requireAuth(req, res, next) {
  const auth = getSessionUser(req);

  if (!auth) {
    return res.status(401).json({
      ok: false,
      error: "Authentication required."
    });
  }

  req.auth = auth;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({
        ok: false,
        error: "Authentication required."
      });
    }

    if (!roles.includes(req.auth.user.role)) {
      return res.status(403).json({
        ok: false,
        error: "Permission denied."
      });
    }

    next();
  };
}

function createUser({
  username,
  password,
  role,
  parentId = null,
  referralCode = null
}) {
  const normalized = normalizeUsername(username);

  if (!/^[a-z0-9_.-]{3,32}$/.test(normalized)) {
    throw new Error(
      "Username must contain 3-32 letters, numbers, dot, dash or underscore."
    );
  }

  if (findUserByUsername(normalized)) {
    throw new Error("Username already exists.");
  }

  if (!["owner", "admin", "user"].includes(role)) {
    throw new Error("Invalid role.");
  }

  if (!validPassword(password)) {
    throw new Error(
      "Password must be 8-128 characters and contain letters and numbers."
    );
  }

  const user = {
    id: nextId("user", "USR"),
    username: normalized,
    passwordHash: hashPassword(password),
    role,
    status: "active",
    balance: 0,
    parentId,
    referralCode,
    resetCount: 0,
    resetWindowStartedAt: null,
    deviceResetCount: 0,
    deviceResetWindowStartedAt: null,
    createdAt: iso(),
    lastLoginAt: null,
    lastLoginIp: null
  };

  db.users.push(user);
  return user;
}

function ensureOwner() {
  let owner = db.users.find(u => u.role === "owner");

  if (owner) {
    return owner;
  }

  const password =
    process.env.LEXI_OWNER_PASSWORD || "ChangeMe123!";

  owner = createUser({
    username: "owner",
    password,
    role: "owner"
  });

  owner.balance = 0;

  saveDatabase();

  console.log(
    "Owner account created. Username: owner"
  );

  if (!process.env.LEXI_OWNER_PASSWORD) {
    console.log(
      "WARNING: Set LEXI_OWNER_PASSWORD before production use."
    );
  }

  return owner;
}

ensureOwner();

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = String(req.body.password || "");
  const user = findUserByUsername(username);

  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({
      ok: false,
      error: "Invalid username or password."
    });
  }

  if (user.status !== "active") {
    return res.status(403).json({
      ok: false,
      error: "Account is blocked."
    });
  }

  const request = getRequestInfo(req);

  if (
    db.settings.optionalIpLock &&
    user.lastLoginIp &&
    user.lastLoginIp !== request.ip
  ) {
    return res.status(403).json({
      ok: false,
      error: "IP lock is active for this account."
    });
  }

  user.lastLoginAt = iso();
  user.lastLoginIp = request.ip;

  const session = createSession(user, req);

  addAuditLog(
    {
      id: user.id,
      username: user.username,
      ip: request.ip
    },
    "login",
    "user",
    user.id
  );

  saveDatabase();

  res.json({
    ok: true,
    token: session.token,
    user: sanitizeUser(user),
    expiresAt: session.expiresAt
  });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  req.auth.session.revokedAt = iso();

  addAuditLog(
    {
      id: req.auth.user.id,
      username: req.auth.user.username,
      ip: getClientIp(req)
    },
    "logout",
    "user",
    req.auth.user.id
  );

  saveDatabase();

  res.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({
    ok: true,
    user: sanitizeUser(req.auth.user),
    session: {
      expiresAt: req.auth.session.expiresAt,
      createdAt: req.auth.session.createdAt,
      actingAs: req.auth.session.ownerSessionId || null
    }
  });
});

app.get("/api/auth/session-info", requireAuth, (req, res) => {
  res.json({
    ok: true,
    user: sanitizeUser(req.auth.user),
    session: {
      id: req.auth.session.id,
      expiresAt: req.auth.session.expiresAt,
      createdAt: req.auth.session.createdAt,
      actingAs: req.auth.session.ownerSessionId || null
    }
  });
});

app.post("/api/auth/change-password", requireAuth, (req, res) => {
  const current = String(req.body.currentPassword || "");
  const next = String(req.body.newPassword || "");

  if (!verifyPassword(current, req.auth.user.passwordHash)) {
    return res.status(400).json({
      ok: false,
      error: "Current password is incorrect."
    });
  }

  if (!validPassword(next)) {
    return res.status(400).json({
      ok: false,
      error: "New password does not meet requirements."
    });
  }

  req.auth.user.passwordHash = hashPassword(next);

  addAuditLog(
    {
      id: req.auth.user.id,
      username: req.auth.user.username,
      ip: getClientIp(req)
    },
    "change_password",
    "user",
    req.auth.user.id
  );

  saveDatabase();

  res.json({
    ok: true,
    message: "Password changed successfully."
  });
});

app.post("/api/auth/reset-password", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const newPassword = String(req.body.newPassword || "");
  const user = findUserByUsername(username);

  if (!user) {
    return res.status(400).json({
      ok: false,
      error: "Invalid reset request."
    });
  }

  if (!validPassword(newPassword)) {
    return res.status(400).json({
      ok: false,
      error: "New password does not meet requirements."
    });
  }

  const request = getRequestInfo(req);

  if (
    user.lastLoginIp &&
    user.lastLoginIp !== request.ip
  ) {
    return res.status(403).json({
      ok: false,
      error: "Password reset requires the same IP."
    });
  }

  const windowStart = user.resetWindowStartedAt
    ? new Date(user.resetWindowStartedAt).getTime()
    : 0;

  if (!windowStart || now() - windowStart >= RESET_WINDOW_MS) {
    user.resetWindowStartedAt = iso();
    user.resetCount = 0;
  }

  if (
    safeNumber(user.resetCount) >=
    Number(db.settings.passwordResetLimit || MAX_RESET_ATTEMPTS)
  ) {
    return res.status(429).json({
      ok: false,
      error: "Password reset limit reached. Try again later."
    });
  }

  user.resetCount = safeNumber(user.resetCount) + 1;
  user.passwordHash = hashPassword(newPassword);

  for (const session of db.sessions) {
    if (session.userId === user.id && !session.revokedAt) {
      session.revokedAt = iso();
    }
  }

  addAuditLog(
    {
      id: user.id,
      username: user.username,
      ip: request.ip
    },
    "password_reset",
    "user",
    user.id
  );

  saveDatabase();

  res.json({
    ok: true,
    message: "Password reset successfully.",
    remaining:
      Number(
        db.settings.passwordResetLimit || MAX_RESET_ATTEMPTS
      ) - user.resetCount
  });
});

app.get("/api/auth/reset-status", (req, res) => {
  const username = normalizeUsername(req.query.username);
  const user = findUserByUsername(username);

  if (!user) {
    return res.json({
      ok: true,
      remaining: Number(
        db.settings.passwordResetLimit || MAX_RESET_ATTEMPTS
      )
    });
  }

  const started = user.resetWindowStartedAt
    ? new Date(user.resetWindowStartedAt).getTime()
    : 0;

  if (!started || now() - started >= RESET_WINDOW_MS) {
    return res.json({
      ok: true,
      remaining: Number(
        db.settings.passwordResetLimit || MAX_RESET_ATTEMPTS
      )
    });
  }

  res.json({
    ok: true,
    remaining: Math.max(
      0,
      Number(
        db.settings.passwordResetLimit || MAX_RESET_ATTEMPTS
      ) - safeNumber(user.resetCount)
    )
  });
});
function generateLicense() {
  let license;

  do {
    const a = randomHex(5).toUpperCase();
    const b = randomHex(5).toUpperCase();
    const c = randomHex(5).toUpperCase();

    license = `LEXI-${a}-${b}-${c}`;
  } while (findKeyByLicense(license));

  return license;
}

function getDurationFromRequest(body, actor) {
  const mode = cleanString(body.mode, 50);

  if (mode === "custom") {
    if (actor.role !== "owner") {
      throw new Error(
        "Custom duration is available only to Owner."
      );
    }

    const hours = safeNumber(body.durationHours, 0);
    const price = safeNumber(body.price, 0);

    if (hours <= 0 || hours > 8760) {
      throw new Error(
        "Custom duration must be between 1 hour and 8760 hours."
      );
    }

    if (price < 0 || price > 100000000) {
      throw new Error("Invalid custom price.");
    }

    return {
      label: `${hours} Hours`,
      hours,
      price
    };
  }

  const pricing = db.pricing[mode];

  if (!pricing) {
    throw new Error("Invalid duration.");
  }

  return {
    label: pricing.label,
    hours: safeNumber(pricing.hours),
    price: safeNumber(pricing.price)
  };
}

function validateDeviceLimit(value) {
  const limit = Math.floor(safeNumber(value, 1));

  if (limit < 1 || limit > 100) {
    throw new Error(
      "Device limit must be between 1 and 100."
    );
  }

  return limit;
}

function validateKeyCount(value) {
  const count = Math.floor(safeNumber(value, 1));

  if (count < 1 || count > 1000) {
    throw new Error(
      "Key count must be between 1 and 1000."
    );
  }

  return count;
}

function keyIsExpired(key) {
  return (
    key.status !== "deleted" &&
    key.status !== "blocked" &&
    new Date(key.expiresAt).getTime() <= now()
  );
}

function syncKeyStatus(key) {
  if (
    key.status === "active" &&
    keyIsExpired(key)
  ) {
    key.status = "expired";
    return true;
  }

  return false;
}

function syncAllKeyStatuses() {
  let changed = false;

  for (const key of db.keys) {
    if (syncKeyStatus(key)) {
      changed = true;
    }
  }

  if (changed) {
    saveDatabase();
  }
}

function canGenerateCustom(actor) {
  return actor.role === "owner";
}

app.post(
  "/api/keys/generate",
  requireAuth,
  async (req, res) => {
    try {
      const actor = req.auth.user;
      const duration = getDurationFromRequest(
        req.body,
        actor
      );

      const deviceLimit = validateDeviceLimit(
        req.body.deviceLimit
      );

      const count = validateKeyCount(
        req.body.count
      );

      const totalCost = duration.price * count;

      if (
        actor.role !== "owner" &&
        safeNumber(actor.balance) < totalCost
      ) {
        return res.status(400).json({
          ok: false,
          error: "Insufficient balance.",
          required: totalCost,
          balance: safeNumber(actor.balance)
        });
      }

      if (actor.role !== "owner") {
        actor.balance =
          safeNumber(actor.balance) - totalCost;

        addTransaction(
          actor,
          "debit",
          -totalCost,
          "Key generation",
          {
            durationHours: duration.hours,
            count,
            deviceLimit
          }
        );
      }

      const created = [];
      const createdAt = now();

      for (let i = 0; i < count; i++) {
        const key = {
          id: nextId("key", "KEY"),
          license: generateLicense(),
          creatorId: actor.id,
          creatorUsername: actor.username,
          durationHours: duration.hours,
          price: duration.price,
          deviceLimit,
          createdAt: iso(createdAt),
          expiresAt: iso(
            createdAt + duration.hours * 60 * 60 * 1000
          ),
          status: "active",
          blockedAt: null,
          deletedAt: null,
          resetCount: 0,
          resetWindowStartedAt: null
        };

        db.keys.push(key);
        created.push(sanitizeKey(key));
      }

      addAuditLog(
        {
          id: actor.id,
          username: actor.username,
          ip: getClientIp(req)
        },
        "generate_keys",
        "key_batch",
        {
          count,
          durationHours: duration.hours,
          price: duration.price,
          deviceLimit
        }
      );

      saveDatabase();

      res.json({
        ok: true,
        keys: created,
        charged: actor.role === "owner" ? 0 : totalCost,
        balance: safeNumber(actor.balance)
      });
    } catch (error) {
      res.status(400).json({
        ok: false,
        error: error.message || "Key generation failed."
      });
    }
  }
);

app.get("/api/keys", requireAuth, (req, res) => {
  syncAllKeyStatuses();

  const actor = req.auth.user;

  let keys;

  if (actor.role === "owner") {
    keys = db.keys;
  } else if (actor.role === "admin") {
    keys = db.keys.filter(
      k =>
        k.creatorId === actor.id ||
        hierarchyContains(actor.id, k.creatorId)
    );
  } else {
    keys = db.keys.filter(
      k => k.creatorId === actor.id
    );
  }

  const search = cleanString(req.query.search, 200)
    .toLowerCase();

  const status = cleanString(req.query.status, 30)
    .toLowerCase();

  const binding = cleanString(req.query.binding, 30)
    .toLowerCase();

  if (search) {
    keys = keys.filter(key => {
      const devices = db.devices.filter(
        d => d.keyId === key.id
      );

      const text = [
        key.license,
        key.id,
        key.creatorUsername,
        ...devices.map(d => d.hwid)
      ]
        .join(" ")
        .toLowerCase();

      return text.includes(search);
    });
  }

  if (
    ["active", "blocked", "expired", "deleted"].includes(
      status
    )
  ) {
    keys = keys.filter(k => k.status === status);
  }

  if (binding === "bound") {
    keys = keys.filter(k =>
      db.devices.some(d => d.keyId === k.id)
    );
  }

  if (binding === "unbound") {
    keys = keys.filter(
      k =>
        !db.devices.some(d => d.keyId === k.id)
    );
  }

  const limit = Math.min(
    1000,
    Math.max(1, Math.floor(safeNumber(req.query.limit, 200)))
  );

  keys = keys
    .slice()
    .sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    )
    .slice(0, limit);

  res.json({
    ok: true,
    keys: keys.map(sanitizeKey),
    total: keys.length
  });
});

app.get("/api/keys/:id", requireAuth, (req, res) => {
  syncAllKeyStatuses();

  const key = findKeyById(req.params.id);

  if (!key || !canManageKey(req.auth.user, key)) {
    return res.status(404).json({
      ok: false,
      error: "Key not found."
    });
  }

  res.json({
    ok: true,
    key: sanitizeKey(key)
  });
});

app.post("/api/keys/:id/block", requireAuth, (req, res) => {
  const key = findKeyById(req.params.id);

  if (!key || !canManageKey(req.auth.user, key)) {
    return res.status(404).json({
      ok: false,
      error: "Key not found."
    });
  }

  if (key.status === "deleted") {
    return res.status(400).json({
      ok: false,
      error: "Deleted key cannot be blocked."
    });
  }

  key.status = "blocked";
  key.blockedAt = iso();

  addAuditLog(
    {
      id: req.auth.user.id,
      username: req.auth.user.username,
      ip: getClientIp(req)
    },
    "block_key",
    "key",
    key.id
  );

  saveDatabase();

  res.json({
    ok: true,
    key: sanitizeKey(key)
  });
});

app.post("/api/keys/:id/unblock", requireAuth, (req, res) => {
  const key = findKeyById(req.params.id);

  if (!key || !canManageKey(req.auth.user, key)) {
    return res.status(404).json({
      ok: false,
      error: "Key not found."
    });
  }

  if (key.status === "deleted") {
    return res.status(400).json({
      ok: false,
      error: "Deleted key cannot be unblocked."
    });
  }

  if (keyIsExpired(key)) {
    key.status = "expired";
  } else {
    key.status = "active";
  }

  key.blockedAt = null;

  addAuditLog(
    {
      id: req.auth.user.id,
      username: req.auth.user.username,
      ip: getClientIp(req)
    },
    "unblock_key",
    "key",
    key.id
  );

  saveDatabase();

  res.json({
    ok: true,
    key: sanitizeKey(key)
  });
});

app.delete("/api/keys/:id", requireAuth, (req, res) => {
  const key = findKeyById(req.params.id);

  if (!key || !canManageKey(req.auth.user, key)) {
    return res.status(404).json({
      ok: false,
      error: "Key not found."
    });
  }

  key.status = "deleted";
  key.deletedAt = iso();

  addAuditLog(
    {
      id: req.auth.user.id,
      username: req.auth.user.username,
      ip: getClientIp(req)
    },
    "delete_key",
    "key",
    key.id
  );

  saveDatabase();

  res.json({
    ok: true,
    message: "Key deleted."
  });
});
function getDeviceRecords(keyId) {
  return db.devices.filter(d => d.keyId === keyId);
}

function resetDeviceWindow(key) {
  const started = key.resetWindowStartedAt
    ? new Date(key.resetWindowStartedAt).getTime()
    : 0;

  if (
    !started ||
    now() - started >= DEVICE_RESET_WINDOW_MS
  ) {
    key.resetWindowStartedAt = iso();
    key.resetCount = 0;
  }
}

app.post(
  "/api/keys/:id/reset-device",
  requireAuth,
  (req, res) => {
    const key = findKeyById(req.params.id);

    if (!key || !canManageKey(req.auth.user, key)) {
      return res.status(404).json({
        ok: false,
        error: "Key not found."
      });
    }

    if (key.status === "deleted") {
      return res.status(400).json({
        ok: false,
        error: "Deleted key cannot be reset."
      });
    }

    resetDeviceWindow(key);

    const limit = Number(
      db.settings.deviceResetLimit ||
      MAX_DEVICE_RESETS
    );

    if (safeNumber(key.resetCount) >= limit) {
      return res.status(429).json({
        ok: false,
        error: "Device reset limit reached.",
        remaining: 0
      });
    }

    const removed = db.devices.filter(
      d => d.keyId === key.id
    );

    db.devices = db.devices.filter(
      d => d.keyId !== key.id
    );

    key.resetCount = safeNumber(key.resetCount) + 1;

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "reset_device",
      "key",
      key.id,
      {
        removedDevices: removed.length
      }
    );

    saveDatabase();

    res.json({
      ok: true,
      message: "Device binding reset.",
      removedDevices: removed.length,
      remaining: Math.max(
        0,
        limit - key.resetCount
      )
    });
  }
);

function getDeviceHwid(req) {
  return cleanString(
    req.body?.hwid ||
    req.headers["x-device-hwid"] ||
    "",
    300
  );
}

function getDeviceName(req) {
  return cleanString(
    req.body?.deviceName ||
    req.headers["x-device-name"] ||
    "",
    200
  );
}

function bindKeyDevice(key, req) {
  const hwid = getDeviceHwid(req);

  if (!hwid) {
    return {
      ok: false,
      code: "HWID_REQUIRED",
      error: "Device HWID is required."
    };
  }

  const existing = getDeviceRecords(key.id);

  const same = existing.find(
    d => safeEqual(d.hwid, hwid)
  );

  const request = getRequestInfo(req);

  if (same) {
    same.lastSeenAt = iso();
    same.ip = request.ip;

    if (request.country) {
      same.country = request.country;
    }

    return {
      ok: true,
      device: same,
      newlyBound: false
    };
  }

  if (existing.length >= key.deviceLimit) {
    return {
      ok: false,
      code: "DEVICE_LIMIT",
      error: "Device limit reached."
    };
  }

  const device = {
    id: nextId("device", "DEV"),
    keyId: key.id,
    hwid,
    deviceName: getDeviceName(req),
    boundAt: iso(),
    lastSeenAt: iso(),
    ip: request.ip,
    country: request.country || null,
    region: request.region || null
  };

  db.devices.push(device);

  return {
    ok: true,
    device,
    newlyBound: true
  };
}

app.post(
  "/api/loader/verify",
  (req, res) => {
    syncAllKeyStatuses();

    const license = String(
      req.body.license ||
      req.body.key ||
      ""
    ).trim().toUpperCase();

    if (!license) {
      return res.status(400).json({
        ok: false,
        valid: false,
        error: "License key is required."
      });
    }

    const key = findKeyByLicense(license);

    if (!key) {
      return res.status(404).json({
        ok: true,
        valid: false,
        error: "Invalid license key."
      });
    }

    if (!db.settings.loaderStatus) {
      return res.status(503).json({
        ok: true,
        valid: false,
        maintenance: true,
        error:
          db.settings.maintenanceMessage ||
          "Loader is under maintenance."
      });
    }

    if (key.status === "blocked") {
      return res.json({
        ok: true,
        valid: false,
        error: "License is blocked."
      });
    }

    if (
      key.status === "deleted" ||
      key.status === "expired"
    ) {
      return res.json({
        ok: true,
        valid: false,
        error: "License has expired or is unavailable."
      });
    }

    if (keyIsExpired(key)) {
      key.status = "expired";
      saveDatabase();

      return res.json({
        ok: true,
        valid: false,
        error: "License has expired."
      });
    }

    const deviceResult = bindKeyDevice(key, req);

    if (!deviceResult.ok) {
      return res.status(403).json({
        ok: true,
        valid: false,
        code: deviceResult.code,
        error: deviceResult.error
      });
    }

    addAuditLog(
      {
        id: key.creatorId,
        username: key.creatorUsername,
        ip: getClientIp(req)
      },
      "loader_verify",
      "key",
      key.id,
      {
        hwid: getDeviceHwid(req),
        newlyBound: deviceResult.newlyBound
      }
    );

    saveDatabase();

    res.json({
      ok: true,
      valid: true,
      license: key.license,
      expiresAt: key.expiresAt,
      serverTime: iso(),
      deviceLimit: key.deviceLimit,
      devicesUsed: getDeviceRecords(key.id).length,
      branding: {
        name:
          db.settings.loaderName ||
          "Lexi Loader V4.5 AIM",
        version:
          db.settings.panelVersion ||
          "V4.5",
        features: ["BT", "ESP"]
      }
    });
  }
);

app.get("/api/loader/status", (req, res) => {
  res.json({
    ok: true,
    enabled: !!db.settings.loaderStatus,
    maintenanceMessage:
      db.settings.maintenanceMessage ||
      "Loader is temporarily under maintenance.",
    serverTime: iso()
  });
});

app.get("/api/loader/config", (req, res) => {
  res.json({
    ok: true,
    loader: {
      name:
        db.settings.loaderName ||
        "Lexi Loader V4.5 AIM",
      version:
        db.settings.panelVersion ||
        "V4.5",
      features: {
        bt: true,
        esp: true
      },
      serverTime: iso(),
      loaderStatus: !!db.settings.loaderStatus
    }
  });
});

app.get("/api/loader/time", (req, res) => {
  res.json({
    ok: true,
    serverTime: iso(),
    unix: now()
  });
});

app.get("/api/keys/:id/devices", requireAuth, (req, res) => {
  const key = findKeyById(req.params.id);

  if (!key || !canManageKey(req.auth.user, key)) {
    return res.status(404).json({
      ok: false,
      error: "Key not found."
    });
  }

  res.json({
    ok: true,
    devices: getDeviceRecords(key.id)
  });
});

app.get("/api/users", requireAuth, (req, res) => {
  const actor = req.auth.user;
  let users = [];

  if (actor.role === "owner") {
    users = db.users.slice();
  } else if (actor.role === "admin") {
    users = db.users.filter(
      u =>
        u.id === actor.id ||
        u.parentId === actor.id ||
        hierarchyContains(actor.id, u.id)
    );
  } else {
    users = [actor];
  }

  const search = cleanString(
    req.query.search,
    200
  ).toLowerCase();

  const role = cleanString(
    req.query.role,
    30
  ).toLowerCase();

  const status = cleanString(
    req.query.status,
    30
  ).toLowerCase();

  if (search) {
    users = users.filter(u =>
      [
        u.username,
        u.id,
        u.referralCode || ""
      ]
        .join(" ")
        .toLowerCase()
        .includes(search)
    );
  }

  if (
    ["owner", "admin", "user"].includes(role)
  ) {
    users = users.filter(u => u.role === role);
  }

  if (
    ["active", "blocked"].includes(status)
  ) {
    users = users.filter(u => u.status === status);
  }

  users.sort(
    (a, b) =>
      new Date(b.createdAt || 0) -
      new Date(a.createdAt || 0)
  );

  res.json({
    ok: true,
    users: users.map(sanitizeUser),
    total: users.length
  });
});
function referralForUser(userId) {
  return db.referrals.find(
    r => r.ownerId === userId
  );
}

function createReferralCode() {
  let code;

  do {
    code =
      "LEXI-" +
      randomHex(4).toUpperCase();
  } while (
    db.referrals.some(
      r => r.code === code
    )
  );

  return code;
}

app.post(
  "/api/users/create",
  requireAuth,
  (req, res) => {
    try {
      const actor = req.auth.user;
      const username = normalizeUsername(
        req.body.username
      );
      const password = String(
        req.body.password || ""
      );

      let role = cleanString(
        req.body.role,
        20
      ).toLowerCase();

      if (role === "normal") {
        role = "user";
      }

      if (actor.role === "owner") {
        if (
          !["owner", "admin", "user"].includes(role)
        ) {
          return res.status(400).json({
            ok: false,
            error: "Invalid role."
          });
        }
      } else if (actor.role === "admin") {
        if (role !== "user") {
          return res.status(403).json({
            ok: false,
            error:
              "Admin can create only Normal Users."
          });
        }
      } else {
        return res.status(403).json({
          ok: false,
          error: "Permission denied."
        });
      }

      let parentId = null;

      if (role !== "owner") {
        parentId = actor.id;
      }

      const user = createUser({
        username,
        password,
        role,
        parentId
      });

      if (role === "admin" || role === "user") {
        const referral = {
          id: nextId("referral", "REF"),
          code: createReferralCode(),
          ownerId: user.id,
          ownerUsername: user.username,
          parentId,
          createdAt: iso()
        };

        db.referrals.push(referral);
        user.referralCode = referral.code;
      }

      addAuditLog(
        {
          id: actor.id,
          username: actor.username,
          ip: getClientIp(req)
        },
        "create_user",
        "user",
        user.id,
        {
          role
        }
      );

      saveDatabase();

      res.json({
        ok: true,
        user: sanitizeUser(user),
        referralCode:
          user.referralCode || null
      });
    } catch (error) {
      res.status(400).json({
        ok: false,
        error:
          error.message ||
          "Unable to create user."
      });
    }
  }
);

app.post(
  "/api/users/:id/block",
  requireAuth,
  (req, res) => {
    const target = findUserById(
      req.params.id
    );

    if (
      !target ||
      !canManageUser(
        req.auth.user,
        target
      )
    ) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    if (target.role === "owner") {
      return res.status(403).json({
        ok: false,
        error: "Owner cannot be blocked."
      });
    }

    target.status = "blocked";

    for (const session of db.sessions) {
      if (
        session.userId === target.id &&
        !session.revokedAt
      ) {
        session.revokedAt = iso();
      }
    }

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "block_user",
      "user",
      target.id
    );

    saveDatabase();

    res.json({
      ok: true,
      user: sanitizeUser(target)
    });
  }
);

app.post(
  "/api/users/:id/unblock",
  requireAuth,
  (req, res) => {
    const target = findUserById(
      req.params.id
    );

    if (
      !target ||
      !canManageUser(
        req.auth.user,
        target
      )
    ) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    target.status = "active";

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "unblock_user",
      "user",
      target.id
    );

    saveDatabase();

    res.json({
      ok: true,
      user: sanitizeUser(target)
    });
  }
);

app.delete(
  "/api/users/:id",
  requireAuth,
  (req, res) => {
    const target = findUserById(
      req.params.id
    );

    if (
      !target ||
      !canManageUser(
        req.auth.user,
        target
      )
    ) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    if (target.role === "owner") {
      return res.status(403).json({
        ok: false,
        error: "Owner cannot be deleted."
      });
    }

    const descendants = db.users.filter(
      u =>
        u.parentId === target.id ||
        hierarchyContains(target.id, u.id)
    );

    if (
      req.auth.user.role === "admin" &&
      descendants.some(
        u => u.id !== target.id
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Remove subordinate users first."
      });
    }

    target.status = "blocked";
    target.deletedAt = iso();

    for (const session of db.sessions) {
      if (
        session.userId === target.id &&
        !session.revokedAt
      ) {
        session.revokedAt = iso();
      }
    }

    for (const key of db.keys) {
      if (key.creatorId === target.id) {
        key.status = "deleted";
        key.deletedAt = iso();
      }
    }

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "delete_user",
      "user",
      target.id
    );

    saveDatabase();

    res.json({
      ok: true,
      message: "User deleted."
    });
  }
);

app.post(
  "/api/users/:id/balance",
  requireAuth,
  (req, res) => {
    if (req.auth.user.role !== "owner") {
      return res.status(403).json({
        ok: false,
        error:
          "Only Owner can adjust balance."
      });
    }

    const target = findUserById(
      req.params.id
    );

    if (!target) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    const mode = cleanString(
      req.body.mode,
      20
    ).toLowerCase();

    const amount = safeNumber(
      req.body.amount,
      0
    );

    if (
      !["add", "subtract", "set"].includes(mode)
    ) {
      return res.status(400).json({
        ok: false,
        error: "Invalid balance mode."
      });
    }

    if (
      !Number.isFinite(amount) ||
      amount < 0 ||
      amount > 1000000000
    ) {
      return res.status(400).json({
        ok: false,
        error: "Invalid amount."
      });
    }

    if (mode === "add") {
      target.balance =
        safeNumber(target.balance) + amount;
    }

    if (mode === "subtract") {
      target.balance = Math.max(
        0,
        safeNumber(target.balance) - amount
      );
    }

    if (mode === "set") {
      target.balance = amount;
    }

    addTransaction(
      target,
      mode === "add"
        ? "credit"
        : "adjustment",
      mode === "add"
        ? amount
        : mode === "subtract"
        ? -amount
        : 0,
      "Owner balance adjustment",
      {
        actorId: req.auth.user.id,
        mode
      }
    );

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "balance_adjust",
      "user",
      target.id,
      {
        mode,
        amount,
        balanceAfter: target.balance
      }
    );

    saveDatabase();

    res.json({
      ok: true,
      user: sanitizeUser(target)
    });
  }
);

app.get(
  "/api/referrals",
  requireAuth,
  (req, res) => {
    const actor = req.auth.user;

    let referrals;

    if (actor.role === "owner") {
      referrals = db.referrals.slice();
    } else {
      referrals = db.referrals.filter(
        r =>
          r.ownerId === actor.id ||
          hierarchyContains(
            actor.id,
            r.ownerId
          )
      );
    }

    res.json({
      ok: true,
      referrals
    });
  }
);

app.get(
  "/api/users/:id/referral",
  requireAuth,
  (req, res) => {
    const target = findUserById(
      req.params.id
    );

    if (!target) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    const actor = req.auth.user;

    if (
      actor.role !== "owner" &&
      actor.id !== target.id &&
      !hierarchyContains(
        actor.id,
        target.id
      )
    ) {
      return res.status(403).json({
        ok: false,
        error: "Permission denied."
      });
    }

    const referral = referralForUser(
      target.id
    );

    res.json({
      ok: true,
      referral: referral || null
    });
  }
);
app.post(
  "/api/owner/enter-user/:id",
  requireAuth,
  requireRole("owner"),
  (req, res) => {
    const target = findUserById(
      req.params.id
    );

    if (!target) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    if (target.status !== "active") {
      return res.status(400).json({
        ok: false,
        error: "User is blocked."
      });
    }

    const ownerSession = req.auth.session;

    const session = createSession(
      target,
      req,
      ownerSession.id
    );

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "enter_user_panel",
      "user",
      target.id
    );

    saveDatabase();

    res.json({
      ok: true,
      token: session.token,
      user: sanitizeUser(target),
      ownerSessionId: ownerSession.id
    });
  }
);

app.post(
  "/api/auth/exit-user-panel",
  requireAuth,
  (req, res) => {
    const acting = req.auth.session;

    if (!acting.ownerSessionId) {
      return res.status(400).json({
        ok: false,
        error: "This is not an entered user session."
      });
    }

    const ownerSession = db.sessions.find(
      s =>
        s.id === acting.ownerSessionId &&
        !s.revokedAt &&
        s.expiresAt > now()
    );

    if (!ownerSession) {
      return res.status(401).json({
        ok: false,
        error: "Owner session is no longer valid."
      });
    }

    acting.revokedAt = iso();

    const owner = findUserById(
      ownerSession.userId
    );

    if (!owner) {
      return res.status(401).json({
        ok: false,
        error: "Owner account not found."
      });
    }

    addAuditLog(
      {
        id: owner.id,
        username: owner.username,
        ip: getClientIp(req)
      },
      "exit_user_panel",
      "user",
      req.auth.user.id
    );

    saveDatabase();

    res.json({
      ok: true,
      token: ownerSession.token,
      user: sanitizeUser(owner)
    });
  }
);

app.get(
  "/api/dashboard",
  requireAuth,
  (req, res) => {
    syncAllKeyStatuses();

    const actor = req.auth.user;

    let visibleUsers;
    let visibleKeys;

    if (actor.role === "owner") {
      visibleUsers = db.users;
      visibleKeys = db.keys;
    } else if (actor.role === "admin") {
      visibleUsers = db.users.filter(
        u =>
          u.id === actor.id ||
          hierarchyContains(
            actor.id,
            u.id
          )
      );

      visibleKeys = db.keys.filter(
        k =>
          k.creatorId === actor.id ||
          hierarchyContains(
            actor.id,
            k.creatorId
          )
      );
    } else {
      visibleUsers = [actor];
      visibleKeys = db.keys.filter(
        k => k.creatorId === actor.id
      );
    }

    const stats = {
      users: visibleUsers.length,
      admins: visibleUsers.filter(
        u => u.role === "admin"
      ).length,
      normalUsers: visibleUsers.filter(
        u => u.role === "user"
      ).length,
      totalKeys: visibleKeys.length,
      activeKeys: visibleKeys.filter(
        k => k.status === "active"
      ).length,
      blockedKeys: visibleKeys.filter(
        k => k.status === "blocked"
      ).length,
      expiredKeys: visibleKeys.filter(
        k => k.status === "expired"
      ).length,
      boundKeys: visibleKeys.filter(
        k =>
          db.devices.some(
            d => d.keyId === k.id
          )
      ).length,
      balance: safeNumber(actor.balance)
    };

    res.json({
      ok: true,
      stats,
      serverTime: iso(),
      loaderStatus:
        !!db.settings.loaderStatus
    });
  }
);

app.get(
  "/api/transactions",
  requireAuth,
  (req, res) => {
    const actor = req.auth.user;

    let list;

    if (actor.role === "owner") {
      list = db.transactions.slice();
    } else if (actor.role === "admin") {
      const ids = new Set(
        db.users
          .filter(
            u =>
              u.id === actor.id ||
              hierarchyContains(
                actor.id,
                u.id
              )
          )
          .map(u => u.id)
      );

      list = db.transactions.filter(
        t => ids.has(t.userId)
      );
    } else {
      list = db.transactions.filter(
        t => t.userId === actor.id
      );
    }

    list.sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

    res.json({
      ok: true,
      transactions: list.slice(0, 1000)
    });
  }
);

app.get(
  "/api/audit-logs",
  requireAuth,
  requireRole("owner"),
  (req, res) => {
    const search = cleanString(
      req.query.search,
      200
    ).toLowerCase();

    let logs = db.auditLogs.slice();

    if (search) {
      logs = logs.filter(log =>
        JSON.stringify(log)
          .toLowerCase()
          .includes(search)
      );
    }

    logs.sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

    res.json({
      ok: true,
      logs: logs.slice(0, 1000)
    });
  }
);

app.get(
  "/api/settings",
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,
      settings: {
        ...db.settings
      }
    });
  }
);

app.post(
  "/api/settings/update",
  requireAuth,
  requireRole("owner"),
  (req, res) => {
    const allowed = [
      "panelName",
      "panelVersion",
      "loaderName",
      "maintenanceMessage",
      "supportUrl",
      "theme",
      "sessionTimeoutHours",
      "passwordResetLimit",
      "passwordResetWindowHours",
      "deviceResetLimit",
      "deviceResetWindowHours",
      "optionalIpLock",
      "optionalGeoLock",
      "serverCountry",
      "serverRegion"
    ];

    for (const field of allowed) {
      if (
        Object.prototype.hasOwnProperty.call(
          req.body,
          field
        )
      ) {
        db.settings[field] =
          req.body[field];
      }
    }

    db.settings.sessionTimeoutHours =
      Math.max(
        1,
        Math.min(
          168,
          safeNumber(
            db.settings.sessionTimeoutHours,
            24
          )
        )
      );

    db.settings.passwordResetLimit =
      Math.max(
        1,
        Math.min(
          20,
          safeNumber(
            db.settings.passwordResetLimit,
            3
          )
        )
      );

    db.settings.deviceResetLimit =
      Math.max(
        1,
        Math.min(
          20,
          safeNumber(
            db.settings.deviceResetLimit,
            3
          )
        )
      );

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "update_settings",
      "settings",
      "global"
    );

    saveDatabase();

    res.json({
      ok: true,
      settings: db.settings
    });
  }
);

app.post(
  "/api/settings/loader",
  requireAuth,
  requireRole("owner"),
  (req, res) => {
    db.settings.loaderStatus =
      !!req.body.enabled;

    if (
      Object.prototype.hasOwnProperty.call(
        req.body,
        "maintenanceMessage"
      )
    ) {
      db.settings.maintenanceMessage =
        cleanString(
          req.body.maintenanceMessage,
          1000
        );
    }

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      db.settings.loaderStatus
        ? "loader_enable"
        : "loader_disable",
      "settings",
      "loader"
    );

    saveDatabase();

    res.json({
      ok: true,
      loaderStatus:
        !!db.settings.loaderStatus,
      maintenanceMessage:
        db.settings.maintenanceMessage
    });
  }
);

app.get(
  "/api/pricing",
  requireAuth,
  (req, res) => {
    res.json({
      ok: true,
      pricing: db.pricing
    });
  }
);

app.post(
  "/api/pricing/update",
  requireAuth,
  requireRole("owner"),
  (req, res) => {
    const pricing =
      req.body.pricing;

    if (
      !pricing ||
      typeof pricing !== "object"
    ) {
      return res.status(400).json({
        ok: false,
        error: "Invalid pricing data."
      });
    }

    for (const [key, value] of Object.entries(
      pricing
    )) {
      const hours = safeNumber(
        value?.hours,
        0
      );

      const price = safeNumber(
        value?.price,
        0
      );

      const label = cleanString(
        value?.label,
        100
      );

      if (
        !label ||
        hours <= 0 ||
        hours > 8760 ||
        price < 0 ||
        price > 100000000
      ) {
        return res.status(400).json({
          ok: false,
          error:
            `Invalid pricing for ${key}.`
        });
      }

      db.pricing[key] = {
        label,
        hours,
        price
      };
    }

    addAuditLog(
      {
        id: req.auth.user.id,
        username: req.auth.user.username,
        ip: getClientIp(req)
      },
      "update_pricing",
      "pricing",
      "global"
    );

    saveDatabase();

    res.json({
      ok: true,
      pricing: db.pricing
    });
  }
);
app.get(
  "/register",
  (req, res) => {
    res.type("html").send(
      REGISTRATION_HTML
    );
  }
);

const PANEL_HTML = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">
<title>Lexi Loader Panel</title>
<style>
:root{
 --bg:#090b10;
 --panel:#11151d;
 --panel2:#171c25;
 --line:#252c38;
 --text:#f3f5f8;
 --muted:#8d96a6;
 --accent:#f3c969;
 --danger:#ef6b73;
 --success:#64d69a;
}
*{box-sizing:border-box}
body{
 margin:0;
 background:var(--bg);
 color:var(--text);
 font-family:Arial,Helvetica,sans-serif;
}
button,input,select{
 font:inherit;
}
button{
 cursor:pointer;
}
.hidden{
 display:none!important;
}
#login{
 min-height:100vh;
 display:flex;
 align-items:center;
 justify-content:center;
 padding:20px;
}
.login-card{
 width:100%;
 max-width:410px;
 background:var(--panel);
 border:1px solid var(--line);
 border-radius:18px;
 padding:28px;
 box-shadow:0 20px 70px #0008;
}
.logo{
 font-size:22px;
 font-weight:800;
 letter-spacing:.3px;
}
.logo span{
 color:var(--accent);
}
.muted{
 color:var(--muted);
}
.field{
 margin-top:16px;
}
.field label{
 display:block;
 font-size:13px;
 color:var(--muted);
 margin-bottom:7px;
}
.field input,.field select{
 width:100%;
 padding:12px;
 color:var(--text);
 background:#0c1017;
 border:1px solid var(--line);
 border-radius:10px;
 outline:none;
}
.field input:focus,
.field select:focus{
 border-color:var(--accent);
}
.btn{
 border:1px solid var(--line);
 background:#191f29;
 color:var(--text);
 border-radius:10px;
 padding:10px 14px;
}
.btn:hover{
 border-color:#555f70;
}
.btn.primary{
 background:var(--accent);
 color:#111;
 border-color:var(--accent);
 font-weight:700;
}
.btn.danger{
 color:#ffdadd;
 border-color:#63343a;
}
.btn.success{
 color:#d7ffea;
 border-color:#315d48;
}
.full{
 width:100%;
}
#app{
 min-height:100vh;
 display:flex;
}
.sidebar{
 width:245px;
 border-right:1px solid var(--line);
 background:#0c0f15;
 padding:18px;
 position:fixed;
 top:0;
 bottom:0;
 left:0;
}
.nav{
 margin-top:28px;
 display:grid;
 gap:7px;
}
.nav button{
 text-align:left;
 background:transparent;
 color:#aeb7c5;
 border:0;
 padding:12px;
 border-radius:9px;
}
.nav button.active,
.nav button:hover{
 background:#171c25;
 color:#fff;
}
.main{
 margin-left:245px;
 width:calc(100% - 245px);
 padding:20px;
}
.topbar{
 display:flex;
 justify-content:space-between;
 align-items:center;
 gap:15px;
 border-bottom:1px solid var(--line);
 padding-bottom:16px;
}
.top-actions{
 display:flex;
 gap:8px;
 flex-wrap:wrap;
}
.page{
 display:none;
}
.page.active{
 display:block;
}
.grid{
 display:grid;
 gap:14px;
}
.stats{
 grid-template-columns:
 repeat(auto-fit,minmax(160px,1fr));
 margin-top:20px;
}
.card{
 background:var(--panel);
 border:1px solid var(--line);
 border-radius:14px;
 padding:17px;
}
.stat-value{
 font-size:27px;
 font-weight:800;
 margin-top:8px;
}
.toolbar{
 display:flex;
 gap:8px;
 flex-wrap:wrap;
 margin:18px 0;
}
.toolbar input,.toolbar select{
 background:#0d1118;
 color:#fff;
 border:1px solid var(--line);
 border-radius:9px;
 padding:10px;
}
.table-wrap{
 overflow:auto;
 border:1px solid var(--line);
 border-radius:13px;
}
table{
 width:100%;
 border-collapse:collapse;
 min-width:850px;
}
th,td{
 text-align:left;
 padding:12px;
 border-bottom:1px solid var(--line);
 font-size:13px;
}
th{
 color:var(--muted);
 background:#0d1118;
}
.badge{
 display:inline-block;
 padding:4px 8px;
 border-radius:20px;
 font-size:11px;
 border:1px solid var(--line);
}
.badge.active{
 color:var(--success);
}
.badge.blocked{
 color:var(--danger);
}
.badge.expired{
 color:#d4b9ff;
}
.modal{
 position:fixed;
 inset:0;
 background:#000b;
 display:flex;
 align-items:center;
 justify-content:center;
 padding:18px;
 z-index:20;
}
.modal-box{
 width:100%;
 max-width:550px;
 max-height:90vh;
 overflow:auto;
 background:var(--panel);
 border:1px solid var(--line);
 border-radius:16px;
 padding:20px;
}
.modal-head{
 display:flex;
 justify-content:space-between;
 align-items:center;
 margin-bottom:10px;
}
.key-output{
 background:#080b10;
 border:1px solid var(--line);
 border-radius:10px;
 padding:12px;
 margin-top:12px;
 white-space:pre-wrap;
 word-break:break-all;
}
.notice{
 padding:12px;
 border-radius:10px;
 background:#171c25;
 color:#c5cbd5;
 margin-top:12px;
}
@media(max-width:800px){
 .sidebar{
  width:70px;
  padding:10px;
 }
 .sidebar .brand-text,
 .sidebar .user-info,
 .nav button span{
  display:none;
 }
 .main{
  margin-left:70px;
  width:calc(100% - 70px);
  padding:12px;
 }
}
</style>
</head>
<body>

<div id="login">
 <div class="login-card">
  <div class="logo">
   Lexi <span>Loader</span>
  </div>
  <p class="muted">
   Reseller & License Management Panel
  </p>

  <form id="loginForm">
   <div class="field">
    <label>Username</label>
    <input id="loginUser"
     autocomplete="username" required>
   </div>

   <div class="field">
    <label>Password</label>
    <input id="loginPass"
     type="password"
     autocomplete="current-password"
     required>
   </div>

   <div class="field">
    <button class="btn primary full">
     Login
    </button>
   </div>

   <div class="field">
    <button type="button"
     class="btn full"
     onclick="showReset()">
     Reset Password
    </button>
   </div>

   <div id="loginMsg" class="notice hidden"></div>
  </form>
 </div>
</div>

<div id="app" class="hidden">

<aside class="sidebar">
 <div class="logo brand-text">
  Lexi <span>Loader</span>
 </div>

 <div id="sideUser"
  class="muted user-info"
  style="margin-top:8px">
 </div>

 <div class="nav">
  <button onclick="page('dashboard')">
   <span>Dashboard</span>
  </button>
  <button onclick="page('keys')">
   <span>Keys</span>
  </button>
  <button id="usersNav"
   onclick="page('users')">
   <span>Users</span>
  </button>
  <button onclick="page('referrals')">
   <span>Referrals</span>
  </button>
  <button id="settingsNav"
   onclick="page('settings')">
   <span>Settings</span>
  </button>
  <button id="pricingNav"
   onclick="page('pricing')">
   <span>Pricing</span>
  </button>
 </div>
</aside>

<main class="main">

<header class="topbar">
 <div>
  <div id="pageTitle"
   style="font-size:21px;font-weight:800">
   Dashboard
  </div>
  <div id="serverClock"
   class="muted"></div>
 </div>

 <div class="top-actions">
  <button class="btn"
   onclick="toggleTheme()">
   Theme
  </button>
  <button class="btn"
   onclick="changePassword()">
   Password
  </button>
  <button id="returnOwner"
   class="btn primary hidden"
   onclick="returnOwnerPanel()">
   Return to Owner
  </button>
  <button class="btn"
   onclick="logout()">
   Logout
  </button>
 </div>
</header>

<section id="dashboard"
 class="page active">
 <div class="grid stats">
  <div class="card">
   <div class="muted">Users</div>
   <div id="sUsers"
    class="stat-value">0</div>
  </div>
  <div class="card">
   <div class="muted">Keys</div>
   <div id="sKeys"
    class="stat-value">0</div>
  </div>
  <div class="card">
   <div class="muted">Active Keys</div>
   <div id="sActive"
    class="stat-value">0</div>
  </div>
  <div class="card">
   <div class="muted">Bound Keys</div>
   <div id="sBound"
    class="stat-value">0</div>
  </div>
  <div class="card">
   <div class="muted">Balance</div>
   <div id="sBalance"
    class="stat-value">₹0</div>
  </div>
 </div>

 <div class="card"
  style="margin-top:14px">
  <div style="font-weight:700">
   Loader Status
  </div>
  <div id="loaderStatus"
   class="notice"></div>
 </div>
</section>

<section id="keys"
 class="page">
 <div class="toolbar">
  <button class="btn primary"
   onclick="openGenerate()">
   Generate Keys
  </button>
  <input id="keySearch"
   placeholder="Search license / HWID">
  <select id="keyStatus">
   <option value="">All Status</option>
   <option value="active">Active</option>
   <option value="blocked">Blocked</option>
   <option value="expired">Expired</option>
   <option value="deleted">Deleted</option>
  </select>
  <select id="keyBinding">
   <option value="">All Devices</option>
   <option value="bound">Bound</option>
   <option value="unbound">Unbound</option>
  </select>
  <button class="btn"
   onclick="loadKeys()">
   Refresh
  </button>
 </div>

 <div class="table-wrap">
  <table>
   <thead>
    <tr>
     <th>License</th>
     <th>Creator</th>
     <th>Duration</th>
     <th>Devices</th>
     <th>Expiry</th>
     <th>Status</th>
     <th>Actions</th>
    </tr>
   </thead>
   <tbody id="keysBody"></tbody>
  </table>
 </div>
</section>

<section id="users"
 class="page">
 <div class="toolbar">
  <button class="btn primary"
   onclick="openCreateUser()">
   Create User
  </button>
  <input id="userSearch"
   placeholder="Search username / User ID">
  <select id="userRole">
   <option value="">All Roles</option>
   <option value="owner">Owner</option>
   <option value="admin">Admin</option>
   <option value="user">Normal User</option>
  </select>
  <button class="btn"
   onclick="loadUsers()">
   Refresh
  </button>
 </div>

 <div class="table-wrap">
  <table>
   <thead>
    <tr>
     <th>User</th>
     <th>ID</th>
     <th>Role</th>
     <th>Balance</th>
     <th>Status</th>
     <th>Created</th>
     <th>Actions</th>
    </tr>
   </thead>
   <tbody id="usersBody"></tbody>
  </table>
 </div>
</section>

<section id="referrals"
 class="page">
 <div class="card">
  <h3>Referral Links</h3>
  <div id="referralList"></div>
 </div>
</section>

<section id="settings"
 class="page">
 <div class="card">
  <h3>Global Settings</h3>

  <div class="field">
   <label>Panel Name</label>
   <input id="setPanelName">
  </div>

  <div class="field">
   <label>Panel Version</label>
   <input id="setVersion">
  </div>

  <div class="field">
   <label>Loader Name</label>
   <input id="setLoaderName">
  </div>

  <div class="field">
   <label>Maintenance Message</label>
   <input id="setMaintenance">
  </div>

  <div class="field">
   <label>Support URL</label>
   <input id="setSupport">
  </div>

  <div class="field">
   <label>Optional IP Lock</label>
   <select id="setIp">
    <option value="false">Disabled</option>
    <option value="true">Enabled</option>
   </select>
  </div>

  <div class="field">
   <label>Optional Geo Lock</label>
   <select id="setGeo">
    <option value="false">Disabled</option>
    <option value="true">Enabled</option>
   </select>
  </div>

  <div class="field">
   <button class="btn primary"
    onclick="saveSettings()">
    Save Settings
   </button>
  </div>

  <div class="field">
   <button id="loaderToggle"
    class="btn"
    onclick="toggleLoader()">
    Toggle Loader
   </button>
  </div>
 </div>
</section>

<section id="pricing"
 class="page">
 <div class="card">
  <h3>Pricing</h3>
  <div id="pricingBox"></div>
  <button class="btn primary"
   onclick="savePricing()">
   Save Pricing
  </button>
 </div>
</section>

</main>
</div>

<div id="modal"
 class="modal hidden">
 <div class="modal-box">
  <div class="modal-head">
   <strong id="modalTitle">
    Modal
   </strong>
   <button class="btn"
    onclick="closeModal()">
    Close
   </button>
  </div>
  <div id="modalBody"></div>
 </div>
</div>

<script>
let token =
 localStorage.getItem("lexi_token") || "";

let ownerToken =
 localStorage.getItem("lexi_owner_token") || "";

let currentUser = null;
let serverOffset = 0;

function esc(value){
 return String(value ?? "")
  .replaceAll("&","&amp;")
  .replaceAll("<","&lt;")
  .replaceAll(">","&gt;")
  .replaceAll('"',"&quot;")
  .replaceAll("'","&#039;");
}

async function api(url, options={}){
 const headers = {
  "Content-Type":"application/json",
  ...(options.headers || {})
 };

 if(token){
  headers.Authorization =
   "Bearer " + token;
 }

 const response = await fetch(
  url,
  {...options,headers}
 );

 let data;

 try{
  data = await response.json();
 }catch{
  data = {
   ok:false,
   error:"Invalid server response."
  };
 }

 if(response.status === 401){
  logout(false);
 }

 if(!response.ok && !data.error){
  data.error = "Request failed.";
 }

 return data;
}

function page(name){
 document
  .querySelectorAll(".page")
  .forEach(x=>x.classList.remove("active"));

 const target =
  document.getElementById(name);

 if(target){
  target.classList.add("active");
 }

 document
  .querySelectorAll(".nav button")
  .forEach(x=>x.classList.remove("active"));

 const title = {
  dashboard:"Dashboard",
  keys:"Keys",
  users:"Users",
  referrals:"Referrals",
  settings:"Settings",
  pricing:"Pricing"
 }[name] || "Dashboard";

 document.getElementById(
  "pageTitle"
 ).textContent = title;

 if(name === "dashboard") loadDashboard();
 if(name === "keys") loadKeys();
 if(name === "users") loadUsers();
 if(name === "referrals") loadReferrals();
 if(name === "settings") loadSettings();
 if(name === "pricing") loadPricing();
}

function openModal(title,html){
 document.getElementById(
  "modalTitle"
 ).textContent = title;

 document.getElementById(
  "modalBody"
 ).innerHTML = html;

 document.getElementById(
  "modal"
 ).classList.remove("hidden");
}

function closeModal(){
 document.getElementById(
  "modal"
 ).classList.add("hidden");
}

function message(text){
 alert(String(text));
}

function formatDate(value){
 if(!value) return "-";

 return new Date(value)
  .toLocaleString();
}

function updateClock(serverTime){
 if(serverTime){
  serverOffset =
   new Date(serverTime).getTime()
   - Date.now();
 }
}

function clock(){
 const time =
  new Date(Date.now()+serverOffset);

 document.getElementById(
  "serverClock"
 ).textContent =
  time.toLocaleString();
}

setInterval(clock,1000);

document.getElementById(
 "loginForm"
).addEventListener("submit",
 async e=>{
  e.preventDefault();

  const data = await api(
   "/api/auth/login",
   {
    method:"POST",
    body:JSON.stringify({
     username:
      document.getElementById(
       "loginUser"
      ).value,
     password:
      document.getElementById(
       "loginPass"
      ).value
    })
   }
  );

  if(!data.ok){
   const box =
    document.getElementById("loginMsg");

   box.textContent =
    data.error || "Login failed.";

   box.classList.remove("hidden");
   return;
  }

  token = data.token;
  currentUser = data.user;

  localStorage.setItem(
   "lexi_token",
   token
  );

  if(
   currentUser.role === "owner" &&
   !ownerToken
  ){
   ownerToken = token;
   localStorage.setItem(
    "lexi_owner_token",
    ownerToken
   );
  }

  updateClock(data.expiresAt);
  showApp();
 });

function showApp(){
 document.getElementById(
  "login"
 ).classList.add("hidden");

 document.getElementById(
  "app"
 ).classList.remove("hidden");

 document.getElementById(
  "sideUser"
 ).textContent =
  currentUser.username +
  " · " +
  currentUser.role;

 document.getElementById(
  "usersNav"
 ).classList.toggle(
  "hidden",
  currentUser.role === "user"
 );

 document.getElementById(
  "settingsNav"
 ).classList.toggle(
  "hidden",
  currentUser.role !== "owner"
 );

 document.getElementById(
  "pricingNav"
 ).classList.toggle(
  "hidden",
  currentUser.role !== "owner"
 );

 document.getElementById(
  "returnOwner"
 ).classList.toggle(
  "hidden",
  currentUser.role === "owner" ||
  !ownerToken
 );

 page("dashboard");
}

function logout(callServer=true){
 if(callServer && token){
  fetch("/api/auth/logout",{
   method:"POST",
   headers:{
    Authorization:
     "Bearer "+token
   }
  }).catch(()=>{});
 }

 token = "";
 currentUser = null;

 localStorage.removeItem(
  "lexi_token"
 );

 document.getElementById(
  "app"
 ).classList.add("hidden");

 document.getElementById(
  "login"
 ).classList.remove("hidden");
}

async function restore(){
 if(!token) return;

 const data =
  await api("/api/auth/me");

 if(!data.ok){
  logout(false);
  return;
 }

 currentUser = data.user;

 updateClock(
  data.session?.expiresAt
 );

 showApp();
}

async function loadDashboard(){
 const data =
  await api("/api/dashboard");

 if(!data.ok) return;

 const s = data.stats;

 document.getElementById(
  "sUsers"
 ).textContent = s.users;

 document.getElementById(
  "sKeys"
 ).textContent = s.totalKeys;

 document.getElementById(
  "sActive"
 ).textContent = s.activeKeys;

 document.getElementById(
  "sBound"
 ).textContent = s.boundKeys;

 document.getElementById(
  "sBalance"
 ).textContent =
  "₹"+Number(s.balance).toLocaleString();

 updateClock(data.serverTime);

 document.getElementById(
  "loaderStatus"
 ).textContent =
  data.loaderStatus
   ? "Loader is ON."
   : "Loader is OFF / maintenance mode.";
}

async function loadKeys(){
 const search =
  document.getElementById(
   "keySearch"
  ).value;

 const status =
  document.getElementById(
   "keyStatus"
  ).value;

 const binding =
  document.getElementById(
   "keyBinding"
  ).value;

 const query = new URLSearchParams();

 if(search) query.set(
  "search",search
 );

 if(status) query.set(
  "status",status
 );

 if(binding) query.set(
  "binding",binding
 );

 const data =
  await api(
   "/api/keys?"+query.toString()
  );

 if(!data.ok){
  message(data.error);
  return;
 }

 const body =
  document.getElementById(
   "keysBody"
  );

 body.innerHTML =
  data.keys.map(k=>{
   const devices =
    k.devices || [];

   const actions = [];

   actions.push(
    '<button class="btn" onclick="copyText('+
    JSON.stringify(k.license)+
    ')">Copy</button>'
   );

   actions.push(
    '<button class="btn" onclick="keyDetails('+
    JSON.stringify(k.id)+
    ')">Details</button>'
   );

   if(k.status === "blocked"){
    actions.push(
     '<button class="btn success" onclick="keyAction('+
     JSON.stringify(k.id)+
     ',"unblock")">Unblock</button>'
    );
   }else if(k.status !== "deleted"){
    actions.push(
     '<button class="btn" onclick="keyAction('+
     JSON.stringify(k.id)+
     ',"block")">Block</button>'
    );
   }

   if(k.status !== "deleted"){
    actions.push(
     '<button class="btn" onclick="resetDevice('+
     JSON.stringify(k.id)+
     ')">Reset</button>'
    );

    actions.push(
     '<button class="btn danger" onclick="deleteKey('+
     JSON.stringify(k.id)+
     ')">Delete</button>'
    );
   }

   return '<tr>'+
    '<td>'+esc(k.license)+'</td>'+
    '<td>'+esc(k.creatorUsername)+'</td>'+
    '<td>'+esc(k.durationHours)+'h</td>'+
    '<td>'+devices.length+
      ' / '+esc(k.deviceLimit)+'</td>'+
    '<td>'+esc(formatDate(k.expiresAt))+
      '</td>'+
    '<td><span class="badge '+
      esc(k.status)+'">'+
      esc(k.status)+'</span></td>'+
    '<td>'+actions.join(" ")+'</td>'+
    '</tr>';
  }).join("");
}

async function keyAction(id,action){
 const data =
  await api(
   "/api/keys/"+encodeURIComponent(id)+
   "/"+action,
   {method:"POST"}
  );

 if(!data.ok){
  message(data.error);
  return;
 }

 loadKeys();
}

async function deleteKey(id){
 if(!confirm(
  "Delete this key?"
 )) return;

 const data =
  await api(
   "/api/keys/"+encodeURIComponent(id),
   {method:"DELETE"}
  );

 if(!data.ok){
  message(data.error);
  return;
 }

 loadKeys();
}

async function resetDevice(id){
 if(!confirm(
  "Reset all device bindings for this key?"
 )) return;

 const data =
  await api(
   "/api/keys/"+encodeURIComponent(id)+
   "/reset-device",
   {method:"POST"}
  );

 if(!data.ok){
  message(data.error);
  return;
 }

 message(
  "Device binding reset. Remaining: "+
  data.remaining
 );

 loadKeys();
}
</script>
</body>
</html>`;
const REGISTRATION_HTML = String.raw`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">
<title>Lexi Loader Registration</title>
<style>
body{
 margin:0;
 min-height:100vh;
 display:flex;
 align-items:center;
 justify-content:center;
 background:#090b10;
 color:#fff;
 font-family:Arial,sans-serif;
 padding:20px;
}
.box{
 width:100%;
 max-width:420px;
 background:#11151d;
 border:1px solid #252c38;
 border-radius:16px;
 padding:25px;
}
h2{margin-top:0}
label{
 display:block;
 margin-top:15px;
 color:#8d96a6;
 font-size:13px;
}
input{
 width:100%;
 box-sizing:border-box;
 margin-top:7px;
 padding:12px;
 border-radius:9px;
 border:1px solid #252c38;
 background:#0c1017;
 color:#fff;
}
button{
 width:100%;
 margin-top:18px;
 padding:12px;
 border-radius:9px;
 border:0;
 background:#f3c969;
 color:#111;
 font-weight:700;
 cursor:pointer;
}
#msg{
 margin-top:15px;
 color:#aeb7c5;
 white-space:pre-wrap;
}
</style>
</head>
<body>
<div class="box">
<h2>Lexi Loader</h2>
<div>
Create your account using the referral link.
</div>

<form id="reg">
<label>Username</label>
<input id="u" required minlength="3">

<label>Password</label>
<input id="p" type="password"
 required minlength="8">

<button>Create Account</button>
</form>

<div id="msg"></div>
</div>

<script>
const params =
 new URLSearchParams(location.search);

const ref =
 params.get("ref") || "";

const form =
 document.getElementById("reg");

form.addEventListener(
 "submit",
 async e=>{
  e.preventDefault();

  const response =
   await fetch("/api/register",{
    method:"POST",
    headers:{
     "Content-Type":
      "application/json"
    },
    body:JSON.stringify({
     username:
      document.getElementById("u").value,
     password:
      document.getElementById("p").value,
     referralCode:ref
    })
   });

  const data =
   await response.json();

  document.getElementById(
   "msg"
  ).textContent =
   data.ok
    ? "Account created successfully. You can now login."
    : (data.error ||
       "Registration failed.");
 });
</script>
</body>
</html>`;

app.post(
  "/api/register",
  (req, res) => {
    try {
      const referralCode =
        cleanString(
          req.body.referralCode,
          100
        );

      if (!referralCode) {
        return res.status(400).json({
          ok: false,
          error:
            "A valid referral link is required."
        });
      }

      const referral =
        db.referrals.find(
          r => r.code === referralCode
        );

      if (!referral) {
        return res.status(400).json({
          ok: false,
          error: "Invalid referral code."
        });
      }

      const parent =
        findUserById(
          referral.ownerId
        );

      if (!parent) {
        return res.status(400).json({
          ok: false,
          error:
            "Referral owner no longer exists."
        });
      }

      if (parent.status !== "active") {
        return res.status(400).json({
          ok: false,
          error:
            "Referral owner is inactive."
        });
      }

      const user =
        createUser({
          username:
            req.body.username,
          password:
            req.body.password,
          role: "user",
          parentId: parent.id
        });

      const newReferral = {
        id: nextId("referral", "REF"),
        code: createReferralCode(),
        ownerId: user.id,
        ownerUsername: user.username,
        parentId: parent.id,
        createdAt: iso()
      };

      db.referrals.push(
        newReferral
      );

      user.referralCode =
        newReferral.code;

      addAuditLog(
        {
          id: user.id,
          username: user.username,
          ip: getClientIp(req)
        },
        "register",
        "user",
        user.id,
        {
          parentId: parent.id
        }
      );

      saveDatabase();

      res.json({
        ok: true,
        message:
          "Account created successfully.",
        user: sanitizeUser(user)
      });
    } catch (error) {
      res.status(400).json({
        ok: false,
        error:
          error.message ||
          "Registration failed."
      });
    }
  }
);

app.get(
  "/",
  (req, res) => {
    res.type("html").send(
      PANEL_HTML
    );
  }
);

app.get(
  "/panel",
  (req, res) => {
    res.type("html").send(
      PANEL_HTML
    );
  }
);

const rateMap = new Map();

function rateLimit(
  windowMs,
  maxRequests
) {
  return (req, res, next) => {
    const ip = getClientIp(req);
    const key =
      ip + ":" + req.path;

    const current =
      rateMap.get(key);

    const time = now();

    if (
      !current ||
      time - current.started >= windowMs
    ) {
      rateMap.set(key,{
        started:time,
        count:1
      });

      return next();
    }

    current.count++;

    if (
      current.count > maxRequests
    ) {
      return res.status(429).json({
        ok:false,
        error:
          "Too many requests. Try again later."
      });
    }

    next();
  };
}

app.use(
  "/api/auth/login",
  rateLimit(60 * 1000, 20)
);

app.use(
  "/api/auth/reset-password",
  rateLimit(60 * 1000, 10)
);

app.use((req,res,next)=>{
  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "DENY"
  );

  res.setHeader(
    "Referrer-Policy",
    "no-referrer"
  );

  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );

  next();
});

app.use(
  "/api",
  rateLimit(
    60 * 1000,
    300
  )
);

app.use(
  (req,res)=>{
    if(req.path.startsWith("/api/")){
      return res.status(404).json({
        ok:false,
        error:"API endpoint not found."
      });
    }

    res.status(404).type("html").send(
      "<h1>404</h1><p>Page not found.</p>"
    );
  }
);

app.use(
  (error,req,res,next)=>{
    console.error(
      "Unhandled error:",
      error
    );

    if(res.headersSent){
      return next(error);
    }

    res.status(500).json({
      ok:false,
      error:"Internal server error."
    });
  }
);

setInterval(()=>{
  const current = now();

  db.sessions =
    db.sessions.filter(
      s =>
        !s.revokedAt &&
        s.expiresAt > current
    );

  let changed = false;

  for(const key of db.keys){
    if(syncKeyStatus(key)){
      changed = true;
    }
  }

  if(changed){
    saveDatabase();
  }
},60 * 1000);

setInterval(()=>{
  const cutoff =
    now() -
    2 * 60 * 60 * 1000;

  for(
    const [key,value]
    of rateMap.entries()
  ){
    if(
      value.started < cutoff
    ){
      rateMap.delete(key);
    }
  }
},10 * 60 * 1000);

process.on(
  "SIGINT",
  ()=>{
    try{
      saveDatabase();
    }finally{
      process.exit(0);
    }
  }
);

process.on(
  "SIGTERM",
  ()=>{
    try{
      saveDatabase();
    }finally{
      process.exit(0);
    }
  }
);

app.listen(
  PORT,
  HOST,
  ()=>{
    console.log(
      `Lexi Loader running on ${HOST}:${PORT}`
    );
    console.log(
      `Panel: http://localhost:${PORT}/panel`
    );
    console.log(
      `Register: http://localhost:${PORT}/register`
    );
  }
);
