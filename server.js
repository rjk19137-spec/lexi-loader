const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const DB_FILE = path.join(__dirname, 'database.json');

if (!fs.existsSync(DB_FILE)) {
    const initialData = {
        settings: { loaderStatus: true, maintenanceMsg: "Lexi Loader is currently under maintenance." },
        users: [
            { username: "owner", password: "ownerpassword", role: "owner", balance: 99999, parent: null, resetChances: 3, lastResetTime: 0 }
        ],
        keys: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
}

function readDB() {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

const PRICING = {
    "3h": { hours: 3, cost: 10 },
    "1d": { hours: 24, cost: 100 },
    "3d": { hours: 72, cost: 200 },
    "7d": { hours: 168, cost: 350 },
    "15d": { hours: 360, cost: 500 },
    "30d": { hours: 720, cost: 750 },
    "60d": { hours: 1440, cost: 1000 }
};

app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lexi Loader - Secure Access</title>
        <style>
            :root {
                --bg-color: #0b0f19;
                --card-bg: #111827;
                --border-color: #1f2937;
                --text-color: #ffffff;
                --text-muted: #9ca3af;
                --accent-blue: #6366f1;
                --accent-blue-hover: #4f46e5;
                --accent-red: #ef4444;
                --accent-green: #10b981;
            }
            body { background-color: var(--bg-color); color: var(--text-color); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 15px; display: flex; justify-content: center; align-items: center; min-height: 100vh; box-sizing: border-box; }
            .container { width: 100%; max-width: 420px; }
            .card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 16px; padding: 25px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); box-sizing: border-box; }
            .brand-header { text-align: center; margin-bottom: 20px; }
            .brand-header h2 { margin: 10px 0 5px 0; font-size: 22px; font-weight: 700; color: #fff; }
            .brand-header p { margin: 0; font-size: 13px; color: var(--text-muted); }
            
            .tabs { display: flex; justify-content: center; gap: 15px; border-bottom: 1px solid var(--border-color); margin-bottom: 20px; padding-bottom: 10px; }
            .tab-btn { background: none; border: none; color: var(--text-muted); font-size: 14px; font-weight: 600; cursor: pointer; padding: 5px 10px; transition: color 0.2s; }
            .tab-btn.active { color: var(--accent-blue); border-bottom: 2px solid var(--accent-blue); }

            .form-group { margin-bottom: 15px; position: relative; }
            label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
            input, select { width: 100%; padding: 12px 14px; background: #0b0f19; color: var(--text-color); border: 1px solid var(--border-color); border-radius: 10px; box-sizing: border-box; font-size: 14px; outline: none; transition: border-color 0.2s; }
            input:focus, select:focus { border-color: var(--accent-blue); }
            
            .password-wrapper { position: relative; }
            .password-wrapper span { position: absolute; right: 14px; top: 14px; cursor: pointer; font-size: 16px; color: var(--text-muted); }

            .btn-primary { width: 100%; padding: 12px; background: var(--accent-blue); color: #fff; border: none; border-radius: 10px; font-weight: 600; font-size: 14px; cursor: pointer; transition: background 0.2s; margin-top: 5px; box-sizing: border-box; }
            .btn-primary:hover { background: var(--accent-blue-hover); }
            .btn-danger { background: var(--accent-red); }

            .support-link { text-align: center; margin-top: 20px; font-size: 13px; }
            .support-link a { color: var(--text-muted); text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 6px; }
            .support-link a:hover { color: #fff; }

            .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
            .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px; }
            .stat-box { background: #0b0f19; border: 1px solid var(--border-color); padding: 15px; border-radius: 12px; text-align: center; }
            .stat-box span { font-size: 18px; font-weight: bold; color: var(--accent-blue); }
            .key-card, .user-card { background: #0b0f19; border: 1px solid var(--border-color); border-radius: 10px; padding: 12px; margin-bottom: 10px; font-size: 13px; }
            .flex-row { display: flex; justify-content: space-between; align-items: center; }
            .badge { padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
            .badge.active { background: rgba(16,185,129,0.15); color: var(--accent-green); }
            .badge.expired { background: rgba(239,68,68,0.15); color: var(--accent-red); }
            .badge.blocked { background: rgba(245,158,11,0.15); color: #f59e0b; }
            .action-buttons { display: flex; gap: 6px; margin-top: 8px; }
            .action-buttons button { padding: 6px 10px; font-size: 11px; border-radius: 6px; border: none; cursor: pointer; font-weight: 600; color: #fff; }
            .btn-secondary { background: #374151; }
            .btn-warning { background: #f59e0b; color: #000; }
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Auth Card -->
            <div id="auth-card" class="card">
                <div class="brand-header">
                    <h2>🛡️ Lexi Loader</h2>
                    <p>Secure access to your account</p>
                </div>

                <div class="tabs">
                    <button class="tab-btn active" onclick="switchTab('login', event)">Login</button>
                    <button class="tab-btn" onclick="switchTab('register', event)">Register</button>
                    <button class="tab-btn" onclick="switchTab('reset', event)">Reset</button>
                </div>

                <!-- Login Form -->
                <div id="tab-login">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="login-username" placeholder="Enter username">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="login-password" placeholder="Enter password">
                            <span id="login-eye" onclick="togglePassword('login-password', 'login-eye')">👁️</span>
                        </div>
                    </div>
                    <button class="btn-primary" onclick="login()">Login</button>
                </div>

                <!-- Register Form -->
                <div id="tab-register" style="display:none;">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="reg-username" placeholder="Choose username">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="reg-password" placeholder="Choose password">
                            <span id="reg-eye" onclick="togglePassword('reg-password', 'reg-eye')">👁️</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Referral / Invite Token</label>
                        <input type="text" id="reg-token" placeholder="Required for registration">
                    </div>
                    <button class="btn-primary" onclick="registerUser()">Register</button>
                </div>

                <!-- Reset Form -->
                <div id="tab-reset" style="display:none;">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="reset-username" placeholder="Enter username">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <div class="password-wrapper">
                            <input type="password" id="reset-password" placeholder="Enter password">
                            <span id="reset-eye" onclick="togglePassword('reset-password', 'reset-eye')">👁️</span>
                        </div>
                    </div>
                    <button class="btn-primary btn-danger" onclick="resetDevice()">Reset Device Binding</button>
                    <p style="font-size:11px; color:var(--text-muted); text-align:center; margin-top:10px;">Limit: 3 resets per 24 hours</p>
                </div>

                <div class="support-link">
                    <a href="https://t.me/" target="_blank">✈️ Contact Support</a>
                </div>
            </div>

            <!-- Dashboard Panel -->
            <div id="dashboard" class="card" style="display:none; max-width: 500px;">
                <div class="top-bar">
                    <div>
                        <h3 id="welcome-text" style="margin:0; font-size:18px;"></h3>
                        <span id="role-text" style="font-size:11px; color:var(--text-muted);"></span>
                    </div>
                    <button onclick="logout()" class="btn-primary btn-danger" style="width:auto; padding:6px 12px; margin:0; font-size:12px;">Logout</button>
                </div>

                <div class="stats-grid">
                    <div class="stat-box">
                        <div style="font-size:11px; color:var(--text-muted);">BALANCE</div>
                        <span id="stat-balance">0</span>
                    </div>
                    <div class="stat-box">
                        <div style="font-size:11px; color:var(--text-muted);">ACTIVE KEYS</div>
                        <span id="stat-keys">0</span>
                    </div>
                </div>

                <div id="user-mgmt-section" style="display:none; margin-bottom:15px; background:#0b0f19; padding:12px; border-radius:10px; border:1px solid var(--border-color);">
                    <h4 style="margin:0 0 8px 0; font-size:13px;">Create Sub-User / Reseller</h4>
                    <input type="text" id="new-username" placeholder="Username" style="margin-bottom:6px;">
                    <input type="password" id="new-password" placeholder="Password" style="margin-bottom:6px;">
                    <select id="new-role" style="margin-bottom:6px;">
                        <option value="admin">Admin</option>
                        <option value="limited">Limited Reseller</option>
                    </select>
                    <input type="number" id="new-balance" placeholder="Initial Balance" value="0" style="margin-bottom:6px;">
                    <button class="btn-primary" onclick="createUser()" style="padding:8px;">Create User</button>
                </div>

                <div style="margin-bottom:15px; background:#0b0f19; padding:12px; border-radius:10px; border:1px solid var(--border-color);">
                    <h4 style="margin:0 0 8px 0; font-size:13px;">Generate License Key</h4>
                    <select id="duration" style="margin-bottom:6px;">
                        <option value="3h">3 Hours (10 Bal)</option>
                        <option value="1d">1 Day (100 Bal)</option>
                        <option value="3d">3 Days (200 Bal)</option>
                        <option value="7d">7 Days (350 Bal)</option>
                        <option value="15d">15 Days (500 Bal)</option>
                        <option value="30d">30 Days (750 Bal)</option>
                        <option value="60d">60 Days (1000 Bal)</option>
                    </select>
                    <div style="display:flex; gap:6px; margin-bottom:6px;">
                        <input type="number" id="key-count" placeholder="Count" value="1" min="1">
                        <input type="number" id="device-limit" placeholder="Devices" value="1" min="1">
                    </div>
                    <button class="btn-primary" onclick="generateKeys()" style="padding:8px;">Generate Key</button>
                </div>

                <div>
                    <h4 style="margin:0 0 8px 0; font-size:13px;">Manage Keys</h4>
                    <input type="text" id="search-keys" placeholder="Search Keys or HWID..." onkeyup="loadDashboard()" style="margin-bottom:8px;">
                    <div id="keys-list" style="max-height:200px; overflow-y:auto;"></div>
                </div>

                <div id="users-list-card" style="display:none; margin-top:15px;">
                    <h4 style="margin:0 0 8px 0; font-size:13px;">Users List</h4>
                    <div id="users-list" style="max-height:150px; overflow-y:auto;"></div>
                </div>
            </div>
        </div>

        <script>
            let token = localStorage.getItem('token');
            if(token) fetchDashboard();

            function switchTab(tab, event) {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.getElementById('tab-login').style.display = 'none';
                document.getElementById('tab-register').style.display = 'none';
                document.getElementById('tab-reset').style.display = 'none';

                if(tab === 'login') {
                    document.getElementById('tab-login').style.display = 'block';
                    event.currentTarget.classList.add('active');
                } else if(tab === 'register') {
                    document.getElementById('tab-register').style.display = 'block';
                    event.currentTarget.classList.add('active');
                } else if(tab === 'reset') {
                    document.getElementById('tab-reset').style.display = 'block';
                    event.currentTarget.classList.add('active');
                }
            }

            function togglePassword(inputId, iconId) {
                let p = document.getElementById(inputId);
                let icon = document.getElementById(iconId);
                if (p.type === 'password') {
                    p.type = 'text';
                    icon.innerText = '🙈';
                } else {
                    p.type = 'password';
                    icon.innerText = '👁️';
                }
            }

            async function login() {
                let u = document.getElementById('login-username').value;
                let p = document.getElementById('login-password').value;
                let res = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: u, password: p})
                });
                let data = await res.json();
                if(data.success) {
                    localStorage.setItem('token', data.token);
                    fetchDashboard();
                } else {
                    alert(data.message);
                }
            }

            async function registerUser() {
                let username = document.getElementById('reg-username').value;
                let password = document.getElementById('reg-password').value;
                let token = document.getElementById('reg-token').value;
                let res = await fetch('/api/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password, token})
                });
                let data = await res.json();
                alert(data.message);
                if(data.success) location.reload();
            }

            async function resetDevice() {
                let username = document.getElementById('reset-username').value;
                let password = document.getElementById('reset-password').value;
                let res = await fetch('/api/reset-device', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                let data = await res.json();
                alert(data.message);
            }

            async function logout() {
                localStorage.clear();
                location.reload();
            }

            async function fetchDashboard() {
                document.getElementById('auth-card').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                loadDashboard();
            }

            async function loadDashboard() {
                let searchKeys = document.getElementById('search-keys').value;
                let res = await fetch('/api/dashboard?searchKeys=' + encodeURIComponent(searchKeys), {
                    headers: {'Authorization': localStorage.getItem('token')}
                });
                if(res.status === 401) { logout(); return; }
                let data = await res.json();

                document.getElementById('welcome-text').innerText = 'Welcome, ' + data.user.username;
                document.getElementById('role-text').innerText = 'ROLE: ' + data.user.role.toUpperCase();
                document.getElementById('stat-balance').innerText = data.user.balance;
                document.getElementById('stat-keys').innerText = data.keys.filter(k => k.status === 'active').length;

                if(data.user.role === 'owner' || data.user.role === 'admin') {
                    document.getElementById('user-mgmt-section').style.display = 'block';
                    document.getElementById('users-list-card').style.display = 'block';
                }

                let kList = document.getElementById('keys-list');
                kList.innerHTML = '';
                if(data.keys.length === 0) {
                    kList.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:10px;">No keys found</div>';
                } else {
                    data.keys.forEach(k => {
                        let div = document.createElement('div');
                        div.className = 'key-card';
                        div.innerHTML = '<div class="flex-row">' +
                            '<span style="font-family:monospace; font-weight:bold; color:#fff;">' + k.key + '</span>' +
                            '<span class="badge ' + k.status + '">' + k.status + '</span>' +
                            '</div>' +
                            '<div style="color:var(--text-muted); margin-top:4px; font-size:11px;">' +
                            'Duration: <b>' + k.duration + '</b> | HWID: <b>' + (k.hwid || 'None') + '</b>' +
                            '</div>' +
                            '<div class="action-buttons">' +
                            '<button class="btn-secondary" onclick="navigator.clipboard.writeText(\'' + k.key + '\'); alert(\'Copied!\');">Copy</button>' +
                            '<button class="btn-warning" onclick="keyAction(\'' + k.key + '\', \'reset\')">Reset</button>' +
                            '<button class="btn-secondary" onclick="keyAction(\'' + k.key + '\', \'block\')">' + (k.status === 'blocked' ? 'Unblock' : 'Block') + '</button>' +
                            '<button class="btn-primary btn-danger" onclick="keyAction(\'' + k.key + '\', \'delete\')">Delete</button>' +
                            '</div>';
                        kList.appendChild(div);
                    });
                }

                if(document.getElementById('users-list')) {
                    let uList = document.getElementById('users-list');
                    uList.innerHTML = '';
                    data.users.forEach(u => {
                        let uDiv = document.createElement('div');
                        uDiv.className = 'user-card';
                        uDiv.innerHTML = '<div class="flex-row">' +
                            '<span style="font-weight:bold; color:#fff;">' + u.username + '</span>' +
                            '<span class="badge active">' + u.role + '</span>' +
                            '</div>' +
                            '<div style="color:var(--text-muted); margin-top:4px; font-size:11px;">Balance: <b>' + u.balance + '</b></div>';
                        uList.appendChild(uDiv);
                    });
                }
            }

            async function createUser() {
                let username = document.getElementById('new-username').value;
                let password = document.getElementById('new-password').value;
                let role = document.getElementById('new-role').value;
                let balance = document.getElementById('new-balance').value;

                let res = await fetch('/api/create-user', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token')},
                    body: JSON.stringify({username, password, role, balance})
                });
                let data = await res.json();
                alert(data.message);
                loadDashboard();
            }

            async function generateKeys() {
                let duration = document.getElementById('duration').value;
                let count = document.getElementById('key-count').value;
                let deviceLimit = document.getElementById('device-limit').value;
                let res = await fetch('/api/generate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token')},
                    body: JSON.stringify({duration, count, deviceLimit})
                });
                let data = await res.json();
                alert(data.message);
                loadDashboard();
            }

            async function keyAction(key, action) {
                let res = await fetch('/api/key-action', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token')},
                    body: JSON.stringify({key, action})
                });
                let data = await res.json();
                alert(data.message);
                loadDashboard();
            }
        </script>
    </body>
    </html>
    `);
});

app.post('/api/login', (req, res) => {
    let { username, password } = req.body;
    let db = readDB();
    let user = db.users.find(u => u.username === username && u.password === password);
    if(user) {
        let token = crypto.createHash('sha256').update(username + Date.now() + Math.random()).digest('hex');
        user.token = token;
        writeDB(db);
        res.json({ success: true, token });
    } else {
        res.json({ success: false, message: "Invalid credentials" });
    }
});

app.post('/api/register', (req, res) => {
    let { username, password, token } = req.body;
    let db = readDB();
    if(!username || !password) return res.json({ success: false, message: "Fill all fields!" });
    if(db.users.some(u => u.username === username)) return res.json({ success: false, message: "Username already exists!" });
    
    db.users.push({
        username,
        password,
        role: "limited",
        balance: 0,
        parent: "owner",
        resetChances: 3,
        lastResetTime: 0
    });
    writeDB(db);
    res.json({ success: true, message: "Registered successfully! You can login now." });
});

app.post('/api/reset-device', (req, res) => {
    let { username, password } = req.body;
    let db = readDB();
    let user = db.users.find(u => u.username === username && u.password === password);
    if(!user) return res.json({ success: false, message: "Invalid username or password!" });

    let now = Date.now();
    if(now - user.lastResetTime > 86400000) {
        user.resetChances = 3;
    }

    if(user.resetChances > 0) {
        user.resetChances -= 1;
        user.lastResetTime = now;
        db.keys.forEach(k => {
            if(k.creator === user.username) k.hwid = null;
        });
        writeDB(db);
        res.json({ success: true, message: "Device binding reset successfully! Remaining chances: " + user.resetChances });
    } else {
        res.json({ success: false, message: "Reset limit reached! Try again after 24 hours." });
    }
});

function auth(req, res, next) {
    let token = req.headers['authorization'];
    let db = readDB();
    let user = db.users.find(u => u.token === token);
    if(user) {
        req.user = user;
        next();
    } else {
        res.status(401).json({ message: "Unauthorized" });
    }
}

app.get('/api/dashboard', auth, (req, res) => {
    let db = readDB();
    let searchKeys = (req.query.searchKeys || "").toLowerCase();
    let keys = db.keys;
    let users = [];

    if(req.user.role !== 'owner') {
        keys = keys.filter(k => k.creator === req.user.username && k.status !== 'deleted');
    } else {
        keys = keys.filter(k => k.status !== 'deleted');
        users = db.users.filter(u => u.username !== 'owner');
    }

    if(searchKeys) {
        keys = keys.filter(k => k.key.toLowerCase().includes(searchKeys) || (k.hwid && k.hwid.toLowerCase().includes(searchKeys)));
    }

    res.json({ user: req.user, keys: keys.reverse(), users: users.reverse() });
});

app.post('/api/create-user', auth, (req, res) => {
    if(req.user.role !== 'owner' && req.user.role !== 'admin') {
        return res.json({ message: "Permission denied!" });
    }
    let { username, password, role, balance } = req.body;
    let db = readDB();
    if(db.users.some(u => u.username === username)) {
        return res.json({ message: "Username already exists!" });
    }
    db.users.push({
        username,
        password,
        role,
        balance: parseInt(balance) || 0,
        parent: req.user.username,
        resetChances: 3,
        lastResetTime: 0
    });
    writeDB(db);
    res.json({ message: "User created successfully!" });
});

app.post('/api/generate', auth, (req, res) => {
    let { duration, count, deviceLimit } = req.body;
    count = parseInt(count) || 1;
    let db = readDB();
    let cost = PRICING[duration].cost * count;
    let userIdx = db.users.findIndex(u => u.username === req.user.username);

    if(db.users[userIdx].role !== 'owner' && db.users[userIdx].balance < cost) {
        return res.json({ message: "Insufficient Balance!" });
    }

    if(db.users[userIdx].role !== 'owner') {
        db.users[userIdx].balance -= cost;
    }

    for(let i=0; i<count; i++) {
        let keyString = "LEXI-" + crypto.randomBytes(4).toString('hex').toUpperCase() + "-" + crypto.randomBytes(4).toString('hex').toUpperCase();
        db.keys.push({
            key: keyString,
            duration: duration,
            deviceLimit: parseInt(deviceLimit) || 1,
            status: "active",
            hwid: null,
            creator: db.users[userIdx].username,
            expiry: null
        });
    }

    writeDB(db);
    res.json({ message: "Keys generated successfully!" });
});

app.post('/api/key-action', auth, (req, res) => {
    let { key, action } = req.body;
    let db = readDB();
    let kIdx = db.keys.findIndex(k => k.key === key);
    if(kIdx === -1) return res.json({ message: "Key not found" });

    if(action === 'reset') {
        db.keys[kIdx].hwid = null;
        db.keys[kIdx].status = 'active';
    } else if(action === 'block') {
        db.keys[kIdx].status = db.keys[kIdx].status === 'blocked' ? 'active' : 'blocked';
    } else if(action === 'delete') {
        db.keys[kIdx].status = 'deleted';
    }
    writeDB(db);
    res.json({ message: "Action executed successfully!" });
});

app.post('/api/verify', (req, res) => {
    let { key, hwid } = req.body;
    let db = readDB();
    if(!db.settings.loaderStatus) {
        return res.json({ success: false, message: db.settings.maintenanceMsg });
    }
    let k = db.keys.find(item => item.key === key);
    if(!k || k.status === 'deleted' || k.status === 'blocked') {
        return res.json({ success: false, message: "Invalid or blocked key!" });
    }
    if(!k.hwid) {
        k.hwid = hwid;
        let hours = PRICING[k.duration].hours;
        k.expiry = Date.now() + (hours * 3600 * 1000);
        writeDB(db);
    } else if(k.hwid !== hwid) {
        return res.json({ success: false, message: "Device mismatch! HWID locked." });
    }

    if(k.expiry < Date.now()) {
        k.status = 'expired';
        writeDB(db);
        return res.json({ success: false, message: "Key expired!" });
    }

    let dateObj = new Date(k.expiry);
    let formattedExpiry = dateObj.getFullYear() + "/" + String(dateObj.getMonth()+1).padStart(2,'0') + "/" + String(dateObj.getDate()).padStart(2,'0') + " " + String(dateObj.getHours()).padStart(2,'0') + ":" + String(dateObj.getMinutes()).padStart(2,'0') + ":" + String(dateObj.getSeconds()).padStart(2,'0');

    res.json({ success: true, expiry: formattedExpiry });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));