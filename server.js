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
            { username: "owner", password: "ownerpassword", role: "owner", balance: 99999, parent: null }
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
        <title>Lexi Loader Control Panel</title>
        <style>
            :root {
                --bg-color: #000000;
                --card-bg: #0a0a0a;
                --border-color: #222222;
                --text-color: #ffffff;
                --text-muted: #888888;
                --accent-blue: #007bff;
                --accent-blue-hover: #0056b3;
                --accent-red: #dc3545;
                --accent-amber: #ffc107;
                --accent-orange: #fd7e14;
                --accent-green: #28a745;
            }
            body.light-mode {
                --bg-color: #f4f6f9;
                --card-bg: #ffffff;
                --border-color: #dcdcdc;
                --text-color: #111111;
                --text-muted: #666666;
            }
            body { background-color: var(--bg-color); color: var(--text-color); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 15px; transition: background 0.3s, color 0.3s; }
            .container { max-width: 500px; margin: auto; }
            .card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }
            h2, h3 { margin-top: 0; font-weight: 600; letter-spacing: 0.5px; }
            input, select, button { width: 100%; padding: 12px; margin: 8px 0; background: var(--bg-color); color: var(--text-color); border: 1px solid var(--border-color); border-radius: 8px; box-sizing: border-box; font-size: 14px; outline: none; }
            input:focus, select:focus { border-color: var(--accent-blue); }
            button { background: var(--accent-blue); color: #fff; border: none; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
            button:hover { opacity: 0.9; }
            button.delete { background: var(--accent-red); }
            button.reset { background: var(--accent-amber); color: #000; }
            button.block { background: var(--accent-orange); color: #fff; }
            button.secondary { background: #333; color: #fff; }
            .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px; }
            .stat-box { background: var(--card-bg); border: 1px solid var(--border-color); padding: 15px; border-radius: 8px; text-align: center; }
            .stat-box span { font-size: 18px; font-weight: bold; color: var(--accent-blue); }
            .key-card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; margin-bottom: 10px; font-size: 13px; position: relative; }
            .flex-row { display: flex; justify-content: space-between; align-items: center; gap: 5px; }
            .badge { padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
            .badge.active { background: rgba(40,167,69,0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
            .badge.expired { background: rgba(220,53,69,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
            .badge.blocked { background: rgba(253,126,20,0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
            .badge.deleted { background: rgba(100,100,100,0.2); color: #888; border: 1px solid #888; }
            .action-buttons { display: flex; gap: 5px; margin-top: 8px; }
            .action-buttons button { padding: 6px; font-size: 11px; margin: 0; }
            .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div id="login-box" class="card" style="margin-top: 50px;">
                <h2 style="text-align:center; color:var(--accent-blue);">Lexi Loader</h2>
                <input type="text" id="username" placeholder="Username">
                <input type="password" id="password" placeholder="Password">
                <button onclick="login()">Login to Panel</button>
            </div>

            <div id="dashboard" style="display:none;">
                <div class="top-bar">
                    <div>
                        <h2 id="welcome-text" style="margin:0; font-size:20px;"></h2>
                        <span id="role-text" style="font-size:12px; color:var(--text-muted);"></span>
                    </div>
                    <div style="display:flex; gap:8px;">
                        <button onclick="toggleTheme()" class="secondary" style="width:auto; padding:8px 12px; margin:0;">🌓</button>
                        <button onclick="logout()" class="delete" style="width:auto; padding:8px 12px; margin:0;">Logout</button>
                    </div>
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

                <div class="card" id="gen-card">
                    <h3>Generate License Key</h3>
                    <select id="duration">
                        <option value="3h">3 Hours (10 Bal)</option>
                        <option value="1d">1 Day (100 Bal)</option>
                        <option value="3d">3 Days (200 Bal)</option>
                        <option value="7d">7 Days (350 Bal)</option>
                        <option value="15d">15 Days (500 Bal)</option>
                        <option value="30d">30 Days (750 Bal)</option>
                        <option value="60d">60 Days (1000 Bal)</option>
                    </select>
                    <div style="display:flex; gap:10px;">
                        <input type="number" id="key-count" placeholder="Count (1)" value="1" min="1">
                        <input type="number" id="device-limit" placeholder="Devices (1)" value="1" min="1">
                    </div>
                    <button onclick="generateKeys()">Generate Key</button>
                </div>

                <div class="card">
                    <h3>Manage Keys</h3>
                    <input type="text" id="search-keys" placeholder="Search Keys or HWID..." onkeyup="loadDashboard()">
                    <div id="keys-list" style="margin-top:10px;"></div>
                </div>
            </div>
        </div>

        <script>
            let token = localStorage.getItem('token');
            if(token) fetchDashboard();

            function toggleTheme() {
                document.body.classList.toggle('light-mode');
            }

            async function login() {
                let u = document.getElementById('username').value;
                let p = document.getElementById('password').value;
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

            async function logout() {
                localStorage.clear();
                location.reload();
            }

            async function fetchDashboard() {
                document.getElementById('login-box').style.display = 'none';
                document.getElementById('dashboard').style.display = 'block';
                loadDashboard();
            }

            async function loadDashboard() {
                let search = document.getElementById('search-keys').value;
                let res = await fetch('/api/dashboard?search=' + encodeURIComponent(search), {
                    headers: {'Authorization': localStorage.getItem('token')}
                });
                if(res.status === 401) { logout(); return; }
                let data = await res.json();

                document.getElementById('welcome-text').innerText = 'Welcome, ' + data.user.username;
                document.getElementById('role-text').innerText = 'Role: ' + data.user.role.toUpperCase();
                document.getElementById('stat-balance').innerText = data.user.balance;
                document.getElementById('stat-keys').innerText = data.keys.filter(k => k.status === 'active').length;

                let list = document.getElementById('keys-list');
                list.innerHTML = '';
                
                if(data.keys.length === 0) {
                    list.innerHTML = '<div style="text-align:center; color:var(--text-muted); padding:20px;">No keys found</div>';
                    return;
                }

                data.keys.forEach(k => {
                    let div = document.createElement('div');
                    div.className = 'key-card';
                    div.innerHTML = \`
                        <div class="flex-row">
                            <span style="font-family:monospace; font-weight:bold; font-size:14px;">\${k.key}</span>
                            <span class="badge \${k.status}">\${k.status}</span>
                        </div>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:5px;">
                            Duration: <b>\${k.duration}</b> | Limit: <b>\${k.deviceLimit}</b> | HWID: <b>\${k.hwid || 'None'}</b>
                        </div>
                        <div class="action-buttons">
                            <button class="secondary" onclick="navigator.clipboard.writeText('\${k.key}'); alert('Key Copied!');">Copy</button>
                            <button class="reset" onclick="keyAction('\${k.key}', 'reset')">Reset</button>
                            <button class="block" onclick="keyAction('\${k.key}', 'block')">\${k.status === 'blocked' ? 'Unblock' : 'Block'}</button>
                            <button class="delete" onclick="keyAction('\${k.key}', 'delete')">Delete</button>
                        </div>
                    \`;
                    list.appendChild(div);
                });
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
    let search = (req.query.search || "").toLowerCase();
    let keys = db.keys;

    if(req.user.role !== 'owner') {
        keys = keys.filter(k => k.creator === req.user.username && k.status !== 'deleted');
    } else {
        keys = keys.filter(k => k.status !== 'deleted' || req.user.role === 'owner');
    }

    if(search) {
        keys = keys.filter(k => k.key.toLowerCase().includes(search) || (k.hwid && k.hwid.toLowerCase().includes(search)));
    }

    res.json({ user: req.user, keys: keys.reverse() });
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
