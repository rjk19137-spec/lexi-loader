const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Static HTML files

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
    console.error("❌ Please add MONGO_URI to your .env file");
} else {
    mongoose.connect(MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
        .then(() => console.log("✅ Connected to MongoDB Atlas"))
        .catch(err => console.error("❌ MongoDB Connection Error:", err));
}

// Schema Definition
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    expiry: { type: Date, required: true },
    isActive: { type: Boolean, default: true }
});

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Route: Check User Access
app.post('/api/check', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username, password });

        if (!user) {
            return res.json({ status: 'invalid' });
        }

        if (user.expiry < new Date()) {
            return res.json({ status: 'expired' });
        }

        if (!user.isActive) {
            return res.json({ status: 'revoked' });
        }

        res.json({ status: 'active' });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
});

// Route: Admin Login
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const admin = await Admin.findOne({ username, password });

        if (admin) {
            res.json({
                success: true,
                message: "Login Successful"
            });
        } else {
            res.json({
                success: false,
                message: "Invalid Credentials"
            });
        }
    } catch (err) {
        res.json({
            success: false,
            message: err.message
        });
    }
});

// Route: Create User (Admin Only)
app.post('/api/admin/create', async (req, res) => {
    const { username, password, days } = req.body;

    try {
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + parseInt(days));

        const newUser = new User({
            username,
            password,
            expiry: expiryDate
        });

        await newUser.save();

        res.json({
            success: true,
            message: "User Created"
        });
    } catch (err) {
        res.json({
            success: false,
            message: err.message
        });
    }
});

// Route: Get All Users (Admin Only)
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find({});
        res.json(users);
    } catch (err) {
        res.json({ error: err.message });
    }
});

// Route: Revoke User (Admin Only)
app.post('/api/admin/revoke', async (req, res) => {
    const { username } = req.body;

    try {
        await User.findOneAndUpdate(
            { username },
            { isActive: false }
        );

        res.json({
            success: true,
            message: "User Revoked"
        });
    } catch (err) {
        res.json({
            success: false,
            message: err.message
        });
    }
});

// Route: Serve Admin Panel
app.get('/admin', async (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});


<!-- ==================== public/admin.html ==================== -->

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lexi Admin</title>

    <style>
        body {
            font-family: sans-serif;
            padding: 20px;
            background: #1a1a1a;
            color: white;
        }

        input,
        button {
            padding: 10px;
            margin: 5px 0;
            width: 100%;
        }

        button {
            background: #007bff;
            color: white;
            border: none;
            cursor: pointer;
        }

        #status {
            margin-top: 20px;
            padding: 10px;
            background: #333;
        }

        #users-list {
            margin-top: 20px;
        }
    </style>
</head>

<body>
    <h2>🔒 Admin Login</h2>

    <input type="text" id="adminUser" placeholder="Username">
    <input type="password" id="adminPass" placeholder="Password">

    <button onclick="login()">Login</button>

    <div id="panel" style="display:none;">
        <h3>Create User</h3>

        <input type="text" id="newUser" placeholder="Username">
        <input type="password" id="newPass" placeholder="Password">
        <input type="number" id="days" placeholder="Days (e.g., 30)">

        <button onclick="createUser()">Create</button>

        <h3>Users List</h3>

        <button onclick="fetchUsers()">Refresh List</button>

        <div id="users-list"></div>
    </div>

    <script>
        async function login() {
            const u = document.getElementById('adminUser').value;
            const p = document.getElementById('adminPass').value;

            const res = await fetch('/api/admin/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: u,
                    password: p
                })
            });

            const data = await res.json();

            if (data.success) {
                document.getElementById('panel').style.display = 'block';
                fetchUsers();
            } else {
                alert('Invalid Admin Credentials');
            }
        }

        async function createUser() {
            const u = document.getElementById('newUser').value;
            const p = document.getElementById('newPass').value;
            const d = document.getElementById('days').value;

            const res = await fetch('/api/admin/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: u,
                    password: p,
                    days: d
                })
            });

            const data = await res.json();

            alert(data.message);
            fetchUsers();
        }

        async function fetchUsers() {
            const res = await fetch('/api/admin/users');
            const users = await res.json();

            const list = document.getElementById('users-list');
            list.innerHTML = '';

            users.forEach(user => {
                const div = document.createElement('div');

                div.style.padding = "5px";
                div.style.borderBottom = "1px solid #555";

                div.innerHTML = `
                    <strong>${user.username}</strong> |
                    Exp: ${new Date(user.expiry).toLocaleDateString()} |
                    Status: ${user.isActive ? '✅ Active' : '❌ Revoked'}
                    <button
                        onclick="revokeUser('${user.username}')"
                        style="width: auto; background: red;">
                        Revoke
                    </button>
                `;

                list.appendChild(div);
            });
        }

        async function revokeUser(username) {
            await fetch('/api/admin/revoke', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: username
                })
            });

            fetchUsers();
        }
    </script>
</body>
</html>
