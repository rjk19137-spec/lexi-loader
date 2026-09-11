const express = require("express");
const mongoose = require("mongoose");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 4000;

// 🔌 MongoDB Connection
mongoose.connect(process.env.MONGO_URI || "mongodb://localhost:27017/lexi_loader_db", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

// 📦 Mongoose Models (Schemas for Old Features)
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'reseller'], default: 'reseller' },
    isBanned: { type: Boolean, default: false },
    balance: { type: Number, default: 0 },
    referralCode: { type: String, unique: true, sparse: true },
    referredBy: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});

const LicenseSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    expiry: { type: Date, required: true },
    deviceLocked: { type: Boolean, default: false },
    usedDevices: [{ type: String, default: [] }]
});

const DeviceSchema = new mongoose.Schema({
    username: { type: String, required: true },
    deviceId: { type: String, required: true },
    firstSeen: { type: Date, default: Date.now }
});

const AuditLogSchema = new mongoose.Schema({
    action: { type: String, required: true },
    user: { type: String, required: true },
    details: { type: String, default: "" },
    timestamp: { type: Date, default: Date.now }
});

const ReferralSchema = new mongoose.Schema({
    referrer: { type: String, required: true },
    user: { type: String, required: true },
    amount: { type: Number, default: 0 },
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);
const License = mongoose.model("License", LicenseSchema);
const Device = mongoose.model("Device", DeviceSchema);
const AuditLog = mongoose.model("AuditLog", AuditLogSchema);
const Referral = mongoose.model("Referral", ReferralSchema);

// 🧹 Helper Functions
const generateLicense = () => crypto.randomBytes(16).toString("hex");
const generateReferralCode = () => crypto.randomBytes(8).toString("hex").toUpperCase();

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// 🔐 Login Route
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username, password });
        if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
        if (user.isBanned) return res.status(403).json({ success: false, message: "Account banned" });
        
        // Log login
        new AuditLog({ action: "User Login", user: username }).save();
        
        res.json({ 
            success: true, 
            user: { username: user.username, role: user.role, balance: user.balance } 
        });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 👤 Register Route (With Referral)
app.post("/register", async (req, res) => {
    try {
        const { username, password, role, referralCode } = req.body;
        if (await User.findOne({ username })) return res.status(400).json({ success: false, message: "User exists" });
        
        let referredBy = null;
        let referrerBonus = 0;
        
        if (referralCode) {
            const referrer = await User.findOne({ referralCode });
            if (!referrer) return res.status(400).json({ success: false, message: "Invalid referral code" });
            referredBy = referrer.username;
            referrerBonus = 10; // Example bonus
        }

        const newUser = new User({ 
            username, 
            password, 
            role, 
            referralCode: generateReferralCode(), 
            referredBy 
        });
        await newUser.save();

        if (referredBy) {
            const refUser = await User.findOne({ username: referredBy });
            if (refUser) {
                refUser.balance += referrerBonus;
                await refUser.save();
                new Referral({ referrer: referredBy, user: username, amount: referrerBonus }).save();
            }
        }

        new AuditLog({ action: "User Registered", user: username }).save();
        res.json({ success: true, user: newUser });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 🎟️ Generate License
app.post("/generate-license", async (req, res) => {
    try {
        const { username, password, days } = req.body;
        const expiry = new Date();
        expiry.setDate(expiry.getDate() + parseInt(days));

        const newLicense = new License({ username, password, expiry });
        await newLicense.save();
        new AuditLog({ action: "License Created", user: username, details: `Expires: ${expiry}` }).save();
        res.json({ success: true, license: newLicense });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 🚫 Revoke License
app.post("/revoke-license", async (req, res) => {
    try {
        const { username } = req.body;
        const license = await License.findOne({ username });
        if (license) {
            license.expiry = new Date("2020-01-01"); // Set to past to revoke
            await license.save();
        }
        new AuditLog({ action: "License Revoked", user: username }).save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 🔒 Lock Device
app.post("/lock-device", async (req, res) => {
    try {
        const { username, deviceId } = req.body;
        const license = await License.findOne({ username });
        if (!license) return res.status(404).json({ success: false, message: "User not found" });

        await Device.create({ username, deviceId });
        
        license.deviceLocked = true;
        if (!license.usedDevices.includes(deviceId)) {
            license.usedDevices.push(deviceId);
        }
        await license.save();
        
        new AuditLog({ action: "Device Locked", user: username, details: deviceId }).save();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 📜 Get Audit Logs
app.get("/audit-logs", async (req, res) => {
    try {
        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(50);
        res.json({ success: true, logs });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 📈 Get User Stats (For Admin Panel)
app.get("/stats", async (req, res) => {
    try {
        const users = await User.countDocuments();
        const licenses = await License.countDocuments();
        const devices = await Device.countDocuments();
        res.json({ success: true, stats: { users, licenses, devices } });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 🚀 Start Server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
