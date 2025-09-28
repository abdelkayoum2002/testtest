require("dotenv").config();
const express = require('express');
const fs = require("fs");
const http = require('http');
const multer = require("multer");
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid'); 
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');
const UAParser = require('ua-parser-js');
const jwt = require('jsonwebtoken');
const cookie = require("cookie");
const bcrypt = require('bcryptjs');
const { sysDb, userDb } = require('./database');
const {Set_event} = require('./db')
const { Console } = require("console");
const {disconnectMQTTDevice} = require("./broker");
const {hashPassword} =require('./security')
try{
  sysDb.prepare(`ATTACH DATABASE './test.db' AS userDb;`).run();
}catch(err){
  console.error('Failed to attach userDb to systemDb:',(err));
}
// Initialize the app 
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  path: '/socket.io',
  cors: { origin: '*' },
});
const UPLOADS_DIR = path.join(__dirname, "uploads");
const TEMP_DIR = path.join(__dirname, "temp");
const ProfPic_DIR = path.join(__dirname, "uploads/profilePic");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR);

// --- Multer setup: save files in temp
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, TEMP_DIR),
  filename: (req, file, cb) => {
    // original extension
    const ext = path.extname(file.originalname).toLowerCase();
    // original base name (without extension)
    const base = path.basename(file.originalname, ext);

    // unique suffix
    const unique = Date.now() + "_" + Math.round(Math.random() * 1e9);

    // final filename: original + "_" + unique + ext
    cb(null, `${base}_${unique}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  // Allow letters, numbers, dots, dashes, spaces
  const safeName = /^[a-zA-Z0-9.\- ]+$/;

  if (!safeName.test(file.originalname)) {
    return cb(new Error("Invalid filename"));
  }

  cb(null, true);
};

const profilePicStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, ProfPic_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const uniqueName = uuidv4() + ext; // generate UUID 
    cb(null, uniqueName);
  }
});

const profilePicUpload = multer({ storage: profilePicStorage});

const upload = multer({ storage, fileFilter });

function authenticate(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    req.user_id = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }

}


function checkAccess(req, res, next) {
  try {
    const device_id = req.user.device_id;
    console.log(device_id)
    const user_id = req.user_id; // set in authenticate()

    if (!device_id) {
      return res.status(401).json({ error: 'Missing device_id' });
    }
     // 1️⃣ Check user status
    const user = userDb.prepare(`
      SELECT status 
      FROM Users 
      WHERE id = ?
    `).get(user_id);

    if (!user) {
      res.clearCookie('token');
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.status === 'Disactive') {
      return res.status(401).json({ error: 'Profile disactive' });
    }
    // 2️⃣ Check device status
    const device = userDb.prepare(`
      SELECT status 
      FROM Devices 
      WHERE device_id = ? AND user_id = ?
    `).get(device_id, user_id);

    if (!device) {
      res.clearCookie('token');
      return res.status(401).json({ error: 'Device not found' });
    }


    if (device.status === 'Disconnected') {
      return res.status(401).json({ error: 'Device disconnected' });
    }
    // ✅ Both checks passed
    next();
  } catch (err) {
    console.error('Access check error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}
function updateLastSeen(req,res,next) {
  try {
    const stmt = userDb.prepare(`
      UPDATE Devices
      SET last_seen = datetime('now'),
          status = 'Online'
      WHERE device_id = ?
      RETURNING 
        device_id,
        user_id,
        name,
        os,
        browser,
        status,
        login_at,
        last_seen;
    `);

    const device = stmt.get(req.user.device_id);
    if(device.user_id){
      io.to(`user:${device.user_id}`).emit("device",device);
    }
  } catch (err) {
    console.error("Error updating last_seen:", err);
  } finally{
    next();
  }
}
function sendJwtCookie(req,res, next) {
  const { iat, exp, ...cleanPayload } = req.user;
  console.log(cleanPayload)
  const token = jwt.sign(cleanPayload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  res.cookie('token', token, {
    httpOnly: true,                 // Not accessible via JS
    secure: process.env.NODE_ENV === 'production', // Only over HTTPS in production
    sameSite: 'lax',
    maxAge: parseDuration(process.env.JWT_EXPIRES_IN), // Convert to ms
  });
  next();
}
function parseDuration(duration) {
  const match = duration.match(/^(\d+)(s|m|h|d)$/);
  if (!match) return 3600000; // default 1h
  const value = parseInt(match[1]);
  const unit = match[2];
  switch (unit) {
    case 's': return value * 1000;
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default: return 3600000;
  }
}
// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// JWT secret key (in production, use environment variable)
const JWT_SECRET = process.env.JWT_SECRET || "defaultsecret";

// Routes
app.get('/', (req, res) => {
  res.render('login');
});
app.get('/dashboard',authenticate,checkAccess,sendJwtCookie, (req, res) => {

  let welcome = null;
  const row = userDb.prepare(`
    SELECT first_login
    FROM Devices
    WHERE device_id = ?
  `).get(req.user.device_id);

  if (row.first_login) {
    try {
      const row = userDb.prepare(`
        SELECT name
        FROM Devices
        WHERE device_id = ?
      `).get(req.user.device_id);
      const device_name = row.name;
      const user = userDb.prepare(`
            SELECT full_name
            FROM Users
            WHERE id = ?
      `).get(req.user.id);
      userDb.prepare(`UPDATE Devices SET first_login = 0 WHERE device_id = ?`).run(req.user.device_id);
      welcome = {
          user_name: user.full_name,     // from auth middleware
          device_name: device_name ,         // from URL
          device_id: req.user.device_id
      };
    } catch (err) {
        console.error("Failed to welcoming:", err);
    }
  }
  console.log(welcome)
  res.render('dashboard',{welcome});
});
app.get('/system', (req, res) => {
  res.render('system');
});
app.get('/analytics', (req, res) => {
  res.render('analytics');
});
app.get('/SCADA', (req, res) => {
  res.render('scada');
});
app.get('/messages', (req, res) => {
  res.render('messages');
});
app.get('/settings', (req, res) => {
  res.render('settings_myprofile');
});
app.get('/settings/:setting', (req, res) => {
  const setting = req.params.setting;
  res.render(`settings_${setting}`);
});
app.get('/profile', (req, res) => {
  res.render('myprofile');
});
app.get("/pop/:page", (req, res) => {
  const page = req.params.page;
  res.render(`pop/${page}`, { msg: req.query.msg || null });
});
app.get('/mqtt-credentials', authenticate, (req, res) => {
  const jwtToken = req.cookies.token;
  const { device_id } = req.user;  // assume `authenticate` puts this in req.user
  console.log(req.user);

  try {
      // First check if device already has a client ID
      const {client_id} = userDb.prepare(`
        SELECT client_id 
        FROM MQTT
        WHERE device_id = ?
      `).get(device_id);
      const mqtt_client_id = client_id
      // Get username
      const username = userDb.prepare(`
        SELECT u.username
        FROM Devices d
        JOIN Users u ON d.user_id = u.id
        WHERE d.device_id = ?;
      `).get(device_id);
      const {role} = userDb.prepare(`
        SELECT r.role
        FROM Devices d
        JOIN Users r ON d.user_id = r.id
        WHERE d.device_id = ?;
      `).get(device_id);
      console.log(role)
      // Get topics
      const stmt = userDb.prepare(`
          SELECT topic, type, action
          FROM MQTT_Topics
          WHERE role = ?
        `);

        const rows = stmt.all(role);
        // Structure output
        const topics = {
          sub_topics: {},
          pub_topics: {},
          pubsub_topics: {}
        };

        rows.forEach(row => {
          let category;
          if (row.action === 'sub') {
            category = topics.sub_topics;
          } else if (row.action === 'pub') {
            category = topics.pub_topics;
          } else if (row.action === 'pub/sub') {
            category = topics.pubsub_topics;
          }

          if (!category[row.type]) {
            category[row.type] = [];
          }
          category[row.type].push(row.topic);
        });

      console.log(topics);
    const isProd = process.env.NODE_ENV === "production";

    const brokerUrl = isProd
      ? `wss://${req.get("host")}/mqtt`
      : "ws://localhost:1884";
      console.log(brokerUrl)
    res.json({
      brokerUrl,
      clientId: mqtt_client_id,
      username: username?.username || "",
      password: jwtToken,
      topics
    });
  } catch (err) {
      console.error('DB error:', err);
      res.status(500).json({ error: 'Internal server error' });
  }
});
function randomDeviceName() {
  const adjectives = [
    "Fast", "Silent", "Red", "Blue", "Smart", "Cool", "Heavy", "Light",
    "Dark", "Bright", "Sharp", "Brave", "Loud", "Calm", "Swift", "Mighty",
    "Golden", "Silver", "Iron", "Crystal", "Shadow", "Wild", "Electric",
    "Frozen", "Fiery", "Stormy", "Cloudy", "Sunny", "Moonlit", "Lucky"
  ];

  const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
  const num = Math.floor(Math.random() * 10000);

  return `${adj}-${num}`;
}
// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const parser = new UAParser(req.headers['user-agent']);
  const uaResult = parser.getResult();
  const os = uaResult.os.name + " " + (uaResult.os.version || "");
  const browser = uaResult.browser.name + " " + (uaResult.browser.version || "");
  const deviceName = randomDeviceName();
  try {
    const user = userDb.prepare('SELECT * FROM Users WHERE username = ?').get(username);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    const deviceId = `DEV-${uuidv4()}`;
    const mqtt_client_id = `MQTT_${uuidv4().slice(0, 8)}`;
    const stmt = userDb.prepare(`
      INSERT INTO Devices (device_id, user_id, type, name, os, browser, status, login_at, first_login)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)
      RETURNING device_id, name, os, browser, status, login_at, last_seen
    `);

    const device = stmt.get(
      deviceId,
      user.id,
      'user_device',
      deviceName,
      os || "Unknown OS",
      browser || "Unknown Browser",
      'Online',
      '1'
    );

    device.add = true;

    io.to(`user:${user.id}`).emit("device", device);
    // generate token
    const token = jwt.sign(
      { device_id : deviceId, username:user.username,user:user.full_name,id:user.id,role:user.role},
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );
    // set cookies
    res.cookie('token', token, {
      httpOnly: true,      // prevent JavaScript access
      secure: process.env.NODE_ENV === 'production',        // true if using HTTPS
      sameSite: 'strict',  // protect against CSRF
      maxAge:  parseDuration(process.env.JWT_EXPIRES_IN) 
    });
    const decoded = jwt.decode(token);

    // exp is in UNIX seconds (UTC)
    const expire = decoded.exp;
    const now = decoded.iat; // issued at, also UNIX seconds

    const created_date = now;
    const expire_date = expire;
    userDb.prepare(`
      INSERT INTO Tokens (device_id, token, created_date, expire_date)
      VALUES (?, ?, ?, ?)
    `).run(deviceId, token, created_date, expire_date);
    userDb.prepare(`
        INSERT INTO MQTT (client_id, device_id, status)
        VALUES (?, ?, ?)
    `).run(mqtt_client_id, deviceId, 'login...');
    res.redirect(`/dashboard`);
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'Internal server error' });
  }
});

app.get("/download/:file", (req, res) => {
  function cleanFileName(filename) {
      const dotIndex = filename.lastIndexOf(".");
      const ext = filename.slice(dotIndex);              // ".docx"
      const base = filename.slice(0, dotIndex);          // "1756776453009_307014997"
      const cleanBase = base.split("_")[0];              // "1756776453009"
      return cleanBase + ext;
  }
  const fileName = req.params.file; // e.g. "report.pdf"
  const filePath = path.join(__dirname, "uploads", fileName);

  res.download(filePath, cleanFileName(fileName), (err) => {
    if (err) {
      console.error("Download error:", err);
      res.status(500).send("File not found or error while downloading.");
    }
  });
});

app.get("/MyProfilePic", authenticate, (req, res) => {
  const userId = req.user_id;
  console.log(req.user_id)
  // Look up the hashed file in DB
  const row = userDb.prepare("SELECT profile_pic FROM Users WHERE id = ?").get(userId);

  if (!row || !row.profile_pic) {
    return res.status(404).json({ error: "Picture not found" });
  }

  const hashed_name = row.profile_pic;
  console.log(row)
  const storedFile = path.join(ProfPic_DIR, hashed_name);
  console.log(storedFile)
  if (!fs.existsSync(storedFile)) {
    return res.status(404).json({ error: "Stored file missing" });
  }

  // Random suffix
  const randomStr = uuidv4().split("-")[0];
  const newFileName = `ProfilePic_${randomStr}`;

  // Headers
  res.setHeader("Content-Disposition", `inline; filename="${newFileName}"`);
  res.setHeader("Content-Type", "image/jpeg");

  // Stream file
  fs.createReadStream(storedFile).pipe(res);
});

app.get('/MyProfileInfo', authenticate, (req, res) => {
  try {
    const userId = req.user_id;
    console.log(userId)
    // SQL query (with JOIN to include role description)
    const stmt = userDb.prepare(`
      SELECT 
        u.id,
        u.full_name,
        u.phone_number,
        u.email,
        u.role,
        r.description AS role_description,
        u.status,
        u.location,
        u.created_date
      FROM Users u
      LEFT JOIN Users_Roles r ON u.role = r.role
      WHERE u.id = ?
    `);

    const user = stmt.get(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
function getDeviceById(deviceId) {
  
  const stmt = userDb.prepare(`
    SELECT *
    FROM Devices
    WHERE device_id = ?;
  `);
  const device= (stmt.get(deviceId) || null)
  if(device.user_id){
    io.to(`user:${device.user_id}`).emit("device",device);
  }
}

app.get("/MyProfileDevices", authenticate, (req, res) => {
  const userId = req.user_id; // from auth middleware
  const currentDeviceId = req.user.device_id; // from auth middleware
  console.log("User ID:", userId, "Current device ID:", currentDeviceId);

  try {
    const stmt = userDb.prepare(`
      SELECT *
      FROM Devices
      WHERE user_id = ?
        AND type = 'user_device'
    `);

    let devices = stmt.all(userId);
    // Find my device
    const myDevice = devices.find(dev => dev.device_id === currentDeviceId) || null;
    // Exclude my device from the "devices" list
    const otherDevices = devices.filter(dev => dev.device_id !== currentDeviceId);
    console.log({my_device: myDevice,
      devices: otherDevices})
    res.json({
      my_device: myDevice,
      devices: otherDevices
    });
  } catch (err) {
    console.error("Error fetching profile devices:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post('/device/disconnect', authenticate, (req, res) => {
  const { device_id } = req.body;
  const user_id = req.user_id;
  console.log("🔌 Disconnect request:", device_id, user_id);

  try {
    const result = {};

    // 1. Check ownership
    const ownership = userDb.prepare(`
      SELECT device_id, status
      FROM Devices
      WHERE device_id = ? AND user_id = ?
    `).get(device_id, user_id);

    if (!ownership) {
      return res.status(403).json({ error: "Device does not belong to user" });
    }

    // 2. Make sure status is not already disconnected/offline
    if (["Offline", "Disconnected"].includes(ownership.status)) {
      return res.status(400).json({ 
        error: `Device is already ${ownership.status}`, 
        status: ownership.status 
      });
    }

    // 3. Disconnect MQTT client
    const row = userDb.prepare(
      'SELECT client_id FROM MQTT WHERE device_id = ?'
    ).get(device_id);

    if (!row?.client_id) {
      result.mqtt = { ok: false, error: "no-mqtt-client-for-device" };
    } else {
      const ok = disconnectMQTTDevice(row.client_id);
      result.mqtt = ok ? { ok: true } : { ok: false, error: 'mqtt-client-not-found' };
    }

    // 4. Disconnect Socket.IO session
    const okSocket = disconnectSocketDevice(device_id);
    result.socket = okSocket ? { ok: true } : { ok: false, error: 'socket-not-found' };

    // 5. Update device status and return updated row
    const stmt = userDb.prepare(`
      UPDATE Devices
      SET status = 'Disconnected',
          last_seen = datetime('now')
      WHERE device_id = ?
      RETURNING 
        device_id,
        user_id,
        name,
        os,
        browser,
        status,
        login_at,
        last_seen;
    `);  

    const updatedDevice = stmt.get(device_id);

    if (updatedDevice) {
      console.log(req.user_id)
      io.to(`user:${req.user_id}`).emit("device", updatedDevice);
    }

    console.log("✅ Disconnection result:", result);
    res.json({ result, device: updatedDevice });
  } catch (err) {
    console.error("❌ Error in /device/disconnect:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post('/device/connect', authenticate, (req, res) => {
  const { device_id } = req.body;
  const user_id = req.user_id;

  try {
    // 1. Check ownership
    const device = userDb.prepare(`
      SELECT device_id, status
      FROM Devices
      WHERE device_id = ? AND user_id = ?
    `).get(device_id, user_id);

    if (!device) {
      return res.status(403).json({ error: "Device does not belong to user" });
    }

    // 2. Don’t allow connecting if already Online or Ready
    if (["Online", "Ready"].includes(device.status)) {
      return res.status(400).json({
        error: `Device is already ${device.status}`,
        status: device.status
      });
    }

    const result = { mqtt: { ok: false } };

    // 3. Find mqtt client
    const row = userDb.prepare(
      'SELECT client_id FROM MQTT WHERE device_id = ?'
    ).get(device_id);

    if (row?.client_id) {
      userDb.prepare(`
        UPDATE MQTT
        SET status = 'Ready', last_seen = datetime('now')
        WHERE client_id = ?
      `).run(row.client_id);

      result.mqtt = { ok: true };
    } else {
      result.mqtt.error = "no-mqtt-client-for-device";
    }

    // 4. Update device status
    const stmt = userDb.prepare(`
      UPDATE Devices
      SET status = 'Ready'
      WHERE device_id = ?
      RETURNING 
        device_id,
        user_id,
        name,
        os,
        browser,
        status,
        login_at,
        last_seen;
    `);

    const updatedDevice = stmt.get(device_id);
    if (updatedDevice) {
      console.log(req.user_id)
      io.to(`user:${req.user_id}`).emit("device", updatedDevice);
    }

    console.log("✅ Connection result:", result);
    res.json({ result });

  } catch (err) {
    console.error("❌ Error in /device/connect:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post('/device/delete', authenticate, (req, res) => {
  try {
    const { device_id } = req.body;
    const user_id = req.user_id; // from authenticate()

    if (!device_id) {
      return res.status(400).json({ error: 'Missing device_id' });
    }
    if (req.user.device_id === device_id) {
      return res.status(403).json({
        error: 'You cannot delete the device you are currently logged in with.'
      });
    }
    // Delete device from DB
    const result = userDb.prepare(`
      DELETE FROM Devices 
      WHERE device_id = ? AND user_id = ?
    `).run(device_id, user_id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Device not found or not yours' });
    }


    res.json({ success: true, message: 'Device disconnected and deleted' });
  } catch (err) {
    console.error('Device disconnect error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get("/profiles", authenticate, (req, res) => {
  try {
    const stmt = userDb.prepare(`
      SELECT
        id, 
        full_name, 
        role, 
        status, 
        created_by,
        created_date
      FROM Users
    `);

    const users = stmt.all();
    res.json({ success: true, users });
  } catch (err) {
    console.error("Error fetching users:", err.message);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});
app.get ("/ProfilePic/:id", authenticate, (req, res) => {
  const userId = req.params.id;  // 👈 this is the user ID from the URL

  if (!userId) {
    return res.status(400).json({ error: "userId is required" });
  }
  // Look up the hashed file in DB
  const row = userDb.prepare("SELECT profile_pic FROM Users WHERE id = ?").get(userId);

  if (!row || !row.profile_pic) {
    return res.status(404).json({ error: "Picture not found" });
  }

  const hashed_name = row.profile_pic;
  console.log(row)
  const storedFile = path.join(ProfPic_DIR, hashed_name);
  if (!fs.existsSync(storedFile)) {
    return res.status(404).json({ error: "Stored file missing" });
  }

  // Random suffix
  const randomStr = uuidv4().split("-")[0];
  const newFileName = `ProfilePic_${randomStr}`;

  // Headers
  res.setHeader("Content-Disposition", `inline; filename="${newFileName}"`);
  res.setHeader("Content-Type", "image/jpeg");

  // Stream file
  fs.createReadStream(storedFile).pipe(res);
});
app.get('/ProfileInfo/:id', authenticate, (req, res) => {
  try {
    const userId = req.params.id;  // 👈 this is the user ID from the URL
    console.log(userId)
    // SQL query (with JOIN to include role description)
    const stmt = userDb.prepare(`
      SELECT 
        u.id,
        u.full_name,
        u.phone_number,
        u.email,
        u.role,
        r.description AS role_description,
        u.status,
        u.location,
        u.created_date
      FROM Users u
      LEFT JOIN Users_Roles r ON u.role = r.role
      WHERE u.id = ?
    `);

    const user = stmt.get(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.delete("/profiles/:id", authenticate, (req, res) => {
    const userId = req.params.id;
    const currentUserId = req.user.id; // 👈 from authenticate middleware

    // Prevent deleting own account
    if (userId === currentUserId) {
        return res.status(403).json({ error: "You cannot delete your own account" });
    }
    try {
        // 1. Find all devices for this user
        const devices = userDb.prepare(`
            SELECT device_id FROM Devices WHERE user_id = ?
        `).all(userId);

        devices.forEach(d => {
            disconnectSocketDevice(d.device_id); // 👈 disconnect socket
        });

        // 2. For each device, find all MQTT clients and disconnect them
        devices.forEach(d => {
            const mqttClients = userDb.prepare(`
                SELECT client_id FROM MQTT WHERE device_id = ?
            `).all(d.device_id);

            mqttClients.forEach(m => {
                disconnectMQTTDevice(m.client_id); // 👈 disconnect MQTT
            });
        });

        // 3. Delete the user (CASCADE should clean up devices and MQTT rows if FK is set correctly)
        const result = userDb.prepare(`
            DELETE FROM Users WHERE id = ?
        `).run(userId);

        if (result.changes === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ success: true, message: "User deleted" });
    } catch (err) {
        console.error("Error deleting user:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/upload-profilePic/:id' , authenticate, profilePicUpload.single('profile'),(req, res) => {
    try {
      const userId = req.params.id;

      if (!req.file) {
        return res.status(400).send({ error: 'No file uploaded' });
      }

      const fileName = req.file.filename;

      // 1. Get current profile_pic
      const row = userDb.prepare(
        `SELECT profile_pic FROM Users WHERE id = ?`
      ).get(userId);

      if (!row) {
        return res.status(404).send({ error: 'User not found' });
      }

      // 2. Delete old profile picture if exists
      if (row.profile_pic) {
        const oldPath = path.join(ProfPic_DIR, row.profile_pic);
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }

      // 3. Update DB with new profile_pic
      userDb
        .prepare(`UPDATE Users SET profile_pic = ? WHERE id = ?`)
        .run(fileName, userId);

      res.send({ success: true, profile_pic: fileName });
    } catch (err) {
      console.error('Upload profile pic error:', err);
      res.status(500).send({ error: err.message });
    }
  }
);

app.put('/update-profile/:id', authenticate, async (req, res) => {
  const userId = req.params.id;

  try {
    // 1️⃣ Fetch the user
    const user = userDb.prepare(`SELECT * FROM Users WHERE id = ?`).get(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // 2️⃣ Prepare fields to update
    const fields = [
      'username', 'password', 'full_name', 'phone_number',
      'email', 'profile_pic', 'role', 'status', 'location'
    ];

    const updates = [];
    const values = [];
    let triggerDeviceDisconnect = false;

    for (const field of fields) {
      if (req.body[field] !== undefined) {
        if (field === 'password') {
          const hashed = await hashPassword(req.body.password);
          updates.push('password = ?');
          values.push(hashed);
          triggerDeviceDisconnect = true;
        } else if (field === 'username') {
          updates.push('username = ?');
          values.push(req.body.username);
          triggerDeviceDisconnect = true;
        } else {
          updates.push(`${field} = ?`);
          values.push(req.body[field]);
        }
      }
    }

    if (updates.length === 0)
      return res.status(400).json({ error: 'No valid fields provided' });

    values.push(userId); // for WHERE clause

    // 3️⃣ Update the user with unique/foreign key checks
    try {
      const sql = `UPDATE Users SET ${updates.join(', ')} WHERE id = ?`;
      userDb.prepare(sql).run(values);
    } catch (err) {
      if (err.message.includes('UNIQUE constraint failed: Users.username')) {
        return res.status(400).json({ error: 'Username already exists' });
      } else if (err.message.includes('UNIQUE constraint failed: Users.email')) {
        return res.status(400).json({ error: 'Email already exists' });
      } else if (err.message.includes('FOREIGN KEY constraint failed')) {
        return res.status(400).json({ error: 'Role not supported' });
      } else {
        throw err;
      }
    }

    // 4️⃣ Disconnect devices if username or password changed
    if (triggerDeviceDisconnect) {
      const devices = userDb.prepare(
        `SELECT device_id FROM Devices WHERE user_id = ?`
      ).all(userId);

      for (const d of devices) {
        try { disconnectSocketDevice(d.device_id); } 
        catch (err) { console.warn(`Failed to disconnect socket device ${d.device_id}`, err); }

        const mqttClients = userDb.prepare(
          `SELECT client_id FROM MQTT WHERE device_id = ?`
        ).all(d.device_id);

        for (const m of mqttClients) {
          try { disconnectMQTTDevice(m.client_id); } 
          catch (err) { console.warn(`Failed to disconnect MQTT client ${m.client_id}`, err); }
        }
      }

      userDb.prepare(`DELETE FROM Devices WHERE user_id = ?`).run(userId);
    }

    // 5️⃣ Return updated user (excluding password)
    const updatedUser = userDb.prepare(`
      SELECT id, username, full_name, phone_number, email, role, status, location, created_by, created_date
      FROM Users WHERE id = ?
    `).get(userId);

    res.json({
      success: true,
      message: 'User updated successfully',
      user: updatedUser
    });

  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});


app.post("/add-profile", authenticate, (req, res) => {
  const {
    username,
    password,
    full_name,
    phone_number,
    email,
    role,
    status,
    location,
  } = req.body;
  const created_by = req.user.user;

  console.log(req.body);
  console.log(created_by);

  // Validate required fields
  if (!username || !password || !full_name || !phone_number || !email || !role || !status || !location || !created_by) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // Validate role (example: only "admin" and "user" allowed)
  const allowedRoles = ["admin", "user"];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: "Role not supported" });
  }

  try {
    const stmt = userDb.prepare(`
      INSERT INTO Users (
        username, password, full_name, phone_number, email,
        role, status, location, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      username,
      password,
      full_name,
      phone_number,
      email,
      role,
      status,
      location,
      created_by
    );

    res.json({ success: true, userId: result.lastInsertRowid });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      // Check if username or email already exists
      const existingUser = userDb.prepare(
        `SELECT username, email FROM Users WHERE username = ? OR email = ?`
      ).get(username, email);

      if (existingUser) {
        console.lo
        if (existingUser.username === username) {
          return res.status(400).json({ error: "Username already exists" });
        }
        if (existingUser.email === email) {
          return res.status(400).json({ error: "Email already exists" });
        }
      }

      return res.status(400).json({ error: "Username or email already exists" });
    }

    console.error("Add user failed:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});



let serverSocket = null;
const pending = new Map(); // uuid -> { resolve, reject }
function socketAuthenticate(socket, next) {
  try {
    // Server-to-server key auth
    const serverKey = socket.handshake.auth?.serverKey;
    if (serverKey && serverKey === process.env.SERVER_KEY) {
      socket.isServer = true;
      serverSocket = socket;
      return next();
    }

    // Cookie-based auth
    const rawCookie = socket.handshake.headers.cookie;
    if (!rawCookie) return next(new Error("Unauthorized"));

    const cookies = cookie.parse(rawCookie);
    const token = cookies.token;
    if (!token) return next(new Error("Unauthorized"));

    const decoded = jwt.verify(token, JWT_SECRET);

    // Attach user info to socket
    socket.user = decoded.user;
    socket.user_id = decoded.id;
    socket.device_id = decoded.device_id;
    socket.role = decoded.role;
    next();
  } catch (err) {
    console.error("❌ JWT verification failed:", err.message);
    next(new Error("Unauthorized"));
  }
}

// 2️⃣ Access check middleware
function socketCheckAccess(socket, next) {
  try {
    if (socket.isServer) {
      // 🚫 Don't put serverSocket in any rooms
      return next();
    }
    // Check user profile status
    const user = userDb.prepare(`
      SELECT status FROM Users WHERE id = ?
    `).get(socket.user_id);

    if (!user) {
      return next(new Error("User not found"));
    }

    if (user.status === "Disactive") {
      return next(new Error("Profile disactive"));
    }

    // Check device status
    const device = userDb.prepare(`
      SELECT status FROM Devices WHERE device_id = ? AND user_id = ?
    `).get(socket.device_id, socket.user_id);

    if (!device) {
      return next(new Error("Device not registered"));
    }

    if (device.status === "Disconnected") {
      return next(new Error("Device is disconnected"));
    }
    // ✅ Join user-specific room (or role room)
    socket.join(`user:${socket.user_id}`);
    socket.join(`role:${socket.role}`);
    // ✅ Both checks passed
    console.log("✅ Socket Authenticated:", socket.user);
    next();
  } catch (err) {
    console.error("❌ Access check failed:", err.message);
    next(new Error("Unauthorized"));
  }
}

function socketUpdateLastSeen(socket, next) {
  try {
    const stmt = userDb.prepare(`
      UPDATE Devices
      SET last_seen = datetime('now'),
          status = 'Online'
      WHERE device_id = ?
      RETURNING 
        device_id,
        user_id,
        name,
        os,
        browser,
        status,
        login_at,
        last_seen;
    `);

    const device = stmt.get(socket.device_id);

    if (device && device.user_id) {
      io.to(`user:${device.user_id}`).emit("device", device);
    }

    next();
  } catch (err) {
    console.error("❌ Error updating last_seen (socket):", err);
    next(new Error("Internal error"));
  }
}

// 🔗 Apply middlewares
io.use(socketAuthenticate);
io.use(socketCheckAccess);
function disconnectSocketDevice(deviceId) {
  try {
    let success = false;

    // 🔌 Loop sockets and act on match
    for (const socket of io.sockets.sockets.values()) {
      if (socket.device_id === deviceId) {
        try {
          socket.emit("forceDisconnect", { reason: "You have been kicked out" }, () => {
            socket.disconnect(true);
          });
          setTimeout(() => socket.disconnect(true), 1000);
          console.log(`🔌 Device ${deviceId} disconnected`);
          success = true;
        } catch (sockErr) {
          console.error(`❌ Socket deconecting error for ${deviceId}:`, sockErr);
        }
        break;
      }
    }

    return success;
  } catch (err) {
    console.error("❌ Unexpected error:", err);
    return false;
  }
}

function cleanupExpiredDevices() {
  const now = Math.floor(Date.now() / 1000); // current UNIX timestamp (seconds)

  // Step 1: Get all expired device_ids
  const expiredDevices = userDb.prepare(`
    SELECT device_id FROM Tokens WHERE expire_date < ?
  `).all(now);

  if (expiredDevices.length === 0) {
    console.log("✅ No expired devices found");
    return;
  }

  // Step 2: Delete devices (tokens auto-deleted due to ON DELETE CASCADE)
  const deleteStmt = userDb.prepare(`
    DELETE FROM Devices WHERE device_id = ?
  `);
  const getUserStmt = userDb.prepare(`
    SELECT user_id FROM Devices WHERE device_id = ?
  `);

  const transaction = userDb.transaction((devices) => {
    for (const { device_id } of devices) {
      // Get user_id first
      const row = getUserStmt.get(device_id);
      if (!row) {
        console.warn(`⚠️ Device ${device_id} not found in DB`);
        continue;
      }
      const userId = row.user_id;

      // Delete device
      deleteStmt.run(device_id);

      // Emit event to correct user
      const device = { device_id, deleted: true };
      io.to(`user:${userId}`).emit("device", device);

      console.log(`🗑️ Deleted expired device: ${device_id} (user ${userId})`);
    }
  });

  transaction(expiredDevices);
}

// Run every 24h (86400000 ms)
setInterval(cleanupExpiredDevices, 1 * 1 * 60 * 1000);

// Optionally: run once on server start too
cleanupExpiredDevices();

// socket io
io.on('connection', (socket) => {
  console.log(`✅ User ${socket.user_id} on device ${socket.device_id} connected`); 
  socket.use((packet, next) => {
    console.log("📦 Incoming event:", packet[0]); // e.g. event name
    if(!socket.isServer){
      socketUpdateLastSeen(socket, next)}
      next();
  });
  socket.on("disconnect", (reason) => {
    try {
      console.log(`❌ Socket disconnected for device ${socket.device_id}, user ${socket.user_id}, reason: ${reason}`);

      // Ignore server-forced disconnects
      const ignoreReasons = ["server namespace disconnect"]; 
      if (ignoreReasons.includes(reason)) {
        console.log("ℹ️ Disconnect was server-forced, skipping DB update");
        return;
      }
      // Check current status in DB
      const row = userDb.prepare(`
        SELECT status FROM Devices WHERE device_id = ?
      `).get(socket.device_id);

      // Don't overwrite forbidden statuses
      const forbidden = ["Disconnected"];
      if (!row || forbidden.includes(row.status)) {
        return;
      }

      // Update device to Offline
      const stmt = userDb.prepare(`
        UPDATE Devices
        SET last_seen = datetime('now'),
            status = 'Offline'
        WHERE device_id = ?
        RETURNING 
          device_id,
          user_id,
          name,
          os,
          browser,
          status,
          login_at,
          last_seen;
      `);
      const device = stmt.get(socket.device_id);

      if (device && device.user_id) {
        io.to(`user:${device.user_id}`).emit("device", device);
      }
    } catch (err) {
      console.error("❌ Error in disconnect handler:", err);
    }
  });

  socket.on('get_silos', () => {
    try {
      const query = sysDb.prepare(`
        SELECT 
            e.id AS equipment_id,

            -- status
            es.name AS status_name,
            es.value AS status_value,
            es.last_update AS status_last_update,

            -- parameters
            ep.name AS param_name,
            ep.value AS param_value,
            ep.last_update AS param_last_update,

            -- sensors
            est.sensor_type,
            est.value AS sensor_value,
            st.unit AS sensor_unit,

            -- consignes
            c.name AS consigne_name,
            c.value AS consigne_value,
            c.last_time_change AS consigne_last_update

        FROM Equipments e
        JOIN EquipmentTypes et
            ON e.type = et.type
        LEFT JOIN EquipmentStatus es
            ON e.id = es.equipment_id
        LEFT JOIN EquipmentParameters ep
            ON e.id = ep.equipment_id
        LEFT JOIN EquipmentSensorTypes est
            ON e.id = est.equipment_id
        LEFT JOIN SensorTypes st
            ON est.sensor_type = st.type
        LEFT JOIN EquipmentSensorTypeConsigne c
            ON est.equipment_id = c.equipment_id
            AND est.sensor_type = c.sensor_type
        WHERE et.type = 'Silo'
        ORDER BY e.id;
      `);

      const rows = query.all();
      const result = {};

      rows.forEach(row => {
        const siloId = `${row.equipment_id}`;

        if (!result[siloId]) {
          result[siloId] = {
            status: {},
            parameters: {},
            sensors: {}
          };
        }

        // --- statuses
        if (row.status_name) {
          result[siloId].status[row.status_name] = {
            value: row.status_value,
            last_update: row.status_last_update
          };
        }

        // --- parameters
        if (row.param_name) {
          result[siloId].parameters[row.param_name] = {
            value: row.param_value,
            last_update: row.param_last_update
          };
        }

        // --- sensors & consignes
        if (row.sensor_type) {
          if (!result[siloId].sensors[row.sensor_type]) {
            result[siloId].sensors[row.sensor_type] = {
              value: row.sensor_value,
              unit: row.sensor_unit,
              consignes: {}
            };
          }

          if (row.consigne_name) {
            result[siloId].sensors[row.sensor_type].consignes[row.consigne_name] = {
              value: row.consigne_value,
              last_update: row.consigne_last_update
            };
          }
        }
      });

      console.log(result);
      socket.emit('silos', result);

    } catch (err) {
      console.error('DB error:', err);
      socket.emit('silos', { error: 'Database error' });
    }
  });

  socket.on('get_silos_grid', () => {
    try {
      const rows = sysDb.prepare(`
        SELECT 
            e.id AS silo_id,
            est.sensor_type,
            CASE 
                WHEN est.sensor_type = 'Level_SILO' THEN est.value
                ELSE NULL
            END AS level_value,
            sgm.max_level,
            sgm.max_x,
            sgm.max_y,
            s.id AS sensor_id,
            s.value AS sensor_value,
            s.status AS sensor_status,
            sp.level AS pos_level,
            sp.x AS pos_x,
            sp.y AS pos_y,
            sc.name AS consigne_name,
            sc.value AS consigne_value
        FROM Equipments e
        JOIN EquipmentSensorTypes est 
            ON e.id = est.equipment_id
        LEFT JOIN SensorGridMatrixSize sgm 
            ON est.sensor_type = sgm.sensor_type 
            AND est.sensor_type != 'Level_SILO'
        LEFT JOIN Sensors s 
            ON s.equipment_id = e.id 
            AND s.type = est.sensor_type
            AND est.sensor_type != 'Level_SILO'
        LEFT JOIN SensorPosition sp 
            ON sp.sensor_id = s.id
        LEFT JOIN SensorConsigns sc 
            ON sc.sensor_id = s.id
        WHERE e.type = 'Silo'
        ORDER BY e.id, est.sensor_type, s.id, sc.name
      `).all();

      const silos = {};

      for (const row of rows) {
        const siloId = row.silo_id;

        if (!silos[siloId]) {
          silos[siloId] = {
            gridmatrix: { level: 0, x: 0, y: 0 },
            level: null,
            positions: {}
          };
        }

        // Update gridmatrix with max values
        silos[siloId].gridmatrix.level = Math.max(
          silos[siloId].gridmatrix.level,
          row.max_level || 0
        );
        silos[siloId].gridmatrix.x = Math.max(
          silos[siloId].gridmatrix.x,
          row.max_x || 0
        );
        silos[siloId].gridmatrix.y = Math.max(
          silos[siloId].gridmatrix.y,
          row.max_y || 0
        );

        // Handle Level_SILO
        if (row.sensor_type === 'Level_SILO' && row.level_value !== null) {
          silos[siloId].level = row.level_value;
          continue; // skip sensor handling
        }

        if (!row.sensor_id) continue; // no sensor instance

        // Build positions[level-x][sensor_type][y]
        const posKey = `${row.pos_level}-${row.pos_x}`;
        if (!silos[siloId].positions[posKey]) {
          silos[siloId].positions[posKey] = {};
        }

        if (!silos[siloId].positions[posKey][row.sensor_type]) {
          silos[siloId].positions[posKey][row.sensor_type] = {};
        }

        if (!silos[siloId].positions[posKey][row.sensor_type][row.pos_y]) {
          silos[siloId].positions[posKey][row.sensor_type][row.pos_y] = {
            name: row.sensor_id,
            value: row.sensor_value,
            status: row.sensor_status,
            consigne: []
          };
        }

        // Push consigne if present
        if (row.consigne_name) {
          silos[siloId].positions[posKey][row.sensor_type][row.pos_y].consigne.push({
            name: row.consigne_name,
            value: row.consigne_value
          });
        }
      }
      console.log(silos);
      socket.emit('silos_grid', silos);
    } catch (err) {
      console.error('DB error:', err);
      socket.emit('silos_grid', { error: 'Database error' });
    }
  });

  socket.on('get_minisilos', () => {
    try {
        const query = sysDb.prepare(`
          SELECT 
              e.id AS equipment_id,
              ep_country.value AS country,
              ep_contenttype.value AS content_type,
              ep_role.value AS role,
              ep_capacity.value AS capacity,
              es.value AS status,
              st.type AS sensor_type,
              st.unit AS sensor_unit,
              CASE 
                  WHEN st.unit = 'BOOL' THEN s.value
                  ELSE est.value
              END AS sensor_value,
              CASE 
                  WHEN st.unit = 'BOOL' THEN sp.level
                  ELSE NULL
              END AS sensor_level
          FROM Equipments e
          JOIN EquipmentTypes et 
              ON e.type = et.type
          LEFT JOIN EquipmentStatus es  -- Added for operating status
              ON e.id = es.equipment_id 
              AND es.name = 'OperatingStatus'
          LEFT JOIN EquipmentParameters ep_country 
              ON e.id = ep_country.equipment_id 
              AND ep_country.name = 'Country'
          LEFT JOIN EquipmentParameters ep_contenttype 
              ON e.id = ep_contenttype.equipment_id 
              AND ep_contenttype.name = 'ContentType'
          LEFT JOIN EquipmentParameters ep_role 
              ON e.id = ep_role.equipment_id 
              AND ep_role.name = 'Role'
          LEFT JOIN EquipmentParameters ep_capacity
              ON e.id = ep_capacity.equipment_id 
              AND ep_capacity.name = 'Capacity'
          LEFT JOIN EquipmentSensorTypes est 
              ON e.id = est.equipment_id
          LEFT JOIN SensorTypes st
              ON st.type = est.sensor_type
          LEFT JOIN Sensors s 
              ON e.id = s.equipment_id
              AND s.type = st.type
          LEFT JOIN SensorPosition sp
              ON s.id = sp.sensor_id
          WHERE et.type = 'MiniSilo'
          ORDER BY e.id;
        `);
        const rows = query.all();
        const result = {};

        rows.forEach(row => {
            const siloId = `${row.equipment_id}`;
            
            // Initialize silo object if not exists
            if (!result[siloId]) {
                result[siloId] = {
                    status: row.operating_status || null,
                    country: row.country || null,
                    content: row.content_type || null,
                    capacity: row.capacity ? Number(row.capacity) : null,
                    full: null,  // For LevelIndc_MSILO High
                    empty: null // For LevelIndc_MSILO Low
                };
            }
            
            // Process LevelIndc_MSILO sensor
            if (row.sensor_type === 'LevelIndc_MSILO') {
                if (row.sensor_level === 2) {
                    result[siloId].full = row.sensor_value;
                } else if (row.sensor_level === 1) {
                    result[siloId].empty = row.sensor_value;
                }
            }
            // Process other sensors
            else if (row.sensor_type) {
                // Clean sensor name by removing '_MSILO' suffix
                const cleanType = row.sensor_type.replace(/_MSILO$/, '');
                
                // Only add sensor if not already present
                if (!result[siloId][cleanType]) {
                    result[siloId][cleanType] = {
                        value: row.sensor_value,
                        unit: row.sensor_unit === 'BOOL' ? '' : row.sensor_unit
                    };
                }
            }
        });

        socket.emit('minisilos', result);
    } catch (err) {
        console.error('DB error:', err);
        socket.emit('minisilos', { error: 'Database error' });
    }
  });

  socket.on('get_silos_sensor_detail', (type, id) => {
    try {
      const query = `
        SELECT 
            a.level,
            a.value AS avg_value,
            c.name AS consign_name,
            c.value AS consign_value,
            c.last_update AS consign_time,

            sp.sensor_id,
            s.type AS sensor_type,
            s.value AS sensor_value,
            sc.value AS target_value

        FROM SenserType_Averages_per_Level a
        LEFT JOIN SensorConsigns_per_level c 
            ON a.level = c.level
          AND a.equipment_id = c.equipment_id
          AND a.sensor_type = c.sensor_type
        LEFT JOIN SensorPosition sp
            ON sp.level = a.level
        LEFT JOIN Sensors s
            ON s.id = sp.sensor_id
          AND s.equipment_id = a.equipment_id
        LEFT JOIN SensorConsigns sc
            ON sc.sensor_id = sp.sensor_id
          AND sc.name = 'TARGET'
        WHERE a.equipment_id = ?
          AND a.sensor_type = ?
        ORDER BY a.level, c.name;
      `;

      const rows = sysDb.prepare(query).all(id, type);

      const result = {};
      for (const row of rows) {
        if (!result[row.level]) {
          result[row.level] = {
            value: row.avg_value,
            consigns: {},
            sensors: {}
          };
        }

        // --- consigns per level
        if (row.consign_name) {
          result[row.level].consigns[row.consign_name] = {
            value: row.consign_value,
            time: row.consign_time
          };
        }

        // --- sensors (only if type matches the input)
        if (row.sensor_id && row.sensor_type === type) {
          if (!result[row.level].sensors[row.sensor_id]) {
            result[row.level].sensors[row.sensor_id] = {
              value: row.sensor_value,
              target: row.target_value !== undefined ? row.target_value : null
            };
          }
        }
      }

      console.log(result);
      socket.emit('sensor_detail', result);
    } catch (err) {
      console.error('DB error:', err);
      socket.emit('sensor_detail', { error: 'Database error' });
    }
  });

  socket.on('get_timed_sensor_data', (equipment_id,windowSizeVal,windowSizeUnit) => {
    console.log(windowSizeVal,windowSizeUnit,equipment_id)
    try {
      const query = `
          SELECT
              r.type AS sensor_type,
              r.value AS sensor_value,
              r.date
          FROM Equipments e
          JOIN EquipmentSensorTypes est 
              ON e.id = est.equipment_id
          JOIN EquipmentSensorTypeAveragesReadings r 
              ON r.equipment_id = e.id 
              AND r.type = est.sensor_type
          CROSS JOIN (
              SELECT MAX(date) AS max_date 
              FROM EquipmentSensorTypeAveragesReadings
          ) md
          WHERE 
              e.id = ?
              AND r.date BETWEEN datetime(md.max_date, '-' || ? || ' ' || ?) AND md.max_date
          ORDER BY r.date ASC;
      `;

      const rows = sysDb.prepare(query).all(equipment_id, windowSizeVal, windowSizeUnit);
      
      // Organize data by sensor type
      const result = {};
      
      for (const row of rows) {
          const sensorType = row.sensor_type;
          
          if (!result[sensorType]) {
              result[sensorType] = [];
          }
          
          result[sensorType].push({
              value: row.sensor_value,
              date: row.date
          });
      }
      console.log(result)
      socket.emit('timed_sensor_data', result);

    } catch (err) {
      console.error('Error fetching timed sensor data:', err);
      socket.emit('timed_sensor_data', { error: err.message });
    }
  });

  socket.on('get_equipment_types', () => {
    try {
      const query = `
        SELECT type 
        FROM EquipmentTypes;
      `;

      const result = sysDb.prepare(query).all();

      // convert from [{type: 'Silo'}, {type: 'Conveyor'}] -> ['Silo', 'Conveyor']
      const types = result.map(row => row.type);

      socket.emit('equipment_types', types);

    } catch (err) {
      console.error('Error fetching equipment types:', err);
      socket.emit('equipment_types', { error: err.message });
    }
  });

  socket.on('get_equipments', (type) => {
    try {
      // 1️⃣ Fetch all equipment IDs for this type
      const query = `
        SELECT id
        FROM Equipments
        WHERE type = ?;
      `;

      const result = sysDb.prepare(query).all(type);

      // convert to array of strings
      const equipments = result.map(row => row.id);

      // 2️⃣ Fetch the last date for these equipments
      let lastDate = null;
      if (equipments.length > 0) {
        const placeholders = equipments.map(() => '?').join(", "); // ?,?,?
        const lastDateQuery = `
          SELECT r.date
          FROM EquipmentSensorTypeAveragesReadings r
          WHERE r.equipment_id IN (${placeholders})
          ORDER BY r.date DESC
          LIMIT 1;
        `;

        const dateResult = sysDb.prepare(lastDateQuery).get(...equipments);
        if (dateResult) {
          lastDate = dateResult.date;
        }
      }

      // 3️⃣ Send both results back
      socket.emit('equipments', { equipments, lastDate });

    } catch (err) {
      console.error('Error fetching equipments:', err);
      socket.emit('equipments', { error: err.message });
    }
  });


  socket.on('get_sensor_types', (equipmentId) => {
    try {
      const query = `
        SELECT est.sensor_type, st.unit
        FROM EquipmentSensorTypes est
        JOIN SensorTypes st
          ON est.sensor_type = st.type
        WHERE est.equipment_id = ?
          AND st.unit != 'BOOL';   

      `;

      const stmt = sysDb.prepare(query);
      const rows = stmt.all(equipmentId);

      // format into array of { sensor_type, unit }
      const sensorTypes = rows.map(row => ({
        sensor_type: row.sensor_type,
        unit: row.unit
      }));
      socket.emit('sensor_types', sensorTypes);

    } catch (err) {
      console.error('Error fetching sensor_types:', err);
      socket.emit('sensor_types', { error: err.message });
    }
  });

  socket.on('get_sensor_data', (equipmentId, start_time, end_time) => {
    try {
      console.log("Params:", equipmentId, start_time, end_time);

      // 🔹 Query 1: sensor readings
      const query1 = `
        SELECT
            r.type AS sensor_type,
            st.unit AS sensor_unit,
            r.value AS sensor_value,
            r.date
        FROM EquipmentSensorTypeAveragesReadings r
        JOIN SensorTypes st
            ON r.type = st.type
        WHERE r.equipment_id = ?
          AND r.date BETWEEN ? AND ?
        ORDER BY r.date ASC;
      `;

      const stmt1 = sysDb.prepare(query1);
      const rows = stmt1.all(equipmentId, start_time, end_time);

      // ✅ Build result format
      const result = {};
      for (const row of rows) {
        if (!result[row.sensor_type]) {
          result[row.sensor_type] = {
            unit: row.sensor_unit,
            values: [],
            consignes: {}   // 🔹 grouped by consigne name
          };
        }
        result[row.sensor_type].values.push({
          value: row.sensor_value,
          date: row.date
        });
      }

      // 🔹 Query 2: consigne changes (for each sensor_type)
      const query2 = `
        WITH range_changes AS (
            SELECT 
                name,
                value,
                change_at
            FROM EquipmentSensorTypeConsigneHistory
            WHERE equipment_id = :eq_id
              AND sensor_type = :sensor_type
              AND change_at BETWEEN :start_time AND :end_time
        ),
        last_before AS (
            SELECT 
                h.name,
                h.value,
                h.change_at
            FROM EquipmentSensorTypeConsigneHistory h
            WHERE h.equipment_id = :eq_id
              AND h.sensor_type = :sensor_type
              AND h.change_at < :start_time
              AND h.change_at = (
                  SELECT MAX(h2.change_at)
                  FROM EquipmentSensorTypeConsigneHistory h2
                  WHERE h2.equipment_id = h.equipment_id
                    AND h2.sensor_type = h.sensor_type
                    AND h2.name = h.name
                    AND h2.change_at < :start_time
              )
        )
        SELECT * FROM range_changes
        UNION
        SELECT * FROM last_before
        ORDER BY change_at;
      `;

      const stmt2 = sysDb.prepare(query2);

      // 🔹 Loop over each sensor_type found in readings
      for (const sensor_type of Object.keys(result)) {
        const consigneRows = stmt2.all({
          eq_id: equipmentId,
          sensor_type,
          start_time,
          end_time
        });

        for (const c of consigneRows) {
          // ensure consigne[name] array exists
          if (!result[sensor_type].consignes[c.name]) {
            result[sensor_type].consignes[c.name] = [];
          }

          result[sensor_type].consignes[c.name].push({
            value: c.value,
            date: c.change_at
          });
        }
      }

      // ✅ Send back full structured result
      socket.emit('sensor_data', result);

    } catch (err) {
      console.error('Error fetching sensor_data:', err);
      socket.emit('sensor_data', { error: err.message });
    }
  });
  
  socket.on('get_system_log', (limit, offset) => {
    try {
      console.log("Params:",  limit, offset);
      console.log(socket.user_id)
      // Get user info including role
      const userStmt = sysDb.prepare(`
        SELECT role
        FROM userDb.Users
        WHERE id = ? 
      `);
      const user = userStmt.get(socket.user_id);

      if (!user) {
        socket.emit('system_log', { error: "User not found" });
        return;
      }

      const userId = socket.user_id;
      const userRole = user.role;

      // Fetch logs and check read_permession includes user's role
      const query = `
        SELECT 
            l.id,
            l.name,
            l.message,
            l.type,
            l.sender,
            l.log_date,
            CASE WHEN r.log_id IS NOT NULL THEN 1 ELSE 0 END AS is_read
        FROM system_log l
        LEFT JOIN userDb.system_logs_readed r
            ON r.log_id = l.id
          AND r.user_id = ?
        WHERE l.read_permession IS NULL 
          OR ',' || l.read_permession || ',' LIKE '%,' || ? || ',%'
        ORDER BY l.log_date DESC
        LIMIT ? OFFSET ?;
      `;

      const stmt = sysDb.prepare(query);
      const rows = stmt.all(userId, userRole, limit, offset);

      console.log(rows);
      socket.emit('system_log', rows);

    } catch (err) {
      console.error("Error fetching system logs:", err.message);
      socket.emit('system_log', { error: err.message });
    }
  });

  // 1️⃣ Fetch log detail (does NOT mark as read)
  socket.on("get_system_log_detail", (logId) => {
    try {
      const stmt = sysDb.prepare(`SELECT detail, extra_files
        FROM system_log
        WHERE id = ? 
          AND (
            read_permession LIKE '%' || ? || '%' 
            OR read_permession IS NULL 
            OR read_permession = ''
          );
        `);
      const row = stmt.get(logId,socket.role);

      socket.emit("system_log_detail", {
        id: logId,
        detail: row.detail || null,
        extra_files: row.extra_files || null
      });
      console.log(row)
    } catch (err) {
      console.error("Error fetching log detail:", err.message);
      socket.emit("system_log_detail", { error: err.message });
    }
  });

  // 2️⃣ Mark log as read
  socket.on("set_system_log_read", (logId, userFirstName, userLastName) => {
    try {
      // Get user ID
      const userStmt = sysDb.prepare(`
        SELECT id 
        FROM userDb.Users 
        WHERE first_name = ? AND last_name = ?
      `);
      const user = userStmt.get(userFirstName, userLastName);
      if (!user) return socket.emit("system_log_read_status", { error: "User not found" });

      const userId = user.id;

      // Insert into system_logs_readed if not exists
      const insertStmt = userDb.prepare(`
        INSERT OR IGNORE INTO system_logs_readed (user_id, log_id)
        VALUES (?, ?)
      `);
      insertStmt.run(userId, logId);

      socket.emit("system_log_read_status", { id: logId, success: true });
    } catch (err) {
      console.error("Error marking log as read:", err.message);
      socket.emit("system_log_read_status", { error: err.message });
    }
  });
  socket.on('get_logs', (searchWords, Filters, limit = 15, offset = 0) => {
      try {
          console.log("Params:",searchWords, Filters, limit, offset);

          const userId = socket.id;
          const userRole = socket.role;

          // Normalize filters from client
          const clientFilters = Filters || {};
          const filters = {
              sender: clientFilters.Sender || clientFilters.sender || null,
              type: clientFilters.Type || clientFilters.type || null,
              dayFrom: clientFilters.From || clientFilters.from || null,
              dayTo: clientFilters.To || clientFilters.to || null
          };

          const hasFilters = filters.sender || filters.type || filters.dayFrom || filters.dayTo;

          // Start building the query
          let query = `
              SELECT 
                  l.id,
                  l.name,
                  l.message,
                  l.detail,
                  l.sender,
                  l.type,
                  l.log_date,
                  CASE WHEN r.log_id IS NOT NULL THEN 1 ELSE 0 END AS is_read
              FROM system_log l
              LEFT JOIN userDb.system_logs_readed r
                  ON r.log_id = l.id
                AND r.user_id = ?
              WHERE (l.read_permession IS NULL OR ',' || l.read_permession || ',' LIKE '%,' || ? || ',%')
          `;
          const params = [userId, userRole];

          // Multi-word search
          if (Array.isArray(searchWords) && searchWords.length > 0) {
              searchWords.forEach(word => {
                  const pattern = `%${word}%`;
                  if (hasFilters) {
                      // With filters: search in message and detail
                      query += ' AND (l.message LIKE ? OR l.detail LIKE ?)';
                      params.push(pattern, pattern);
                  } else {
                      // No filters: search in message, sender, and type
                      query += ' AND (l.message LIKE ? OR l.sender LIKE ? OR l.type LIKE ?)';
                      params.push(pattern, pattern, pattern);
                  }
              });
          }

          // Exact filters
          if (filters.sender) {
              query += ' AND l.sender = ?';
              params.push(filters.sender);
          }
          if (filters.type) {
              query += ' AND l.type = ?';
              params.push(filters.type);
          }

          // Date filters
          if (filters.dayFrom && filters.dayTo) {
              query += ' AND l.log_date BETWEEN ? AND ?';
              params.push(filters.dayFrom, filters.dayTo);
          } else if (filters.dayFrom && !filters.dayTo) {
              query += ' AND DATE(l.log_date) = ?';
              params.push(filters.dayFrom);
          }

          // Pagination
          query += ' ORDER BY l.log_date DESC LIMIT ? OFFSET ?';
          params.push(limit, offset);

          const stmt = sysDb.prepare(query);
          const rows = stmt.all(...params);

          console.log(rows);
          socket.emit('logs_result', rows);

      } catch (err) {
          console.error("Error fetching system logs:", err.message);
          socket.emit('logs_result', { error: err.message });
      }
  });
  


});

app.post("/api/uploadeventfilles/:event", authenticate, upload.array("files"), async (req, res) => {
  const { event } = req.params;
  const sender = req.user.user;   
  console.log("Sender:", sender);

  uploadEventFilles(req, res, event, sender);
});

async function uploadEventFilles(data, res, event, sender) {
  const {meta} = data.body
  const body = meta;
  const { value } = body;
  console.log(meta)
  const tempBundleFile = path.join(TEMP_DIR, Date.now() + "_bundle.json");

  // Ensure files is always an array internally
  const bundle = { 
    fields: body, 
    files: data.files || [], 
    status: "waiting" 
  };

  fs.writeFileSync(tempBundleFile, JSON.stringify(bundle, null, 2));

  if (!serverSocket) {
    return res.status(400).json({ error: "Server socket not connected" });
  }

  try {
    // Wait for socket response
    const approve = await new Promise((resolve, reject) => {
      const id = uuidv4();
      console.log("body",body)
      serverSocket.emit(event, { data:body, uploadID: id });

      const responseHandler = ({ uploadID, approve }) => {
        console.log(uploadID)
        if (uploadID === id) {
          serverSocket.off(`${event}_ack`, responseHandler);
          resolve(approve);
        }
      };

      serverSocket.on(`${event}_ack`, responseHandler);

      setTimeout(() => {
        serverSocket.off(`${event}_ack`, responseHandler);
        reject(new Error("Socket response timeout"));
      }, 15000);
    });

    if (approve) {
      const newFileNames = [];

      if (bundle.files.length > 0) {
        // Move uploaded files to permanent dir
        bundle.files.forEach(f => {
          const oldPath = f.path;
          const newPath = path.join(UPLOADS_DIR, path.basename(f.path));
          fs.renameSync(oldPath, newPath);
          f.path = newPath;
          newFileNames.push(f.filename);
        });

        body.files = newFileNames; // only add if there are files
      }

      bundle.status = "saved";
      fs.writeFileSync(tempBundleFile, JSON.stringify(bundle, null, 2));
      fs.unlinkSync(tempBundleFile);

      body.sender = sender;
      const payload = body;
      console.log(payload)
      console.log("Payload:", payload);
      Set_event(event,payload);
      return res.json({ success: true, ...payload });
    } else {
      // Clean up temp files
      bundle.files.forEach(f => fs.unlinkSync(f.path));
      fs.unlinkSync(tempBundleFile);
      return res.json({ success: false, message: "Rejected by socket" });
    }
  } catch (err) {
    console.error("Upload approval error:", err);
    try {
      bundle.files.forEach(f => fs.unlinkSync(f.path));
      fs.unlinkSync(tempBundleFile);
    } catch (cleanupErr) {
      console.error("Cleanup error:", cleanupErr);
    }
    return res.status(500).json({ error: "Approval process failed" });
  }
}

// Start the server
const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
