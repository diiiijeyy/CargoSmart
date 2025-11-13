require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const http = require("http");
const axios = require("axios"); // Only if you use it
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const { PDFDocument, StandardFonts, rgb } = require("pdf-lib");
const UAParser = require("ua-parser-js");
const logAction = require("./utils/auditLogger");
const pgSession = require("connect-pg-simple")(session);
const fetch = require("node-fetch");

//pinaltan ni jade

// =====================================
// ✅ Server setup
// =====================================
const PORT = process.env.PORT || 5001;
const app = express();
const server = http.createServer(app);
const WebSocket = require("ws");
const wss = new WebSocket.Server({ server });

const latestGPSData = {};

// ==========================
// 📡 broadcast GPS to frontend
// ==========================
function broadcastUpdate(shipmentId) {
  const latest = latestGPSData[shipmentId];
  if (!latest) return;

  // 🟢 Fetch the device_id for this shipment
  pool
    .query(
      `SELECT device_id FROM gps_assignments 
     WHERE shipment_id = $1 AND released_at IS NULL 
     ORDER BY assigned_at DESC LIMIT 1`,
      [shipmentId]
    )
    .then((result) => {
      const deviceId = result.rows[0]?.device_id || null;

      const payload = {
        deviceId, // ✅ added
        shipmentId,
        latitude: Number(latest.latitude),
        longitude: Number(latest.longitude),
        speed: latest.speed,
        timestamp: latest.timestamp,
      };

      const json = JSON.stringify(payload);
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(json);
        }
      });
    })
    .catch((err) => console.error("broadcastUpdate() error:", err));
}

//pinaltan ni jade

// =====================================
// 📁 Serve Frontend (Ngrok compatible)
// =====================================
app.use("/frontend", express.static(path.join(__dirname, "../frontend")));

//for frontend

app.use(express.static(path.join(__dirname, "frontend")));

// =====================================
// 🌐 CORS Configuration (Ngrok + Credentials)
// =====================================
app.set("trust proxy", 1);

app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] === "https") req.secure = true;
  next();
});

app.use(
  cors({
    origin: [
      "https://tslfreightmovers.com",
      "https://www.tslfreightmovers.com",
      "http://localhost:5001"
    ],
    credentials: true
  })
);

// =====================================
// 🧩 Essential Middlewares
// =====================================
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Serve uploaded documents (static route for download/display)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use("/invoices", express.static(path.join(__dirname, "invoices")));

// =====================================
// 🍪 Session Setup (Ngrok Compatible)
// =====================================
app.use(
  session({
    secret: process.env.Session_Secret || "dev-secret",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: true, // required for HTTPS cookies
      sameSite: "none", // allow frontend on different origin
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
  })
);

// Wrap the fetch call in an async function
const loginUser = async (input, password) => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include", // This ensures that the session cookie is sent
      body: JSON.stringify({ input, password }),
    });

    const data = await response.json();
    console.log("Login successful:", data); // Use the data as needed
  } catch (err) {
    console.error("Error during login:", err);
  }
};

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "CARGOSMART",
  password: process.env.DB_PASSWORD || "",
  port: process.env.DB_PORT || 5432,
});

pool.query("SELECT NOW()", (err) => {
  if (err) console.error("Database connection error:", err);
  else console.log("✅ Database connected successfully");
});

//-----------------------//
//  CLIENT VERIFICATION //
//---------------------//

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.verify((err, success) => {
  if (err) console.error("❌ Mail transporter error:", err);
  else console.log("✅ Mail transporter ready");
});

/* ----------------------------------------
   🟢 STEP 1: SIGNUP - Store directly in clients
---------------------------------------- */
app.post("/api/client/signup", async (req, res) => {
  const {
    company_name,
    contact_person,
    contact_number,
    email,
    password,
    address,
  } = req.body;

  try {
    // 1️⃣ Check if already exists
    const existing = await pool.query(
      "SELECT * FROM clients WHERE email = $1",
      [email]
    );
    if (existing.rows.length > 0) {
      const client = existing.rows[0];
      if (client.is_verified) {
        return res
          .status(400)
          .json({ error: "Email already registered and verified." });
      } else {
        // Remove old unverified record
        await pool.query("DELETE FROM clients WHERE email = $1", [email]);
      }
    }

    // 2️⃣ Generate verification code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();
    const codeExpiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3️⃣ Insert into clients table (unverified)
    await pool.query(
      `INSERT INTO clients 
        (company_name, contact_person, contact_number, email, address, password,
         failed_attempts, lockout_time, archived, role, photo,
         is_verified, verification_code, code_expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6,
               0, NULL, false, 'client', NULL,
               false, $7, $8, NOW())`,
      [
        company_name,
        contact_person,
        contact_number,
        email,
        address,
        hashedPassword,
        verificationCode,
        codeExpiresAt,
      ]
    );

    // 4️⃣ Send verification email
    await transporter.sendMail({
      from: `"TSL Freight Movers" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Verify Your Email - TSL Freight Movers",
      html: `
        <h2>Welcome to TSL Freight Movers!</h2>
        <p>Your verification code is:</p>
        <h1 style="letter-spacing: 4px;">${verificationCode}</h1>
        <p>This code will expire in <b>5 minutes</b>.</p>
      `,
    });

    res.json({ message: "Verification code sent to your email." });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ----------------------------------------
   🟢 STEP 2: VERIFY CODE
---------------------------------------- */
app.post("/api/client/verify", async (req, res) => {
  const { email, code } = req.body;

  try {
    const result = await pool.query("SELECT * FROM clients WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res
        .status(400)
        .json({ error: "Email not found. Please sign up again." });
    }

    const client = result.rows[0];

    // Check if already verified
    if (client.is_verified) {
      return res
        .status(400)
        .json({ error: "This account is already verified." });
    }

    // Compare code
    if (client.verification_code.trim() !== code.trim()) {
      return res.status(400).json({ error: "Invalid verification code." });
    }

    // Check expiration
    if (new Date() > new Date(client.code_expires_at)) {
      return res.status(400).json({
        error: "Verification code expired. Please request a new one.",
      });
    }

    // ✅ Mark as verified
    await pool.query(
      `UPDATE clients 
       SET is_verified = true, verification_code = NULL, code_expires_at = NULL 
       WHERE email = $1`,
      [email]
    );

    res.json({ message: "Email verified successfully!" });
  } catch (error) {
    console.error("Verification error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

/* ----------------------------------------
   🟢 STEP 3: RESEND CODE
---------------------------------------- */
app.post("/api/client/resend-code", async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query("SELECT * FROM clients WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "No account found for this email." });
    }

    const client = result.rows[0];

    if (client.is_verified) {
      return res.status(400).json({ error: "Account already verified." });
    }

    // Generate new code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();
    const codeExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await pool.query(
      `UPDATE clients 
       SET verification_code = $1, code_expires_at = $2 
       WHERE email = $3`,
      [verificationCode, codeExpiresAt, email]
    );

    await transporter.sendMail({
      from: `"TSL Freight Movers" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "New Verification Code - TSL Freight Movers",
      html: `
        <h2>Here’s your new verification code</h2>
        <h1 style="letter-spacing: 4px;">${verificationCode}</h1>
        <p>This code will expire in <b>5 minutes</b>.</p>
      `,
    });

    res.json({ message: "New verification code sent to your email." });
  } catch (error) {
    console.error("Resend code error:", error);
    res.status(500).json({ error: "Internal server error." });
  }
});

// ========================
// || CHECK RESET CODE ||
// ========================
app.post("/api/check-reset-code", async (req, res) => {
  const { email, resetCode } = req.body;

  if (!email || !resetCode) {
    return res.status(400).json({ error: "Missing email or reset code." });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM password_resets WHERE email = $1 AND code = $2",
      [email, resetCode]
    );

    // If code not found
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Invalid or expired reset code." });
    }

    // Optional: check expiry time (within 15 minutes)
    const createdAt = new Date(result.rows[0].created_at);
    const now = new Date();
    const minutesPassed = (now - createdAt) / 60000;

    if (minutesPassed > 15) {
      await pool.query("DELETE FROM password_resets WHERE email = $1", [email]);
      return res.status(400).json({ error: "Reset code expired." });
    }

    // ✅ Code valid
    res.json({ message: "Reset code verified." });
  } catch (err) {
    console.error("Check Reset Code Error:", err);
    res.status(500).json({ error: "Server error while verifying code." });
  }
});

// ========================
// || PASSWORD RESET CODE ||
// ========================
app.post("/api/send-reset-code", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required." });
  }

  try {
    const result = await pool.query("SELECT * FROM clients WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "No account found with that email." });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const createdAt = new Date();

    // Save to password_resets table
    await pool.query(
      "INSERT INTO password_resets (email, code, created_at) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET code = $2, created_at = $3",
      [email, code, createdAt]
    );

    // Email
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: `"TSL Freight Movers" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "New Verification Code - TSL Freight Movers",
      html: `
        <h2>Here’s your password reset code</h2>
        <h1 style="letter-spacing: 4px;">${code}</h1>
        <p>This code will expire in <b>5 minutes</b>.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.json({ message: "Reset code sent." });
  } catch (err) {
    console.error("Send Reset Code Error:", err);
    res.status(500).json({ error: "Failed to send reset code." });
  }
});

// ========================
// || RESET PASSWORD ||
// ========================
app.post("/api/reset-password", async (req, res) => {
  const { email, resetCode, newPassword } = req.body;

  if (!email || !resetCode || !newPassword) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM password_resets WHERE email = $1 AND code = $2",
      [email, resetCode]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Invalid or expired reset code." });
    }

    const resetEntry = result.rows[0];
    const now = new Date();
    const createdAt = new Date(resetEntry.created_at);
    const minutesPassed = (now - createdAt) / 60000;

    if (minutesPassed > 15) {
      return res.status(400).json({ error: "Reset code expired." });
    }

    // ✅ Hash and update password + mark as verified
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      "UPDATE clients SET password = $1, is_verified = true WHERE email = $2",
      [hashedPassword, email]
    );

    // Delete reset record
    await pool.query("DELETE FROM password_resets WHERE email = $1", [email]);

    res.json({ message: "Password has been reset successfully." });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ error: "Failed to reset password." });
  }
});

// ======================
// || Google signin
// ======================

const { OAuth2Client } = require("google-auth-library");
const { error } = require("console");
const GOOGLE_CLIENT_ID =
  "722110448522-5ft0t59s11g2gg14cll3r973r3r1h3eg.apps.googleusercontent.com"; // replace with your Client ID
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Helper to verify Google ID token
async function verifyGoogleToken(token) {
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    return {
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    };
  } catch (err) {
    console.error("verifyGoogleToken error:", err);
    return null;
  }
}

// ------------------ POST /auth/google ------------------ //
app.post("/auth/google", async (req, res) => {
  const { token } = req.body;

  // 1. Verify the Google token
  const userInfo = await verifyGoogleToken(token);
  if (!userInfo) {
    return res
      .status(401)
      .json({ success: false, error: "Invalid Google token" });
  }

  try {
    // 2. Check if client exists
    const { rows } = await pool.query(
      "SELECT * FROM clients WHERE email = $1",
      [userInfo.email]
    );
    let clientData;

    if (rows.length > 0) {
      const client = rows[0];
      if (client.archived) {
        return res.status(403).json({
          success: false,
          error: "Your account has been archived. Please contact support.",
        });
      }
      clientData = client;
    } else {
      // 3. Insert a new client
      const insertQuery = `
        INSERT INTO clients 
          (company_name, contact_person, contact_number, email, address, created_at, password, failed_attempts, lockout_time, archived, photo, role)
        VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8, $9, $10, $11)
        RETURNING *
      `;

      const insertValues = [
        "N/A", // company_name
        userInfo.name, // contact_person
        "", // contact_number
        userInfo.email, // email
        "", // address
        null, // password
        0, // failed_attempts
        null, // lockout_time
        false, // archived
        userInfo.picture || "", // photo
        "client", // role
      ];

      const result = await pool.query(insertQuery, insertValues);
      clientData = result.rows[0];
    }

    // 4. Create unified session object
    req.session.user = {
      id: clientData.id,
      role: clientData.role || "client",
      type: "client",
      company_name: clientData.company_name,
      contact_person: clientData.contact_person,
      contact_number: clientData.contact_number,
      email: clientData.email,
      address: clientData.address,
      photo: clientData.photo || userInfo.picture || null,
    };

    // 5. Return JSON response
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error("Google auth error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ======================
// || UNIFIED LOGIN (Account-Based Lockout) ||
// ======================
const LOCKOUT_THRESHOLD = 5; // max wrong attempts
const LOCKOUT_DURATION_MINUTES = 1; // lockout duration (1 minute)

app.post("/api/login", async (req, res) => {
  try {
    const { input, password } = req.body;
    let user = null;
    let isAdminUser = false;

    // 1️⃣ Try admin/staff first (username IS email)
    let result = await pool.query("SELECT * FROM users WHERE username = $1", [
      input,
    ]);
    if (result.rows.length > 0) {
      user = result.rows[0];
      isAdminUser = true;
    }

    // 2️⃣ Try client (email-based login)
    if (!user) {
      result = await pool.query(
        `SELECT id, email, password, archived, is_verified, failed_attempts, lockout_time, 
                company_name, contact_person, contact_number, address, photo
         FROM clients 
         WHERE email = $1`,
        [input]
      );

      if (result.rows.length > 0) {
        user = result.rows[0];

        // ⚠️ Handle archived flag safely (varchar or boolean)
        if (user.archived === true || user.archived === "true") {
          return res.status(403).json({
            error: "Your account has been archived. Please contact support.",
          });
        }

        // ✅ Handle verification check (allow admin-created OR verified)
        if (
          (user.verified === false ||
            user.verified === "false" ||
            user.verified === 0) &&
          (user.created_by_admin === false ||
            user.created_by_admin === "false" ||
            !user.created_by_admin)
        ) {
          return res.status(403).json({
            error:
              "Your account is not verified. Please verify your email or contact admin support.",
          });
        }
      }
    }

    // 3️⃣ If user not found
    if (!user) {
      return res.status(400).json({ error: "Wrong username or password." });
    }

    // 4️⃣ Check if account is locked
    if (user.lockout_time && new Date(user.lockout_time) > new Date()) {
      const remainingSec = Math.ceil(
        (new Date(user.lockout_time) - new Date()) / 1000
      );
      return res.status(429).json({
        error: `Account locked. Try again in ${remainingSec} seconds.`,
      });
    }

    // 5️⃣ Check password
    const isMatch =
      user.password && (await bcrypt.compare(password, user.password));
    if (!isMatch) {
      const newAttempts = (user.failed_attempts || 0) + 1;

      if (newAttempts >= LOCKOUT_THRESHOLD) {
        const lockUntil = new Date(
          Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000
        );
        await pool.query(
          `UPDATE ${isAdminUser ? "users" : "clients"}
           SET failed_attempts = 0, lockout_time = $1
           WHERE id = $2`,
          [lockUntil, user.id]
        );

        return res.status(429).json({
          error: `Account locked for ${LOCKOUT_DURATION_MINUTES} minute(s).`,
        });
      } else {
        await pool.query(
          `UPDATE ${isAdminUser ? "users" : "clients"}
           SET failed_attempts = $1
           WHERE id = $2`,
          [newAttempts, user.id]
        );

        return res.status(400).json({
          error: `Please check Email and Password. Attempts left: ${
            LOCKOUT_THRESHOLD - newAttempts
          }`,
        });
      }
    }

    // 6️⃣ Reset failed_attempts & lock on success
    await pool.query(
      `UPDATE ${isAdminUser ? "users" : "clients"}
       SET failed_attempts = 0, lockout_time = NULL
       WHERE id = $1`,
      [user.id]
    );

    // 7️⃣ Create session object
    req.session.user = {
      id: user.id,
      role: isAdminUser ? user.role || "admin" : "client",
      type: isAdminUser ? "admin" : "client",
      company_name: isAdminUser ? user.username : user.company_name,
      contact_person: user.contact_person || user.username,
      contact_number: user.contact_number || "",
      email: user.email || user.username, // ✅ username is email for admins
      address: user.address || "",
      photo: user.photo || null,
    };

    // 8️⃣ Force save session before responding (important for ngrok)
    req.session.save((err) => {
      if (err) {
        console.error("❌ Session save error:", err);
        return res.status(500).json({ error: "Failed to save session" });
      }

      console.log("✅ Session successfully saved:", req.session);

      // ✅ CORS headers (for ngrok + localhost)
      const origin = req.headers.origin;
      if (
        origin === "https://tslfreightmovers.com" ||
        origin === "https://www.tslfreightmovers.com" ||
        origin === "https://tslfreightmovers.com"
      ) {
        res.setHeader("Access-Control-Allow-Origin", origin);
      }
      res.setHeader("Access-Control-Allow-Credentials", "true");

      // ✅ Return login success
      return res.status(200).json({
        message: "Login successful",
        user: req.session.user,
      });
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ======================
// || Shipment Creation Protection (Client only) ||
// ======================
app.post("/api/shipments", async (req, res) => {
  try {
    const {
      client_id,
      tracking_number,
      port_origin,
      port_delivery,
      service_type,
      delivery_mode,
      expected_delivery_date,
    } = req.body;

    // 🧭 Step 1: Convert addresses to coordinates
    const originCoords = await geocodeAddress(port_origin);
    const destCoords = await geocodeAddress(port_delivery);

    // 🧭 Step 2: Insert with coordinates
    const query = `
      INSERT INTO shipments (
        client_id,
        tracking_number,
        service_type,
        delivery_mode,
        port_origin,
        port_delivery,
        origin_latitude,
        origin_longitude,
        delivery_latitude,
        delivery_longitude,
        status,
        expected_delivery_date,
        created_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'Pending',$11,NOW())
      RETURNING *;
    `;

    const values = [
      client_id,
      tracking_number,
      service_type,
      delivery_mode,
      port_origin,
      port_delivery,
      originCoords?.lat,
      originCoords?.lon,
      destCoords?.lat,
      destCoords?.lon,
      expected_delivery_date,
    ];

    const result = await pool.query(query, values);
    res.status(201).json({
      message: "Shipment created successfully!",
      shipment: result.rows[0],
    });
  } catch (err) {
    console.error("❌ Error creating shipment:", err);
    res.status(500).json({ error: "Failed to create shipment" });
  }
});

//----------------------------------//
//       History in clients        //
//--------------------------------//
// GET route to fetch booking history for logged-in client
app.get("/api/bookings/history", async (req, res) => {
  try {
    // 🔑 Make sure the client is logged in
    if (!req.session?.user) {
      console.error("❌ No session client found");
      return res
        .status(401)
        .json({ message: "Unauthorized: Client not logged in" });
    }

    const clientSession = req.session.user;

    // ✅ Make sure it’s really a client
    if (clientSession.role !== "client") {
      console.error("❌ Unauthorized role:", clientSession.role);
      return res
        .status(403)
        .json({ message: "Forbidden: Only clients can view history" });
    }

    // ✅ Validate clientId
    const clientId = Number(clientSession.id);
    if (isNaN(clientId)) {
      console.error("❌ Invalid clientId from session:", clientSession.id);
      return res.status(400).json({ message: "Invalid client ID" });
    }

    // ✅ Query shipments for this client (include decline_reason!)
    const result = await pool.query(
      `
      SELECT 
        id,
        tracking_number,
        delivery_type,
        service_type,
        shipment_type,
        delivery_mode,
        port_origin,
        port_delivery,
        gross_weight,
        net_weight,
        gross_weight_unit,
        net_weight_unit,
        num_packages,
        packing_list,
        commercial_invoice,
        status,
        decline_reason,   -- ✅ added this field
        created_at
      FROM shipments
      WHERE client_id = $1
      ORDER BY created_at DESC
      `,
      [clientId]
    );

    res.json({ bookings: result.rows });
  } catch (err) {
    console.error("🔥 Error fetching booking history:", err.message, err.stack);
    res.status(500).json({ message: "Internal server error" });
  }
});

// ===============================//
//        ADMIN DASHBOARD         //
// ===============================//

// -------------------------------
// 1️⃣ KPI Cards
// -------------------------------
app.get("/api/analytics/kpis", async (req, res) => {
  try {
    const { rows: currentBookings } = await pool.query(`
      SELECT COUNT(*) AS count
      FROM shipments
      WHERE created_at >= date_trunc('month', CURRENT_DATE)
    `);

    // Pending bookings
    const { rows: pendingBookings } = await pool.query(`
      SELECT COUNT(*) AS count
      FROM shipments
      WHERE status = 'Pending'
    `);

    // Active = Approved (but not yet completed)
    const { rows: activeShipments } = await pool.query(`
      SELECT COUNT(*) AS count
      FROM shipments
      WHERE status = 'Approved'
    `);

    // Completed = Completed
    const { rows: completedDeliveries } = await pool.query(`
      SELECT COUNT(*) AS count
      FROM shipments
      WHERE status = 'Completed'
    `);

    const { rows: monthlyRevenue } = await pool.query(`
      SELECT COALESCE(SUM(amount_due),0) AS total
      FROM invoices
      WHERE status='paid'
        AND DATE_TRUNC('month', created_at)=DATE_TRUNC('month', CURRENT_DATE)
    `);

    res.json({
      current_bookings: Number(currentBookings[0].count),
      pending_bookings: Number(pendingBookings[0].count),
      active_shipments: Number(activeShipments[0].count),
      completed_deliveries: Number(completedDeliveries[0].count),
      monthly_revenue: Number(monthlyRevenue[0].total),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch KPI data" });
  }
});

// -------------------------------
// 2️⃣ Revenue Trend Chart
// -------------------------------
app.get("/api/analytics/revenue", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(created_at,'Mon') AS month,
             SUM(amount_due) AS total
      FROM invoices
      WHERE status='paid'
      GROUP BY month, DATE_TRUNC('month', created_at)
      ORDER BY DATE_TRUNC('month', created_at)
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch revenue data" });
  }
});

// ===============================
// 2️⃣ Payment Status (for Chart)
// ===============================
app.get("/api/analytics/payment-status", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        SUM(
          CASE 
            WHEN status = 'paid' AND updated_at <= due_date THEN 1
            ELSE 0 
          END
        ) AS on_time,
        SUM(
          CASE 
            WHEN status = 'paid' AND updated_at > due_date THEN 1
            ELSE 0
          END
        ) AS late
      FROM invoices;
    `);

    // Safeguard: return empty defaults if no data
    res.json(rows[0] || { on_time: 0, late: 0 });
  } catch (err) {
    console.error("Error fetching payment status data:", err);
    res.status(500).json({ error: "Failed to fetch payment status data" });
  }
});

app.get("/api/analytics/payment-decision", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id AS client_id,
        c.company_name,
        COUNT(i.id) AS total_invoices,
        SUM(CASE WHEN i.status = 'paid' AND i.updated_at <= i.due_date THEN 1 ELSE 0 END) AS on_time,
        SUM(CASE WHEN i.status = 'paid' AND i.updated_at > i.due_date THEN 1 ELSE 0 END) AS late,
        ROUND(
          (SUM(CASE WHEN i.status = 'paid' AND i.updated_at <= i.due_date THEN 1 ELSE 0 END)::numeric
          / NULLIF(COUNT(i.id), 0)) * 100, 2
        ) AS on_time_rate,
        ROUND(
          (SUM(CASE WHEN i.status = 'paid' AND i.updated_at > i.due_date THEN 1 ELSE 0 END)::numeric
          / NULLIF(COUNT(i.id), 0)) * 100, 2
        ) AS late_rate,
        CASE
          WHEN COUNT(i.id) = 0 THEN 'No available payment records for this client.'
          WHEN (SUM(CASE WHEN i.status = 'paid' AND i.updated_at > i.due_date THEN 1 ELSE 0 END)::numeric
                / NULLIF(COUNT(i.id), 0)) >= 0.5
            THEN 'Client frequently pays invoices late (over 50% of total) and may require review or possible removal.'
          WHEN (SUM(CASE WHEN i.status = 'paid' AND i.updated_at > i.due_date THEN 1 ELSE 0 END)::numeric
                / NULLIF(COUNT(i.id), 0)) BETWEEN 0.3 AND 0.49
            THEN 'Client occasionally pays late (30–49% of total) and should be monitored for consistency.'
          ELSE 'Client consistently pays on time and is in good financial standing.'
        END AS status_flag
      FROM clients c
      LEFT JOIN invoices i ON c.id = i.client_id
      GROUP BY c.id, c.company_name
      ORDER BY on_time_rate DESC NULLS LAST;
    `);

    res.json(rows);
  } catch (err) {
    console.error("Error fetching payment decision analytics:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch payment decision analytics" });
  }
});

// -------------------------------
// 4️⃣ Client Revenue Chart
// -------------------------------
app.get("/api/analytics/client-revenue", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.company_name, TO_CHAR(i.created_at,'Mon') AS month, SUM(i.amount_due) AS total
      FROM invoices i
      JOIN shipments s ON s.id=i.shipment_id
      JOIN clients c ON c.id=s.client_id
      WHERE i.status='paid'
      GROUP BY c.company_name, month, DATE_TRUNC('month', i.created_at)
      ORDER BY c.company_name, DATE_TRUNC('month', i.created_at)
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch client revenue data" });
  }
});

// -------------------------------
// 5️⃣ Booking Status Chart
// -------------------------------
app.get("/api/analytics/booking-status", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT status, COUNT(*) AS count
      FROM shipments
      GROUP BY status
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch booking status data" });
  }
});

// ==============================
// Admin Dashboard: Shipment Volume (Current Month)
// ==============================
app.get("/api/dashboard/shipment-volume", async (req, res) => {
  try {
    const query = `
      WITH week_ranges AS (
        SELECT unnest(ARRAY[
          'Week 1 (1–7)',
          'Week 2 (8–14)',
          'Week 3 (15–21)',
          'Week 4 (22–31)'
        ]) AS week_label
      ),
      weekly_shipments AS (
        SELECT 
          CASE
            WHEN EXTRACT(DAY FROM created_at) BETWEEN 1 AND 7 THEN 'Week 1 (1–7)'
            WHEN EXTRACT(DAY FROM created_at) BETWEEN 8 AND 14 THEN 'Week 2 (8–14)'
            WHEN EXTRACT(DAY FROM created_at) BETWEEN 15 AND 21 THEN 'Week 3 (15–21)'
            ELSE 'Week 4 (22–31)'
          END AS week_label,
          COUNT(*) AS total
        FROM shipments
        WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE)
        GROUP BY 1
      )
      SELECT wr.week_label,
             COALESCE(ws.total, 0) AS total
      FROM week_ranges wr
      LEFT JOIN weekly_shipments ws ON wr.week_label = ws.week_label
      ORDER BY wr.week_label;
    `;

    const { rows } = await pool.query(query);

    // keep the same format for frontend
    const formatted = rows.map((r) => ({
      month: r.week_label,
      total: Number(r.total),
    }));

    res.json(formatted);
  } catch (err) {
    console.error("Error fetching shipment volume for current month:", err);
    res.status(500).json({ error: "Failed to fetch shipment volume data" });
  }
});

// ==============================
// Enhanced Shipment Volume Analytics (Improved)
// ==============================
app.get("/api/analytics/shipment-volume", async (req, res) => {
  try {
    const { filter = "this_month", start, end } = req.query;
    let query = "";
    const params = [];

    if (filter === "this_month" || filter === "last_month") {
      const monthOffset =
        filter === "last_month" ? " - INTERVAL '1 month'" : "";

      query = `
        WITH week_ranges AS (
          SELECT unnest(ARRAY['1–7', '8–14', '15–21', '22–31']) AS label
        ),
        shipment_counts AS (
          SELECT 
            CASE
              WHEN EXTRACT(DAY FROM created_at) BETWEEN 1 AND 7 THEN '1–7'
              WHEN EXTRACT(DAY FROM created_at) BETWEEN 8 AND 14 THEN '8–14'
              WHEN EXTRACT(DAY FROM created_at) BETWEEN 15 AND 21 THEN '15–21'
              ELSE '22–31'
            END AS label,
            COUNT(*) AS total
          FROM shipments
          WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE${monthOffset})
          GROUP BY label
        )
        SELECT w.label, COALESCE(s.total, 0) AS total
        FROM week_ranges w
        LEFT JOIN shipment_counts s USING(label)
        ORDER BY 
          CASE 
            WHEN w.label = '1–7' THEN 1
            WHEN w.label = '8–14' THEN 2
            WHEN w.label = '15–21' THEN 3
            ELSE 4
          END;
      `;
    } else if (filter === "this_year") {
      query = `
        SELECT TO_CHAR(DATE_TRUNC('month', created_at), 'Mon') AS label,
               COUNT(*) AS total
        FROM shipments
        WHERE DATE_TRUNC('year', created_at) = DATE_TRUNC('year', CURRENT_DATE)
        GROUP BY label, DATE_TRUNC('month', created_at)
        ORDER BY DATE_TRUNC('month', created_at);
      `;
    } else if (filter === "custom" && start && end) {
      query = `
        SELECT TO_CHAR(DATE_TRUNC('day', created_at), 'Mon DD') AS label,
               COUNT(*) AS total
        FROM shipments
        WHERE created_at BETWEEN $1 AND $2
        GROUP BY label, DATE_TRUNC('day', created_at)
        ORDER BY DATE_TRUNC('day', created_at);
      `;
      params.push(start, end);
    }

    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching shipment volume:", err);
    res.status(500).json({ error: "Failed to fetch shipment volume data" });
  }
});

// -------------------------------
// 7️⃣ Top Clients
// -------------------------------
app.get("/api/analytics/top-clients", async (req, res) => {
  try {
    const { rows } = await pool.query(`
          SELECT c.company_name AS name, COALESCE(SUM(i.amount_due),0) AS revenue
          FROM clients c
          LEFT JOIN shipments s ON c.id = s.client_id
          LEFT JOIN invoices i ON i.shipment_id = s.id AND i.status='paid'
          GROUP BY c.id, c.company_name
          ORDER BY revenue DESC
          LIMIT 5
        `);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching top clients:", err);
    res.status(500).json({ error: "Failed to fetch top clients" });
  }
});

// -------------------------------
// Recent Shipments (for Admin Dashboard)
// -------------------------------
app.get("/api/analytics/recent-shipments", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        s.id AS shipment_id,
        s.tracking_number,
        c.company_name AS client_name,
        s.port_origin,
        s.port_delivery,
        s.created_at,
        s.status
      FROM shipments s
      JOIN clients c ON s.client_id = c.id
      ORDER BY s.created_at DESC
      LIMIT 5
    `);

    res.json(rows);
  } catch (err) {
    console.error("Error fetching recent shipments:", err);
    res.status(500).json({ error: "Failed to fetch recent shipments" });
  }
});

// ===============================//
//      END ADMIN DASHBOARD        //
// ===============================//

// ===============================
// || CLIENT MANAGEMENT IN ADMIN ||
// ===============================

// 1️⃣ Fetch clients (with shipment count)
app.get("/api/admin/clients", async (req, res) => {
  try {
    const { includeArchived } = req.query;

    let query = `
      SELECT c.*,
             COUNT(s.id) AS total_shipments
      FROM clients c
      LEFT JOIN shipments s ON c.id = s.client_id
    `;

    if (includeArchived === "true") {
      query += " GROUP BY c.id ORDER BY c.id DESC";
    } else {
      query += " WHERE c.archived = FALSE GROUP BY c.id ORDER BY c.id DESC";
    }

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching clients:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 2️⃣ Add a new client (always starts as Active & Verified)
app.post("/api/admin/clients", async (req, res) => {
  try {
    const {
      company_name,
      contact_person,
      email,
      contact_number,
      address,
      password,
    } = req.body;

    // ✅ 1. Validate required fields
    if (!email || !password || !company_name) {
      return res.status(400).json({ message: "Missing required fields." });
    }

    // Normalize email (case-insensitive)
    const normalizedEmail = email.trim().toLowerCase();

    // ✅ 2. Insert new client (auto-verified)
    const insertQuery = `
  INSERT INTO clients (
    company_name, contact_person, email, contact_number, address, password,
    archived, verified, created_by_admin
  )
  VALUES ($1, $2, $3, $4, $5, $6, FALSE, TRUE, TRUE)
  RETURNING *;
`;
    const result = await pool.query(insertQuery, [
      company_name,
      contact_person,
      normalizedEmail,
      contact_number,
      address,
      password,
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("❌ Error adding client:", error);

    // ✅ Handle duplicate email constraint
    if (error.code === "23505" && error.detail.includes("email")) {
      return res.status(409).json({ message: "Email already exists" });
    }

    res.status(500).json({ message: "Internal Server Error" });
  }
});

// 3️⃣ Archive a client
app.patch("/api/admin/clients/:id/archive", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("UPDATE clients SET archived = TRUE WHERE id = $1", [id]);
    res.json({ message: "Client archived successfully!" });
  } catch (err) {
    console.error("Error archiving client:", err);
    res.status(500).json({ message: "Server error!" });
  }
});

// 4️⃣ Unarchive a client
app.patch("/api/admin/clients/:id/unarchive", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("UPDATE clients SET archived = FALSE WHERE id = $1", [id]);
    res.json({ message: "Client unarchived successfully!" });
  } catch (err) {
    console.error("Error unarchiving client:", err);
    res.status(500).json({ message: "Server error!" });
  }
});

// 5️⃣ Update client details
app.put("/api/admin/clients/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { company_name, contact_person, email, contact_number, address } =
      req.body;

    const updateQuery = `
      UPDATE clients
      SET company_name = $1,
          contact_person = $2,
          email = $3,
          contact_number = $4,
          address = $5
      WHERE id = $6
      RETURNING *;
    `;

    const { rows } = await pool.query(updateQuery, [
      company_name,
      contact_person,
      email,
      contact_number,
      address,
      id,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({ message: "Client not found" });
    }

    res.json({ message: "Client updated successfully!", client: rows[0] });
  } catch (error) {
    console.error("Error updating client:", error);
    res.status(500).json({ error: "Failed to update client" });
  }
});

app.get("/api/admin/clients/search", async (req, res) => {
  try {
    const { q } = req.query;
    const query = `
      SELECT * FROM clients
      WHERE company_name ILIKE $1 OR email ILIKE $1
      ORDER BY id DESC;
    `;
    const { rows } = await pool.query(query, [`%${q}%`]);
    res.json(rows);
  } catch (err) {
    console.error("Error searching clients:", err);
    res.status(500).json({ message: "Search failed" });
  }
});

// 7 Get shipments of a specific client
app.get("/api/admin/clients/:id/shipments", async (req, res) => {
  try {
    const { id } = req.params;
    const query = `
      SELECT 
        id, 
        tracking_number, 
        service_type, 
        status, 
        created_at,
        num_packages  -- ✅ include number of packages
      FROM shipments
      WHERE client_id = $1
      ORDER BY created_at DESC;
    `;
    const { rows } = await pool.query(query, [id]);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching client shipments:", error);
    res.status(500).json({ error: "Failed to fetch client shipments" });
  }
});
// =======================================
// || END OF CLIENT MANAGEMENT IN ADMIN ||
// =======================================

// ===============================
// || BOOKINGS PER CLIENT        ||
// ===============================

app.get("/api/bookings/:clientId", async (req, res) => {
  try {
    const { clientId } = req.params;

    const query = `
      SELECT 
        s.id AS booking_id,
        c.company_name AS client_name,
        s.service_type,
        s.delivery_mode,
        s.port_origin,
        s.port_delivery,
        s.gross_weight,
        s.net_weight,
        s.num_packages,
        s.status,
        TO_CHAR(s.created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at
      FROM shipments s
      INNER JOIN clients c ON s.client_id = c.id
      WHERE s.client_id = $1
      ORDER BY s.created_at DESC;
    `;

    const { rows } = await pool.query(query, [clientId]);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching bookings:", error);
    res.status(500).json({ error: "Failed to fetch client bookings" });
  }
});

// ==================================
// || ADMIN: BOOKINGS MANAGEMENT   ||
// ==================================
// ===============================
// || ADMIN: GET ALL BOOKINGS   ||
// ===============================
app.get("/api/admin/bookings", async (req, res) => {
  try {
    const query = `
      SELECT 
        s.id,
        s.tracking_number,
        c.company_name AS client_name,
        s.service_type,
        s.delivery_mode AS mode,
        s.port_origin AS origin,
        s.port_delivery AS destination,
        s.packing_list,
        s.commercial_invoice,
        s.gross_weight,
        s.gross_weight_unit,
        s.net_weight,
        s.net_weight_unit,
        s.expected_delivery_date,
        s.num_packages,
        s.consignee,
        s.remarks,
        s.status,
        s.created_at
      FROM shipments s
      INNER JOIN clients c ON s.client_id = c.id
      WHERE LOWER(s.status) IN ('pending', 'approved', 'declined', 'cancel by client')
      ORDER BY s.created_at DESC;
    `;
    const { rows } = await pool.query(query);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching all bookings:", error);
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

// ===============================
// || ADMIN: CREATE NEW BOOKING  ||
// ===============================
app.post("/api/admin/bookings", async (req, res) => {
  try {
    const {
      tracking_number,
      client_id,
      service_type,
      delivery_mode,
      port_origin,
      port_delivery,
      packing_list,
      commercial_invoice,
      status,
    } = req.body;

    const query = `
      INSERT INTO shipments
      (tracking_number, client_id, service_type, delivery_mode, port_origin, port_delivery, packing_list, commercial_invoice, status, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      RETURNING *;
    `;

    const { rows } = await pool.query(query, [
      tracking_number,
      client_id,
      service_type,
      delivery_mode,
      port_origin,
      port_delivery,
      packing_list || null,
      commercial_invoice || null,
      status || "Pending",
    ]);

    res
      .status(201)
      .json({ message: "Booking created successfully", booking: rows[0] });
  } catch (error) {
    console.error("Error creating booking:", error);
    res.status(500).json({ error: "Failed to create booking" });
  }
});

// -------------------------------
// ADMIN: UPDATE BOOKING STATUS
// -------------------------------
// -------------------------------
// ADMIN: UPDATE BOOKING STATUS
// -------------------------------
app.put("/api/admin/bookings/:bookingId/status", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { status } = req.body;

    // ✅ Only allow booking-related statuses
    const allowedStatuses = [
      "Pending",
      "Approved",
      "Declined",
      "Cancel By Client",
    ];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid booking status." });
    }

    const query = `
      UPDATE shipments
      SET status = $1
      WHERE id = $2
      RETURNING *;
    `;
    const values = [status, bookingId];

    const { rows } = await pool.query(query, values);
    if (rows.length === 0)
      return res.status(404).json({ error: "Booking not found" });

    const updatedBooking = rows[0];

    // 📩 Notify client
    await pool.query(
      `INSERT INTO client_notifications (client_id, shipment_id, title, message, type, is_read, created_at)
       VALUES ($1, $2, $3, $4, $5, false, NOW())`,
      [
        updatedBooking.client_id,
        updatedBooking.id,
        "Booking Status Update",
        `Your booking #${updatedBooking.tracking_number} status has been updated to "${status}".`,
        "booking",
      ]
    );

    // 📝 Audit log
    await logAction(
      req.session?.admin?.email || "Unknown admin",
      `Updated booking ID ${bookingId} status to "${status}"`,
      req.ip,
      req.headers["user-agent"],
      "Admin Dashboard"
    );

    res.json({
      message: "Status updated successfully",
      booking: updatedBooking,
    });
  } catch (error) {
    console.error("❌ Error updating booking status:", error);
    res.status(500).json({ error: "Failed to update status" });
  }
});

//edited ni jade
// -------------------------------
// ADMIN: UPDATE EXPECTED DELIVERY
// -------------------------------
app.put("/api/admin/bookings/:id/expected-delivery", async (req, res) => {
  try {
    const { id } = req.params;
    const { expected_delivery_date } = req.body; // ✅ Match frontend key

    if (!expected_delivery_date) {
      return res
        .status(400)
        .json({ error: "Expected delivery date is required" });
    }

    const query = `
      UPDATE shipments
      SET expected_delivery_date = $1
      WHERE id = $2
      RETURNING id, expected_delivery_date;
    `;
    const { rows } = await pool.query(query, [expected_delivery_date, id]);

    if (rows.length === 0)
      return res.status(404).json({ error: "Booking not found" });

    res.json(rows[0]);
  } catch (err) {
    console.error("Error updating expected delivery:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// =======================================
// || END OF BOOKING MANAGEMENT IN ADMIN ||
// =======================================

// ======================
// || SHIPMENT TRACKING ||
// ======================
app.post("/api/add-shipment", async (req, res) => {
  const {
    client_name,
    tracking_number,
    product,
    quantity,
    origin,
    destination,
  } = req.body;
  if (
    !client_name ||
    !tracking_number ||
    !product ||
    !quantity ||
    !origin ||
    !destination
  ) {
    return res.status(400).json({ message: "All fields are required!" });
  }

  try {
    await pool.query(
      `INSERT INTO shipments (client_name, tracking_number, product, quantity, origin, destination)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [client_name, tracking_number, product, quantity, origin, destination]
    );
    res.status(201).json({ message: "Shipment added successfully!" });
  } catch (err) {
    console.error("Error adding shipment:", err);
    res
      .status(500)
      .json({ message: "Error adding shipment. Please try again." });
  }
});

app.get("/api/shipment/:trackingNumber", async (req, res) => {
  const { trackingNumber } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM shipments WHERE tracking_number = $1",
      [trackingNumber]
    );
    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).json({ message: "Shipment not found." });
    }
  } catch (err) {
    console.error("Error fetching shipment:", err);
    res.status(500).json({ message: "Error fetching shipment details." });
  }
});

// Fetch tracking number for client
app.get("/api/shipments/latest-tracking/:clientId", async (req, res) => {
  const { clientId } = req.params;

  try {
    // Query the latest shipment based on client_id
    const result = await pool.query(
      "SELECT tracking_number FROM shipments WHERE client_id = $1 ORDER BY created_at DESC LIMIT 1",
      [clientId]
    );

    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]); // Return the latest tracking number
    } else {
      res.status(404).json({ message: "No shipments found for this client." });
    }
  } catch (err) {
    console.error("Error fetching latest tracking number:", err);
    res.status(500).json({ message: "Error fetching shipment details." });
  }
});

// =================================================
// 📡 REST API Endpoints for Shipments
// =================================================
app.get("/api/shipments", (req, res) => {
  res.json(latestGPSData);
});

app.get("/api/shipments/:id", (req, res) => {
  const shipmentId = req.params.id;
  if (latestGPSData[shipmentId]) {
    res.json(latestGPSData[shipmentId]);
  } else {
    res.status(404).json({ error: "Shipment not found" });
  }
});

// Cleanup stale data every hour
setInterval(() => {
  const now = Date.now();
  Object.keys(latestGPSData).forEach((id) => {
    if (now - latestGPSData[id].timestamp > 24 * 60 * 60 * 1000) {
      console.log(`⏳ Removed stale GPS data for shipment ${id}`);
      delete latestGPSData[id];
    }
  });
}, 60 * 60 * 1000);

// Serve your frontend files from /frontend
app.use(express.static(path.join(__dirname, "frontend")));

// Body parsers
app.use(express.urlencoded({ extended: true }));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safeName = `${Date.now()}-${file.originalname.replace(/\s+/g, "_")}`;
    cb(null, safeName);
  },
});

const upload = multer({ storage });

app.post("/upload", upload.single("packingList"), (req, res) => {
  res.json({ file: req.file });
});

// DEBUG MIDDLEWARE - Log all requests to the bookings endpoint
app.use("/api/bookings", (req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} request to /api/bookings`
  );
  console.log("Headers:", req.headers);
  next();
});

// ==================================================
// 🔽 WebSocket Server & Admin Notification Helper
// ==================================================
let adminClients = [];

wss.on("connection", (ws, req) => {
  console.log(`📡 WebSocket connected: ${req.socket.remoteAddress}`);
  adminClients.push(ws);

  ws.on("close", () => {
    adminClients = adminClients.filter((client) => client !== ws);
    console.log("WebSocket client disconnected");
  });

  ws.on("error", (err) => console.error("WebSocket error:", err));
});

function notifyAdmins(notification) {
  const message = JSON.stringify({
    type: "newBooking",
    payload: notification,
  });

  adminClients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
}

app.get("/api/admin/notifications", async (req, res) => {
  console.log("📩 GET /api/admin/notifications hit");
  try {
    const result = await pool.query(`
      SELECT n.id,
             COALESCE(c.company_name, 'Unknown') AS client,
             n.booking_id,
             n.message,
             n.is_read,
             n.created_at
      FROM notifications n
      LEFT JOIN clients c ON n.client_id = c.id
      WHERE n.recipient_type = 'admin'
      ORDER BY n.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Error fetching admin notifications:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/notifications", async (req, res) => {
  const clientId = req.session.client?.id;
  if (!clientId) return res.status(401).json({ error: "Not authenticated" });

  try {
    const result = await pool.query(
      `SELECT id, shipment_id, title, message, type, is_read, created_at
       FROM notifications
       WHERE client_id = $1
       ORDER BY created_at DESC`,
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching client notifications:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// ==================================================
// 🔽 MARK NOTIFICATION AS READ
// ==================================================
app.put("/api/admin/notifications/mark-read/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("UPDATE notifications SET is_read = true WHERE id = $1", [
      id,
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error marking notification as read:", err);
    res.status(500).json({ error: "Failed to update notification" });
  }
});

app.put("/api/notifications/mark-all-read", async (req, res) => {
  const clientId = req.session.client?.id;
  if (!clientId) return res.status(401).json({ error: "Not authenticated" });

  try {
    await pool.query(
      "UPDATE notifications SET is_read = TRUE WHERE client_id = $1",
      [clientId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Error marking all as read:", err);
    res.status(500).json({ error: "Failed to update notifications" });
  }
});

// ==================================================
// 🔽 END OF ADMIN NOTIFICATIONS
// ==================================================

/*
// ==================================================
// 📦 CREATE BOOKING (CLIENT SIDE)
// ==================================================
// ==================================================
// 📦 CREATE BOOKING (CLIENT SIDE)
// ==================================================
app.post(
  "/api/bookings",
  upload.fields([
    { name: "packingList", maxCount: 1 },
    { name: "commercialInvoice", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      console.log("Processing booking request...");

      // ✅ Use req.session.client instead of req.session.user
      const clientSession = req.session.client;
      if (!clientSession || clientSession.role !== "client") {
        return res.status(401).json({ message: "Unauthorized - Client access required" });
      }

      const clientId = clientSession.id;

      const {
        service_type,
        delivery_mode,
        port_origin,
        port_delivery,
        gross_weight,
        gross_weight_unit,
        net_weight,
        net_weight_unit,
        num_packages,
        delivery_type,
        consignee,
        remarks,
      } = req.body;

      // ---- Validation ----
      const missingFields = [];
      if (!service_type) missingFields.push("service_type");
      if (!port_origin) missingFields.push("port_origin");
      if (!port_delivery) missingFields.push("port_delivery");
      if ((delivery_type === "Sea" || delivery_type === "Air") && !delivery_mode) {
        missingFields.push("delivery_mode");
      }
      if (missingFields.length > 0) {
        return res.status(400).json({ message: "Missing required fields", missing: missingFields });
      }
      if (gross_weight_unit && net_weight_unit && gross_weight_unit !== net_weight_unit) {
        return res.status(400).json({ message: "Gross and Net weight units must match" });
      }

      // ---- Handle Files ----
      const packingList = req.files?.packingList?.[0]?.filename || null;
      const commercialInvoice = req.files?.commercialInvoice?.[0]?.filename || null;

      // ---- Get Shipper ----
      const clientResult = await pool.query(
        "SELECT company_name FROM clients WHERE id = $1",
        [clientId]
      );
      if (clientResult.rows.length === 0) {
        return res.status(404).json({ message: "Client not found" });
      }
      const shipper = clientResult.rows[0].company_name || "Unknown";

      // ---- Generate Tracking Number ----
      const trackingNumber =
        "TSL" + Date.now().toString().slice(-6) + Math.floor(1000 + Math.random() * 9000);

      // ---- Insert into Shipments ----
      const insertShipmentQuery = `
        INSERT INTO shipments (
          client_id, shipper, consignee, service_type, delivery_mode,
          port_origin, port_delivery, gross_weight, net_weight, num_packages,
          packing_list, commercial_invoice, status, created_at, delivery_type,
          tracking_number, remarks
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'Pending',NOW(),$13,$14,$15)
        RETURNING id, tracking_number
      `;
      const values = [
        clientId, shipper, consignee, service_type, delivery_mode || null,
        port_origin, port_delivery, gross_weight, net_weight, num_packages,
        packingList, commercialInvoice, delivery_type, trackingNumber, remarks || null
      ];
      const { rows } = await pool.query(insertShipmentQuery, values);
      const shipment = rows[0];

      console.log("✅ Booking created successfully:", shipment);

      // ---- Insert Admin Notification ----
      const notifTitle = "New Booking Created";
      const notifMessage = `${shipper} created a new booking (Tracking: ${shipment.tracking_number})`;

      await pool.query(
        `INSERT INTO notifications 
          (client_id, shipment_id, title, message, type, is_read, delivery_method, recipient_type, created_at)
        VALUES ($1,$2,$3,$4,'booking',FALSE,'system','admin',NOW())`,
        [clientId, shipment.id, notifTitle, notifMessage]
      );

      // ---- Broadcast to Admins via WebSocket ----
      notifyAdmins({
        id: shipment.id,
        client: shipper,
        bookingId: shipment.tracking_number,
        message: notifMessage,
        date: new Date().toLocaleString(),
        is_read: false,
      });

      // ---- Response ----
      res.status(201).json({
        message: "Booking created successfully",
        booking: shipment
      });

    } catch (error) {
      console.error("❌ Error creating booking:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);



// ==================================================
// 🔽 Booking submission route IN CLIENT SIDE
// ==================================================

 */

// ===============================
// Get current logged-in user (Admin or Client)
// ===============================
// ==================================================
// 🟢 Auth: Get Current Logged-in User (Admin or Client)
// ==================================================
app.get("/api/auth/me", async (req, res) => {
  try {
    console.log("📌 Incoming /api/auth/me request");
    console.log("📦 Current session:", req.session); // 👈 show full session

    // 1️⃣ Check if Admin is logged in
    if (req.session.admin) {
      const adminId = req.session.admin.id;

      const { rows } = await pool.query(
        `SELECT id, username, username AS email, role 
         FROM users 
         WHERE id = $1`,
        [adminId]
      );

      if (rows.length === 0) {
        console.log("❌ Admin not found in DB");
        return res.status(404).json({ error: "Admin not found" });
      }

      const admin = rows[0];
      console.log("🔎 /api/auth/me result:", { type: "admin", ...admin });

      return res.json({
        type: "admin",
        id: admin.id,
        username: admin.username,
        email: admin.email, // alias of username
        role: admin.role,
      });
    }

    // 2️⃣ Check if User (Client) is logged in
    if (req.session.user && req.session.user.role === "client") {
      const clientId = req.session.user.id;

      const { rows } = await pool.query(
        `SELECT id, email, company_name 
     FROM clients 
     WHERE id = $1`,
        [clientId]
      );

      if (rows.length === 0) {
        console.log("❌ Client not found in DB");
        delete req.session.user;
        return res.status(404).json({ error: "Client not found" });
      }

      const client = rows[0];
      console.log("🔎 /api/auth/me result:", { type: "client", ...client });

      return res.json({
        type: "client",
        id: client.id,
        email: client.email,
        company_name: client.company_name,
        role: "client",
      });
    }

    // 3️⃣ If neither admin nor client is logged in
    console.log("⚠️ No admin/client in session");
    return res.status(401).json({ error: "Not authenticated" });
  } catch (error) {
    console.error("❌ Error in /api/auth/me:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ---------------------------------------------------------------------------------
// 📦 Booking API (files optional) with Notifications integrated for admin
// ---------------------------------------------------------------------------------

// ==================================================
// 🟢 Middleware: Require Logged-in Client OR Admin
// ==================================================
// ==================================================
// 🟢 Middleware: Require Logged-in Client
// ==================================================
async function requireClient(req, res, next) {
  try {
    const sessionUser = req.session.user;

    if (!sessionUser || sessionUser.role !== "client") {
      return res.status(401).json({
        message:
          "Unauthorized - You must be logged in as a client to access this page.",
      });
    }

    // Fetch client info from DB
    const { rows } = await pool.query(
      `SELECT id, company_name, email 
       FROM clients 
       WHERE id = $1`,
      [sessionUser.id]
    );

    if (rows.length === 0) {
      req.session.destroy(() => {});
      return res.status(404).json({ message: "Client not found" });
    }

    const client = rows[0];

    // Keep session minimal + consistent
    req.session.user = {
      id: client.id,
      role: "client",
      email: client.email,
    };

    req.client = client; // attach DB client row
    next();
  } catch (err) {
    console.error("❌ requireClient middleware error:", err);
    res.status(500).json({ message: "Server error" });
  }
}

// ==================================================
// 📍 LocationIQ Reverse Geocoding
// ==================================================
async function reverseLocationIQ(lat, lon) {
  try {
    const apiKey = "";
    const url = `https://us1.locationiq.com/v1/reverse?key=${apiKey}&lat=${lat}&lon=${lon}&format=json`;

    const res = await fetch(url);
    if (!res.ok) {
      console.error("LocationIQ API error:", res.statusText);
      return null;
    }

    const data = await res.json();
    return {
      display_name: data.display_name,
      address: data.address || {},
      city:
        data.address?.city || data.address?.town || data.address?.village || "",
      region: data.address?.state || "",
      country: data.address?.country || "",
    };
  } catch (err) {
    console.error("reverseLocationIQ error:", err);
    return null;
  }
}

// ==================================================
// 🌍 Geoapify Forward Geocoding Validator
// ==================================================
async function validateGeoapifyLocation(address) {
  if (!address || !address.trim()) return null;
  try {
    const apiKey = "pk.cb06d9dc8a074f0eab5d70fb8a492649";
    const url = `https://api.geoapify.com/v1/geocode/search?text=${encodeURIComponent(
      address
    )}&filter=countrycode:ph&limit=1&apiKey=${apiKey}`;
    const res = await fetch(url);
    if (!res.ok) {
      console.error("Geoapify error:", res.statusText);
      return null;
    }
    const data = await res.json();
    if (data.features && data.features.length > 0) {
      const f = data.features[0];
      return {
        lat: parseFloat(f.geometry.coordinates[1]),
        lon: parseFloat(f.geometry.coordinates[0]),
        display_name: f.properties.formatted,
      };
    }
  } catch (err) {
    console.error("validateGeoapifyLocation error:", err);
  }
  return null;
}

// ==================================================
// 🌍 LocationIQ + Geoapify Forward Geocoding Validator (Improved Fallback)
// ==================================================
async function validateLocationIQ(address) {
  if (!address || !address.trim()) return null;

  const LOCATIONIQ_KEY = "pk.cb06d9dc8a074f0eab5d70fb8a492649"; // 🔑 LocationIQ key
  const GEOAPIFY_KEY = "e5e95eba533c4eb69344256d49166905"; // 🔑 Geoapify fallback key

  // 1️⃣ Try LocationIQ first
  const locIQUrl = `https://us1.locationiq.com/v1/search?key=${LOCATIONIQ_KEY}&q=${encodeURIComponent(
    address
  )}&countrycodes=ph&format=json&limit=1`;

  try {
    const res = await fetch(locIQUrl);
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        const loc = data[0];
        console.log(`✅ LocationIQ matched: ${loc.display_name}`);
        return {
          lat: parseFloat(loc.lat),
          lon: parseFloat(loc.lon),
          display_name: loc.display_name,
          provider: "LocationIQ",
        };
      } else {
        console.warn(`⚠️ LocationIQ found no results for: ${address}`);
      }
    } else {
      console.warn(`⚠️ LocationIQ error ${res.status} for: ${address}`);
    }
  } catch (err) {
    console.error(`❌ LocationIQ request failed for: ${address}`, err);
  }

  // 2️⃣ Fallback to Geoapify if LocationIQ failed or returned nothing
  try {
    console.log(`🔁 Fallback to Geoapify for: ${address}`);
    const geoUrl = `https://api.geoapify.com/v1/geocode/search?text=${encodeURIComponent(
      address
    )}&filter=countrycode:ph&limit=1&apiKey=${GEOAPIFY_KEY}`;
    const geoRes = await fetch(geoUrl);
    if (geoRes.ok) {
      const geoData = await geoRes.json();
      if (geoData.features && geoData.features.length > 0) {
        const f = geoData.features[0];
        console.log(`✅ Geoapify matched: ${f.properties.formatted}`);
        return {
          lat: parseFloat(f.geometry.coordinates[1]),
          lon: parseFloat(f.geometry.coordinates[0]),
          display_name: f.properties.formatted,
          provider: "Geoapify",
        };
      } else {
        console.warn(`⚠️ Geoapify found no results for: ${address}`);
      }
    } else {
      console.warn(`⚠️ Geoapify error ${geoRes.status} for: ${address}`);
    }
  } catch (geoErr) {
    console.error(`❌ Geoapify fallback failed for: ${address}`, geoErr);
  }

  // 3️⃣ No valid result
  console.error(`❌ No geocode match found for: ${address}`);
  return null;
}

// ==================================================
// 📦 CREATE BOOKING ENDPOINT (with LocationIQ + Gmail Admin Notification)
// ==================================================
app.post(
  "/api/bookings",
  requireClient,
  upload.fields([{ name: "packing_list", maxCount: 1 }]),
  async (req, res) => {
    try {
      console.log("🔹 Processing booking request...");
      const client = req.client;
      const shipper = client.company_name;

      const {
        service_type,
        delivery_mode,
        port_origin,
        port_delivery,
        gross_weight,
        gross_weight_unit,
        net_weight,
        net_weight_unit,
        num_packages,
        delivery_type,
        consignee,
        remarks,
        expected_delivery_date,
        revenue_amount,
      } = req.body;

      // ✅ Basic validation
      const missingFields = [];
      if (!service_type) missingFields.push("service_type");
      if (!port_origin) missingFields.push("port_origin");
      if (!port_delivery) missingFields.push("port_delivery");
      if (
        (delivery_type === "Sea" || delivery_type === "Air") &&
        !delivery_mode
      )
        missingFields.push("delivery_mode");

      if (missingFields.length > 0) {
        return res.status(400).json({
          message: "Missing required fields",
          missing: missingFields,
          received: Object.keys(req.body),
        });
      }

      // ✅ Weight unit check
      if (
        gross_weight_unit &&
        net_weight_unit &&
        gross_weight_unit !== net_weight_unit
      ) {
        return res
          .status(400)
          .json({ message: "Gross and Net weight units must match" });
      }

      // 🌍 Validate locations using LocationIQ
      const originPlace = await validateLocationIQ(port_origin);
      const deliveryPlace = await validateLocationIQ(port_delivery);

      if (!originPlace || !deliveryPlace) {
        return res.status(400).json({
          message:
            "Invalid port_origin or port_delivery. Please enter valid locations.",
        });
      }

      // 📄 File uploads
      const packingList = req.files?.packing_list?.[0]?.filename || null;
      const commercialInvoice =
        req.files?.commercial_invoice?.[0]?.filename || null;

      // 🔢 Tracking number
      const trackingNumber =
        "TSL" +
        Date.now().toString().slice(-6) +
        Math.floor(1000 + Math.random() * 9000);

      // 💾 Insert into DB
      const insertShipmentQuery = `
        INSERT INTO shipments (
          client_id, shipper, consignee, service_type, shipment_type, delivery_mode,
          port_origin, port_delivery, gross_weight, net_weight, num_packages,
          packing_list, commercial_invoice, revenue_amount, status, created_at,
          delivery_type, gross_weight_unit, net_weight_unit, tracking_number, remarks,
          delivered_at, expected_delivery_date, origin_lat, origin_lon, delivery_lat, delivery_lon, device_id
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,
          $7,$8,$9,$10,$11,
          $12,$13,$14,'Pending',NOW(),
          $15,$16,$17,$18,$19,
          $20,$21,$22,$23,$24,$25,$26
        )
        RETURNING id, tracking_number
      `;

      const values = [
        client.id,
        shipper,
        consignee,
        service_type,
        req.body.shipment_type || null,
        delivery_mode || null,
        port_origin,
        port_delivery,
        gross_weight,
        net_weight,
        num_packages,
        packingList,
        commercialInvoice,
        revenue_amount || null,
        delivery_type,
        gross_weight_unit,
        net_weight_unit,
        trackingNumber,
        remarks || null,
        null,
        expected_delivery_date || null,
        originPlace.lat,
        originPlace.lon,
        deliveryPlace.lat,
        deliveryPlace.lon,
        req.body.device_id || null,
      ];

      const { rows } = await pool.query(insertShipmentQuery, values);
      const shipment = rows[0];

      // 🔔 In-app Notification (DB)
      const notifTitle = "New Booking Created";
      const notifMessage = `${shipper} created a new booking (Tracking: ${shipment.tracking_number})`;

      await pool.query(
        `INSERT INTO notifications (
          client_id, booking_id, tracking_number, title, message,
          type, is_read, delivery_method, recipient_type, created_at
        ) VALUES (
          $1,$2,$3,$4,$5,'booking',FALSE,'system','admin',NOW()
        )`,
        [
          client.id,
          shipment.id,
          shipment.tracking_number,
          notifTitle,
          notifMessage,
        ]
      );

      // 🔊 WebSocket Admin Notification
      notifyAdmins({
        type: "newBooking",
        payload: {
          client: shipper,
          bookingId: shipment.tracking_number,
          message: notifMessage,
          date: new Date().toLocaleString(),
          is_read: false,
        },
      });

      // ✉️ Gmail Notification to Admin
      try {
        const adminEmail = "tslhead@gmail.com"; // 🟢 admin email

        const mailOptions = {
          from: `"TSL Freight Movers INC." <tslhead@gmail.com>`, // 🟢 the sending Gmail
          to: adminEmail,
          subject: `New Booking Created by ${shipper}`,
          html: `
            <div style="font-family: Arial, sans-serif; color: #333;">
              <h2 style="color:#60adf4;">📦 New Booking Notification</h2>
              <p>Hello Admin,</p>
              <p><strong>${shipper}</strong> has just created a new booking.</p>

              <table style="border-collapse: collapse; width: 100%; margin-top: 10px;">
                <tr><td><strong>Tracking #:</strong></td><td>${
                  shipment.tracking_number
                }</td></tr>
                <tr><td><strong>Service Type:</strong></td><td>${
                  service_type || "N/A"
                }</td></tr>
                <tr><td><strong>Delivery Mode:</strong></td><td>${
                  delivery_mode || "N/A"
                }</td></tr>
                <tr><td><strong>Origin:</strong></td><td>${port_origin}</td></tr>
                <tr><td><strong>Destination:</strong></td><td>${port_delivery}</td></tr>
                <tr><td><strong>Expected Delivery:</strong></td><td>${
                  expected_delivery_date || "Not specified"
                }</td></tr>
                <tr><td><strong>Gross Weight:</strong></td><td>${
                  gross_weight || "N/A"
                } ${gross_weight_unit || ""}</td></tr>
                <tr><td><strong>Net Weight:</strong></td><td>${
                  net_weight || "N/A"
                } ${net_weight_unit || ""}</td></tr>
                <tr><td><strong>Packages:</strong></td><td>${
                  num_packages || "N/A"
                }</td></tr>
              </table>

              ${remarks ? `<p><strong>Remarks:</strong> ${remarks}</p>` : ""}

              <hr style="margin: 15px 0;">
              <p><strong>Booking ID:</strong> ${shipment.id}</p>
              <p><strong>Created At:</strong> ${new Date().toLocaleString()}</p>

              <p style="margin-top: 15px;">Please log in to your <strong>TSL Admin Dashboard</strong> to review the booking.</p>
              <p style="color: gray; font-size: 12px;">This is an automated email from TSL Freight Movers INC.</p>
            </div>
          `,
        };

        await transporter.sendMail(mailOptions);
        console.log(`📧 Booking email sent to Admin (${adminEmail})`);
      } catch (mailErr) {
        console.error("⚠️ Failed to send admin booking email:", mailErr);
      }

      // ✅ Success
      return res.status(201).json({
        message: "Booking created successfully",
        booking: shipment,
      });
    } catch (error) {
      console.error("❌ Error creating booking:", error);
      return res.status(500).json({ message: "Server error" });
    }
  }
);

//Lei
// ==================================================
// PUT /api/bookings/:trackingNumber/cancel
// (Client can cancel "Pending" bookings)
// ==================================================
app.put(
  "/api/bookings/:trackingNumber/cancel",
  requireClient,
  async (req, res) => {
    try {
      const client = req.client;
      const { trackingNumber } = req.params;
      const { reason } = req.body || {};

      if (!trackingNumber)
        return res.status(400).json({ message: "Missing tracking number" });

      const { rows } = await pool.query(
        `SELECT id, status, client_id, tracking_number, service_type, delivery_mode, port_origin, port_delivery, expected_delivery_date 
       FROM shipments WHERE tracking_number = $1`,
        [trackingNumber]
      );

      if (!rows.length)
        return res.status(404).json({ message: "Booking not found" });
      const shipment = rows[0];

      if (shipment.client_id !== client.id)
        return res
          .status(403)
          .json({ message: "Not authorized to cancel this booking" });

      if (!shipment.status || shipment.status.toLowerCase() !== "pending") {
        return res
          .status(400)
          .json({ message: "Only 'Pending' bookings can be cancelled" });
      }

      // Update booking status
      await pool.query(
        "UPDATE shipments SET status = $1, updated_at = NOW() WHERE id = $2",
        ["Cancelled", shipment.id]
      );

      // System notification
      const notifTitle = "Booking Cancelled by Client";
      const notifMessage = `${client.company_name} cancelled booking (Tracking: ${shipment.tracking_number})`;
      await pool.query(
        `INSERT INTO notifications (client_id, booking_id, tracking_number, title, message, type, is_read, delivery_method, recipient_type, created_at)
       VALUES ($1,$2,$3,$4,$5,'booking',FALSE,'system','admin',NOW())`,
        [
          client.id,
          shipment.id,
          shipment.tracking_number,
          notifTitle,
          notifMessage,
        ]
      );

      // Real-time update (WebSocket)
      notifyAdmins({
        type: "bookingCancelled",
        payload: {
          client: client.company_name,
          bookingId: shipment.tracking_number,
          message: notifMessage,
          date: new Date().toLocaleString(),
        },
      });

      // ✉️ Gmail Notification to Admin
      try {
        const adminEmail = "tslhead@gmail.com"; // your admin email
        const mailOptions = {
          from: `"TSL Freight Movers INC." <tslhead@gmail.com>`,
          to: adminEmail,
          subject: `Booking Cancelled by ${client.company_name}`,
          html: `
          <div style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color:#e63946;">🚫 Booking Cancelled</h2>
            <p><strong>${
              client.company_name
            }</strong> has cancelled a booking.</p>

            <table style="border-collapse: collapse; width: 100%; margin-top: 10px;">
              <tr><td><strong>Tracking #:</strong></td><td>${
                shipment.tracking_number
              }</td></tr>
              <tr><td><strong>Service Type:</strong></td><td>${
                shipment.service_type || "N/A"
              }</td></tr>
              <tr><td><strong>Delivery Mode:</strong></td><td>${
                shipment.delivery_mode || "N/A"
              }</td></tr>
              <tr><td><strong>Origin:</strong></td><td>${
                shipment.port_origin
              }</td></tr>
              <tr><td><strong>Destination:</strong></td><td>${
                shipment.port_delivery
              }</td></tr>
              <tr><td><strong>Expected Delivery:</strong></td><td>${
                shipment.expected_delivery_date || "Not specified"
              }</td></tr>
              <tr><td><strong>Reason:</strong></td><td>${
                reason || "No reason provided"
              }</td></tr>
            </table>

            <hr style="margin:15px 0;">
            <p><strong>Cancelled At:</strong> ${new Date().toLocaleString()}</p>
            <p style="margin-top:15px;">Please review this cancellation in your TSL Admin Dashboard.</p>
            <p style="color:gray; font-size:12px;">This is an automated email from TSL Freight Movers INC.</p>
          </div>
        `,
        };

        await transporter.sendMail(mailOptions);
        console.log(`📧 Cancellation email sent to admin (${adminEmail})`);
      } catch (mailErr) {
        console.error("⚠️ Failed to send cancellation email:", mailErr);
      }

      res.json({ message: "Booking cancelled successfully" });
    } catch (err) {
      console.error("Error cancelling booking:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

//Lei
// ==================================================
// PUT /api/bookings/:trackingNumber/edit
// Client can edit pending bookings
// ==================================================
app.put(
  "/api/bookings/:trackingNumber/edit",
  requireClient,
  async (req, res) => {
    try {
      const client = req.client;
      const { trackingNumber } = req.params;
      const {
        service_type,
        delivery_mode,
        port_origin,
        port_delivery,
        gross_weight,
        net_weight,
        num_packages,
        remarks,
        expected_delivery_date,
      } = req.body;

      if (!trackingNumber)
        return res.status(400).json({ message: "Missing tracking number" });

      // Get existing booking
      const { rows } = await pool.query(
        `SELECT * FROM shipments WHERE tracking_number = $1`,
        [trackingNumber]
      );

      if (!rows.length)
        return res.status(404).json({ message: "Booking not found" });
      const shipment = rows[0];

      // Verify ownership
      if (shipment.client_id !== client.id)
        return res
          .status(403)
          .json({ message: "Not authorized to edit this booking" });

      // Verify status
      if (shipment.status.toLowerCase() !== "pending") {
        return res
          .status(400)
          .json({ message: "Only 'Pending' bookings can be edited" });
      }

      // Update the booking
      await pool.query(
        `UPDATE shipments SET 
        service_type = $1,
        delivery_mode = $2,
        port_origin = $3,
        port_delivery = $4,
        gross_weight = $5,
        net_weight = $6,
        num_packages = $7,
        remarks = $8,
        expected_delivery_date = $9,
        updated_at = NOW()
       WHERE tracking_number = $10`,
        [
          service_type || shipment.service_type,
          delivery_mode || shipment.delivery_mode,
          port_origin || shipment.port_origin,
          port_delivery || shipment.port_delivery,
          gross_weight || shipment.gross_weight,
          net_weight || shipment.net_weight,
          num_packages || shipment.num_packages,
          remarks || shipment.remarks,
          expected_delivery_date || shipment.expected_delivery_date,
          trackingNumber,
        ]
      );

      // 🔔 System Notification to Admin
      const notifTitle = "Booking Updated by Client";
      const notifMessage = `${client.company_name} edited booking (Tracking: ${shipment.tracking_number})`;

      await pool.query(
        `INSERT INTO notifications (client_id, booking_id, tracking_number, title, message, type, is_read, delivery_method, recipient_type, created_at)
       VALUES ($1,$2,$3,$4,$5,'booking',FALSE,'system','admin',NOW())`,
        [
          client.id,
          shipment.id,
          shipment.tracking_number,
          notifTitle,
          notifMessage,
        ]
      );

      // WebSocket
      notifyAdmins({
        type: "bookingUpdated",
        payload: {
          client: client.company_name,
          bookingId: shipment.tracking_number,
          message: notifMessage,
          date: new Date().toLocaleString(),
        },
      });

      // ✉️ Gmail Notification to Admin
      try {
        const adminEmail = "tslhead@gmail.com"; // your company email
        const mailOptions = {
          from: `"TSL Freight Movers INC." <tslhead@gmail.com>`,
          to: adminEmail,
          subject: `Booking Updated by ${client.company_name}`,
          html: `
          <div style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color:#0077b6;">✏️ Booking Updated</h2>
            <p>Hello Admin,</p>
            <p><strong>${
              client.company_name
            }</strong> has updated their booking.</p>

            <table style="border-collapse: collapse; width: 100%; margin-top: 10px;">
              <tr><td><strong>Tracking #:</strong></td><td>${
                shipment.tracking_number
              }</td></tr>
              <tr><td><strong>Service Type:</strong></td><td>${
                service_type || shipment.service_type
              }</td></tr>
              <tr><td><strong>Delivery Mode:</strong></td><td>${
                delivery_mode || shipment.delivery_mode
              }</td></tr>
              <tr><td><strong>Origin:</strong></td><td>${
                port_origin || shipment.port_origin
              }</td></tr>
              <tr><td><strong>Destination:</strong></td><td>${
                port_delivery || shipment.port_delivery
              }</td></tr>
              <tr><td><strong>Expected Delivery:</strong></td><td>${
                expected_delivery_date || shipment.expected_delivery_date
              }</td></tr>
              <tr><td><strong>Gross Weight:</strong></td><td>${
                gross_weight || shipment.gross_weight
              }</td></tr>
              <tr><td><strong>Net Weight:</strong></td><td>${
                net_weight || shipment.net_weight
              }</td></tr>
              <tr><td><strong>Packages:</strong></td><td>${
                num_packages || shipment.num_packages
              }</td></tr>
              <tr><td><strong>Remarks:</strong></td><td>${
                remarks || shipment.remarks || "None"
              }</td></tr>
            </table>

            <hr style="margin:15px 0;">
            <p><strong>Updated At:</strong> ${new Date().toLocaleString()}</p>
            <p style="margin-top:15px;">Please review the updated booking in the TSL Admin Dashboard.</p>
            <p style="color:gray; font-size:12px;">This is an automated email from TSL Freight Movers INC.</p>
          </div>
        `,
        };

        await transporter.sendMail(mailOptions);
        console.log(`📧 Booking update email sent to admin (${adminEmail})`);
      } catch (mailErr) {
        console.error("⚠️ Email sending failed:", mailErr);
      }

      res.json({ message: "Booking updated successfully" });
    } catch (err) {
      console.error("Error updating booking:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ===================== Dashboard (client view) ===================== //
app.get("/api/client/dashboard", async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== "client") {
      return res
        .status(401)
        .json({ error: "Unauthorized: Not authenticated as client" });
    }

    const clientId = Number(req.session.user.id);
    if (isNaN(clientId)) {
      return res.status(400).json({ error: "Invalid client ID in session" });
    }

    // -------------------- Descriptive Stats -------------------- //
    const { rows: statsRows } = await pool.query(
      `
      SELECT 
        COUNT(*)::int AS "totalBookings",
        COUNT(*) FILTER (WHERE service_type = 'Air Freight')::int AS "airFreight",
        COUNT(*) FILTER (WHERE service_type = 'Sea Freight')::int AS "seaFreight",
        COUNT(*) FILTER (WHERE status = 'Pending')::int AS "pendingShipments",
        COALESCE(SUM(revenue_amount), 0)::float AS "totalRevenue"
      FROM shipments 
      WHERE client_id = $1
    `,
      [clientId]
    );

    const stats = statsRows[0];

    // Most common freight
    let mostCommonFreight = "Equal";
    if (stats.airFreight > stats.seaFreight) mostCommonFreight = "Air Freight";
    else if (stats.seaFreight > stats.airFreight)
      mostCommonFreight = "Sea Freight";

    // -------------------- Monthly Bookings -------------------- //
    const currentYear = new Date().getFullYear();
    const { rows: monthlyRows } = await pool.query(
      `
      SELECT 
        EXTRACT(MONTH FROM created_at)::int AS month,
        COUNT(*)::int AS count
      FROM shipments 
      WHERE client_id = $1 AND EXTRACT(YEAR FROM created_at) = $2
      GROUP BY month ORDER BY month
    `,
      [clientId, currentYear]
    );

    const monthlyBookings = Array(12).fill(0);
    monthlyRows.forEach((row) => {
      monthlyBookings[row.month - 1] = row.count;
    });

    // -------------------- Recent Bookings -------------------- //
    const { rows: recentBookings } = await pool.query(
      `
      SELECT 
        tracking_number,
        COALESCE(port_origin, 'Unknown') || ' → ' || COALESCE(port_delivery, 'Unknown') AS route,
        service_type,
        status,
        created_at,
        revenue_amount AS value,
        gross_weight AS weight
      FROM shipments
      WHERE client_id = $1
      ORDER BY created_at DESC
    `,
      [clientId]
    );

    // -------------------- Response -------------------- //
    res.json({
      totalBookings: stats.totalBookings,
      airFreight: stats.airFreight,
      seaFreight: stats.seaFreight,
      pendingShipments: stats.pendingShipments,
      totalRevenue: stats.totalRevenue,
      mostCommonFreight,
      monthlyBookings,
      bookings: recentBookings,
    });

    // -------------------- Audit Log (fire-and-forget) -------------------- //
    setImmediate(async () => {
      try {
        const ipAddress =
          req.ip ||
          req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
          req.connection?.remoteAddress ||
          "Unknown";

        const userAgent = req.headers["user-agent"] || "Unknown";
        const UAParser = require("ua-parser-js");
        const parser = new UAParser(userAgent);
        const uaResult = parser.getResult();

        const deviceInfo = uaResult.device.model
          ? `${uaResult.device.vendor || ""} ${uaResult.device.model}`.trim()
          : uaResult.device.type || "Desktop";

        const actionSource =
          uaResult.device.type === "mobile" ? "Mobile App" : "Web";

        const { rows: clientRows } = await pool.query(
          `SELECT email FROM clients WHERE id = $1`,
          [clientId]
        );
        const userEmail = clientRows[0]?.email || "Unknown";

        await pool.query(
          `INSERT INTO audit_logs 
            (client_id, user_email, action, ip_address, device_info, action_source, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
          [
            clientId,
            userEmail,
            "View Dashboard",
            ipAddress,
            deviceInfo,
            actionSource,
          ]
        );
      } catch (err) {
        console.error("Audit log error:", err);
      }
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===================== User Profile (client) ===================== //
app.get("/api/v1/user/profile", async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== "client") {
      return res
        .status(401)
        .json({ error: "Unauthorized: Not authenticated as client" });
    }

    const clientId = Number(req.session.user.id);
    if (isNaN(clientId)) {
      return res.status(400).json({ error: "Invalid client ID in session" });
    }

    // ✅ Fetch complete client profile (including photo)
    const { rows } = await pool.query(
      `
        SELECT 
          id,
          company_name AS company_name,
          contact_person AS contact_person,
          contact_number AS contact_number,
          email,
          address,
          photo, -- ✅ make sure this column exists in your 'clients' table
          created_at AS created_at
        FROM clients 
        WHERE id = $1
      `,
      [clientId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const profile = rows[0];
    res.json(profile);

    // 📝 Audit Log (same as before)
    setImmediate(async () => {
      try {
        const ipAddress = req.ip || "Unknown";
        const userAgent = req.headers["user-agent"] || "Unknown";
        const UAParser = require("ua-parser-js");
        const parser = new UAParser(userAgent);
        const uaResult = parser.getResult();

        const deviceInfo = uaResult.device.model
          ? `${uaResult.device.vendor || ""} ${uaResult.device.model}`.trim()
          : uaResult.device.type || "Desktop";

        const actionSource =
          uaResult.device.type === "mobile" ? "Mobile App" : "Web";

        await pool.query(
          `INSERT INTO audit_logs (client_id, user_email, action, ip_address, device_info, action_source, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
          [
            clientId,
            profile.email,
            "View Profile",
            ipAddress,
            deviceInfo,
            actionSource,
          ]
        );
      } catch (err) {
        console.error("Audit log error:", err);
      }
    });
  } catch (err) {
    console.error("Profile error:", err);
    res.status(500).json({ error: "Failed to load profile" });
  }
});

// ===================== Dashboard Statistics ===================== //
app.get("/api/v1/dashboard/statistics", async (req, res) => {
  const clientId =
    req.session?.user?.role === "client" ? req.session.user.id : null;

  if (!clientId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const { rows } = await pool.query(
      `
            SELECT 
                COUNT(*)::int AS "totalBookings",
                COUNT(*) FILTER (WHERE service_type ILIKE '%air%')::int AS "airFreight",
                COUNT(*) FILTER (WHERE service_type ILIKE '%sea%')::int AS "seaFreight",
                COUNT(*) FILTER (WHERE status = 'Pending')::int AS "pendingShipments"
            FROM shipments 
            WHERE client_id = $1
        `,
      [clientId]
    );

    res.json(rows[0]);
  } catch (err) {
    console.error("Statistics error:", err);
    res.status(500).json({ error: "Failed to load statistics" });
  }
});

// ===================== Recent Bookings ===================== //
app.get("/api/v1/bookings/recent", async (req, res) => {
  const clientId =
    req.session?.user?.role === "client" ? req.session.user.id : null;

  if (!clientId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const limit = Math.min(parseInt(req.query.limit) || 10, 50); // Max 50 records

  try {
    const { rows } = await pool.query(
      `
            SELECT 
                tracking_number AS "trackingNumber",
                port_origin AS origin,
                port_delivery AS destination,
                service_type AS "freightType",
                status,
                created_at AS "createdDate",
                revenue_amount AS value,
                gross_weight AS weight
            FROM shipments 
            WHERE client_id = $1 
            ORDER BY created_at DESC 
            LIMIT $2
        `,
      [clientId, limit]
    );

    res.json(rows);
  } catch (err) {
    console.error("Recent bookings error:", err);
    res.status(500).json({ error: "Failed to load bookings" });
  }
});

// ===================== Recent Notifications ===================== //
app.get("/api/v1/notifications/recent", async (req, res) => {
  const clientId =
    req.session?.user?.role === "client" ? req.session.user.id : null;

  if (!clientId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const limit = Math.min(parseInt(req.query.limit) || 5, 50); // Max 20 notifications

  try {
    const { rows } = await pool.query(
      `
            SELECT 
                id,
                type,
                title,
                description,
                created_at,
                (read = false) AS "isNew"
            FROM notifications 
            WHERE client_id = $1 
            ORDER BY created_at Asc 
            LIMIT $2
        `,
      [clientId, limit]
    );

    res.json(rows);
  } catch (err) {
    console.error("Notifications error:", err);
    res.status(500).json({ error: "Failed to load notifications" });
  }
});

// ===================== Booking Trends ===================== //
app.get("/api/v1/dashboard/trends", async (req, res) => {
  const clientId =
    req.session?.user?.role === "client" ? req.session.user.id : null;

  if (!clientId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const year = parseInt(req.query.year) || new Date().getFullYear();

  // Validate year (reasonable range)
  if (year < 2020 || year > 2030) {
    return res.status(400).json({ error: "Invalid year parameter" });
  }

  try {
    const { rows } = await pool.query(
      `
            SELECT 
                EXTRACT(MONTH FROM created_at)::int AS month,
                COUNT(*)::int AS count
            FROM shipments 
            WHERE client_id = $1 
                AND EXTRACT(YEAR FROM created_at) = $2
            GROUP BY month 
            ORDER BY month
        `,
      [clientId, year]
    );

    const data = Array(12).fill(0);
    rows.forEach((row) => {
      if (row.month >= 1 && row.month <= 12) {
        data[row.month - 1] = parseInt(row.count);
      }
    });

    res.json(data);
  } catch (err) {
    console.error("Trends error:", err);
    res.status(500).json({ error: "Failed to load booking trends" });
  }
});

// ===================== Error Handling Middleware ===================== //
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

//==============================================================//
// ROUTE: GET ALL CLIENT BOOKINGS FOR THE ADMIN WITH FILTERING //
//============================================================//
app.get("/api/admin/bookings", async (req, res) => {
  const { clientId, search } = req.query;

  try {
    let baseQuery = `
      SELECT 
        s.tracking_number,
        c.company_name AS client_name,
        s.service_type,
        s.delivery_mode AS mode,
        s.port_origin AS origin,
        s.port_delivery AS destination,
        s.status,
        s.packing_list,
        s.commercial_invoice,
        s.created_at
      FROM shipments s
      JOIN clients c ON s.client_id = c.id
    `;

    const conditions = [];
    const values = [];

    if (clientId) {
      values.push(clientId);
      conditions.push(`s.client_id = $${values.length}`);
    }

    if (search) {
      values.push(`%${search.toLowerCase()}%`);
      values.push(`%${search.toLowerCase()}%`);
      conditions.push(
        `(LOWER(s.tracking_number) LIKE $${
          values.length - 1
        } OR LOWER(s.service_type) LIKE $${values.length})`
      );
    }

    if (conditions.length > 0) {
      baseQuery += " WHERE " + conditions.join(" AND ");
    }

    baseQuery += " ORDER BY s.created_at DESC";

    const result = await pool.query(baseQuery, values);
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching bookings:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/admin/clients", async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id, company_name AS username FROM clients ORDER BY company_name ASC"
    );
    res.json(rows);
  } catch (err) {
    console.error("Failed to fetch clients:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/admin/bookings/:trackingNumber/status", async (req, res) => {
  const { trackingNumber } = req.params;
  const { status } = req.body;

  try {
    // 1. Get shipment ID and client_id from tracking number
    const result = await pool.query(
      `SELECT id, client_id FROM shipments WHERE tracking_number = $1`,
      [trackingNumber]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Booking not found" });
    }

    const id = result.rows[0].id;
    const clientId = result.rows[0].client_id;

    // 2. Update booking status
    await pool.query(`UPDATE shipments SET status = $1 WHERE id = $2`, [
      status,
      id,
    ]);

    // 3. Compose notification
    let title = "",
      message = "";
    const normalizedStatus = status.trim().toLowerCase();

    if (normalizedStatus === "approved") {
      title = "Booking Approved";
      message = `Your booking #${trackingNumber} has been approved.`;
    } else if (normalizedStatus === "declined") {
      title = "Booking Declined";
      message = `Your booking #${trackingNumber} was declined.`;
    } else {
      return res.status(400).json({ error: "Invalid status" });
    }

    // 4. Insert notification
    const notif = await pool.query(
      `
      INSERT INTO notifications (client_id, shipment_id, title, message, type, is_read, delivery_method, created_at)
      VALUES ($1, $2, $3, $4, 'booking', false, 'system', NOW())
      RETURNING id
    `,
      [clientId, id, title, message]
    );

    res.json({
      message: `Status updated to "${status}" and notification sent.`,
      notificationId: notif.rows[0].id,
    });
  } catch (err) {
    console.error("Error updating booking and sending notification:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("🛑 Shutting down server...");
  wss.close(() => {
    server.close(() => {
      console.log("✅ Shutdown complete");
      process.exit(0);
    });
  });
});

//===========================================//
//    Data Analytics  IN ADMIN DASHBOARD    //
//=========================================//

//==========================================//
//       ADMIN REPORTS: BOOKINGS & OPS      //
//==========================================//

// Middleware (admin only)
function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized: Please log in" });
  }
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden: Admin access only" });
  }
  next();
}

// =======================================================
// 📦 Operational Manager Analytics
// 🚚 Shipment Volume: This Month vs Last Month (Weekly)
// =======================================================
app.get("/api/om/analytics/shipment-volume-compare", async (req, res) => {
  try {
    // 🗓️ Shipments created this month (grouped by week 1–4)
    const { rows: thisMonth } = await pool.query(`
      SELECT 
        ((EXTRACT(DAY FROM created_at) - 1) / 7 + 1)::INT AS week,
        COUNT(*) AS total
      FROM shipments
      WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE)
      GROUP BY week
      ORDER BY week;
    `);

    // 📆 Shipments created last month (grouped by week 1–4)
    const { rows: lastMonth } = await pool.query(`
      SELECT 
        ((EXTRACT(DAY FROM created_at) - 1) / 7 + 1)::INT AS week,
        COUNT(*) AS total
      FROM shipments
      WHERE DATE_TRUNC('month', created_at) = DATE_TRUNC('month', CURRENT_DATE - interval '1 month')
      GROUP BY week
      ORDER BY week;
    `);

    // 🧩 Format data into fixed 4-week structure
    const formatData = (rows) =>
      [1, 2, 3, 4].map((w) => {
        const row = rows.find((r) => r.week === w);
        return row ? Number(row.total) : 0;
      });

    // 🧾 Return structured response for chart.js
    res.json({
      labels: ["Week 1", "Week 2", "Week 3", "Week 4"],
      thisMonth: formatData(thisMonth),
      lastMonth: formatData(lastMonth),
    });
  } catch (err) {
    console.error("❌ OM shipment volume compare error:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch OM shipment volume comparison" });
  }
});

// =============================
// Total Shipments This Quarter
// =============================
app.get("/api/analytics/shipments-quarter", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT COUNT(*) AS total
      FROM shipments
      WHERE DATE_TRUNC('quarter', created_at) = DATE_TRUNC('quarter', CURRENT_DATE)
    `);

    res.json(rows[0]); // { total: 450 }
  } catch (err) {
    console.error("❌ Error fetching quarterly shipments:", err);
    res.status(500).json({ error: "Failed to fetch quarterly shipments" });
  }
});

// 📦 On-Time vs Delayed Deliveries (NULL = On-Time)
app.get(
  "/api/admin/reports/on-time-vs-delayed",
  requireAdmin,
  async (req, res) => {
    try {
      const { filter = "this_month", start, end } = req.query;
      let dateCondition = "";
      const params = [];

      // 🗓️ Date filters
      if (filter === "this_month") {
        dateCondition = `EXTRACT(MONTH FROM delivered_at) = EXTRACT(MONTH FROM CURRENT_DATE)
                         AND EXTRACT(YEAR FROM delivered_at) = EXTRACT(YEAR FROM CURRENT_DATE)`;
      } else if (filter === "last_month") {
        dateCondition = `EXTRACT(MONTH FROM delivered_at) = EXTRACT(MONTH FROM CURRENT_DATE - INTERVAL '1 month')
                         AND EXTRACT(YEAR FROM delivered_at) = EXTRACT(YEAR FROM CURRENT_DATE - INTERVAL '1 month')`;
      } else if (filter === "this_year") {
        dateCondition = `EXTRACT(YEAR FROM delivered_at) = EXTRACT(YEAR FROM CURRENT_DATE)`;
      } else if (filter === "custom" && start && end) {
        dateCondition = `delivered_at BETWEEN $1 AND $2`;
        params.push(start, end);
      } else {
        dateCondition = `EXTRACT(MONTH FROM delivered_at) = EXTRACT(MONTH FROM CURRENT_DATE)
                         AND EXTRACT(YEAR FROM delivered_at) = EXTRACT(YEAR FROM CURRENT_DATE)`;
      }

      // ✅ Treat NULL expected_delivery_date as on-time
      const query = `
        SELECT
          COALESCE(SUM(
            CASE 
              WHEN expected_delivery_date IS NULL THEN 1
              WHEN delivered_at <= expected_delivery_date THEN 1
              ELSE 0
            END
          ), 0) AS on_time,
          COALESCE(SUM(
            CASE 
              WHEN expected_delivery_date IS NOT NULL AND delivered_at > expected_delivery_date THEN 1
              ELSE 0
            END
          ), 0) AS delayed
        FROM shipments
        WHERE ${dateCondition}
          AND delivered_at IS NOT NULL;
      `;

      const { rows } = await pool.query(query, params);
      const data = rows[0] || { on_time: 0, delayed: 0 };

      res.json({
        on_time: Number(data.on_time) || 0,
        delayed: Number(data.delayed) || 0,
      });
    } catch (err) {
      console.error("On-time vs delayed delivery error:", err);
      res
        .status(500)
        .json({ error: "Failed to fetch on-time vs delayed deliveries" });
    }
  }
);

// 📊 Utilization (% of completed shipments)
app.get("/api/admin/reports/utilization", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        ROUND(
          (SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END)::decimal / NULLIF(COUNT(*), 0)) * 100, 2
        ) AS utilization
      FROM shipments
    `);
    res.json(rows[0] || { utilization: 0 });
  } catch (err) {
    console.error("Utilization error:", err);
    res.status(500).json({ error: "Failed to fetch utilization" });
  }
});

// 📊 Cancelled (Declined) Shipments per Month
app.get("/api/admin/reports/cancelled", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(created_at, 'Mon') AS month, COUNT(*) AS total
      FROM shipments
      WHERE status = 'Declined'
      GROUP BY 1
      ORDER BY MIN(created_at)
    `);
    res.json(rows);
  } catch (err) {
    console.error("Cancelled shipments error:", err);
    res.status(500).json({ error: "Failed to fetch cancelled shipments" });
  }
});

// 📊 Booking Trends per Month
app.get("/api/admin/reports/booking-trends", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(created_at, 'Mon') AS month, COUNT(*) AS total
      FROM shipments
      GROUP BY 1
      ORDER BY MIN(created_at)
    `);
    res.json(rows);
  } catch (err) {
    console.error("Booking trends error:", err);
    res.status(500).json({ error: "Failed to fetch booking trends" });
  }
});

// ===============================
// ON-TIME vs DELAYED Deliveries
// ===============================
app.get("/api/analytics/on-time-delayed", async (req, res) => {
  try {
    const query = `
      SELECT 
        COUNT(*) FILTER (
          WHERE expected_delivery_date IS NOT NULL 
          AND status = 'Completed' 
          AND delivered_at::date <= expected_delivery_date
        ) AS on_time,
        COUNT(*) FILTER (
          WHERE expected_delivery_date IS NOT NULL 
          AND status = 'Completed' 
          AND delivered_at::date > expected_delivery_date
        ) AS delayed
      FROM shipments;
    `;

    const { rows } = await pool.query(query);

    res.json({
      on_time: Number(rows[0].on_time) || 0,
      delayed: Number(rows[0].delayed) || 0,
    });
  } catch (err) {
    console.error("❌ Error fetching on-time vs delayed analytics:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch on-time vs delayed analytics" });
  }
});

app.get("/api/analytics/shipment-status", async (req, res) => {
  try {
    const { filter, start, end } = req.query;

    // 🔹 change this to your real date column!
    const dateCol = "created_at";

    let where = "";
    const params = [];

    if (filter === "this_month") {
      where = `WHERE DATE_TRUNC('month', ${dateCol}) = DATE_TRUNC('month', CURRENT_DATE)`;
    } else if (filter === "last_month") {
      where = `WHERE DATE_TRUNC('month', ${dateCol}) = DATE_TRUNC('month', CURRENT_DATE - INTERVAL '1 month')`;
    } else if (filter === "this_year") {
      where = `WHERE DATE_TRUNC('year', ${dateCol}) = DATE_TRUNC('year', CURRENT_DATE)`;
    } else if (filter === "custom" && start && end) {
      params.push(start, end);
      where = `WHERE ${dateCol}::date BETWEEN $1::date AND $2::date`;
    }

    const sql = `
      SELECT LOWER(TRIM(status)) AS status, COUNT(*)::int AS total
      FROM shipments
      ${where}
      GROUP BY LOWER(TRIM(status));
    `;

    console.log("🚀 SQL:", sql, params);

    const { rows } = await pool.query(sql, params);

    const result = { approved: 0, pending: 0, completed: 0, declined: 0 };
    for (const r of rows) {
      if (r.status === "approved") result.approved = r.total;
      else if (r.status === "pending") result.pending = r.total;
      else if (r.status === "completed") result.completed = r.total;
      else if (r.status === "declined") result.declined = r.total;
    }

    res.json(result);
  } catch (err) {
    console.error("❌ Error fetching shipment status:", err);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------
// Top Clients by Booking
// -------------------------------
app.get("/api/analytics/top-clients-bookings", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.company_name AS name, COUNT(s.id) AS total_bookings
      FROM clients c
      LEFT JOIN shipments s ON c.id = s.client_id
      GROUP BY c.id, c.company_name
      ORDER BY total_bookings DESC
      LIMIT 5
    `);
    res.json(rows);
  } catch (err) {
    console.error("❌ Error fetching top clients by bookings:", err);
    res.status(500).json({ error: "Failed to fetch top clients by bookings" });
  }
});

// -------------------------------
// Client Shipment History (with optional client filter)
// -------------------------------
app.get("/api/analytics/client-history", async (req, res) => {
  try {
    const { client_id, client_name } = req.query;

    console.log("📦 Fetching Client Shipment History:", {
      client_id,
      client_name,
    });

    // Base query
    let query = `
      SELECT 
        c.company_name AS client_name,
        s.tracking_number,
        s.service_type,
        s.port_origin AS origin,
        s.port_delivery AS destination,
        s.status,
        s.created_at AS shipment_date
      FROM shipments s
      INNER JOIN clients c ON s.client_id = c.id
    `;

    const params = [];

    // Apply filters dynamically
    if (client_id && client_id !== "all") {
      query += ` WHERE s.client_id = $1`;
      params.push(client_id);
    } else if (client_name && client_name !== "all") {
      query += ` WHERE c.company_name = $1`;
      params.push(client_name);
    }

    query += ` ORDER BY s.created_at DESC LIMIT 50;`;

    console.log("Executing query:", query, "with params:", params);

    const { rows } = await pool.query(query, params);

    if (!rows || rows.length === 0) {
      console.log("ℹNo shipment records found for given filter.");
    } else {
      console.log(`Found ${rows.length} shipment records.`);
    }

    res.json(rows);
  } catch (err) {
    console.error("Error fetching client shipment history:", err);
    res.status(500).json({ error: "Failed to fetch client shipment history" });
  }
});

//==========================================//
//         ACCOUNTING SIDE REPORTS         //
//========================================//

// Revenue trend (per month)
app.get(
  "/api/reports/revenue",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT TO_CHAR(created_at, 'Mon') AS month,
             SUM(CASE WHEN status='paid' THEN amount_due ELSE 0 END) AS revenue
      FROM invoices
      GROUP BY 1
      ORDER BY MIN(created_at)
    `);
      res.json(rows);
    } catch (err) {
      console.error("Revenue error:", err);
      res.status(500).json({ error: "Failed to fetch revenue" });
    }
  }
);

// Single month (latest)
app.get(
  "/api/analytics/client-revenue",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT c.company_name,
             SUM(i.amount_due) AS total
      FROM clients c
      JOIN shipments s ON c.id = s.client_id
      JOIN invoices i ON i.shipment_id = s.id
      WHERE i.status = 'paid'
        AND DATE_TRUNC('month', i.created_at) = DATE_TRUNC('month', CURRENT_DATE)
      GROUP BY c.company_name
      ORDER BY total DESC
      LIMIT 10
    `);
      res.json(rows);
    } catch (err) {
      console.error("❌ Error fetching single-month revenue:", err);
      res.status(500).json({ error: "Failed to fetch revenue" });
    }
  }
);

// Multi-month (last 6 months, include 0 revenue months)
app.get(
  "/api/analytics/client-revenue-trend",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      WITH months AS (
        SELECT DATE_TRUNC('month', CURRENT_DATE) - (INTERVAL '1 month' * g) AS month_start
        FROM generate_series(0,5) g
      )
      SELECT 
        TO_CHAR(m.month_start, 'Mon YYYY') AS month,
        c.company_name,
        COALESCE(SUM(i.amount_due), 0) AS total
      FROM months m
      CROSS JOIN clients c
      LEFT JOIN shipments s ON c.id = s.client_id
      LEFT JOIN invoices i 
        ON i.shipment_id = s.id
        AND DATE_TRUNC('month', i.created_at) = m.month_start
        AND i.status = 'paid'
      GROUP BY m.month_start, c.company_name   -- ✅ use month_start
      ORDER BY m.month_start, c.company_name;
    `);

      res.json(rows);
    } catch (err) {
      console.error("❌ Error fetching multi-month revenue trend:", err);
      res.status(500).json({ error: "Failed to fetch client revenue trend" });
    }
  }
);

// Payment status distribution
app.get(
  "/api/reports/payment-status",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT
        SUM(CASE WHEN status='paid' AND updated_at <= due_date THEN 1 ELSE 0 END) AS on_time,
        SUM(CASE WHEN status='paid' AND updated_at > due_date THEN 1 ELSE 0 END) AS late,
        SUM(CASE WHEN status IS NULL OR status='unpaid' THEN 1 ELSE 0 END) AS pending
      FROM invoices
    `);
      res.json(rows[0]);
    } catch (err) {
      console.error("Payment status error:", err);
      res.status(500).json({ error: "Failed to fetch payment status" });
    }
  }
);

// Invoice reports (counts per month)
app.get(
  "/api/reports/invoices",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT TO_CHAR(created_at, 'Mon') AS month, COUNT(*) AS total
      FROM invoices
      GROUP BY 1
      ORDER BY MIN(created_at)
    `);
      res.json(rows);
    } catch (err) {
      console.error("Invoices error:", err);
      res.status(500).json({ error: "Failed to fetch invoice reports" });
    }
  }
);

// ===========================
// Aging Report API
// ===========================
app.get(
  "/api/reports/aging",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT
        SUM(CASE WHEN status = 'unpaid' AND NOW() - due_date <= interval '30 days' THEN 1 ELSE 0 END) AS "0_30",
        SUM(CASE WHEN status = 'unpaid' AND NOW() - due_date > interval '30 days' AND NOW() - due_date <= interval '60 days' THEN 1 ELSE 0 END) AS "31_60",
        SUM(CASE WHEN status = 'unpaid' AND NOW() - due_date > interval '60 days' AND NOW() - due_date <= interval '90 days' THEN 1 ELSE 0 END) AS "61_90",
        SUM(CASE WHEN status = 'unpaid' AND NOW() - due_date > interval '90 days' THEN 1 ELSE 0 END) AS "90_plus"
      FROM invoices;
    `);

      res.json(rows[0]);
    } catch (err) {
      console.error("❌ Aging Report SQL error:", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ===========================
// Clients Overview API (with subqueries)
// ===========================
app.get(
  "/api/reports/clients",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT 
        c.company_name AS client_name,

        -- Total bookings
        (SELECT COUNT(*) 
         FROM shipments s 
         WHERE s.client_id = c.id) AS total_bookings,

        -- Total revenue (all invoices)
        (SELECT COALESCE(SUM(i.amount_due), 0) 
         FROM invoices i 
         WHERE i.client_id = c.id) AS total_revenue,

        -- On-time delivery %
        (SELECT 
          CASE 
            WHEN COUNT(*) = 0 THEN 0
            ELSE ROUND(
              (SUM(CASE WHEN s.status = 'Completed' 
                          AND s.delivered_at <= s.expected_delivery_date::date 
                        THEN 1 ELSE 0 END)::decimal / COUNT(*)) * 100, 
              2
            )
          END
         FROM shipments s 
         WHERE s.client_id = c.id
        ) AS on_time_percent,

        -- Late shipments
        (SELECT COUNT(*) 
         FROM shipments s 
         WHERE s.client_id = c.id 
           AND s.status = 'Completed' 
           AND s.delivered_at > s.expected_delivery_date::date
        ) AS late_shipments

      FROM clients c
      ORDER BY total_bookings DESC;
    `);

      res.json(rows);
    } catch (err) {
      console.error("❌ Clients Report error:", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

//==========================================//
//            CLIENT SIDE REPORTS          //
//=========================================//

// Shipment summary by service type
app.get("/api/reports/shipment-summary", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT service_type, COUNT(*) AS total
      FROM shipments
      GROUP BY service_type
    `);
    res.json(rows);
  } catch (err) {
    console.error("Shipment summary error:", err);
    res.status(500).json({ error: "Failed to fetch shipment summary" });
  }
});

// Client revenue trend (top 5 clients)
app.get("/api/reports/client-revenue", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.company_name, SUM(i.amount_due) AS revenue
      FROM clients c
      LEFT JOIN invoices i ON i.client_id = c.id AND i.status='paid'
      GROUP BY c.company_name
      ORDER BY revenue DESC
      LIMIT 5
    `);
    res.json(rows);
  } catch (err) {
    console.error("Client revenue error:", err);
    res.status(500).json({ error: "Failed to fetch client revenue" });
  }
});

//=======================//
// END OF ADMIN REPORTS //
//=====================//

// ========================
//    USERS PROFILE API
// ========================

// ========================
// GET PROFILE
// ========================
app.get("/api/profile", async (req, res) => {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: "Not authenticated" });

  try {
    let row;

    if (user.role === "client") {
      const { rows } = await pool.query(
        `
        SELECT id, company_name, contact_person, contact_number, email, address, photo, role
        FROM clients
        WHERE id = $1 AND archived = false
      `,
        [user.id]
      );

      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: "Client not found" });
      }

      row = rows[0];
    } else if (user.role === "admin") {
      const { rows } = await pool.query(
        `
        SELECT id, username, role
        FROM users
        WHERE id = $1
      `,
        [user.id]
      );

      if (!rows || rows.length === 0) {
        return res.status(404).json({ error: "Admin not found" });
      }

      // Normalize fields for frontend compatibility
      row = {
        id: rows[0].id,
        company_name: rows[0].username || "",
        contact_person: rows[0].username || "",
        contact_number: "",
        email: "", // no email column in users table
        address: "",
        photo: null,
        role: rows[0].role,
      };
    }

    res.json(row);
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// UPDATE PROFILE (CLIENT ONLY)
// ========================
app.put("/api/profile", async (req, res) => {
  const user = req.session.user;
  if (!user || user.role !== "client") {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const {
    company_name,
    contact_person,
    contact_number,
    email,
    address,
    password,
  } = req.body;

  if (!password) {
    return res
      .status(400)
      .json({ error: "Password is required to update profile" });
  }

  try {
    // 1. Verify current password
    const { rows: pwRows } = await pool.query(
      "SELECT password FROM clients WHERE id = $1",
      [user.id]
    );

    if (pwRows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    const isMatch = await bcrypt.compare(password, pwRows[0].password);
    if (!isMatch) {
      return res.status(403).json({ error: "Incorrect password" });
    }

    // 2. Update DB
    await pool.query(
      `
      UPDATE clients SET
        company_name = COALESCE($1, company_name),
        contact_person = COALESCE($2, contact_person),
        contact_number = COALESCE($3, contact_number),
        email = COALESCE($4, email),
        address = COALESCE($5, address)
      WHERE id = $6
    `,
      [company_name, contact_person, contact_number, email, address, user.id]
    );

    // 3. Fetch updated record
    const { rows } = await pool.query(
      `
      SELECT id, company_name, contact_person, contact_number, email, address, photo, role
      FROM clients
      WHERE id = $1
    `,
      [user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Client not found after update" });
    }

    const updatedUser = rows[0];

    // 4. Refresh session
    req.session.user = {
      ...req.session.user,
      id: updatedUser.id,
      company_name: updatedUser.company_name,
      contact_person: updatedUser.contact_person,
      contact_number: updatedUser.contact_number,
      email: updatedUser.email,
      address: updatedUser.address,
      photo: updatedUser.photo,
      role: updatedUser.role || "client",
    };

    // 5. Respond
    res.json({ message: "Profile updated", user: req.session.user });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// UPLOAD PHOTO
// ========================
app.post("/api/profile/photo", upload.single("photo"), async (req, res) => {
  const user = req.session.user;
  if (!user || user.role !== "client")
    return res.status(401).json({ error: "Not authenticated" });
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  try {
    await pool.query("UPDATE clients SET photo = $1 WHERE id = $2", [
      req.file.filename,
      user.id,
    ]);

    // refresh session with new photo
    req.session.user = {
      ...req.session.user,
      photo: req.file.filename,
    };

    res.json({ message: "Photo uploaded", user: req.session.user });
  } catch (err) {
    console.error("Upload photo error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// REMOVE PHOTO
// ========================
app.delete("/api/profile/photo", async (req, res) => {
  const user = req.session.user;
  if (!user || user.role !== "client")
    return res.status(401).json({ error: "Not authenticated" });

  try {
    await pool.query("UPDATE clients SET photo = NULL WHERE id = $1", [
      user.id,
    ]);

    // refresh session
    req.session.user = {
      ...req.session.user,
      photo: null,
    };

    res.json({ message: "Photo removed", user: req.session.user });
  } catch (err) {
    console.error("Remove photo error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// CHANGE PASSWORD
// ========================
app.put("/api/profile/password", async (req, res) => {
  const user = req.session.user;
  if (!user || user.role !== "client")
    return res.status(401).json({ error: "Not authenticated" });

  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: "Both passwords required" });
  }

  try {
    const { rows } = await pool.query(
      "SELECT password FROM clients WHERE id = $1",
      [user.id]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: "Client not found" });

    const match = await bcrypt.compare(oldPassword, rows[0].password);
    if (!match)
      return res.status(400).json({ error: "Incorrect old password" });

    const hashed = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE clients SET password = $1 WHERE id = $2", [
      hashed,
      user.id,
    ]);

    // refresh session stays same (photo intact)
    res.json({ message: "Password changed", user: req.session.user });
  } catch (err) {
    console.error("Password change error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
//       AUDIT LOGS
// ========================

app.get("/api/audit-logs", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        TO_CHAR(a.timestamp, 'YYYY-MM-DD') AS date,
        TO_CHAR(a.timestamp, 'HH24:MI:SS') AS time,
        a.user_email AS user_identifier,
        COALESCE(u.role, c.role, 'Unknown') AS role,
        a.ip_address,
        a.action,
        CONCAT_WS(' | ', a.device_info, a.action_source) AS details,
        COALESCE(u.username, c.contact_person, a.user_email) AS user
      FROM audit_logs a
      LEFT JOIN users u ON a.user_email = u.username OR a.user_email = u.id::text
      LEFT JOIN clients c ON a.user_email = c.email OR a.user_email = c.id::text
      ORDER BY a.timestamp DESC
      LIMIT 100
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching audit logs:", err.message);
    res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

// ========================
//       NOTIFICATIONS
// ========================

// ==========================================
//      ADMIN CREATE/SEND NOTIFICATIONS
// ==========================================

// Enhanced notifications fetch with better error handling
app.get("/api/notifications", async (req, res) => {
  const clientId = req.session.client?.id;

  if (!clientId) {
    console.log("Client not authenticated");
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const { rows } = await pool.query(
      `
      SELECT id, title, message, type, is_read, delivery_method, created_at
      FROM notifications
      WHERE client_id = $1
      ORDER BY created_at DESC
    `,
      [clientId]
    );

    // ✅ Log audit trail
    await logAction(
      req.session.client?.email || "Unknown client",
      "Viewed notifications",
      req.ip,
      req.headers["user-agent"],
      "Client Dashboard"
    );

    res.json(rows);
  } catch (err) {
    console.error("Error fetching notifications:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch notifications", details: err.message });
  }
});

app.put("/api/notifications/:id/read", async (req, res) => {
  const clientId = req.session.client?.id;
  const notifId = req.params.id;

  if (!clientId) return res.status(401).json({ error: "Not authenticated" });

  try {
    // 🔍 Fetch notification details before updating
    const notifDetails = await pool.query(
      "SELECT title FROM notifications WHERE id = $1 AND client_id = $2",
      [notifId, clientId]
    );

    if (notifDetails.rows.length === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    const title = notifDetails.rows[0]?.title || "Untitled Notification";

    // ✅ Mark as read
    await pool.query(
      `
      UPDATE notifications SET is_read = TRUE WHERE id = $1 AND client_id = $2
    `,
      [notifId, clientId]
    );

    // ✅ Log audit action
    await logAction(
      req.session.client?.email || "Unknown client",
      `Marked notification "${title}" as read`,
      req.ip,
      req.headers["user-agent"],
      "Client Portal"
    );

    res.json({ message: "Notification marked as read" });
  } catch (err) {
    console.error("Error marking notification as read:", err);
    res.status(500).json({ error: "Failed to mark as read" });
  }
});

app.put("/api/bookings/:id/status", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  console.log(`📦 Updating booking ID ${id} to status: ${status}`);

  try {
    // 1. Fetch client_id and tracking number from shipment
    const shipmentResult = await pool.query(
      `SELECT client_id, tracking_number FROM shipments WHERE id = $1`,
      [id]
    );

    if (shipmentResult.rows.length === 0) {
      console.log("❌ No shipment found for that ID.");
      return res.status(404).json({ error: "Booking not found" });
    }

    const clientId = shipmentResult.rows[0].client_id;
    const trackingNumber =
      shipmentResult.rows[0].tracking_number || `TSL-${id}`;
    console.log(
      `✅ Found client ID: ${clientId}, Tracking #: ${trackingNumber}`
    );

    // 2. Update booking status
    const updateResult = await pool.query(
      `UPDATE shipments SET status = $1 WHERE id = $2`,
      [status, id]
    );
    console.log(
      `📝 Booking status updated. Rows affected: ${updateResult.rowCount}`
    );

    // 3. Prepare notification
    let title = "",
      message = "";
    const normalizedStatus = status.trim().toLowerCase();

    if (normalizedStatus === "approved") {
      title = "Booking Approved";
      message = `Your booking #${trackingNumber} has been approved.`;
    } else if (normalizedStatus === "declined") {
      title = "Booking Declined";
      message = `Your booking #${trackingNumber} was declined.`;
    } else {
      return res.status(400).json({ error: "Invalid status" });
    }

    console.log("📢 Preparing to insert client notification:", {
      clientId,
      shipmentId: id,
      title,
      message,
    });

    // 4. Insert into CLIENT notifications
    const notifResult = await pool.query(
      `INSERT INTO client_notifications (client_id, title, message, type, is_read, created_at)
       VALUES ($1, $2, $3, 'booking', FALSE, NOW())
       RETURNING id`,
      [clientId, title, message]
    );

    const notifId = notifResult.rows[0]?.id;
    console.log(`✅ Client notification inserted with ID: ${notifId}`);

    return res.json({
      message: `Booking updated and client notified.`,
      notificationId: notifId,
    });
  } catch (err) {
    console.error(
      "❌ Server error while updating booking or inserting client notification:",
      err
    );
    return res
      .status(500)
      .json({ error: "Server error", details: err.message });
  }
});

// Additional helper endpoint to check notifications for debugging
app.get("/api/notifications/debug/:clientId", async (req, res) => {
  const { clientId } = req.params;

  try {
    const notifications = await pool.query(
      `
      SELECT id, client_id, shipment_id, title, message, type, is_read, 
             delivery_method, created_at
      FROM notifications 
      WHERE client_id = $1 
      ORDER BY created_at DESC 
      LIMIT 10
    `,
      [clientId]
    );

    res.json({
      clientId: clientId,
      notificationCount: notifications.rows.length,
      notifications: notifications.rows,
    });
  } catch (err) {
    console.error("Error fetching notifications:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

app.get("/api/debug/notifications-table", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_name = 'notifications'
      ORDER BY ordinal_position
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("Error checking table structure:", err);
    res.status(500).json({ error: err.message });
  }
});

// Add this endpoint to manually test notification creation
app.post("/api/debug/test-notification", async (req, res) => {
  const { client_id, message } = req.body;

  try {
    const result = await pool.query(
      `
      INSERT INTO notifications (client_id, title, message, type, is_read, delivery_method, created_at)
      VALUES ($1, $2, $3, $4, FALSE, $5, NOW())
      RETURNING *
    `,
      [
        client_id,
        "Test Notification",
        message || "This is a test notification",
        "info",
        "system",
      ]
    );

    res.json({
      message: "Test notification created",
      notification: result.rows[0],
    });
  } catch (err) {
    console.error("Error creating test notification:", err);
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
//      CLIENT NOTIFICATIONS
// ==========================================

// Get client notifications
app.get("/api/client/notifications", async (req, res) => {
  const clientId = req.session.user?.id;
  if (!clientId || req.session.user?.role !== "client") {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const { rows } = await pool.query(
      `
      SELECT id, title, message, type, is_read, created_at
      FROM client_notifications
      WHERE client_id = $1
      ORDER BY created_at DESC
    `,
      [clientId]
    );

    res.json(rows);
  } catch (err) {
    console.error("Error fetching client notifications:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch notifications", details: err.message });
  }
});

// Mark notification as read
app.put("/api/client/notifications/:id/read", async (req, res) => {
  const clientId = req.session.user?.id;
  const notifId = req.params.id;

  if (!clientId || req.session.user?.role !== "client") {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const { rowCount } = await pool.query(
      `UPDATE client_notifications SET is_read = TRUE WHERE id = $1 AND client_id = $2`,
      [notifId, clientId]
    );

    if (rowCount === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    res.json({ message: "Notification marked as read" });
  } catch (err) {
    console.error("Error marking notification as read:", err);
    res.status(500).json({ error: "Failed to mark as read" });
  }
});

//-----------------------------//
//      SHARED INVOICE API     //
//  For Admin & Accounting     //
//-----------------------------//

// Middleware to check role
function checkInvoiceAccess(req, res, next) {
  const user = req.session.user; // Assuming you store logged-in user in session
  if (!user) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  if (!["admin", "accounting"].includes(user.role)) {
    return res.status(403).json({ error: "Access denied" });
  }
  next();
}

// GET /api/invoices (ALL bookings/shipments + invoice info + client name)
app.get("/api/invoices", checkInvoiceAccess, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        s.id AS shipment_id,
        s.tracking_number,
        s.client_id,
        c.company_name AS client_name,
        c.contact_person,
        c.contact_number,
        c.email AS client_email,
        s.service_type,
        s.delivery_mode,
        s.port_origin,
        s.port_delivery,
        s.gross_weight,
        s.net_weight,
        s.num_packages,
        s.delivery_type,
        s.status AS shipment_status,
        s.created_at,

        -- Invoice (if exists)
        i.id AS invoice_id,
        i.invoice_number,
        i.status AS invoice_status,
        i.amount_due,
        i.due_date,
        i.paid_at
      FROM shipments s
      JOIN clients c ON s.client_id = c.id
      LEFT JOIN invoices i ON i.shipment_id = s.id
      ORDER BY s.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching invoices/bookings:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===============================
// POST /api/invoices/generate/:shipmentId
// Generate Invoice + Notify Client (in-app + Gmail)
// ===============================
app.post(
  "/api/invoices/generate/:shipmentId",
  checkInvoiceAccess,
  async (req, res) => {
    const { shipmentId } = req.params;
    const {
      amount_due,
      tax_rate,
      accountant_name,
      accountant_signature,
      notes,
    } = req.body;

    try {
      const amountDue = Number(amount_due);
      const taxRate = Number(tax_rate) || 0;

      if (!amountDue || isNaN(amountDue) || amountDue <= 0) {
        return res.status(400).json({ error: "Invalid amount provided" });
      }

      if (taxRate < 0 || taxRate > 100) {
        return res.status(400).json({ error: "Invalid tax rate (0–100%)" });
      }

      // 💰 Calculate tax and total
      const taxAmount = (amountDue * taxRate) / 100;
      const totalAmount = amountDue + taxAmount;

      // 1️⃣ Get shipment + client
      const shipmentRes = await pool.query(
        `
      SELECT s.*, c.company_name, c.contact_person, c.contact_number, c.email, c.address
      FROM shipments s
      JOIN clients c ON s.client_id = c.id
      WHERE s.id = $1
    `,
        [shipmentId]
      );

      const shipment = shipmentRes.rows[0];
      if (!shipment)
        return res.status(400).json({ error: "Shipment not found" });

      // 2️⃣ Prevent duplicate invoice
      const checkInvoice = await pool.query(
        "SELECT * FROM invoices WHERE shipment_id = $1",
        [shipmentId]
      );
      if (checkInvoice.rows.length > 0) {
        return res
          .status(400)
          .json({ error: "Invoice already generated for this shipment" });
      }

      // 3️⃣ Generate random invoice number
      let newInvoiceNumber;
      let exists = true;
      while (exists) {
        const randomDigits = Math.floor(
          Math.random() * (10 ** 12 - 10 ** 6) + 10 ** 6
        );
        newInvoiceNumber = `INV-${randomDigits}`;
        const checkDup = await pool.query(
          "SELECT 1 FROM invoices WHERE invoice_number = $1",
          [newInvoiceNumber]
        );
        exists = checkDup.rows.length > 0;
      }

      const dueDate = new Date();
      dueDate.setMonth(dueDate.getMonth() + 1);

      // 🧾 Create PDF
      const pdfDoc = await PDFDocument.create();
      const page = pdfDoc.addPage([595, 842]); // A4
      const { height } = page.getSize();

      const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
      const normalFont = await pdfDoc.embedFont(StandardFonts.Helvetica);

      // Logo
      const logoPath = path.join(__dirname, "invoices", "logo.png");
      if (fs.existsSync(logoPath)) {
        const logoBytes = fs.readFileSync(logoPath);
        const logoImage = await pdfDoc.embedPng(logoBytes);
        const scaledLogo = logoImage.scale(0.39);
        page.drawImage(logoImage, {
          x: 50,
          y: height - 100,
          width: scaledLogo.width,
          height: scaledLogo.height,
        });
      }

      // Header
      page.drawText("TSL Freight Movers INC.", {
        x: 200,
        y: height - 60,
        size: 18,
        font: boldFont,
      });
      page.drawText("Official Invoice", {
        x: 200,
        y: height - 80,
        size: 14,
        font: normalFont,
      });

      // Divider line
      page.drawLine({
        start: { x: 50, y: height - 110 },
        end: { x: 545, y: height - 110 },
        thickness: 1,
        color: rgb(0, 0, 0),
      });

      // Invoice Info
      page.drawText(`Invoice No: ${newInvoiceNumber}`, {
        x: 400,
        y: height - 130,
        size: 12,
        font: normalFont,
      });
      page.drawText(`Date Issued: ${new Date().toLocaleDateString()}`, {
        x: 400,
        y: height - 150,
        size: 12,
        font: normalFont,
      });
      page.drawText(`Due Date: ${dueDate.toLocaleDateString()}`, {
        x: 400,
        y: height - 170,
        size: 12,
        font: normalFont,
      });

      // Bill To
      page.drawText("Bill To:", {
        x: 50,
        y: height - 140,
        size: 12,
        font: boldFont,
      });
      page.drawText(`${shipment.company_name || ""}`, {
        x: 50,
        y: height - 160,
        size: 12,
        font: normalFont,
      });
      page.drawText(`${shipment.contact_person || ""}`, {
        x: 50,
        y: height - 175,
        size: 12,
        font: normalFont,
      });
      page.drawText(`${shipment.contact_number || ""}`, {
        x: 50,
        y: height - 190,
        size: 12,
        font: normalFont,
      });
      page.drawText(`${shipment.email || ""}`, {
        x: 50,
        y: height - 205,
        size: 12,
        font: normalFont,
      });
      page.drawText(`${shipment.address || ""}`.substring(0, 90), {
        x: 50,
        y: height - 220,
        size: 12,
        font: normalFont,
      });

      // Divider line
      page.drawLine({
        start: { x: 50, y: height - 250 },
        end: { x: 545, y: height - 250 },
        thickness: 1,
        color: rgb(0, 0, 0),
      });

      // Shipment Details
      let yPos = height - 270;
      page.drawText("Shipment Details:", {
        x: 50,
        y: yPos,
        size: 12,
        font: boldFont,
      });
      yPos -= 20;

      const shipmentFields = [
        `Tracking #: ${shipment.tracking_number || ""}`,
        `Service: ${shipment.service_type || ""}`,
        `Mode: ${shipment.delivery_mode || ""}`,
        `Origin: ${shipment.port_origin || ""}`,
        `Destination: ${shipment.port_delivery || ""}`,
      ];

      shipmentFields.forEach((line) => {
        page.drawText(line, { x: 50, y: yPos, size: 12, font: normalFont });
        yPos -= 15;
      });

      // 💰 Amount Section
      const amountStartY = height - 300;
      page.drawText("Subtotal:", {
        x: 400,
        y: amountStartY,
        size: 12,
        font: boldFont,
      });
      page.drawText(
        `PHP ${amountDue.toLocaleString(undefined, {
          minimumFractionDigits: 2,
        })}`,
        { x: 480, y: amountStartY, size: 12, font: normalFont }
      );

      page.drawText(`Tax (${taxRate}%):`, {
        x: 400,
        y: amountStartY - 20,
        size: 12,
        font: boldFont,
      });
      page.drawText(
        `PHP ${taxAmount.toLocaleString(undefined, {
          minimumFractionDigits: 2,
        })}`,
        { x: 480, y: amountStartY - 20, size: 12, font: normalFont }
      );

      page.drawText("Total Due:", {
        x: 400,
        y: amountStartY - 40,
        size: 13,
        font: boldFont,
      });
      page.drawText(
        `PHP ${totalAmount.toLocaleString(undefined, {
          minimumFractionDigits: 2,
        })}`,
        { x: 480, y: amountStartY - 40, size: 13, font: boldFont }
      );

      // Footer
      page.drawLine({
        start: { x: 50, y: 80 },
        end: { x: 545, y: 80 },
        thickness: 1,
        color: rgb(0.5, 0.5, 0.5),
      });
      page.drawText("Thank you for your business!", {
        x: 200,
        y: 60,
        size: 12,
        font: normalFont,
      });

      // Save PDF
      const invoicesDir = path.join(__dirname, "invoices");
      if (!fs.existsSync(invoicesDir)) fs.mkdirSync(invoicesDir);
      const pdfPath = path.join(invoicesDir, `${newInvoiceNumber}.pdf`);
      const pdfBytes = await pdfDoc.save();
      fs.writeFileSync(pdfPath, pdfBytes);

      // 5️⃣ Save to DB
      const insert = await pool.query(
        `INSERT INTO invoices 
       (shipment_id, client_id, invoice_number, amount_due, tax_rate, tax_amount, total_due, currency, due_date, status, accountant_name, accountant_signature, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'PHP', $8, $9, $10, $11, $12) RETURNING *`,
        [
          shipmentId,
          shipment.client_id,
          newInvoiceNumber,
          amountDue,
          taxRate,
          taxAmount,
          totalAmount,
          dueDate,
          "unpaid",
          accountant_name || null,
          accountant_signature || null,
          notes || null,
        ]
      );

      const invoice = insert.rows[0];

      // 6️⃣ Notify Client (in-app)
      await pool.query(
        `INSERT INTO client_notifications (client_id, title, message, type, is_read, created_at)
       VALUES ($1, $2, $3, 'invoice', FALSE, NOW())`,
        [
          shipment.client_id,
          "New Invoice Generated",
          `Invoice ${newInvoiceNumber} has been generated for your shipment #${shipment.tracking_number}.`,
        ]
      );

      // 7️⃣ Send Gmail Notification
      try {
        const mailOptions = {
          from: `"TSL Freight Movers INC." <tslhead@gmail.com>`,
          to: shipment.email,
          subject: `Your Invoice ${newInvoiceNumber} is ready`,
          html: `
          <div style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color:#60adf4;">TSL Freight Movers INC.</h2>
            <p>Dear <strong>${shipment.contact_person}</strong>,</p>
            <p>Your invoice <strong>${newInvoiceNumber}</strong> has been generated for your shipment:</p>

            <table style="border-collapse: collapse; width: 100%; margin-top: 10px;">
              <tr><td><strong>Tracking #:</strong></td><td>${
                shipment.tracking_number
              }</td></tr>
              <tr><td><strong>Origin:</strong></td><td>${
                shipment.port_origin
              }</td></tr>
              <tr><td><strong>Destination:</strong></td><td>${
                shipment.port_delivery
              }</td></tr>
              <tr><td><strong>Service Type:</strong></td><td>${
                shipment.service_type
              }</td></tr>
              <tr><td><strong>Delivery Mode:</strong></td><td>${
                shipment.delivery_mode
              }</td></tr>
            </table>

            <hr style="margin: 15px 0;">

            <p><strong>Subtotal:</strong> PHP ${amountDue.toLocaleString(
              undefined,
              { minimumFractionDigits: 2 }
            )}</p>
            <p><strong>Tax (${taxRate}%):</strong> PHP ${taxAmount.toLocaleString(
            undefined,
            { minimumFractionDigits: 2 }
          )}</p>
            <p><strong>Total Due:</strong> <span style="font-size: 16px;">PHP ${totalAmount.toLocaleString(
              undefined,
              { minimumFractionDigits: 2 }
            )}</span></p>
            <p><strong>Due Date:</strong> ${dueDate.toLocaleDateString()}</p>

            <p>Thank you for choosing <strong>TSL Freight Movers INC.</strong></p>
            <p style="color: gray; font-size: 12px;">This is an automated email. Please do not reply directly.</p>
          </div>
        `,
          attachments: [
            {
              filename: `${newInvoiceNumber}.pdf`,
              path: path.join(__dirname, "invoices", `${newInvoiceNumber}.pdf`),
            },
          ],
        };

        await transporter.sendMail(mailOptions);
        console.log(`📧 Invoice email sent to ${shipment.email}`);
      } catch (mailErr) {
        console.error("⚠️ Email sending failed:", mailErr);
      }

      // ✅ Done
      res.json({
        message: "Invoice generated with tax & client notified!",
        invoice,
        pdf_url: `/invoices/${invoice.invoice_number}.pdf`,
      });
    } catch (err) {
      console.error("Invoice Error:", err.stack || err);
      res.status(500).json({ error: err.message });
    }
  }
);

app.put("/api/invoices/:id/pay", checkInvoiceAccess, async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
      UPDATE invoices
      SET status = 'paid',   -- ✅ lowercase
          paid_at = NOW(),
          updated_at = NOW()
      WHERE id = $1
      RETURNING *;
    `;

    const { rows } = await pool.query(query, [id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Invoice not found" });
    }

    res.json(rows[0]); // return updated invoice
  } catch (err) {
    console.error("❌ Error updating invoice:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// DELETE /api/invoices/:id/undo
app.delete("/api/invoices/:id/undo", checkInvoiceAccess, async (req, res) => {
  const { id } = req.params;
  try {
    const deleted = await pool.query(
      "DELETE FROM invoices WHERE id = $1 RETURNING *",
      [id]
    );
    if (deleted.rows.length === 0) {
      return res.status(404).json({ error: "Invoice not found" });
    }
    res.json({ message: "Invoice undone successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// pinaltan ni jade

wss.on("connection", (ws, req) => {
  console.log(`📡 WebSocket connected: ${req.socket.remoteAddress}`);

  // Send initial GPS cache
  ws.send(JSON.stringify({ type: "init", data: latestGPSData }));

  ws.on("message", async (message) => {
    try {
      const data = JSON.parse(message);
      const shipmentId = data.shipmentid || data.shipment_id; // ✅ flexible key name

      if (
        !shipmentId ||
        typeof data.latitude !== "number" ||
        typeof data.longitude !== "number"
      ) {
        console.warn("⚠️ Invalid GPS payload:", data);
        return;
      }

      // ✅ Ignore small GPS drift (less than ~5 meters)
      const prev = latestGPSData[shipmentId];
      const moved =
        !prev ||
        Math.abs(prev.latitude - data.latitude) > 0.00005 ||
        Math.abs(prev.longitude - data.longitude) > 0.00005;

      if (!moved) {
        console.log(
          `🟡 Shipment ${shipmentId}: position unchanged — skipping broadcast`
        );
        return; // 🚫 Stop here — no DB update, no broadcast
      }

      // ✅ Update in-memory data
      latestGPSData[shipmentId] = {
        latitude: data.latitude,
        longitude: data.longitude,
        timestamp: Date.now(),
        speed: data.speed || null,
      };

      // ✅ Save to DB
      try {
        const result = await pool.query(
          `UPDATE shipments
           SET specific_lat = $1,
               specific_lon = $2
           WHERE id = $3`,
          [data.latitude, data.longitude, Number(shipmentId)]
        );

        console.log(
          `✅ GPS DB update for shipment ${shipmentId}: ${result.rowCount} row(s)`
        );

        if (result.rowCount === 0) {
          console.warn(`⚠️ No shipment found with id ${shipmentId}`);
        }
      } catch (dbErr) {
        console.error("❌ Database update failed:", dbErr);
      }

      // ✅ Broadcast to connected clients
      broadcastUpdate(shipmentId);
    } catch (err) {
      console.error("❌ WebSocket message error:", err);
    }
  });
});

// ==========================
// ✅ FIXED broadcastUpdate()
// ==========================
async function broadcastUpdate(shipmentId) {
  const data = latestGPSData[shipmentId];
  if (!data) return;

  // 🟢 Get the active device for this shipment
  let deviceId = null;
  try {
    const result = await pool.query(
      `SELECT device_id FROM gps_assignments 
       WHERE shipment_id = $1 AND released_at IS NULL 
       ORDER BY assigned_at DESC LIMIT 1`,
      [shipmentId]
    );
    deviceId = result.rows[0]?.device_id || null;
  } catch (err) {
    console.error("❌ Error fetching device_id for broadcast:", err);
  }

  // ✅ Broadcast with correct property names
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(
        JSON.stringify({
          type: "gps_update",
          shipmentId: shipmentId,
          deviceId: deviceId,
          latitude: data.latitude,
          longitude: data.longitude,
          timestamp: data.timestamp,
        })
      );
    }
  });
}

// ============================================================
// ✅ ADMIN: Fetch all shipments (includes live GPS coordinates)
// ============================================================
app.get("/api/admin/shipments", async (req, res) => {
  try {
    const query = `
      SELECT 
        s.id,
        s.tracking_number,
        s.service_type,
        s.delivery_mode,
        s.port_origin AS origin,
        s.port_delivery AS destination,
        s.origin_lat,
        s.origin_lon,
        s.delivery_lat,
        s.delivery_lon,
        s.specific_lat,        -- ✅ now included (live)
        s.specific_lon,        -- ✅ now included (live)
        s.status,
        s.expected_delivery_date,
        s.created_at,
        c.company_name,
        s.device_id
      FROM shipments s
      LEFT JOIN clients c ON s.client_id = c.id
      LEFT JOIN gps_assignments ga ON ga.shipment_id = s.id
      ORDER BY s.created_at DESC;
    `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching admin shipments:", err);
    res.status(500).json({ error: err.message });
  }
});

// ==============================
// Update shipment status + notify client
// ==============================
app.put("/api/admin/shipments/:id/status", async (req, res) => {
  const shipmentId = req.params.id;
  const { status } = req.body;

  try {
    // 1️⃣ Normalize status from button (e.g. "Shipping" → "shipping")
    const normalizedStatus = status.trim().toLowerCase();

    // 2️⃣ Update shipment status
    const { rows } = await pool.query(
      `UPDATE shipments 
       SET status = $1, updated_at = NOW() 
       WHERE id = $2 
       RETURNING id, tracking_number, client_id, status`,
      [normalizedStatus, shipmentId]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Shipment not found" });
    }

    const shipment = rows[0];
    console.log(`✅ Shipment ${shipmentId} updated → ${status}`);

    // 3️⃣ Prepare notification details (user-friendly message)
    let title, message;
    switch (normalizedStatus) {
      case "shipping":
        title = "Shipment Dispatched";
        message = `Your shipment #${shipment.tracking_number} has been dispatched and is now shipping.`;
        break;
      case "in transit":
        title = "Shipment In Transit";
        message = `Your shipment #${shipment.tracking_number} is currently in transit.`;
        break;
      case "delivered":
        title = "Shipment Delivered";
        message = `Your shipment #${shipment.tracking_number} has been successfully delivered.`;
        break;
      default:
        title = "Shipment Update";
        message = `Your shipment #${shipment.tracking_number} status has been updated to "${status}".`;
        break;
    }

    // 4️⃣ Save notification to database
    await pool.query(
      `INSERT INTO client_notifications 
        (client_id, title, message, type, is_read, created_at)
       VALUES ($1, $2, $3, 'shipment', false, NOW())`,
      [shipment.client_id, title, message]
    );

    // 5️⃣ Respond to frontend
    res.json({
      success: true,
      message: `Shipment status updated to "${status}" and client notified.`,
      shipment,
    });
  } catch (err) {
    console.error("❌ Error updating shipment status:", err);
    res.status(500).json({ error: "Failed to update shipment status" });
  }
});

// ==============================
// 🌍 Geocoding Helper (Geoapify)
// ==============================

async function geocodeAddress(address) {
  if (!address) return null;
  const apiKey = "e5e95eba533c4eb69344256d49166905"; // replace with your real key
  const res = await fetch(
    `https://api.geoapify.com/v1/geocode/search?text=${encodeURIComponent(
      address
    )}&apiKey=${apiKey}`
  );
  const data = await res.json();
  const coords = data.features?.[0]?.geometry?.coordinates;
  return coords ? { lon: coords[0], lat: coords[1] } : null;
}

// ===============================
// Middleware for authentication & roles
// ===============================

// Require any logged-in user
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Unauthorized: Please log in" });
  }
  next();
}

// Generic role-based middleware
function requireRole(allowedRoles = []) {
  return function (req, res, next) {
    if (!req.session.user) {
      return res.status(401).json({ error: "Unauthorized: Please log in" });
    }

    const role = req.session.user.role?.toLowerCase();

    if (!allowedRoles.includes(role)) {
      return res
        .status(403)
        .json({ error: `Forbidden: ${role || "unknown"} not allowed` });
    }

    next();
  };
}

module.exports = { requireLogin, requireRole };

// ===============================
// ACCOUNTING Dashboard Route
// ===============================
app.get(
  "/api/accounting/dashboard",
  requireRole(["accounting", "admin"]), // allow accounting + admin
  async (req, res) => {
    try {
      // 1) KPI totals (count NULL as unpaid)
      const kpiQuery = `
        SELECT
          COALESCE(SUM(CASE WHEN i.status = 'paid' THEN i.amount_due ELSE 0 END), 0) AS total_revenue,
          COALESCE(SUM(CASE WHEN i.status <> 'paid' OR i.status IS NULL THEN i.amount_due ELSE 0 END), 0) AS outstanding_amount,
          COALESCE(SUM(CASE WHEN i.status = 'paid' THEN 1 ELSE 0 END), 0) AS paid_count,
          COALESCE(SUM(CASE WHEN i.status <> 'paid' OR i.status IS NULL THEN 1 ELSE 0 END), 0) AS unpaid_count
        FROM invoices i;
      `;
      const kpiRes = await pool.query(kpiQuery);
      const kpi = kpiRes.rows[0];

      // 2) Unpaid invoices
      const unpaidQuery = `
        SELECT i.id, i.invoice_number, i.amount_due, i.due_date, i.created_at,
               COALESCE(i.status, 'unpaid') AS status,
               c.id AS client_id, c.company_name AS client_name,
               s.id AS shipment_id, s.tracking_number
        FROM invoices i
        JOIN clients c ON i.client_id = c.id
        LEFT JOIN shipments s ON s.id = i.shipment_id
        WHERE i.status <> 'paid' OR i.status IS NULL
        ORDER BY i.due_date ASC NULLS LAST, i.created_at DESC
        LIMIT 200;
      `;
      const unpaidRes = await pool.query(unpaidQuery);

      // 3) Paid invoices
      const paidQuery = `
        SELECT i.id, i.invoice_number, i.amount_due, i.updated_at, i.created_at,
               COALESCE(i.status, 'paid') AS status,
               c.id AS client_id, c.company_name AS client_name,
               s.id AS shipment_id, s.tracking_number
        FROM invoices i
        JOIN clients c ON i.client_id = c.id
        LEFT JOIN shipments s ON s.id = i.shipment_id
        WHERE i.status = 'paid'
        ORDER BY i.updated_at DESC NULLS LAST, i.created_at DESC
        LIMIT 200;
      `;
      const paidRes = await pool.query(paidQuery);

      // 4) Monthly revenue (last 12 months, only paid invoices)
      const monthlyQuery = `
        SELECT to_char(date_trunc('month', COALESCE(i.updated_at, i.created_at)), 'YYYY-MM') AS month,
               to_char(date_trunc('month', COALESCE(i.updated_at, i.created_at)), 'Mon YYYY') AS label,
               COALESCE(SUM(CASE WHEN i.status = 'paid' THEN i.amount_due ELSE 0 END),0)::numeric::float8 AS total
        FROM invoices i
        WHERE (i.updated_at IS NOT NULL OR i.created_at IS NOT NULL)
          AND i.status = 'paid'
          AND date_trunc('month', COALESCE(i.updated_at, i.created_at)) >= date_trunc('month', CURRENT_DATE) - INTERVAL '11 months'
        GROUP BY 1,2
        ORDER BY 1;
      `;
      const monthlyRes = await pool.query(monthlyQuery);

      // Build continuous 12-month series
      const months = [];
      for (let m = 11; m >= 0; m--) {
        const d = new Date();
        d.setMonth(d.getMonth() - m);
        const label = d.toLocaleString("en-US", {
          month: "short",
          year: "numeric",
        });
        const monthKey = `${d.getFullYear()}-${String(
          d.getMonth() + 1
        ).padStart(2, "0")}`;
        months.push({ monthKey, label });
      }

      const monthlyMap = {};
      monthlyRes.rows.forEach(
        (r) => (monthlyMap[r.month] = Number(r.total || 0))
      );
      const monthlyData = months.map((m) => ({
        month: m.label,
        total: monthlyMap[m.monthKey] || 0,
      }));

      // 5) Client payments summary
      const clientQuery = `
        SELECT c.id AS client_id, c.company_name AS client_name,
               COALESCE(SUM(CASE WHEN i.status = 'paid' THEN i.amount_due ELSE 0 END),0)::numeric::float8 AS total
        FROM clients c
        LEFT JOIN invoices i ON i.client_id = c.id
        GROUP BY c.id, c.company_name
        ORDER BY total DESC
        LIMIT 5;
      `;
      const clientRes = await pool.query(clientQuery);

      // 6) On-Time vs Late Payments
      const paymentStatusQuery = `
        SELECT
          SUM(CASE WHEN i.status = 'paid' AND i.updated_at <= i.due_date THEN 1 ELSE 0 END) AS on_time,
          SUM(CASE WHEN i.status = 'paid' AND i.updated_at > i.due_date THEN 1 ELSE 0 END) AS late
        FROM invoices i;
      `;
      const paymentStatusRes = await pool.query(paymentStatusQuery);
      const paymentStatus = paymentStatusRes.rows[0];

      // ✅ Response payload
      res.json({
        totalRevenue: Number(kpi.total_revenue || 0),
        outstandingAmount: Number(kpi.outstanding_amount || 0),
        paidCount: Number(kpi.paid_count || 0),
        unpaidCount: Number(kpi.unpaid_count || 0),
        unpaidInvoices: unpaidRes.rows,
        paidInvoices: paidRes.rows,
        monthlyRevenue: monthlyData,
        clientPayments: clientRes.rows,
        paymentStatus: {
          onTime: Number(paymentStatus.on_time || 0),
          late: Number(paymentStatus.late || 0),
        },
      });
    } catch (err) {
      console.error("Accounting dashboard error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// ===============================
// Ledger Route
// ===============================
app.get(
  "/api/accounting/clients/:clientId/ledger",
  requireRole(["accounting", "admin"]), // allow accounting + admin
  async (req, res) => {
    const { clientId } = req.params;

    try {
      // Client info
      const clientRes = await pool.query(
        `SELECT 
            id, 
            company_name, 
            contact_person AS contact_name, 
            contact_number, 
            email
         FROM clients 
         WHERE id = $1`,
        [clientId]
      );
      if (clientRes.rows.length === 0) {
        return res.status(404).json({ error: "Client not found" });
      }
      const client = clientRes.rows[0];

      // Invoices
      const invoicesRes = await pool.query(
        `
        SELECT i.id, i.invoice_number, i.amount_due, i.status,
               i.created_at, i.due_date, i.updated_at,
               s.tracking_number
        FROM invoices i
        LEFT JOIN shipments s ON s.id = i.shipment_id
        WHERE i.client_id = $1
        ORDER BY i.due_date ASC NULLS LAST, i.created_at DESC
      `,
        [clientId]
      );

      const invoices = invoicesRes.rows;

      // Aging buckets
      const today = new Date();
      let aging = { current: 0, "1-30": 0, "31-60": 0, "61-90": 0, "90+": 0 };

      invoices.forEach((inv) => {
        const dueDate = inv.due_date ? new Date(inv.due_date) : null;
        if (inv.status !== "paid" && dueDate) {
          const diffDays = Math.floor(
            (today - dueDate) / (1000 * 60 * 60 * 24)
          );
          const amount = Number(inv.amount_due || 0);
          if (diffDays <= 0) aging.current += amount;
          else if (diffDays <= 30) aging["1-30"] += amount;
          else if (diffDays <= 60) aging["31-60"] += amount;
          else if (diffDays <= 90) aging["61-90"] += amount;
          else aging["90+"] += amount;
        }
      });

      res.json({ client, aging, invoices });
    } catch (err) {
      console.error("Client ledger error:", err.message);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// ===============================
// PUT /api/invoices/:id/approve
// ===============================
app.put("/api/invoices/:id/approve", checkInvoiceAccess, async (req, res) => {
  const { id } = req.params;
  const { accountant_name, accountant_signature, notes } = req.body;

  try {
    const query = `
      UPDATE invoices
      SET accountant_name = $1,
          accountant_signature = $2,
          notes = $3,
          updated_at = NOW()
      WHERE id = $4
      RETURNING *;
    `;

    const { rows } = await pool.query(query, [
      accountant_name || null,
      accountant_signature || null,
      notes || null,
      id,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Invoice not found" });
    }

    res.json({
      message: "Invoice updated with accountant signature",
      invoice: rows[0],
    });
  } catch (err) {
    console.error("❌ Error updating invoice:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===============================
// Invoice Payment Action
// ===============================
app.put(
  "/api/invoices/:id/pay",
  requireRole(["accounting", "admin"]), // allow accounting + admin to mark paid
  async (req, res) => {
    const { id } = req.params;
    try {
      const updateRes = await pool.query(
        `UPDATE invoices SET status = 'paid', updated_at = NOW() WHERE id = $1 RETURNING *`,
        [id]
      );
      if (updateRes.rowCount === 0) {
        return res.status(404).json({ error: "Invoice not found" });
      }
      res.json({
        message: "Invoice marked as paid",
        invoice: updateRes.rows[0],
      });
    } catch (err) {
      console.error("Mark invoice paid error:", err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// ✅ Get single shipment with client info (for Accounting)
app.get("/api/admin/shipments/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const shipmentRes = await pool.query(
      `SELECT s.*, c.company_name, c.contact_person, c.contact_number, c.email, c.address
       FROM shipments s
       JOIN clients c ON s.client_id = c.id
       WHERE s.id = $1`,
      [id]
    );

    if (shipmentRes.rows.length === 0)
      return res.status(404).json({ error: "Shipment not found" });

    res.json(shipmentRes.rows[0]);
  } catch (err) {
    console.error("Error fetching shipment:", err);
    res.status(500).json({ error: "Server error fetching shipment" });
  }
});

// ======================
// CLIENT INVOICE ROUTES
// ======================

// ---------------------------
// GET /api/client/invoices
// ---------------------------
app.get("/api/client/invoices", async (req, res) => {
  try {
    const user = req.session.user; // Assuming session stores client
    if (!user || user.role !== "client") {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const clientId = user.id; // ✅ use logged-in client ID

    const result = await pool.query(
      `
      SELECT 
        s.id AS shipment_id,
        s.tracking_number,
        s.service_type,
        s.status AS shipment_status,
        i.id AS invoice_id,
        i.invoice_number,
        i.status AS invoice_status,
        i.amount_due,
        i.due_date,
        i.created_at AS date_issued
      FROM shipments s
      LEFT JOIN invoices i ON i.shipment_id = s.id
      WHERE s.client_id = $1
      ORDER BY COALESCE(i.created_at, s.created_at) DESC
    `,
      [clientId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching invoices:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ---------------------------
// GET /api/client/invoice/:invoiceNumber/pdf
// ---------------------------
app.get("/api/client/invoice/:invoiceNumber/pdf", async (req, res) => {
  try {
    const { invoiceNumber } = req.params;

    const pdfPath = path.join(__dirname, "invoices", `${invoiceNumber}.pdf`);
    if (!fs.existsSync(pdfPath)) {
      return res.status(404).send("PDF not found");
    }

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `inline; filename="invoice_${invoiceNumber}.pdf"`
    );
    res.sendFile(pdfPath);
  } catch (err) {
    console.error("Error serving PDF:", err);
    res.status(500).send("Server error");
  }
});

// ---------------------------
// Test invoices folder
// ---------------------------
app.get("/api/test/invoices-dir", (req, res) => {
  const invoicesDir = path.join(__dirname, "invoices");
  const exists = fs.existsSync(invoicesDir);
  const files = exists
    ? fs.readdirSync(invoicesDir).filter((f) => f.endsWith(".pdf"))
    : [];
  res.json({ exists, files });
});

//=====================//
// ACCOUNTING REPORTS  //
//=====================//
// ===========================
// Revenue Trend (All History with 0 months)
// ===========================
app.get(
  "/api/reports/revenue-trend",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      WITH all_months AS (
        SELECT DATE_TRUNC('month', MIN(created_at)) AS start_month,
               DATE_TRUNC('month', MAX(created_at)) AS end_month
        FROM invoices
      ),
      months AS (
        SELECT generate_series(start_month, end_month, interval '1 month') AS month_start
        FROM all_months
      )
      SELECT 
        TO_CHAR(m.month_start, 'YYYY-MM') AS month,       -- machine readable
        TO_CHAR(m.month_start, 'Mon YYYY') AS label,      -- human readable
        COALESCE(SUM(i.amount_due), 0) AS revenue
      FROM months m
      LEFT JOIN invoices i
        ON DATE_TRUNC('month', i.created_at) = m.month_start
        AND i.status = 'paid'
      GROUP BY m.month_start
      ORDER BY m.month_start;
    `);

      res.json(rows);
    } catch (err) {
      console.error("Revenue Trend API error:", err);
      res.status(500).json({ error: "Failed to fetch revenue trend" });
    }
  }
);

// ===========================
// Invoice Status Report
// ===========================
app.get(
  "/api/reports/invoice-status",
  requireRole(["admin", "accounting"]),
  async (req, res) => {
    try {
      const { rows } = await pool.query(`
      SELECT
        i.invoice_number AS invoice_no,
        c.company_name AS client,
        i.amount_due AS amount,
        i.status,
        i.due_date
      FROM invoices i
      LEFT JOIN clients c ON i.client_id = c.id
      ORDER BY i.due_date ASC;
    `);
      res.json(rows);
    } catch (err) {
      console.error("Invoice Status API error: ", err);
      res.status(500).json({ error: "Failed to fetch invoice status" });
    }
  }
);

// ===========================//
// Operational Manager Side  //
// =========================//

// ============================
// APIs for Charts
// ============================

// 1. Shipment Status (Doughnut Chart)
app.get("/api/analytics/shipment-status", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT status, COUNT(*) AS count
      FROM shipments
      GROUP BY status
    `);

    // default categories to always return 0 if missing
    const categories = ["In Progress", "Completed", "Delayed", "Declined"];
    const data = categories.map((cat) => {
      const row = rows.find((r) => r.status === cat);
      return row ? Number(row.count) : 0;
    });

    res.json({ labels: categories, data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch shipment status" });
  }
});

// 2. Operational Manager: Shipment Status
app.get("/api/analytics/operational/shipment-status", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT LOWER(status) AS status, COUNT(*) AS total
      FROM shipments
      GROUP BY LOWER(status)
    `);

    const categories = ["approved", "pending", "completed", "declined"];
    const data = categories.map((cat) => {
      const row = rows.find((r) => r.status === cat);
      return row ? Number(row.total) : 0;
    });

    res.json({
      labels: ["Approved", "Pending", "Completed", "Declined"],
      data,
    });
  } catch (err) {
    console.error("❌ Operational Manager shipment status error:", err);
    res.status(500).json({ error: "Failed to fetch shipment status" });
  }
});

// 📊 Operational Manager: Top 5 Clients by Bookings/Shipments
// 📊 Operational Manager: Top 5 Clients by Bookings
app.get("/api/analytics/operational/top-clients", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.company_name AS name, COUNT(s.id) AS total_bookings
      FROM shipments s
      JOIN clients c ON s.client_id = c.id
      GROUP BY c.company_name
      ORDER BY total_bookings DESC
      LIMIT 5;
    `);

    res.json({
      labels: rows.map((r) => r.name),
      data: rows.map((r) => Number(r.total_bookings)),
    });
  } catch (err) {
    console.error("❌ Error fetching top clients:", err.message);
    res
      .status(500)
      .json({ error: "Failed to fetch top clients", details: err.message });
  }
});

// 5. On-time vs Late (Pie Chart)
app.get("/api/analytics/on-time-vs-late", async (req, res) => {
  try {
    // ✅ Get month and year from query params (or default to current)
    const { month, year } = req.query;
    const selectedMonth = month ? Number(month) : new Date().getMonth() + 1; // 1–12
    const selectedYear = year ? Number(year) : new Date().getFullYear();

    // ✅ Query: count on-time vs late deliveries for selected month & year
    const { rows } = await pool.query(
      `
      SELECT
        CASE 
          WHEN delivered_at <= expected_delivery_date THEN 'On-time'
          ELSE 'Late'
        END AS category,
        COUNT(*) AS count
      FROM shipments
      WHERE 
        delivered_at IS NOT NULL
        AND EXTRACT(MONTH FROM delivered_at) = $1
        AND EXTRACT(YEAR FROM delivered_at) = $2
      GROUP BY category;
    `,
      [selectedMonth, selectedYear]
    );

    // ✅ Ensure we always return both categories (even if 0)
    const categories = ["On-time", "Late"];
    const data = categories.map((cat) => {
      const row = rows.find((r) => r.category === cat);
      return row ? Number(row.count) : 0;
    });

    res.json({ labels: categories, data });
  } catch (err) {
    console.error("❌ Error fetching on-time vs late analytics:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch on-time vs late analytics" });
  }
});

// 6. Weekly Bookings (Bar Chart)
app.get("/api/analytics/weekly-bookings", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT TO_CHAR(created_at, 'Dy') AS day, COUNT(*) AS total
      FROM shipments
      WHERE created_at >= NOW() - interval '7 days'
      GROUP BY day, EXTRACT(DOW FROM created_at)
      ORDER BY EXTRACT(DOW FROM created_at)
    `);

    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const data = days.map((d) => {
      const row = rows.find((r) => r.day === d);
      return row ? Number(row.total) : 0;
    });

    res.json({ labels: days, data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch weekly bookings" });
  }
});

app.get("/api/analytics/shipment-status", async (req, res) => {
  try {
    const query = `
      SELECT status, COUNT(*) AS total
      FROM shipments
      GROUP BY status;
    `;
    const { rows } = await pool.query(query);

    const counts = { approved: 0, pending: 0, completed: 0, declined: 0 };

    rows.forEach((row) => {
      const status = row.status ? row.status.trim().toLowerCase() : "";
      if (status === "approved") counts.approved = Number(row.total);
      else if (status === "pending") counts.pending = Number(row.total);
      else if (status === "completed") counts.completed = Number(row.total);
      else if (status === "declined") counts.declined = Number(row.total);
    });

    res.json({
      labels: ["Approved", "Pending", "Completed", "Declined"],
      data: [
        counts.approved,
        counts.pending,
        counts.completed,
        counts.declined,
      ],
    });
  } catch (err) {
    console.error("❌ Error fetching shipment status (OM):", err);
    res.status(500).json({ error: "Failed to fetch shipment status" });
  }
});

app.get("/api/operational/shipments/recent", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        s.tracking_number,
        s.port_origin,
        s.port_delivery,
        s.status,
        s.created_at,
        c.company_name AS client_name
      FROM shipments s
      LEFT JOIN clients c ON s.client_id = c.id
      ORDER BY s.created_at DESC
      LIMIT 5;
    `);

    res.json(rows);
  } catch (err) {
    console.error("❌ Error fetching recent shipments:", err);
    res.status(500).json({ error: "Failed to fetch recent shipments" });
  }
});

// ==============================//
// Operational Manager REPORTS  //
// ============================//
// ===============================
// 📋 Shipment Status (Reports Page)
// ===============================
app.get("/api/reports/shipment-status", async (req, res) => {
  try {
    const query = `
      SELECT s.tracking_number, c.company_name AS client, s.status, 
      TO_CHAR(s.expected_delivery_date, 'YYYY-MM-DD') AS delivery_date
      FROM shipments s
      JOIN clients c ON s.client_id = c.id
      ORDER BY s.expected_delivery_date DESC;
    `;

    const { rows } = await pool.query(query);

    const result = rows.map((r) => ({
      id: `#${r.tracking_number}`,
      client: r.client || "Unknown Client",
      status: r.status ? r.status.trim() : "Unknown",
      delivery_date: r.delivery_date || "N/A",
    }));

    res.json(result);
  } catch (err) {
    console.error("❌ Error fetching report shipment status:", err);
    res.status(500).json({ error: "Failed to fetch report shipment status" });
  }
});

// ===============================
// 📜 Client Shipment History (Reports Page)
// ===============================
app.get("/api/reports/client-history", async (req, res) => {
  try {
    const client = req.query.client || "Client A";

    const { rows } = await pool.query(
      `
      SELECT s.id, s.created_at::date AS date, s.status, s.port_delivery
      FROM shipments s
      JOIN clients c ON c.id = s.client_id
      WHERE c.company_name = $1
      ORDER BY s.created_at DESC
      LIMIT 10
    `,
      [client]
    );

    res.json(rows);
  } catch (err) {
    console.error("❌ Error fetching report client history:", err);
    res.status(500).json({ error: "Failed to fetch report client history" });
  }
});

// ===============================
// 👥 Get All Clients (Reports Page) - Public
// ===============================
app.get("/api/reports/clients", async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT company_name 
      FROM clients 
      ORDER BY company_name ASC
    `);
    res.json(rows); // Example: [{ company_name: "RC" }, { company_name: "Absolute" }]
  } catch (err) {
    console.error("❌ Error fetching clients:", err.message);
    res
      .status(500)
      .json({ error: "Failed to fetch clients", details: err.message });
  }
});

// ===============================
// 📜 Client Shipment History (Reports Page) - Public
// ===============================
app.get("/api/reports/client-history", async (req, res) => {
  try {
    const client = req.query.client; // e.g. ?client=Absolute
    if (!client) {
      return res.status(400).json({ error: "Client name is required" });
    }

    const query = `
      SELECT 
        s.id,
        s.created_at::date AS shipment_date,
        s.status,
        s.port_origin AS origin,
        s.port_delivery AS destination,
        c.company_name
      FROM shipments s
      INNER JOIN clients c ON s.client_id = c.id
      WHERE c.company_name = $1   -- ✅ filter by client name
      ORDER BY s.created_at DESC
      LIMIT 20;
    `;

    const { rows } = await pool.query(query, [client]);
    res.json(rows);
  } catch (err) {
    console.error("❌ Error fetching report client history:", err.message);
    res.status(500).json({
      error: "Failed to fetch report client history",
      details: err.message,
    });
  }
});

// ================================
// 📂CLIENT NOTIFICATIONS SIDE API
// ================================

// ================================
// 📂 CLIENT NOTIFICATIONS API
// ================================

// -------------------------------
// CLIENT: FETCH NOTIFICATIONS
// -------------------------------
app.get("/api/client/notifications", async (req, res) => {
  try {
    if (!req.session?.client) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const clientId = req.session.client.id;

    const { rows } = await pool.query(
      `SELECT 
         n.id,
         n.client_id,
         n.title,
         n.message,
         n.type,
         n.is_read,
         n.created_at,
         s.tracking_number
       FROM notifications n
       LEFT JOIN shipments s ON n.shipment_id = s.id
       WHERE n.client_id = $1
       ORDER BY n.created_at DESC`,
      [clientId]
    );

    res.json(rows);
  } catch (err) {
    console.error("❌ Error fetching notifications:", err);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// -------------------------------
// CLIENT: MARK SINGLE AS READ
// -------------------------------
app.put("/api/client/notifications/mark-read/:id", async (req, res) => {
  try {
    if (!req.session?.client) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const clientId = req.session.client.id;
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE notifications
       SET is_read = true
       WHERE id = $1 AND client_id = $2
       RETURNING *`,
      [id, clientId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Notification not found" });
    }

    res.json({
      message: "Notification marked as read",
      notification: result.rows[0],
    });
  } catch (err) {
    console.error("❌ Error marking notification as read:", err);
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// -------------------------------
// CLIENT: MARK ALL AS READ
// -------------------------------
app.put("/api/client/notifications/mark-all-read", async (req, res) => {
  try {
    if (!req.session?.client) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const clientId = req.session.client.id;

    await pool.query(
      `UPDATE notifications SET is_read = true WHERE client_id = $1`,
      [clientId]
    );

    res.json({ message: "All notifications marked as read" });
  } catch (err) {
    console.error("❌ Error marking all as read:", err);
    res.status(500).json({ error: "Failed to mark all as read" });
  }
});

// -------------------------------
// ADMIN: TRIGGERS NOTIFICATIONS
// -------------------------------
app.put("/api/admin/bookings/:bookingId/status", async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { status } = req.body;

    let query, values;
    if (status === "Completed") {
      query = `UPDATE shipments SET status=$1, delivered_at=NOW() WHERE id=$2 RETURNING *;`;
      values = [status, bookingId];
    } else {
      query = `UPDATE shipments SET status=$1 WHERE id=$2 RETURNING *;`;
      values = [status, bookingId];
    }

    const { rows } = await pool.query(query, values);
    if (rows.length === 0)
      return res.status(404).json({ error: "Booking not found" });

    const updatedBooking = rows[0];

    // insert notification
    await pool.query(
      `INSERT INTO notifications (client_id, shipment_id, title, message, created_at, is_read, type)
       VALUES ($1, $2, $3, $4, NOW(), false, 'shipment')`,
      [
        updatedBooking.client_id,
        updatedBooking.id,
        "Booking Status Update",
        `Your booking #${updatedBooking.tracking_number} status is now "${status}".`,
      ]
    );

    res.json({ message: "Status updated", booking: updatedBooking });
  } catch (err) {
    console.error("❌ Error updating booking status:", err);
    res.status(500).json({ error: "Failed to update status" });
  }
});

//dinagdag jade

/// ================================
// 📡 TRACCAR GPS ENDPOINT
// ================================
app.post("/api/gps", async (req, res) => {
  try {
    const deviceId = (req.body.device_id || req.body.id || "").trim();
    const latitude = req.body?.location?.coords?.latitude;
    const longitude = req.body?.location?.coords?.longitude;
    const speed = req.body?.location?.coords?.speed ?? 0;
    const timestamp = req.body?.location?.timestamp;

    // 🕒 Parse GPS timestamp
    const gpsTime = timestamp ? new Date(timestamp) : new Date();
    const gpsTimeUTC = gpsTime.toISOString();
    const gpsTimeLocal = new Intl.DateTimeFormat("en-PH", {
      timeZone: "Asia/Manila",
      dateStyle: "short",
      timeStyle: "medium",
    }).format(gpsTime);

    console.log("📡 Incoming GPS (POST):", {
      deviceId,
      latitude,
      longitude,
      speed,
      gpsTimeUTC,
      gpsTimeLocal,
    });

    if (!deviceId || !latitude || !longitude) {
      console.warn("⚠️ Invalid GPS data:", req.body);
      return res.status(400).json({ error: "Invalid GPS data" });
    }

    // 💾 Insert log entry
    await pool.query(
      `INSERT INTO gps_logs (device_id, latitude, longitude, speed, timestamp, recorded_at)
       VALUES ($1, $2, $3, $4, TO_TIMESTAMP(EXTRACT(EPOCH FROM $5::timestamptz)), NOW())`,
      [deviceId, latitude, longitude, speed, gpsTimeUTC]
    );

    // 🧭 Find active shipment
    const result = await pool.query(
      `SELECT shipment_id 
         FROM gps_assignments 
        WHERE device_id = $1 AND released_at IS NULL 
     ORDER BY assigned_at DESC LIMIT 1`,
      [deviceId]
    );

    if (result.rows.length === 0) {
      console.warn(`⚠️ Device ${deviceId} not assigned to any shipment`);
      return res.json({ message: "No active shipment to update." });
    }

    const shipmentId = result.rows[0].shipment_id;

    // 🗺️ Update cache + broadcast
    latestGPSData[shipmentId] = {
      latitude,
      longitude,
      speed,
      timestamp: Date.now(),
    };

    await pool.query(
      `UPDATE shipments
   SET specific_lat = $1,
       specific_lon = $2
   WHERE id = $3`,
      [latitude, longitude, shipmentId]
    );

    console.log(
      `🚀 Broadcasting live GPS for Shipment ${shipmentId} (${deviceId})`
    );
    broadcastUpdate(shipmentId);

    res.json({ message: "✅ GPS data recorded and broadcast." });
  } catch (err) {
    console.error("❌ handleGPSUpdate outer error:", err);
    res.status(500).json({ error: "Failed to save GPS data" });
  }
});

// ================================
// 📡 Add AND Assign GPS Device to Shipment admin function
// ================================
app.post("/api/gps/devices", async (req, res) => {
  const { device_id, shipment_id, notes } = req.body;

  console.log("📦 [API] Assign GPS →", { device_id, shipment_id, notes });

  try {
    if (!device_id || !shipment_id) {
      return res
        .status(400)
        .json({ error: "Device ID and Shipment ID are required." });
    }

    const parsedShipmentId = parseInt(shipment_id, 10);
    if (isNaN(parsedShipmentId)) {
      return res
        .status(400)
        .json({ error: "Invalid Shipment ID format (must be numeric)." });
    }

    // 1️⃣ Verify shipment exists
    console.log("🔍 Checking shipment existence...");
    const shipmentCheck = await pool.query(
      `SELECT id FROM shipments WHERE id = $1`,
      [parsedShipmentId]
    );
    if (shipmentCheck.rows.length === 0) {
      console.log("⚠️ Shipment not found:", parsedShipmentId);
      return res.status(404).json({ error: "Shipment not found." });
    }

    // 2️⃣ Check if device has active assignment
    console.log("🔍 Checking existing GPS assignment...");
    const activeAssign = await pool.query(
      `SELECT shipment_id FROM gps_assignments
       WHERE LOWER(device_id::text) = LOWER($1::text) AND released_at IS NULL
       ORDER BY assigned_at DESC LIMIT 1`,
      [device_id]
    );

    if (
      activeAssign.rows.length > 0 &&
      String(activeAssign.rows[0].shipment_id) !== String(parsedShipmentId)
    ) {
      console.log("⚠️ Device already assigned to another shipment.");
      return res.status(400).json({
        error: `Device ${device_id} is already assigned to another shipment.`,
      });
    }

    // 3️⃣ Check if device exists in gps_devices
    console.log("🔍 Checking if GPS device exists...");
    const existingDevice = await pool.query(
      `SELECT id FROM gps_devices WHERE LOWER(device_id::text) = LOWER($1::text)`,
      [device_id]
    );

    if (existingDevice.rows.length > 0) {
      console.log("🟡 Updating existing GPS device...");
      await pool.query(
        `UPDATE gps_devices
         SET shipment_id = $1, notes = $2, assigned_at = NOW()
         WHERE LOWER(device_id::text) = LOWER($3::text)`,
        [parsedShipmentId, notes || null, device_id]
      );
    } else {
      console.log("🟢 Inserting new GPS device...");
      await pool.query(
        `INSERT INTO gps_devices (device_id, shipment_id, notes, assigned_at, created_at)
         VALUES ($1, $2, $3, NOW(), NOW())`,
        [device_id, parsedShipmentId, notes || null]
      );
    }

    // ✅ Sync shipment record
    console.log("🔄 Syncing shipments table...");
    await pool.query(`UPDATE shipments SET device_id = $1 WHERE id = $2`, [
      device_id,
      parsedShipmentId,
    ]);

    // 4️⃣ Add to gps_assignments if not yet active
    if (activeAssign.rows.length === 0) {
      console.log("📌 Creating gps_assignments entry...");
      await pool.query(
        `INSERT INTO gps_assignments (device_id, shipment_id, assigned_at)
         VALUES ($1, $2, NOW())`,
        [device_id, parsedShipmentId]
      );
    }

    // 🆕 Fetch tracking number from shipments table
    const { rows: trackingRows } = await pool.query(
      `SELECT tracking_number FROM shipments WHERE id = $1`,
      [parsedShipmentId]
    );
    const trackingNumber = trackingRows[0]?.tracking_number || parsedShipmentId;

    // ✅ Log and respond using tracking number
    console.log(
      `✅ Device ${device_id} successfully assigned to shipment ${trackingNumber}.`
    );
    res.json({
      message: `✅ Device ${device_id} successfully assigned to shipment ${trackingNumber}.`,
    });
  } catch (err) {
    console.error("❌ Error assigning GPS device:", err);
    res.status(500).json({ error: "Server error assigning GPS device" });
  }
});

// ================================
// ✅ List available GPS devices
// ================================
app.get("/api/gps/devices", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT device_id
      FROM gps_devices
      WHERE shipment_id IS NULL
    `);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No available GPS devices" });
    }

    res.json(result.rows.map((r) => r.device_id));
  } catch (err) {
    console.error("❌ Error fetching GPS devices:", err);
    res.status(500).json({ error: "Failed to fetch GPS devices" });
  }
});

// ========================================
// 📡 GET Assigned GPS device for shipment (Active Only) admin function
// ========================================
app.get("/api/gps/assigned/:shipmentId", async (req, res) => {
  try {
    const { shipmentId } = req.params;
    const parsedId = parseInt(shipmentId, 10);

    if (isNaN(parsedId)) {
      return res.status(400).json({ error: "Invalid shipment ID format." });
    }

    // 🔍 Find the active (not released) GPS assignment
    const { rows } = await pool.query(
      `SELECT ga.device_id, gd.notes, ga.assigned_at
       FROM gps_assignments ga
       LEFT JOIN gps_devices gd 
         ON LOWER(ga.device_id::text) = LOWER(gd.device_id::text)
       WHERE ga.shipment_id = $1
         AND ga.released_at IS NULL   -- ✅ Only active assignments
       ORDER BY ga.assigned_at DESC
       LIMIT 1`,
      [parsedId]
    );

    if (rows.length === 0) {
      // ✅ Return success (200) but empty info to avoid frontend 404
      return res.status(200).json({
        device_id: null,
        notes: null,
        assigned_at: null,
        message: "No GPS device assigned.",
      });
    }

    res.json(rows[0]); // ✅ Return active assignment only
  } catch (err) {
    console.error("❌ Error fetching assigned GPS device:", err);
    res.status(500).json({ error: "Server error fetching GPS assignment." });
  }
});

// ================================
// 📡 Get GPS history for shipment
// ================================
// ================================
// 🛰️ Get GPS History by Shipment ID
// ================================
app.get("/api/gps/history/:shipmentId", async (req, res) => {
  const { shipmentId } = req.params;

  try {
    // Only fetch active GPS assignment (not released)
    const assignmentRes = await pool.query(
      `
      SELECT device_id
      FROM gps_assignments
      WHERE shipment_id = $1
        AND released_at IS NULL
      `,
      [shipmentId]
    );

    // If no active assignment found
    if (assignmentRes.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "No active GPS device assigned to this shipment" });
    }

    const deviceId = assignmentRes.rows[0].device_id;

    // Fetch GPS logs for the device
    const historyRes = await pool.query(
      `
      SELECT latitude, longitude, recorded_at
      FROM gps_logs
      WHERE LOWER(device_id) = LOWER($1)
      ORDER BY recorded_at DESC
      LIMIT 100
      `,
      [deviceId]
    );

    res.json(historyRes.rows);
  } catch (err) {
    console.error("❌ Error fetching GPS history:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// =====================================
// 📦 Get shipments for logged-in client
// =====================================
// 📦 Get shipments for logged-in client
app.get("/api/client/shipments", async (req, res) => {
  try {
    // 🧠 Debug: log the entire session for diagnosis
    console.log("🔍 Shipment route session:", req.session);

    const clientId = req.session?.user?.id;
    if (!clientId) {
      console.log("❌ No session.user found! Returning 401.");
      return res.status(401).json({ error: "Not authorized" });
    }

    const result = await pool.query(
      `
      SELECT 
        s.id,
        s.tracking_number,
        s.port_origin AS origin,
        s.port_delivery AS destination,
        s.status,
        s.device_id,
        s.created_at,
        st.latitude,
        st.longitude,
        st.updated_at
      FROM shipments s
      LEFT JOIN shipment_tracking st ON st.shipment_id = s.id
      WHERE s.client_id = $1
      ORDER BY s.created_at DESC
    `,
      [clientId]
    );

    console.log(
      `✅ Found ${result.rows.length} shipments for client ${clientId}`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching client shipments:", err);
    res.status(500).json({ error: "Server error fetching shipments" });
  }
});

// ================================
// 🔴 Unassign GPS Device admin function
// ================================
app.put("/api/gps/unassign/:device_id", async (req, res) => {
  const { device_id } = req.params;

  try {
    if (!device_id)
      return res.status(400).json({ error: "Device ID is required." });

    // 1️⃣ Remove assignment from gps_devices
    await pool.query(
      `UPDATE gps_devices
       SET shipment_id = NULL, assigned_at = NULL
       WHERE LOWER(device_id) = LOWER($1)`,
      [device_id]
    );

    // 2️⃣ Mark gps_assignments as released
    await pool.query(
      `UPDATE gps_assignments
       SET released_at = NOW()
       WHERE LOWER(device_id) = LOWER($1) AND released_at IS NULL`,
      [device_id]
    );

    // 3️⃣ Clear the linked shipment record (device_id column)
    await pool.query(
      `UPDATE shipments
       SET device_id = NULL
       WHERE LOWER(device_id) = LOWER($1)`,
      [device_id]
    );

    console.log(`✅ Device ${device_id} fully unassigned (shipments synced)`);
    res.json({ message: `✅ Device ${device_id} unassigned successfully.` });
  } catch (err) {
    console.error("❌ Error unassigning GPS device:", err);
    res.status(500).json({ error: "Failed to unassign GPS device" });
  }
});

// ======================
// START SERVER
// ======================
server.listen(PORT, () => {
  console.log(`🚀 HTTP server running at http://localhost:${PORT}`);
  console.log(`🔄 WebSocket server running at ws://localhost:${PORT}`);
});

// ============================
// Landing Page Content API
// ============================

// Fetch all landing page sections
app.get("/api/landing-content", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT section_key, content FROM landing_page_content"
    );
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching landing page content:", err);
    res.status(500).json({ error: "Failed to fetch landing page content" });
  }
});

// Create or update a specific section
app.post("/api/landing-content/update", async (req, res) => {
  try {
    const { section_key, content } = req.body;

    // Basic validation
    if (!section_key || typeof content !== "string") {
      return res
        .status(400)
        .json({ error: "Both section_key and content are required." });
    }

    await pool.query(
      `
        INSERT INTO landing_page_content (section_key, content)
        VALUES ($1, $2)
        ON CONFLICT (section_key)
        DO UPDATE SET content = EXCLUDED.content;
      `,
      [section_key, content]
    );

    res
      .status(200)
      .json({ success: true, message: "Content updated successfully." });
  } catch (err) {
    console.error("❌ Error updating landing page content:", err);
    res.status(500).json({ error: "Failed to update landing page content" });
  }
});
