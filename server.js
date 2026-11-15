const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const Razorpay = require("razorpay");
const crypto = require("crypto");
const axios = require("axios");
const { normalizePhone, registerOtpRoutes } = require("./otp");
const { createOrderNotificationService } = require("./order-notifications");
const { registerWhatsAppWebhookRoutes } = require("./whatsapp-webhook");


const app = express();
app.use(cors());
registerWhatsAppWebhookRoutes(app);
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb", extended: true }));

const multer = require("multer");
const path = require("path");
const { v4: uuidv4 } = require("uuid");

app.use("/uploads", express.static("uploads"));

/* -------------------- DB -------------------- */
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const orderNotifications = createOrderNotificationService({ db });

/* -------------------- AUTH MIDDLEWARE -------------------- */
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

/* ===============================
RAZORPAY INIT
=============================== */

const razorpay = new Razorpay({

  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET

});

/* ===============================
CREATE RAZORPAY ORDER
=============================== */

app.post("/api/create-razorpay-order", auth, async (req, res) => {

  try {

    const { amount } = req.body;

    const razorpayOrder =
      await razorpay.orders.create({

        amount: Math.round(amount * 100), // ✅ FINAL AMOUNT IN PAISE

        currency: "INR",

        receipt: "receipt_" + Date.now()

      });

    res.json(razorpayOrder);

  }
  catch (err) {

    res.status(500).json({
      message: "Failed to create Razorpay order"
    });

  }

});



/* ===============================
VERIFY PAYMENT
=============================== */

app.post("/api/verify-payment", async (req, res) => {

  try {

    const {

      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature

    } = req.body;


    const generated_signature =
      crypto
        .createHmac(
          "sha256",
          process.env.RAZORPAY_KEY_SECRET
        )
        .update(
          razorpay_order_id +
          "|" +
          razorpay_payment_id
        )
        .digest("hex");


    if (generated_signature !== razorpay_signature) {

      return res.status(400).json({
        message: "Invalid payment"
      });

    }

    res.json({
      success: true
    });

  }
  catch {

    res.status(500).json({
      message: "Verification failed"
    });

  }

});


/* =========================================================
   AUTH ROUTES
========================================================= */
/* ================= GET CURRENT USER ================= */

app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, name, email, phone, role, avatar_url, created_at FROM users WHERE id=?",
      [req.user.id]
    );

    if (!rows.length) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const [existing] = await db.query(
      "SELECT id FROM users WHERE email=?",
      [email]
    );

    if (existing.length) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hash = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users (id, name, email, password) VALUES (UUID(), ?, ?, ?)",
      [name, email, hash]
    );

    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});



/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [users] = await db.query(
      "SELECT * FROM users WHERE email=? AND role='admin'",
      [email]
    );

    if (!users.length) {
      return res.status(400).json({ message: "Admin not found" });
    }

    const admin = users[0];

    const match = await bcrypt.compare(password, admin.password);
    if (!match) {
      return res.status(400).json({ message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: admin.id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: admin.id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const [users] = await db.query("SELECT * FROM users WHERE email=?", [email]);
  if (!users.length) return res.status(400).json({ message: "User not found" });

  const user = users[0];
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, user });
});

/* =========================================================
   GOOGLE AUTH (Sign in / Sign up)
   Frontend obtains an authorization code via Google Identity
   Services (popup code flow) and sends it here. The server
   exchanges it for tokens, verifies the ID token, then either
   logs in the existing user or creates a new one.
========================================================= */
app.post("/api/auth/google", async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ message: "Authorization code is required" });
    }

    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      console.error("GOOGLE AUTH: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET is not set");
      return res.status(500).json({ message: "Google sign-in is not configured on the server" });
    }

    // 1. Exchange the authorization code for tokens.
    //    For the GIS popup code flow the redirect_uri MUST be "postmessage".
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: "postmessage",
        grant_type: "authorization_code",
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { id_token } = tokenResponse.data;

    // 2. Verify the ID token with Google's tokeninfo endpoint.
    //    This validates the signature, issuer, and audience for us.
    const ticket = await axios.get(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${id_token}`
    );

    const payload = ticket.data;

    // Make sure the token was issued for our app.
    if (payload.aud !== clientId) {
      return res.status(400).json({ message: "Invalid Google token" });
    }

    if (payload.email_verified !== "true" && payload.email_verified !== true) {
      return res.status(400).json({ message: "Google account email is not verified" });
    }

    const email = String(payload.email || "").toLowerCase();
    const name = payload.name || email.split("@")[0];
    const picture = payload.picture || null;

    if (!email) {
      return res.status(400).json({ message: "Could not retrieve email from Google" });
    }

    // 3. Look up the user by email.
    const [users] = await db.query("SELECT * FROM users WHERE email=?", [email]);

    let user;
    if (users.length) {
      user = users[0];

      // Backfill missing profile fields from Google.
      const updates = [];
      const values = [];
      if (!user.avatar_url && picture) {
        updates.push("avatar_url = ?");
        values.push(picture);
      }
      if (!user.name && name) {
        updates.push("name = ?");
        values.push(name);
      }
      if (updates.length) {
        values.push(user.id);
        await db.query(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`, values);
        user.avatar_url = user.avatar_url || picture;
        user.name = user.name || name;
      }
    } else {
      // 4. Create a new user (Google sign-up).
      //    Set a random password so the account can't be used with
      //    email/password until the user sets one via reset-password.
      const randomPassword = crypto.randomBytes(32).toString("hex");
      const hash = await bcrypt.hash(randomPassword, 10);

      await db.query(
        "INSERT INTO users (id, name, email, password, avatar_url) VALUES (UUID(), ?, ?, ?, ?)",
        [name, email, hash, picture]
      );

      const [newUsers] = await db.query("SELECT * FROM users WHERE email=?", [email]);
      user = newUsers[0];
    }

    // 5. Issue a JWT for the user.
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar_url: user.avatar_url,
      },
    });
  } catch (err) {
    const details = err.response?.data || err.message;
    console.error("GOOGLE AUTH ERROR:", details);
    res.status(400).json({ message: "Google sign-in failed. Please try again." });
  }
});

app.post("/api/auth/reset-password", auth, async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  await db.query("UPDATE users SET password=? WHERE id=?", [
    hash,
    req.user.id,
  ]);
  res.json({ message: "Password updated" });
});

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get("/api/admin/dashboard", auth, async (req, res) => {
  try {
    const [[orders]] = await db.query(
      "SELECT COUNT(*) AS total FROM orders"
    );

    const [[revenue]] = await db.query(
      "SELECT SUM(final_amount) AS total FROM orders"
    );

    const [[users]] = await db.query(
      "SELECT COUNT(*) AS total FROM users"
    );

    const [[coupons]] = await db.query(
      "SELECT COUNT(*) AS total FROM coupons WHERE is_active = 1"
    );

    const [[pending]] = await db.query(
      "SELECT COUNT(*) AS total FROM orders WHERE status = 'pending'"
    );

    const [recentOrders] = await db.query(`
      SELECT id, status, final_amount, created_at
      FROM orders
      ORDER BY created_at DESC
      LIMIT 5
    `);

    res.json({
      totalOrders: orders.total,
      totalRevenue: revenue.total || 0,
      totalUsers: users.total,
      activeCoupons: coupons.total,
      pendingOrders: pending.total,
      recentOrders,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Dashboard fetch failed" });
  }
});

app.post("/api/checkout", auth, async (req, res) => {

  const connection = await db.getConnection();

  try {

    const {
      items,
      shipping_address,
      coupon,
      payment_method = "online",
      payment_id = null,
      razorpay_order_id = null,
      razorpay_signature = null
    } = req.body;

    if (!items || items.length === 0)
      return res.status(400).json({ message: "Cart is empty" });

    if (payment_method !== "online" &&
        payment_method !== "partial")
      return res.status(400).json({
        message: "Invalid payment method"
      });

    if (!shipping_address?.phone)
      return res.status(400).json({ message: "Phone required" });

    const verifiedPhone = normalizePhone(
      shipping_address.phone,
      process.env.WHATSAPP_DEFAULT_COUNTRY_CODE || ""
    );
    if (!verifiedPhone)
      return res.status(400).json({
        message: "A valid phone number with country code is required"
      });

    /* =========================
       VERIFY PHONE (STRICT)
       Temporary bypass: set OTP_VERIFICATION_REQUIRED=false to let
       customers order with just their phone number, without OTP.
       Set it back to true to restore mandatory verification.
    ========================= */

    if (process.env.OTP_VERIFICATION_REQUIRED !== "false") {

      const [[verified]] =
        await connection.query(
          `SELECT id, expires_at
           FROM phone_otps
           WHERE phone = ?
           AND is_verified = 1
           ORDER BY created_at DESC
           LIMIT 1`,
          [verifiedPhone]
        );

      if (!verified)
        return res.status(400).json({
          message: "Phone not verified"
        });

      if (new Date(verified.expires_at) < new Date())
        return res.status(400).json({
          message: "Phone verification expired"
        });

      // Consume OTP (one-time use)
      await connection.query(
        `UPDATE phone_otps
         SET is_verified = 0
         WHERE id = ?`,
        [verified.id]
      );

    }


    await connection.beginTransaction();

    const orderId = uuidv4();


    /* =========================
       CALCULATE TOTAL
    ========================= */

    let subtotal = 0;

    for (const item of items)
      subtotal +=
        Number(item.price) *
        Number(item.quantity);

    const shipping = 50;
    const tax = Number((subtotal * 0.08).toFixed(2));

    let discount = 0;


    /* =========================
       COUPON VALIDATION
    ========================= */

    if (coupon) {

      const [[couponData]] =
        await connection.query(
          `SELECT *
           FROM coupons
           WHERE code = ?
           AND is_active = 1
           AND (expires_at IS NULL OR expires_at > NOW())
           AND (min_order_amount IS NULL OR ? >= min_order_amount)`,
          [coupon.toUpperCase(), subtotal]
        );

      if (couponData) {

        if (couponData.discount_type === "percentage")
          discount =
            subtotal *
            couponData.discount_value / 100;

        else if (couponData.discount_type === "fixed")
          discount =
            couponData.discount_value;

      }

    }

    discount = Number(discount.toFixed(2));

    const finalAmount =
      Number(
        (subtotal + tax + shipping - discount)
          .toFixed(2)
      );


    /* =========================
       PARTIAL PAYMENT SPLIT
       "partial" = pay 50% online now, rest as Cash on Delivery.
    ========================= */

    const PARTIAL_PREPAID_PERCENT = 50;

    let prepaidAmount = 0;
    let codAmount = 0;

    if (payment_method === "partial") {

      prepaidAmount = Number(
        (finalAmount * PARTIAL_PREPAID_PERCENT / 100)
          .toFixed(2)
      );

      codAmount = Number(
        (finalAmount - prepaidAmount)
          .toFixed(2)
      );

    }


    /* =========================
       VERIFY ONLINE / PARTIAL PAYMENT
    ========================= */

    if (payment_method === "online" ||
        payment_method === "partial") {

      if (!razorpay_order_id ||
          !payment_id ||
          !razorpay_signature)
        throw new Error("Missing payment details");

      const generatedSignature =
        crypto
          .createHmac("sha256",
            process.env.RAZORPAY_KEY_SECRET)
          .update(
            razorpay_order_id + "|" + payment_id
          )
          .digest("hex");

      if (generatedSignature !== razorpay_signature)
        throw new Error("Invalid payment signature");

    }


    /* =========================
       INSERT ORDER
    ========================= */

    await connection.query(

      `INSERT INTO orders
      (
        id,
        user_id,
        subtotal,
        tax,
        shipping_charge,
        discount,
        final_amount,
        payment_method,
        payment_status,
        payment_id,
        razorpay_order_id,
        razorpay_signature,
        status,
        address
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        orderId,
        req.user.id,
        subtotal,
        tax,
        shipping,
        discount,
        finalAmount,
        payment_method,
        payment_method === "online"
          ? "paid"
          : "pending",
        payment_id,
        razorpay_order_id,
        razorpay_signature,
        "pending",
        JSON.stringify(shipping_address)
      ]

    );


    /* =========================
       INSERT ITEMS + STOCK LOCK
    ========================= */

    const orderItems = [];

    for (const item of items) {

      const isCustom =
        item.productId ===
        "customize-phone-cover";

      let productName =
        item.name || "Custom Product";

      if (!isCustom) {

        const [[product]] =
          await connection.query(
            `SELECT name, stock
             FROM products
             WHERE id = ?
             FOR UPDATE`,
            [item.productId]
          );

        if (!product)
          throw new Error("Product not found");

        if (product.stock < item.quantity)
          throw new Error("Insufficient stock");

        productName = product.name;

        await connection.query(
          `UPDATE products
           SET stock = stock - ?
           WHERE id = ?`,
          [item.quantity, item.productId]
        );

      }

      await connection.query(
        `INSERT INTO order_items
        (
          id,
          order_id,
          product_id,
          product_name,
          quantity,
          price,
          customization
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          uuidv4(),
          orderId,
          item.productId,
          productName,
          item.quantity,
          item.price,
          JSON.stringify(
            item.customization || {}
          )
        ]
      );

      orderItems.push({
        product_name: productName,
        quantity: item.quantity,
        price: item.price
      });

    }

    const [[customer]] = await connection.query(
      `SELECT name, email, phone
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [req.user.id]
    );

    await orderNotifications.enqueueForOrder(connection, {
      id: orderId,
      customer_name: shipping_address.full_name || customer?.name,
      customer_phone: verifiedPhone,
      customer_email: customer?.email,
      customer_whatsapp_consent:
        shipping_address.whatsapp_consent === true,
      items: orderItems,
      final_amount: finalAmount,
      payment_method,
      payment_status: payment_method === "online" ? "paid" : "pending",
      payment_id,
      address: shipping_address
    });

    await connection.commit();


    /* =========================
       CLEANUP OLD OTPS
    ========================= */

    try {
      await db.query(
        `DELETE FROM phone_otps
         WHERE phone = ?`,
        [verifiedPhone]
      );
    } catch {
      console.error("OTP cleanup failed after committed order", {
        orderId
      });
    }


    res.json({
      success: true,
      order_id: orderId,
      subtotal,
      tax,
      shipping,
      discount,
      final_amount: finalAmount,
      prepaid_amount: prepaidAmount,
      cod_amount: codAmount
    });

    orderNotifications.kick();

  }
  catch (err) {

    try {
      await connection.rollback();
    } catch {
      console.error("Checkout rollback failed");
    }
    console.error(err);

    res.status(400).json({
      message: err.message
    });

  }
  finally {

    connection.release();

  }

});






/* =========================================================
   COUPONS
========================================================= */

/* =========================================================
   COUPONS - BOTH ROUTES (Admin + Frontend)
========================================================= */
app.get("/coupons/validate/:code", async (req, res) => {
  try {
    const { code } = req.params;
    
    const [[coupon]] = await db.query(
      `
      SELECT * FROM coupons
      WHERE code = ?
        AND is_active = 1
        AND (valid_until IS NULL OR valid_until >= CURDATE())
      `,
      [code.toUpperCase()]
    );

    if (!coupon) {
      return res.status(404).json({ message: "Invalid or expired coupon" });
    }

    // Usage limit check
    if (coupon.usage_limit && (coupon.used_count || 0) >= coupon.usage_limit) {
      return res.status(400).json({ message: "Coupon usage limit reached" });
    }

    res.json(coupon);
  } catch (err) {
    console.error('Coupon validate error:', err);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ ADMIN ROUTES (keep your existing ones)
app.get("/api/admin/coupons", auth, async (_, res) => {
  const [rows] = await db.query("SELECT * FROM coupons ORDER BY created_at DESC");
  res.json(rows);
});

app.post("/api/admin/coupons", auth, async (req, res) => {
  const id = uuidv4();

  await db.query(
    `INSERT INTO coupons (
      id, code, description, discount_type, discount_value,
      min_order_amount, max_discount, usage_limit, valid_until, is_active
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      req.body.code,
      req.body.description || null,
      req.body.discount_type,
      req.body.discount_value,
      req.body.min_order_amount || null,
      req.body.max_discount || null,
      req.body.usage_limit || null,
      req.body.valid_until || null,
      1
    ]
  );

  res.json({ message: "Coupon created", id });
});

app.put("/api/admin/coupons/:id", auth, async (req, res) => {
  await db.query("UPDATE coupons SET ? WHERE id=?", [req.body, req.params.id]);
  res.json({ message: "Coupon updated" });
});

app.patch("/api/admin/coupons/:id/toggle", auth, async (req, res) => {
  await db.query("UPDATE coupons SET is_active = !is_active WHERE id=?", [req.params.id]);
  res.json({ message: "Toggled" });
});

app.delete("/api/admin/coupons/:id", auth, async (req, res) => {
  await db.query("DELETE FROM coupons WHERE id=?", [req.params.id]);
  res.json({ message: "Deleted" });
});

/* =========================================================
   APPLY COUPON (FRONTEND CouponInput)
========================================================= */

app.post("/api/coupons/apply", async (req, res) => {
  const { code, subtotal } = req.body;

  const [rows] = await db.query(
    "SELECT * FROM coupons WHERE code=? AND is_active=1",
    [code]
  );
  if (!rows.length) return res.status(400).json({ message: "Invalid coupon" });

  const coupon = rows[0];

  if (coupon.min_order_amount && subtotal < coupon.min_order_amount) {
    return res.status(400).json({ message: "Minimum order not met" });
  }

  res.json(coupon);
});

/* =========================================================
   ORDERS (ADMIN)
========================================================= */
app.get("/admin/orders", auth, async (req, res) => {
  try {

    const [orders] = await db.query(`
      SELECT 
        o.id,
        o.user_id,

        o.status,

        /* ✅ PAYMENT INFO (FIXED) */
        o.payment_method,
        o.payment_status,
        o.payment_id AS razorpay_payment_id,   -- ✅ FIX HERE
        o.razorpay_order_id,
        o.razorpay_signature,

        o.created_at,

        /* AMOUNT INFO */
        o.subtotal,
        o.tax,
        o.shipping_charge,
        o.discount,
        o.final_amount,

        o.address,

        /* CUSTOMER INFO */
        JSON_UNQUOTE(
          JSON_EXTRACT(o.address, '$.full_name')
        ) AS customer_name,

        JSON_UNQUOTE(
          JSON_EXTRACT(o.address, '$.phone')
        ) AS customer_phone,

        u.email AS customer_email,

        /* ORDER STATS */
        COUNT(oi.id) AS items_count,

        COALESCE(
          SUM(oi.quantity * oi.price),
          0
        ) AS items_total

      FROM orders o

      LEFT JOIN users u
        ON u.id = o.user_id

      LEFT JOIN order_items oi
        ON oi.order_id = o.id

      GROUP BY o.id

      ORDER BY o.created_at DESC
    `);

    /* Amount still to be collected on delivery:
       partial = remaining 50% balance, legacy COD = full total, online = 0. */
    const PARTIAL_PREPAID_PERCENT = 50;

    const withPayOnDelivery = orders.map((order) => {

      const finalAmount = Number(order.final_amount || 0);

      let payOnDelivery = 0;

      if (order.payment_method === "partial") {

        const prepaid = Number(
          (finalAmount * PARTIAL_PREPAID_PERCENT / 100).toFixed(2)
        );

        payOnDelivery = Number(
          (finalAmount - prepaid).toFixed(2)
        );

      } else if (!order.payment_method || order.payment_method === "cod") {

        payOnDelivery = finalAmount;

      }

      return { ...order, pay_on_delivery: payOnDelivery };

    });

    res.json(withPayOnDelivery);

  } catch (err) {

    console.error("Admin orders fetch error:", err);

    res.status(500).json({
      success: false,
      message: "Failed to fetch orders"
    });

  }
});


app.get("/admin/orders/:id/items", auth, async (req, res) => {
  const [items] = await db.query(`
    SELECT 
      oi.*,
      p.name as product_name,
      p.images,
      TRIM(oi.product_id) as clean_product_id
    FROM order_items oi
    LEFT JOIN products p ON TRIM(oi.product_id) = p.id
    WHERE oi.order_id = ?
  `, [req.params.id]);
  res.json(items);
});

app.put("/admin/orders/:id/status", auth, async (req, res) => {
  const { status } = req.body;
  const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
  
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const [result] = await db.query(
    "UPDATE orders SET status = ? WHERE id = ?",
    [status, req.params.id]
  );

  if (result.affectedRows === 0) {
    return res.status(404).json({ error: 'Order not found' });
  }

  res.json({ success: true, message: "Status updated" });
});
app.get("/admin/orders/:id/breakdown", auth, async (req, res) => {

  try {

    const orderId = req.params.id;

    const [[order]] = await db.query(`
      SELECT 
        subtotal,
        tax,
        shipping_charge AS shipping,
        discount,
        final_amount AS total
      FROM orders
      WHERE id = ?
    `, [orderId]);

    if (!order) {
      return res.status(404).json({
        error: "Order not found"
      });
    }

    res.json({
      subtotal: Number(order.subtotal || 0),
      tax: Number(order.tax || 0),
      shipping: Number(order.shipping || 0),
      discount: Number(order.discount || 0),
      total: Number(order.total || 0)
    });

  }
  catch (err) {

    console.error(err);

    res.status(500).json({
      error: "Failed to fetch breakdown"
    });

  }

});


// COMPLETE BACKEND - All Admin Products Routes (Copy-Paste Ready)
/* ================================
   SAFE JSON PARSER - ADD THIS FIRST
================================ */
const safeJsonParse = (value, fallback) => {
  // If null / undefined / empty → return fallback
  if (!value) return fallback;

  // ✅ If already object or array → return directly
  if (typeof value === "object") return value;

  // ✅ If not a string → return fallback
  if (typeof value !== "string") return fallback;

  try {
    return JSON.parse(value);
  } catch (error) {
    // Optional: reduce console noise
    console.warn("Invalid JSON skipped:", value);
    return fallback;
  }
};

/* ================================
   GET ALL PRODUCTS
================================ */
app.get('/api/admin/products', auth, async (req, res) => {
  const [rows] = await db.query(
    'SELECT * FROM products ORDER BY created_at DESC'
  );

  const products = rows.map(p => ({
    ...p,
    images: safeJsonParse(p.images, []),
    tags: safeJsonParse(p.tags, []),
    customization_options: safeJsonParse(p.customization_options, {
      canAddText: false,
      canAddImage: false,
    }),
  }));

  res.json(products);
});

/* ================================
   CREATE PRODUCT
================================ */
app.post('/api/admin/products', auth, async (req, res) => {
  const {
    name,
    description,
    price,
    original_price,
    category,
    images, // ✅ Fixed: expect images array
    stock,
    tags,
    is_active,
    customization_options
  } = req.body;

  await db.query(
    `INSERT INTO products 
     (id, name, description, price, original_price, category, images, stock, tags, is_active, customization_options)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      uuidv4(),
      name,
      description || null,
      price,
      original_price || null,
      category,
      JSON.stringify(images || []), // ✅ Fixed: images array
      stock ?? 0,
      JSON.stringify(tags || []),
      is_active ?? 1,
      JSON.stringify(customization_options || {})
    ]
  );

  res.json({ message: 'Product created' });
});

/* ================================
   UPDATE PRODUCT
================================ */
app.put('/api/admin/products/:id', auth, async (req, res) => {
  const {
    name,
    description,
    price,
    original_price,
    category,
    images, // ✅ Fixed: expect images array
    stock,
    tags,
    is_active,
    customization_options
  } = req.body;

  await db.query(
    `UPDATE products SET
      name=?, description=?, price=?, original_price=?, category=?,
      images=?, stock=?, tags=?, is_active=?, customization_options=?
     WHERE id=?`,
    [
      name,
      description || null,
      price,
      original_price || null,
      category,
      JSON.stringify(images || []), // ✅ Fixed: images array
      stock ?? 0,
      JSON.stringify(tags || []),
      is_active ?? 1,
      JSON.stringify(customization_options || {}),
      req.params.id
    ]
  );

  res.json({ message: 'Product updated' });
});

/* ================================
   DELETE PRODUCT
================================ */
app.delete("/api/admin/products/:id", auth, async (req, res) => {
  try {
    const [[existing]] = await db.query('SELECT id FROM products WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Product not found' });

    await db.query("DELETE FROM products WHERE id=?", [req.params.id]);
    res.json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

/* ================================
   TOGGLE STATUS
================================ */
app.patch("/api/admin/products/:id/status", auth, async (req, res) => {
  try {
    const { is_active } = req.body;
    
    await db.query(
      'UPDATE products SET is_active = ? WHERE id = ?',
      [is_active !== undefined ? Boolean(is_active) : 0, req.params.id]
    );
    
    res.json({ message: 'Status updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update status" });
  }
});

/* ================================
   UPLOAD - Fixed to return correct format
================================ */
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    cb(null, uuidv4() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

app.post('/api/upload', upload.single('image'), (req, res) => {
  res.json({
    imageUrl: `https://api.thedesignhive.tech/uploads/${req.file.filename}`,
  });
});

/* =========================================================
   USERS (ADMIN)
========================================================= */
app.get("/api/admin/users", auth, async (_, res) => {
  const [users] = await db.query(
    `SELECT 
      id,
      COALESCE(name, CONCAT(LEFT(SUBSTRING_INDEX(email, '@', 1), 1), 
             SUBSTRING_INDEX(SUBSTRING_INDEX(email, '@', 1), '.', -1), ' User')) as name,
      email,
      role,
      avatar_url,
      created_at
     FROM users 
     ORDER BY created_at DESC`
  );
  res.json(users);
});

// ✅ FIXED: Toggle works perfectly
app.patch("/api/admin/users/:id/toggle-admin", auth, async (req, res) => {
  try {
    const [[user]] = await db.query("SELECT role FROM users WHERE id=?", [req.params.id]);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    const newRole = user.role === 'admin' ? 'user' : 'admin';
    await db.query("UPDATE users SET role=? WHERE id=?", [newRole, req.params.id]);
    res.json({ message: "Role updated successfully" });
  } catch (err) {
    console.error("Toggle admin error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET ALL PRODUCTS
app.get("/api/products", async (req, res) => {
  try {  // ✅ ADD try-catch for safety
    const [rows] = await db.query(
      "SELECT * FROM products WHERE is_active = 1 ORDER BY created_at DESC"  // ✅ ADD is_active = 1
    );
    
    const products = rows.map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description,
      price: Number(p.price),
      original_price: Number(p.original_price) || null,
      category: p.category,
      stock: p.stock,
      tags: typeof p.tags === "string" ? JSON.parse(p.tags || '[]') : p.tags || [],  // ✅ Add || '[]'

      images: p.images
        ? (typeof p.images === "string" 
            ? JSON.parse(p.images || '[]')  // ✅ Add || '[]' 
            : Array.isArray(p.images) ? p.images : [])  // ✅ Safety check
        : p.image_url ? [p.image_url] : ["/placeholder.svg"],  // ✅ Fix: p.image_url + fallback

      customization_options: typeof p.customization_options === "string" 
        ? JSON.parse(p.customization_options || '{}')  // ✅ FIX: Parse JSON string
        : p.customization_options || {
            canAddText: false,
            canAddImage: false,
          },
    }));

    res.json(products);
  } catch (err) {  // ✅ Error handling
    console.error('Products fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// SINGLE PRODUCT - SAME FIXES
app.get("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await db.query(
      "SELECT * FROM products WHERE id = ? AND is_active = 1",  // ✅ Add is_active = 1
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    const p = rows[0];
    const product = {
      id: p.id,
      name: p.name,
      description: p.description,
      price: Number(p.price),
      original_price: Number(p.original_price) || null,
      category: p.category,
      stock: p.stock,
      tags: typeof p.tags === "string" ? JSON.parse(p.tags || '[]') : p.tags || [],
      
      images: p.images
        ? (typeof p.images === "string"
            ? JSON.parse(p.images || '[]')
            : Array.isArray(p.images) ? p.images : [])
        : p.image_url ? [p.image_url] : ["/placeholder.svg"],
      
      customization_options: typeof p.customization_options === "string" 
        ? JSON.parse(p.customization_options || '{}')
        : p.customization_options || {
            canAddText: false,
            canAddImage: false,
          },
    };

    res.json(product);
  } catch (err) {
    console.error('Product fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});


/* ========================================================= */
// const multer = require("multer");
// const path = require("path");

// app.use("/uploads", express.static("uploads"));

// const storage = multer.diskStorage({
//   destination: "uploads/",
//   filename: (req, file, cb) => {
//     cb(null, Date.now() + path.extname(file.originalname));
//   },
// });

// const upload = multer({ storage });

// app.post("/api/upload", upload.single("image"), (req, res) => {
//   res.json({
//     imageUrl: `http://localhost:5000/uploads/${req.file.filename}`,
//   });
// });

app.post("/api/upload", upload.single("image"), (req, res) => {
  res.json({
    imageUrl: `https://api.thedesignhive.tech/uploads/${req.file.filename}`,
  });
});


/* =========================================================
   USER ORDERS (FOR NAVBAR → MY ORDERS)
========================================================= */
app.get("/api/orders", auth, async (req, res) => {

  try {

    const [orders] = await db.query(
      "SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC",
      [req.user.id]
    );

    const formattedOrders = [];

    for (const order of orders) {

      const [items] = await db.query(`
        SELECT 
          oi.id,
          oi.order_id,
          oi.product_id,
          oi.quantity,
          oi.price,
          oi.customization,
          COALESCE(p.name, 'Custom Product') AS product_name,
          COALESCE(
            p.image,
            COALESCE(JSON_UNQUOTE(JSON_EXTRACT(p.images,'$[0]')), '/placeholder.svg')
          ) AS product_image
        FROM order_items oi
        LEFT JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
      `, [order.id]);

      const processedItems = items.map(item => {

        let customization = null;

        if (item.customization) {

          if (typeof item.customization === 'object')
            customization = item.customization;

          else {
            try {
              customization = JSON.parse(item.customization);
            } catch {
              customization = null;
            }
          }

        }

        return {
          id: item.id,
          product_id: item.product_id,
          product_name: item.product_name,
          product_image: item.product_image,
          quantity: item.quantity,
          price: Number(item.price),
          customization,
        };

      });

      const subtotal = processedItems.reduce(
        (sum, i) => sum + i.price * i.quantity, 0
      );

      const shipping = Number(order.shipping_charge || 50);
      const tax = Number(order.tax || 0);
      const discount = Number(order.discount || 0);

      const total =
        subtotal +
        shipping +
        tax -
        discount;

      /* Amount still to be collected on delivery:
         partial = remaining 50% balance, legacy COD = full total, online = 0. */
      const method = order.payment_method || "cod";

      const PARTIAL_PREPAID_PERCENT = 50;

      let payOnDelivery = 0;

      if (method === "partial") {

        const prepaid = Number(
          (total * PARTIAL_PREPAID_PERCENT / 100).toFixed(2)
        );

        payOnDelivery = Number(
          (total - prepaid).toFixed(2)
        );

      } else if (method === "cod") {

        payOnDelivery = total;

      }

      formattedOrders.push({

        id: order.id,

        order_number:
          `ORD-${order.created_at
            .toISOString()
            .slice(0, 10)
            .replace(/-/g, "")}-${order.id.slice(0, 8)}`,

        status: order.status,

        // ✅ FIXED: use real DB values
        payment_method: order.payment_method || "cod",

        payment_status: order.payment_status || "pending",

        subtotal,
        shipping,
        tax,
        discount,
        total,

        pay_on_delivery: payOnDelivery,

        shipping_address:
          JSON.parse(order.address || "{}"),

        created_at: order.created_at,

        order_items: processedItems,

      });

    }

    res.json(formattedOrders);

  }

  catch (err) {

    console.error("ORDERS ERROR:", err);

    res.status(500).json({
      message: "Failed to fetch orders"
    });

  }

});




// GET ORDER TRACKING
app.get("/api/orders/:id/tracking", auth, async (req, res) => {
  const [rows] = await db.query(
    "SELECT * FROM order_tracking WHERE order_id=? ORDER BY created_at ASC",
    [req.params.id]
  );
  res.json(rows);
});


// GET invoice HTML
// GET invoice HTML
// GET invoice HTML
app.get("/api/orders/:id/invoice", auth, async (req, res) => {
  const { id } = req.params;

  try {

    // ✅ GET ORDER
    const [[order]] = await db.query(
      "SELECT * FROM orders WHERE id=? AND user_id=?",
      [id, req.user.id]
    );

    if (!order)
      return res.status(404).send("Order not found");


    // ✅ GET ORDER ITEMS (LEFT JOIN FIXED)
    const [items] = await db.query(
      `SELECT 
        oi.quantity,
        oi.price,
        oi.customization,

        COALESCE(
          p.name,
          'Custom Product'
        ) AS product_name,

        COALESCE(
          p.image,
          JSON_UNQUOTE(JSON_EXTRACT(p.images,'$[0]')),
          '/placeholder.svg'
        ) AS product_image

       FROM order_items oi

       LEFT JOIN products p
       ON p.id = oi.product_id

       WHERE oi.order_id=?`,
      [id]
    );


    // ✅ SAFE ADDRESS PARSE
    let address = {};
    try {
      address = order.address ? JSON.parse(order.address) : {};
    } catch {
      address = {};
    }


    // ✅ SAFE CUSTOMIZATION PARSE
    const orderItems = items.map(item => {

      let customization = null;

      if (item.customization) {

        if (typeof item.customization === "object")
          customization = item.customization;

        else {
          try {
            customization = JSON.parse(item.customization);
          }
          catch {
            customization = null;
          }
        }
      }

      return {
        ...item,
        customization,
        price: Number(item.price),
        quantity: Number(item.quantity),
        product_name: item.product_name || "Custom Product"
      };
    });


    // ✅ CALCULATIONS
    const subtotal =
      orderItems.reduce(
        (sum, i) =>
          sum + i.price * i.quantity,
        0
      );

    const shipping =
      Number(order.shipping_charge || 50);

    const tax =
      Number(order.tax || (subtotal * 0.08));

    const discount =
      Number(order.discount || 0);

    const total =
      Number(order.final_amount ||
      subtotal + shipping + tax - discount);



    // ✅ COMPANY INFO
    const COMPANY = {
      name: "The Design Hive Pvt. Ltd.",
      gst: "07ABCDE1234F1Z5",
      address: "A-102, Sector 63, Noida, Uttar Pradesh 201301",
      email: "support@thedesignhive.in",
      phone: "+91 98765 43210",
      website: "www.thedesignhive.in"
    };


    // ✅ PAYMENT TEXT (ONLY ADDITION)
    const paymentText =
      order.payment_method === "online"
        ? order.payment_status === "paid"
          ? "Paid Online (Razorpay)"
          : "Online Payment (Pending)"
        : order.payment_method === "partial"
          ? "50% Paid Online (Razorpay), 50% Cash on Delivery"
          : "Cash on Delivery";


    const paymentIdHtml =
      (order.payment_method === "online" ||
       order.payment_method === "partial") &&
      order.payment_id
        ? `<p><strong>Payment ID:</strong> ${order.payment_id}</p>`
        : "";


    // ✅ HTML (UI SAME)
    const html = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Invoice #${id.slice(-8).toUpperCase()}</title>

<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">

<style>

*{
margin:0;
padding:0;
box-sizing:border-box;
}

body{
font-family:'Inter',sans-serif;
background:linear-gradient(135deg,#1e3a8a,#3b82f6);
padding:1rem;
}

.invoice-wrapper{
max-width:1000px;
margin:auto;
background:white;
border-radius:20px;
overflow:hidden;
}

.header{
background:linear-gradient(135deg,#1e40af,#3b82f6);
color:white;
padding:2.5rem;
}

.main-content{
padding:3rem;
}

.section-title{
font-size:1.4rem;
font-weight:700;
margin-bottom:1rem;
}

.items-table-wrapper table{
width:100%;
border-collapse:collapse;
}

th,td{
padding:1rem;
border-bottom:1px solid #eee;
}

.summary-card{
padding:1.5rem;
background:#fef3c7;
border-radius:12px;
margin-top:2rem;
}

.summary-row{
display:flex;
justify-content:space-between;
margin-bottom:.5rem;
}

.summary-row.total{
font-weight:700;
font-size:1.4rem;
margin-top:1rem;
}

.status-badge{
display:inline-flex;
align-items:center;
gap:.5rem;
padding:.4rem .8rem;
border-radius:20px;
background:white;
color:black;
font-weight:600;
}

</style>

</head>

<body>

<div class="invoice-wrapper">

<div class="header">

<h2>${COMPANY.name}</h2>

<p>GST: ${COMPANY.gst}</p>

<p>${COMPANY.address}</p>

<p>${COMPANY.email}</p>

</div>


<div class="main-content">

<div style="display:flex;justify-content:space-between">

<div>

<h3 class="section-title">Bill To</h3>

<p><strong>${address.full_name || "Customer"}</strong></p>

<p>${address.address_line1 || ""}</p>

<p>${address.city || ""}</p>

<p>${address.phone || ""}</p>

</div>


<div>

<h3 class="section-title">Order Info</h3>

<p>Order ID: ${order.id.slice(0,8)}</p>

<p>Date: ${new Date(order.created_at).toLocaleDateString("en-IN")}</p>

<p>
Status:
<span class="status-badge">
${order.status.toUpperCase()}
</span>
</p>


<!-- ✅ ONLY PAYMENT ADDED -->
<p><strong>Payment:</strong> ${paymentText}</p>

${paymentIdHtml}

</div>

</div>



<h3 class="section-title">
Order Items (${orderItems.length})
</h3>

<div class="items-table-wrapper">

<table>

<thead>

<tr>

<th>Description</th>

<th>Qty</th>

<th>Price</th>

<th>Total</th>

</tr>

</thead>

<tbody>

${orderItems.map(i=>`

<tr>

<td>

${i.product_name}

${i.customization?.text ?
`<div style="color:#10b981">
✏️ ${i.customization.text}
</div>`
:""}

</td>

<td>${i.quantity}</td>

<td>₹${i.price}</td>

<td>₹${i.quantity*i.price}</td>

</tr>

`).join("")}

</tbody>

</table>

</div>



<div class="summary-card">

<div class="summary-row">
<span>Subtotal</span>
<span>₹${subtotal}</span>
</div>

<div class="summary-row">
<span>Shipping</span>
<span>₹${shipping}</span>
</div>

<div class="summary-row">
<span>Tax</span>
<span>₹${tax}</span>
</div>

${discount>0?
`<div class="summary-row">
<span>Discount</span>
<span>-₹${discount}</span>
</div>`:""}


<div class="summary-row total">

<span>Total</span>

<span>₹${total}</span>

</div>

</div>


</div>

</div>

</body>

</html>
`;



    res.setHeader(
      "Content-Type",
      "text/html"
    );

    res.send(html);

  }
  catch (err) {

    console.error(err);

    res.status(500).send(
      "Failed to generate invoice"
    );

  }

});


/* ========================================================= */
app.get('/api/products/:id/reviews', async (req, res) => {
  const [rows] = await db.query(
    `
    SELECT 
      r.id,
      r.rating,
      r.comment,
      r.helpful_count,
      r.created_at,
      u.name AS user_name
    FROM reviews r
    LEFT JOIN users u ON u.id = r.user_id
    WHERE r.product_id = ?
    ORDER BY r.created_at DESC
    `,
    [req.params.id]
  );

  res.json(rows);
});
app.post('/api/products/:id/reviews', auth, async (req, res) => {
  const { rating, comment } = req.body;

  const [[existing]] = await db.query(
    'SELECT id FROM reviews WHERE product_id=? AND user_id=?',
    [req.params.id, req.user.id]
  );

  if (existing) {
    return res.status(400).json({ message: 'You already reviewed this product' });
  }

  await db.query(
    `
    INSERT INTO reviews (id, user_id, product_id, rating, comment)
    VALUES (UUID(), ?, ?, ?, ?)
    `,
    [req.user.id, req.params.id, rating, comment]
  );

  res.json({ message: 'Review added' });
});
app.patch('/api/reviews/:id/helpful', async (req, res) => {
  await db.query(
    'UPDATE reviews SET helpful_count = helpful_count + 1 WHERE id=?',
    [req.params.id]
  );
  res.json({ message: 'Marked helpful' });
});

/* ========================================================= */

// ✅ OTP Routes
registerOtpRoutes(app, { db });


/* ========================================================= */

/* =========================================================
   SECURE ADDRESS ROUTES (PRODUCTION SAFE)
========================================================= */


/* ===============================
   GET ALL USER ADDRESSES
=================================*/
app.get("/api/addresses", auth, async (req, res) => {
  try {
    const userId = req.user.id;

    const [addresses] = await db.query(
      `SELECT * FROM addresses 
       WHERE user_id = ? 
       ORDER BY is_default DESC, created_at DESC`,
      [userId]
    );

    res.json(addresses);
  } catch (err) {
    console.error("Fetch addresses error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* ===============================
   CREATE ADDRESS
=================================*/
app.post("/api/addresses", auth, async (req, res) => {
  try {
    const {
      full_name,
      phone,
      address_line1,
      address_line2,
      city,
      state,
      pincode
    } = req.body;

    const userId = req.user.id;

    if (!full_name || !phone || !address_line1 || !city || !state || !pincode) {
      return res.status(400).json({ message: "All required fields missing" });
    }

    const [[existingCount]] = await db.query(
      `SELECT COUNT(*) as count 
       FROM addresses 
       WHERE user_id = ?`,
      [userId]
    );

    const isFirst = existingCount.count === 0;

    await db.query(
      `INSERT INTO addresses 
       (id, full_name, phone, address_line1, address_line2, city, state, pincode, user_id, is_default, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        uuidv4(),
        full_name.trim(),
        phone.trim(),
        address_line1.trim(),
        address_line2?.trim() || null,
        city.trim(),
        state.trim(),
        pincode.trim(),
        userId,
        isFirst ? 1 : 0
      ]
    );

    res.json({ success: true, message: "Address created successfully" });

  } catch (err) {
    console.error("Create address error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* ===============================
   UPDATE ADDRESS
=================================*/
app.put("/api/addresses/:id", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    const {
      full_name,
      phone,
      address_line1,
      address_line2,
      city,
      state,
      pincode
    } = req.body;

    const [result] = await db.query(
      `UPDATE addresses 
       SET full_name = ?, phone = ?, address_line1 = ?, address_line2 = ?, 
           city = ?, state = ?, pincode = ?, updated_at = NOW()
       WHERE id = ? AND user_id = ?`,
      [
        full_name?.trim(),
        phone?.trim(),
        address_line1?.trim(),
        address_line2?.trim() || null,
        city?.trim(),
        state?.trim(),
        pincode?.trim(),
        id,
        userId
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Address not found" });
    }

    res.json({ success: true, message: "Address updated successfully" });

  } catch (err) {
    console.error("Update address error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* ===============================
   DELETE ADDRESS
=================================*/
app.delete("/api/addresses/:id", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    const [result] = await db.query(
      `DELETE FROM addresses 
       WHERE id = ? AND user_id = ?`,
      [id, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Address not found" });
    }

    res.json({ success: true, message: "Address deleted successfully" });

  } catch (err) {
    console.error("Delete address error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* ===============================
   SET DEFAULT ADDRESS
=================================*/
app.patch("/api/addresses/:id/default", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { id } = req.params;

    // Remove old default
    await db.query(
      `UPDATE addresses 
       SET is_default = 0 
       WHERE user_id = ?`,
      [userId]
    );

    // Set new default
    const [result] = await db.query(
      `UPDATE addresses 
       SET is_default = 1 
       WHERE id = ? AND user_id = ?`,
      [id, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Address not found" });
    }

    res.json({ success: true, message: "Default address updated" });

  } catch (err) {
    console.error("Set default error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/auth/profile", auth, async (req, res) => {
  try {
    const { name, phone } = req.body;

    await db.query(
      "UPDATE users SET name = ?, phone = ? WHERE id = ?",
      [name, phone, req.user.id]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* ========================================================= */

app.get("/api/brands", async (req, res) => {
  const [brands] = await db.query("SELECT * FROM phone_brands ORDER BY name");
  res.json(brands);
});

app.get("/api/models/:brandId", async (req, res) => {
  const { brandId } = req.params;

  const [models] = await db.query(
    "SELECT * FROM phone_models WHERE brand_id = ? ORDER BY name",
    [brandId]
  );

  res.json(models);
});

app.get("/api/cover-types/:modelId", async (req, res) => {
  const { modelId } = req.params;

  const [covers] = await db.query(
    `SELECT c.*
     FROM cover_types c
     JOIN model_cover_types mct ON c.id = mct.cover_type_id
     WHERE mct.model_id = ?`,
    [modelId]
  );

  res.json(covers);
});

/* ========================================================= */

orderNotifications.start();

app.listen(process.env.PORT, () =>
  console.log("Server running on port " + process.env.PORT)
);
