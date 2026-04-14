require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

// ─── SECURITY MIDDLEWARE ──────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 60 * 1000, max: 10,
  message: { error: "Too many requests. Please wait a moment." },
});
app.use("/api/auth", limiter);

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const pool = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 10,
});

// ─── SECURITY UTILS ───────────────────────────────────────────────────────────
const SQL_PATTERNS = [
  /('|--|;|\/\*|\*\/|xp_|exec\s|union\s+select|drop\s+table|insert\s+into|delete\s+from)/i,
  /(or\s+1=1|and\s+1=1|'\s*or\s*'|admin'--|1'\s*or\s*'1'='1)/i,
];
const hasSQLInjection = (str) => typeof str === "string" && SQL_PATTERNS.some((p) => p.test(str));

const sanitize = (str) => {
  if (typeof str !== "string") return str;
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;").trim();
};

const validateInput = (req, res, next) => {
  const inputs = { ...req.body, ...req.params, ...req.query };
  for (const [key, value] of Object.entries(inputs)) {
    if (typeof value === "string" && hasSQLInjection(value))
      return res.status(400).json({ error: `SQL Injection attempt detected in: ${key}` });
  }
  next();
};

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized. No token provided." });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid or expired token." }); }
};

const adminOnly = (req, res, next) => {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admins only." });
  next();
};

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.post("/api/auth/register", validateInput, async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Name, email, and password required." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Invalid email." });
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password))
      return res.status(400).json({ error: "Password must be 8+ chars, 1 uppercase, 1 number." });
    const [existing] = await pool.query("SELECT id FROM users WHERE email = ?", [sanitize(email)]);
    if (existing.length > 0) return res.status(409).json({ error: "Email already registered." });
    const hashed = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)",
      [sanitize(name), sanitize(email).toLowerCase(), hashed, sanitize(phone || "")]
    );
    const token = jwt.sign({ id: result.insertId, email, role: "customer" }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.status(201).json({ token, user: { id: result.insertId, name: sanitize(name), email, role: "customer" } });
  } catch (err) { res.status(500).json({ error: "Server error during registration." }); }
});

app.post("/api/auth/login", validateInput, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required." });
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [sanitize(email).toLowerCase()]);
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials." });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials." });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) { res.status(500).json({ error: "Server error during login." }); }
});

// ─── PRODUCTS CRUD ────────────────────────────────────────────────────────────

// READ all
app.get("/api/products", validateInput, async (req, res) => {
  try {
    const { search, category } = req.query;
    let query = "SELECT * FROM products WHERE 1=1";
    const params = [];
    if (search) { query += " AND (name LIKE ? OR brand LIKE ?)"; params.push(`%${sanitize(search)}%`, `%${sanitize(search)}%`); }
    if (category && category !== "All") { query += " AND category = ?"; params.push(sanitize(category)); }
    const [products] = await pool.query(query, params);
    res.json(products);
  } catch (err) { res.status(500).json({ error: "Failed to fetch products." }); }
});

// READ one
app.get("/api/products/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM products WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Product not found." });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: "Failed to fetch product." }); }
});

// CREATE
app.post("/api/products", authenticate, adminOnly, validateInput, async (req, res) => {
  try {
    const { name, brand, price, category, stock, image, color } = req.body;
    if (!name || !price) return res.status(400).json({ error: "Name and price are required." });
    const [result] = await pool.query(
      "INSERT INTO products (name, brand, price, category, stock, image, color) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [sanitize(name), sanitize(brand || ""), parseFloat(price), sanitize(category || ""), parseInt(stock || 0), sanitize(image || "👟"), sanitize(color || "#000000")]
    );
    res.status(201).json({ message: "Product created.", id: result.insertId });
  } catch (err) { res.status(500).json({ error: "Failed to create product." }); }
});

// UPDATE
app.put("/api/products/:id", authenticate, adminOnly, validateInput, async (req, res) => {
  try {
    const { name, brand, price, category, stock, image, color } = req.body;
    await pool.query(
      "UPDATE products SET name=?, brand=?, price=?, category=?, stock=?, image=?, color=? WHERE id=?",
      [sanitize(name), sanitize(brand), parseFloat(price), sanitize(category), parseInt(stock), sanitize(image), sanitize(color), req.params.id]
    );
    res.json({ message: "Product updated." });
  } catch (err) { res.status(500).json({ error: "Failed to update product." }); }
});

// UPDATE stock only
app.put("/api/products/:id/stock", authenticate, adminOnly, validateInput, async (req, res) => {
  try {
    const { stock } = req.body;
    if (isNaN(stock) || stock < 0) return res.status(400).json({ error: "Invalid stock value." });
    await pool.query("UPDATE products SET stock = ? WHERE id = ?", [parseInt(stock), req.params.id]);
    res.json({ message: "Stock updated." });
  } catch (err) { res.status(500).json({ error: "Failed to update stock." }); }
});

// DELETE
app.delete("/api/products/:id", authenticate, adminOnly, async (req, res) => {
  try {
    await pool.query("DELETE FROM products WHERE id = ?", [req.params.id]);
    res.json({ message: "Product deleted." });
  } catch (err) { res.status(500).json({ error: "Failed to delete product." }); }
});

// ─── USERS CRUD ───────────────────────────────────────────────────────────────

// READ all users
app.get("/api/admin/users", authenticate, adminOnly, async (req, res) => {
  try {
    const [users] = await pool.query("SELECT id, name, email, phone, role, created_at FROM users ORDER BY created_at DESC");
    res.json(users);
  } catch (err) { res.status(500).json({ error: "Failed to fetch users." }); }
});

// READ one user
app.get("/api/admin/users/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT id, name, email, phone, role, created_at FROM users WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found." });
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: "Failed to fetch user." }); }
});

// CREATE user (admin)
app.post("/api/admin/users", authenticate, adminOnly, validateInput, async (req, res) => {
  try {
    const { name, email, password, phone, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Name, email, password required." });
    const [existing] = await pool.query("SELECT id FROM users WHERE email = ?", [sanitize(email)]);
    if (existing.length > 0) return res.status(409).json({ error: "Email already registered." });
    const hashed = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password, phone, role) VALUES (?, ?, ?, ?, ?)",
      [sanitize(name), sanitize(email).toLowerCase(), hashed, sanitize(phone || ""), role === "admin" ? "admin" : "customer"]
    );
    res.status(201).json({ message: "User created.", id: result.insertId });
  } catch (err) { res.status(500).json({ error: "Failed to create user." }); }
});

// UPDATE user
app.put("/api/admin/users/:id", authenticate, adminOnly, validateInput, async (req, res) => {
  try {
    const { name, email, phone, role } = req.body;
    await pool.query(
      "UPDATE users SET name=?, email=?, phone=?, role=? WHERE id=?",
      [sanitize(name), sanitize(email).toLowerCase(), sanitize(phone || ""), role === "admin" ? "admin" : "customer", req.params.id]
    );
    res.json({ message: "User updated." });
  } catch (err) { res.status(500).json({ error: "Failed to update user." }); }
});

// DELETE user
app.delete("/api/admin/users/:id", authenticate, adminOnly, async (req, res) => {
  try {
    if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: "Cannot delete your own account." });
    await pool.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "User deleted." });
  } catch (err) { res.status(500).json({ error: "Failed to delete user." }); }
});

// ─── ORDERS CRUD ──────────────────────────────────────────────────────────────

// READ all orders
app.get("/api/orders", authenticate, async (req, res) => {
  try {
    let query, params;
    if (req.user.role === "admin") {
      query = "SELECT o.*, u.name as customer_name, u.email FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC";
      params = [];
    } else {
      query = "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC";
      params = [req.user.id];
    }
    const [orders] = await pool.query(query, params);
    res.json(orders);
  } catch (err) { res.status(500).json({ error: "Failed to fetch orders." }); }
});

// READ one order
app.get("/api/orders/:id", authenticate, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM orders WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Order not found." });
    if (req.user.role !== "admin" && rows[0].user_id !== req.user.id)
      return res.status(403).json({ error: "Access denied." });
    const [items] = await pool.query(
      "SELECT oi.*, p.name, p.image FROM order_items oi JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
      [req.params.id]
    );
    res.json({ ...rows[0], items });
  } catch (err) { res.status(500).json({ error: "Failed to fetch order." }); }
});

// CREATE order
app.post("/api/orders", authenticate, validateInput, async (req, res) => {
  try {
    const { items, shipping_address, total } = req.body;
    if (!items || items.length === 0) return res.status(400).json({ error: "Order must have at least one item." });
    const [order] = await pool.query(
      "INSERT INTO orders (user_id, total, shipping_address) VALUES (?, ?, ?)",
      [req.user.id, total, sanitize(shipping_address)]
    );
    for (const item of items) {
      await pool.query(
        "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
        [order.insertId, item.id, item.qty, item.price]
      );
      await pool.query("UPDATE products SET stock = stock - ? WHERE id = ?", [item.qty, item.id]);
    }
    res.status(201).json({ message: "Order placed.", orderId: order.insertId });
  } catch (err) { res.status(500).json({ error: "Failed to place order." }); }
});

// UPDATE order status
app.put("/api/orders/:id", authenticate, adminOnly, validateInput, async (req, res) => {
  try {
    const { status } = req.body;
    const validStatuses = ["pending", "processing", "shipped", "delivered"];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: "Invalid status." });
    await pool.query("UPDATE orders SET status = ? WHERE id = ?", [status, req.params.id]);
    res.json({ message: "Order status updated." });
  } catch (err) { res.status(500).json({ error: "Failed to update order." }); }
});

// DELETE order
app.delete("/api/orders/:id", authenticate, adminOnly, async (req, res) => {
  try {
    await pool.query("DELETE FROM order_items WHERE order_id = ?", [req.params.id]);
    await pool.query("DELETE FROM orders WHERE id = ?", [req.params.id]);
    res.json({ message: "Order deleted." });
  } catch (err) { res.status(500).json({ error: "Failed to delete order." }); }
});

// ─── ADMIN STATS ──────────────────────────────────────────────────────────────

app.get("/api/admin/stats", authenticate, adminOnly, async (req, res) => {
  try {
    const [[{ totalUsers }]] = await pool.query("SELECT COUNT(*) as totalUsers FROM users WHERE role = 'customer'");
    const [[{ totalOrders }]] = await pool.query("SELECT COUNT(*) as totalOrders FROM orders");
    const [[{ totalRevenue }]] = await pool.query("SELECT COALESCE(SUM(total), 0) as totalRevenue FROM orders");
    const [[{ totalProducts }]] = await pool.query("SELECT COUNT(*) as totalProducts FROM products");
    res.json({ totalUsers, totalOrders, totalRevenue, totalProducts });
  } catch (err) { res.status(500).json({ error: "Failed to fetch stats." }); }
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Sole Spectrum backend running on http://localhost:${PORT}`);
  console.log(`🛡  Security: Helmet, Rate Limiting, JWT, BCrypt, SQLi Protection active`);
  console.log(`📦 CRUD: Products, Users, Orders — all endpoints ready`);
});