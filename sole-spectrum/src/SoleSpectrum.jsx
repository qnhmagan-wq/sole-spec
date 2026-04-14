import { useState, useEffect, useRef } from "react";

const API = "http://localhost:5000/api";

// ─── SECURITY UTILITIES ───────────────────────────────────────────────────────

const sanitizeInput = (str) => {
  if (typeof str !== "string") return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "")
    .replace(/on\w+="[^"]*"/gi, "")
    .trim();
};

const SQL_PATTERNS = [
  /('|--|;|\/\*|\*\/|xp_|exec\s|union\s+select|drop\s+table|insert\s+into|delete\s+from)/i,
  /(or\s+1=1|and\s+1=1|'\s*or\s*'|admin'--|1'\s*or\s*'1'='1)/i,
];
const hasSQLInjection = (str) => SQL_PATTERNS.some((p) => p.test(str));

const generateCSRFToken = () => {
  const arr = new Uint8Array(24);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
};

const validators = {
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
  password: (v) => v.length >= 8 && /[A-Z]/.test(v) && /[0-9]/.test(v),
  name: (v) => /^[a-zA-Z\s'-]{2,50}$/.test(v),
  phone: (v) => /^[\d\s\-+()]{7,20}$/.test(v),
  address: (v) => v.trim().length >= 5 && v.trim().length <= 200,
  cardNumber: (v) => /^\d{4}\s?\d{4}\s?\d{4}\s?\d{4}$/.test(v.replace(/\s/g, "")),
  cvv: (v) => /^\d{3,4}$/.test(v),
  expiry: (v) => /^(0[1-9]|1[0-2])\/\d{2}$/.test(v),
};

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 30000;

// ─── STYLES ───────────────────────────────────────────────────────────────────

const css = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=Inter:wght@300;400;500;600&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #fafaf8; --surface: #ffffff; --dark: #0f0f0f; --gray: #6b7280;
    --light: #f3f3f0; --border: #e5e5e0; --accent: #0f0f0f; --red: #dc2626;
    --green: #16a34a; --orange: #ea580c; --blue: #2563eb;
    --font-head: 'Syne', sans-serif; --font-body: 'Inter', sans-serif;
    --shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.04);
    --shadow-lg: 0 10px 40px rgba(0,0,0,0.12);
  }
  body { background: var(--bg); color: var(--dark); font-family: var(--font-body); }
  .nav {
    position: sticky; top: 0; z-index: 100;
    background: rgba(250,250,248,0.95); backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border); padding: 0 24px;
    display: flex; align-items: center; justify-content: space-between; height: 64px;
  }
  .nav-logo { font-family: var(--font-head); font-size: 20px; font-weight: 800; letter-spacing: -0.5px; cursor: pointer; }
  .nav-logo span { color: var(--orange); }
  .nav-links { display: flex; gap: 4px; }
  .nav-link {
    font-size: 13px; font-weight: 500; padding: 8px 14px; cursor: pointer;
    border-radius: 8px; transition: all 0.15s; color: var(--gray); background: none; border: none;
  }
  .nav-link:hover { background: var(--light); color: var(--dark); }
  .nav-link.active { background: var(--dark); color: white; }
  .nav-right { display: flex; align-items: center; gap: 12px; }
  .cart-btn {
    position: relative; background: var(--dark); color: white; border: none;
    padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600;
    cursor: pointer; display: flex; align-items: center; gap: 6px; font-family: var(--font-body);
  }
  .cart-badge {
    background: var(--orange); color: white; border-radius: 50%;
    width: 18px; height: 18px; font-size: 10px; font-weight: 700;
    display: flex; align-items: center; justify-content: center;
  }
  .user-chip { font-size: 12px; font-weight: 500; color: var(--gray); padding: 6px 12px; background: var(--light); border-radius: 20px; }
  .page { max-width: 1100px; margin: 0 auto; padding: 40px 24px; }
  .auth-wrap {
    min-height: calc(100vh - 64px); display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, #fafaf8 0%, #f0ede8 100%);
  }
  .auth-card {
    background: white; border-radius: 16px; padding: 40px;
    width: 100%; max-width: 420px; box-shadow: var(--shadow-lg); border: 1px solid var(--border);
  }
  .auth-title { font-family: var(--font-head); font-size: 28px; font-weight: 800; margin-bottom: 4px; }
  .auth-sub { font-size: 13px; color: var(--gray); margin-bottom: 28px; }
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 12px; font-weight: 600; color: var(--gray); letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 6px; }
  .field input, .field select {
    width: 100%; padding: 11px 14px; border: 1.5px solid var(--border);
    border-radius: 8px; font-size: 14px; font-family: var(--font-body);
    outline: none; transition: border-color 0.15s, box-shadow 0.15s; background: var(--bg);
  }
  .field input:focus, .field select:focus { border-color: var(--dark); box-shadow: 0 0 0 3px rgba(15,15,15,0.06); }
  .field input.error, .field select.error { border-color: var(--red); }
  .field input.ok { border-color: var(--green); }
  .field-err { font-size: 11px; color: var(--red); margin-top: 4px; font-weight: 500; }
  .field-ok { font-size: 11px; color: var(--green); margin-top: 4px; font-weight: 500; }
  .btn {
    font-family: var(--font-body); font-weight: 600; font-size: 14px;
    padding: 11px 20px; border-radius: 8px; cursor: pointer; border: none;
    transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-primary { background: var(--dark); color: white; width: 100%; justify-content: center; }
  .btn-primary:hover:not(:disabled) { background: #333; transform: translateY(-1px); }
  .btn-primary:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-outline { background: transparent; border: 1.5px solid var(--border); color: var(--dark); }
  .btn-outline:hover { border-color: var(--dark); }
  .btn-danger { background: transparent; border: 1.5px solid var(--red); color: var(--red); }
  .btn-danger:hover { background: #fef2f2; }
  .btn-success { background: var(--green); color: white; border: none; }
  .btn-success:hover { background: #15803d; }
  .btn-sm { padding: 7px 14px; font-size: 12px; }
  .alert { padding: 12px 16px; border-radius: 8px; font-size: 13px; font-weight: 500; margin-bottom: 16px; display: flex; align-items: flex-start; gap: 8px; }
  .alert-red { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }
  .alert-green { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
  .alert-orange { background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; }
  .alert-blue { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
  .sec-panel { background: #f8faff; border: 1px solid #bfdbfe; border-radius: 10px; padding: 14px 16px; margin-bottom: 20px; }
  .sec-panel-title { font-size: 11px; font-weight: 700; color: #1d4ed8; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }
  .sec-tags { display: flex; flex-wrap: wrap; gap: 6px; }
  .sec-tag { font-size: 10px; font-weight: 600; padding: 3px 8px; border-radius: 20px; letter-spacing: 0.3px; }
  .sec-tag.active { background: #dcfce7; color: #15803d; }
  .sec-tag.blocked { background: #fee2e2; color: #b91c1c; }
  .sec-tag.info { background: #eff6ff; color: #1d4ed8; }
  .section-title { font-family: var(--font-head); font-size: 32px; font-weight: 800; margin-bottom: 4px; letter-spacing: -0.5px; }
  .section-sub { font-size: 14px; color: var(--gray); margin-bottom: 32px; }
  .product-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 20px; }
  .product-card { background: white; border-radius: 12px; border: 1px solid var(--border); overflow: hidden; transition: all 0.2s; cursor: pointer; }
  .product-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-lg); }
  .product-img { height: 160px; display: flex; align-items: center; justify-content: center; font-size: 72px; }
  .product-body { padding: 16px; }
  .product-brand { font-size: 11px; font-weight: 600; color: var(--gray); letter-spacing: 1px; text-transform: uppercase; }
  .product-name { font-family: var(--font-head); font-size: 18px; font-weight: 700; margin: 4px 0; }
  .product-cat { font-size: 12px; color: var(--gray); margin-bottom: 12px; }
  .product-footer { display: flex; align-items: center; justify-content: space-between; }
  .product-price { font-size: 18px; font-weight: 700; }
  .product-stock { font-size: 11px; font-weight: 600; }
  .stock-ok { color: var(--green); } .stock-low { color: var(--orange); } .stock-out { color: var(--red); }
  .add-btn { background: var(--dark); color: white; border: none; border-radius: 8px; padding: 8px 14px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s; font-family: var(--font-body); }
  .add-btn:hover { background: #333; }
  .add-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .cart-item { display: flex; align-items: center; gap: 16px; padding: 16px; background: white; border-radius: 10px; border: 1px solid var(--border); margin-bottom: 12px; }
  .cart-item-icon { font-size: 40px; }
  .cart-item-info { flex: 1; }
  .cart-item-name { font-weight: 600; font-size: 15px; }
  .cart-item-brand { font-size: 12px; color: var(--gray); }
  .qty-ctrl { display: flex; align-items: center; gap: 8px; }
  .qty-btn { width: 28px; height: 28px; border: 1.5px solid var(--border); background: white; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; display: flex; align-items: center; justify-content: center; }
  .qty-btn:hover { border-color: var(--dark); }
  .cart-summary { background: white; border-radius: 12px; border: 1px solid var(--border); padding: 24px; margin-top: 24px; }
  .summary-row { display: flex; justify-content: space-between; font-size: 14px; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .summary-total { display: flex; justify-content: space-between; font-size: 18px; font-weight: 700; padding-top: 12px; }
  .checkout-grid { display: grid; grid-template-columns: 1fr 360px; gap: 32px; }
  @media(max-width: 768px) { .checkout-grid { grid-template-columns: 1fr; } }
  .checkout-section { background: white; border-radius: 12px; border: 1px solid var(--border); padding: 24px; margin-bottom: 20px; }
  .checkout-section h3 { font-family: var(--font-head); font-size: 18px; font-weight: 700; margin-bottom: 16px; }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .admin-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; }
  .admin-tabs { display: flex; gap: 4px; margin-bottom: 24px; background: var(--light); padding: 4px; border-radius: 10px; width: fit-content; }
  .admin-tab { font-size: 13px; font-weight: 600; padding: 8px 18px; border-radius: 7px; border: none; cursor: pointer; background: none; color: var(--gray); font-family: var(--font-body); transition: all 0.15s; }
  .admin-tab.active { background: white; color: var(--dark); box-shadow: var(--shadow); }
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  @media(max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
  .stat-card { background: white; border-radius: 12px; border: 1px solid var(--border); padding: 20px; }
  .stat-label { font-size: 12px; font-weight: 600; color: var(--gray); letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 6px; }
  .stat-value { font-family: var(--font-head); font-size: 28px; font-weight: 800; }
  .stat-sub { font-size: 12px; color: var(--gray); margin-top: 2px; }
  .table-wrap { background: white; border-radius: 12px; border: 1px solid var(--border); overflow: hidden; margin-bottom: 24px; }
  .table-head { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
  .table-head h3 { font-family: var(--font-head); font-size: 17px; font-weight: 700; }
  table { width: 100%; border-collapse: collapse; }
  th { background: var(--light); padding: 11px 16px; text-align: left; font-size: 11px; font-weight: 700; color: var(--gray); letter-spacing: 0.5px; text-transform: uppercase; }
  td { padding: 12px 16px; font-size: 14px; border-top: 1px solid var(--border); }
  tr:hover td { background: var(--bg); }
  .badge { padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
  .badge-green { background: #dcfce7; color: #15803d; }
  .badge-orange { background: #fff7ed; color: #c2410c; }
  .badge-red { background: #fee2e2; color: #b91c1c; }
  .badge-blue { background: #eff6ff; color: #1d4ed8; }
  .badge-purple { background: #f3e8ff; color: #7c3aed; }
  .divider { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
  .text-link { color: var(--blue); cursor: pointer; font-weight: 500; font-size: 13px; }
  .text-link:hover { text-decoration: underline; }
  .empty-state { text-align: center; padding: 80px 20px; color: var(--gray); }
  .empty-state .icon { font-size: 56px; margin-bottom: 16px; }
  .empty-state h3 { font-family: var(--font-head); font-size: 22px; font-weight: 700; color: var(--dark); margin-bottom: 8px; }
  .lockout-timer { font-size: 24px; font-weight: 800; font-family: var(--font-head); color: var(--red); }
  .progress-bar-wrap { background: var(--light); border-radius: 4px; height: 4px; margin-top: 8px; overflow: hidden; }
  .progress-bar-fill { height: 100%; background: var(--red); transition: width 1s linear; }
  .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.3); border-top-color: white; border-radius: 50%; animation: spin 0.6s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 200; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .modal { background: white; border-radius: 16px; padding: 32px; width: 100%; max-width: 480px; box-shadow: var(--shadow-lg); max-height: 90vh; overflow-y: auto; }
  .modal-title { font-family: var(--font-head); font-size: 22px; font-weight: 800; margin-bottom: 20px; }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 24px; }
  .confirm-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 300; display: flex; align-items: center; justify-content: center; }
  .confirm-box { background: white; border-radius: 12px; padding: 28px; max-width: 380px; width: 90%; box-shadow: var(--shadow-lg); text-align: center; }
  .confirm-icon { font-size: 40px; margin-bottom: 12px; }
  .confirm-title { font-family: var(--font-head); font-size: 18px; font-weight: 700; margin-bottom: 8px; }
  .confirm-msg { font-size: 14px; color: var(--gray); margin-bottom: 20px; }
  .confirm-btns { display: flex; gap: 10px; justify-content: center; }
  .otp-wrap { display: flex; gap: 10px; justify-content: center; margin: 20px 0; }
  .otp-input { width: 52px; height: 60px; text-align: center; font-size: 24px; font-weight: 800; border: 2px solid var(--border); border-radius: 10px; font-family: var(--font-head); outline: none; transition: border-color 0.15s; background: var(--bg); }
  .otp-input:focus { border-color: var(--dark); }
  .otp-input.filled { border-color: var(--green); }
  .inactivity-banner { position: fixed; bottom: 0; left: 0; right: 0; z-index: 500; background: #fff7ed; border-top: 2px solid var(--orange); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; font-size: 13px; font-weight: 600; color: #c2410c; }
`;

// ─── SHARED COMPONENTS ────────────────────────────────────────────────────────

function SecurityPanel({ defenses }) {
  return (
    <div className="sec-panel">
      <div className="sec-panel-title">🛡 Active Security Defenses</div>
      <div className="sec-tags">
        {defenses.map((d) => (
          <span key={d.label} className={`sec-tag ${d.type}`}>{d.icon} {d.label}</span>
        ))}
      </div>
    </div>
  );
}

function ConfirmDialog({ message, onConfirm, onCancel }) {
  return (
    <div className="confirm-overlay">
      <div className="confirm-box">
        <div className="confirm-icon">⚠️</div>
        <div className="confirm-title">Are you sure?</div>
        <div className="confirm-msg">{message}</div>
        <div className="confirm-btns">
          <button className="btn btn-outline btn-sm" onClick={onCancel}>Cancel</button>
          <button className="btn btn-danger btn-sm" onClick={onConfirm}>Delete</button>
        </div>
      </div>
    </div>
  );
}

// ─── MFA OTP PAGE ─────────────────────────────────────────────────────────────

function MFAPage({ onVerify, onCancel, generatedOTP }) {
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const inputRefs = useRef([]);

  const handleChange = (i, val) => {
    if (!/^\d?$/.test(val)) return;
    const next = [...otp]; next[i] = val; setOtp(next);
    if (val && i < 5) inputRefs.current[i + 1]?.focus();
  };
  const handleKeyDown = (i, e) => { if (e.key === "Backspace" && !otp[i] && i > 0) inputRefs.current[i - 1]?.focus(); };
  const handleVerify = () => {
    const entered = otp.join("");
    if (entered.length < 6) { setError("Please enter the complete 6-digit code."); return; }
    setLoading(true);
    setTimeout(() => {
      if (entered === generatedOTP) { onVerify(); }
      else { setError("Invalid OTP. Please try again."); setLoading(false); }
    }, 800);
  };

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ fontSize: 48, marginBottom: 12 }}>🔐</div>
          <div className="auth-title">Two-Factor Auth</div>
          <div className="auth-sub">Enter the 6-digit code to verify your identity.</div>
        </div>
        <div className="sec-panel">
          <div className="sec-panel-title">🛡 MFA Active</div>
          <div className="sec-tags">
            <span className="sec-tag active">✓ Multi-Factor Authentication</span>
            <span className="sec-tag active">✓ One-Time Password</span>
            <span className="sec-tag active">✓ Session Protection</span>
          </div>
        </div>
        <div style={{ background: "var(--light)", borderRadius: 10, padding: "14px 16px", marginBottom: 20, textAlign: "center", border: "1px dashed var(--border)" }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "var(--gray)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>📱 Simulated OTP (sent via SMS/Email)</div>
          <div style={{ fontFamily: "monospace", fontSize: 28, fontWeight: 800, letterSpacing: 8, color: "var(--dark)" }}>{generatedOTP}</div>
        </div>
        {error && <div className="alert alert-red">⚠ {error}</div>}
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--gray)", textAlign: "center", marginBottom: 8 }}>Enter your OTP code:</div>
        <div className="otp-wrap">
          {otp.map((val, i) => (
            <input key={i} ref={el => inputRefs.current[i] = el}
              style={{ width: 52, height: 60, textAlign: "center", fontSize: 24, fontWeight: 800, border: `2px solid ${val ? "var(--green)" : "var(--border)"}`, borderRadius: 10, outline: "none", background: "var(--bg)", fontFamily: "var(--font-head)" }}
              type="text" maxLength={1} value={val}
              onChange={e => handleChange(i, e.target.value)}
              onKeyDown={e => handleKeyDown(i, e)} />
          ))}
        </div>
        <button className="btn btn-primary" onClick={handleVerify} disabled={loading} style={{ marginTop: 8 }}>
          {loading ? <span className="spinner" /> : "Verify & Sign In"}
        </button>
        <div style={{ textAlign: "center", marginTop: 12 }}>
          <span className="text-link" onClick={onCancel}>← Back to Login</span>
        </div>
      </div>
    </div>
  );
}

// ─── LOGIN PAGE ───────────────────────────────────────────────────────────────



function LoginPage({ onLogin, onGoRegister, csrfToken }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState({});
  const [attempts, setAttempts] = useState(0);
  const [lockout, setLockout] = useState(null);
  const [countdown, setCountdown] = useState(0);
  const [blocked, setBlocked] = useState([]);
  const [loading, setLoading] = useState(false);
  const [mfaStep, setMfaStep] = useState(false);
  const [generatedOTP, setGeneratedOTP] = useState("");
  const [pendingUser, setPendingUser] = useState(null);
  const timerRef = useRef();

  useEffect(() => {
    if (lockout) {
      timerRef.current = setInterval(() => {
        const remaining = Math.ceil((lockout - Date.now()) / 1000);
        if (remaining <= 0) { clearInterval(timerRef.current); setLockout(null); setAttempts(0); setCountdown(0); }
        else setCountdown(remaining);
      }, 500);
    }
    return () => clearInterval(timerRef.current);
  }, [lockout]);

  const validate = () => {
    const errs = {};
    const blockedThreats = [];
    const cleanEmail = sanitizeInput(email);
    if (email !== cleanEmail) blockedThreats.push("XSS attempt in email");
    if (hasSQLInjection(email)) { errs.email = "⛔ SQL Injection detected"; blockedThreats.push("SQL Injection in email"); }
    if (hasSQLInjection(password)) { errs.password = "⛔ SQL Injection detected"; blockedThreats.push("SQL Injection in password"); }
    if (!validators.email(cleanEmail)) errs.email = errs.email || "Enter a valid email address";
    if (!password || password.length < 1) errs.password = errs.password || "Password is required";
    if (blockedThreats.length) setBlocked(blockedThreats); else setBlocked([]);
    setErrors(errs);
    return Object.keys(errs).length === 0 && blockedThreats.length === 0;
  };

  const handleSubmit = async () => {
    if (lockout) return;
    if (!validate()) return;
    setLoading(true);
    try {
      const res = await fetch(`${API}/auth/login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: sanitizeInput(email), password }),
      });
      const data = await res.json();
      if (!res.ok) {
        const next = attempts + 1;
        setAttempts(next);
        if (next >= MAX_ATTEMPTS) {
          setLockout(Date.now() + LOCKOUT_MS); setCountdown(LOCKOUT_MS / 1000);
          // Generic error message - hide system details
          setErrors({ general: "Account temporarily locked. Please try again later." });
        } else {
          // Generic error - don't reveal if email or password is wrong
          setErrors({ general: `Authentication failed. ${MAX_ATTEMPTS - next} attempt(s) remaining.` });
        }
      } else {
        setAttempts(0);
        localStorage.setItem("token", data.token);
        // Trigger MFA step
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        setGeneratedOTP(otp);
        setPendingUser(data.user);
        setMfaStep(true);
      }
    } catch (err) {
      // Generic error - hide system/network details
      setErrors({ general: "An error occurred. Please try again." });
    } finally { setLoading(false); }
  };

  if (mfaStep) return (
    <MFAPage
      generatedOTP={generatedOTP}
      onVerify={() => onLogin(pendingUser)}
      onCancel={() => { setMfaStep(false); setPendingUser(null); setGeneratedOTP(""); }}
    />
  );

  const isLocked = !!lockout;
  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="auth-title">Welcome back 👋</div>
        <div className="auth-sub">Sign in to your Sole Spectrum account</div>
        <SecurityPanel defenses={[
          { label: "XSS Prevention", icon: "✓", type: "active" },
          { label: "SQL Injection Block", icon: "✓", type: "active" },
          { label: "Brute Force Protection", icon: "✓", type: "active" },
          { label: "CSRF Token", icon: "✓", type: "active" },
          { label: `Attempts: ${attempts}/${MAX_ATTEMPTS}`, icon: "⚡", type: attempts >= 3 ? "blocked" : "info" },
        ]} />
        {blocked.length > 0 && <div className="alert alert-red">⛔ Threat Blocked: {blocked.join(", ")}</div>}
        {errors.general && (
          <div className={`alert ${isLocked ? "alert-red" : "alert-orange"}`}>
            {isLocked ? (
              <div>
                <div>🔒 Account temporarily locked. Try again in:</div>
                <div className="lockout-timer">{countdown}s</div>
                <div className="progress-bar-wrap"><div className="progress-bar-fill" style={{ width: `${(countdown / (LOCKOUT_MS / 1000)) * 100}%` }} /></div>
              </div>
            ) : `⚠ ${errors.general}`}
          </div>
        )}
        <div className="field">
          <label>Email Address</label>
          <input type="text" placeholder="you@email.com" value={email} onChange={e => setEmail(e.target.value)} className={errors.email ? "error" : ""} disabled={isLocked} />
          {errors.email && <div className="field-err">{errors.email}</div>}
        </div>
        <div className="field">
          <label>Password</label>
          <input type="password" placeholder="Your password" value={password} onChange={e => setPassword(e.target.value)} className={errors.password ? "error" : ""} disabled={isLocked} onKeyDown={e => e.key === "Enter" && handleSubmit()} />
          {errors.password && <div className="field-err">{errors.password}</div>}
        </div>
        <input type="hidden" value={csrfToken} readOnly />
        <button className="btn btn-primary" onClick={handleSubmit} disabled={isLocked || loading} style={{ marginTop: 8 }}>
          {loading ? <span className="spinner" /> : isLocked ? `🔒 Locked (${countdown}s)` : "Sign In"}
        </button>
        <div style={{ textAlign: "center", marginTop: 16, fontSize: 13, color: "var(--gray)" }}>
          No account? <span className="text-link" onClick={onGoRegister}>Register here</span>
        </div>
        <hr className="divider" />
        <div style={{ fontSize: 11, color: "var(--gray)", lineHeight: 1.6 }}>
          <b>Demo:</b> admin@solespectrum.com / Admin123 &nbsp;|&nbsp; customer@email.com / Customer1
        </div>
      </div>
    </div>
  );
}

// ─── REGISTER PAGE ────────────────────────────────────────────────────────────

function RegisterPage({ onRegister, onGoLogin }) {
  const [form, setForm] = useState({ name: "", email: "", phone: "", password: "", confirm: "" });
  const [errors, setErrors] = useState({});
  const [blocked, setBlocked] = useState([]);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const validate = () => {
    const errs = {};
    const threats = [];
    const clean = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, sanitizeInput(v)]));
    Object.entries(form).forEach(([k, v]) => {
      if (v !== sanitizeInput(v)) threats.push(`XSS attempt in ${k}`);
      if (hasSQLInjection(v)) { errs[k] = "⛔ SQL Injection detected"; threats.push(`SQL Injection in ${k}`); }
    });
    if (!validators.name(clean.name)) errs.name = errs.name || "Name must be 2–50 letters only";
    if (!validators.email(clean.email)) errs.email = errs.email || "Enter a valid email";
    if (clean.phone && !validators.phone(clean.phone)) errs.phone = "Enter a valid phone number";
    if (!validators.password(clean.password)) errs.password = errs.password || "Min 8 chars, 1 uppercase, 1 number";
    if (clean.password !== clean.confirm) errs.confirm = "Passwords do not match";
    setBlocked(threats); setErrors(errs);
    return Object.keys(errs).length === 0 && threats.length === 0;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    setLoading(true);
    const clean = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, sanitizeInput(v)]));
    try {
      const res = await fetch(`${API}/auth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(clean) });
      const data = await res.json();
      if (!res.ok) { setErrors({ general: data.error || "Registration failed." }); }
      else { localStorage.setItem("token", data.token); setSuccess(true); setTimeout(() => onRegister(data.user), 1500); }
    } catch { setErrors({ general: "Cannot connect to server." }); }
    finally { setLoading(false); }
  };

  const getFieldClass = (key) => errors[key] ? "error" : form[key] && !errors[key] ? "ok" : "";

  if (success) return (
    <div className="auth-wrap"><div className="auth-card" style={{ textAlign: "center" }}>
      <div style={{ fontSize: 56, marginBottom: 16 }}>✅</div>
      <div className="auth-title">Account Created!</div>
      <div className="auth-sub">Redirecting you to the store...</div>
    </div></div>
  );

  return (
    <div className="auth-wrap"><div className="auth-card">
      <div className="auth-title">Create Account</div>
      <div className="auth-sub">Join Sole Spectrum today</div>
      <SecurityPanel defenses={[
        { label: "XSS Sanitization", icon: "✓", type: "active" },
        { label: "SQL Injection Block", icon: "✓", type: "active" },
        { label: "Input Validation", icon: "✓", type: "active" },
        { label: "CSRF Token", icon: "✓", type: "active" },
      ]} />
      {blocked.length > 0 && <div className="alert alert-red">⛔ Threat Blocked: {blocked.join(", ")}</div>}
      {errors.general && <div className="alert alert-red">⚠ {errors.general}</div>}
      {[
        { key: "name", label: "Full Name", type: "text", placeholder: "Juan dela Cruz" },
        { key: "email", label: "Email Address", type: "text", placeholder: "you@email.com" },
        { key: "phone", label: "Phone Number (optional)", type: "text", placeholder: "+63 912 345 6789" },
        { key: "password", label: "Password", type: "password", placeholder: "Min 8 chars, 1 uppercase, 1 number" },
        { key: "confirm", label: "Confirm Password", type: "password", placeholder: "Repeat password" },
      ].map(({ key, label, type, placeholder }) => (
        <div className="field" key={key}>
          <label>{label}</label>
          <input type={type} placeholder={placeholder} value={form[key]} onChange={e => update(key, e.target.value)} className={getFieldClass(key)} />
          {errors[key] && <div className="field-err">{errors[key]}</div>}
          {!errors[key] && form[key] && <div className="field-ok">✓ Looks good</div>}
        </div>
      ))}
      <button className="btn btn-primary" onClick={handleSubmit} disabled={loading} style={{ marginTop: 8 }}>
        {loading ? <span className="spinner" /> : "Create Account"}
      </button>
      <div style={{ textAlign: "center", marginTop: 16, fontSize: 13, color: "var(--gray)" }}>
        Already have an account? <span className="text-link" onClick={onGoLogin}>Sign in</span>
      </div>
    </div></div>
  );
}

// ─── BROWSE PAGE ──────────────────────────────────────────────────────────────

function BrowsePage({ onAddToCart }) {
  const [products, setProducts] = useState([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("All");
  const [addedId, setAddedId] = useState(null);
  const [searchWarning, setSearchWarning] = useState("");
  const [loadingProducts, setLoadingProducts] = useState(true);

  useEffect(() => {
    fetch(`${API}/products`).then(r => r.json()).then(d => setProducts(d)).catch(console.error).finally(() => setLoadingProducts(false));
  }, []);

  const categories = ["All", ...new Set(products.map(p => p.category))];

  const handleSearch = (val) => {
    if (hasSQLInjection(val)) { setSearchWarning("⛔ SQL Injection attempt detected and blocked."); return; }
    const clean = sanitizeInput(val);
    setSearchWarning(val !== clean ? "⚠ Potentially unsafe input was sanitized." : "");
    setSearch(clean);
  };

  const filtered = products.filter(p =>
    (filter === "All" || p.category === filter) &&
    (p.name.toLowerCase().includes(search.toLowerCase()) || p.brand.toLowerCase().includes(search.toLowerCase()))
  );

  const handleAdd = (product) => { onAddToCart(product); setAddedId(product.id); setTimeout(() => setAddedId(null), 1200); };

  return (
    <div className="page">
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 16, marginBottom: 24 }}>
        <div><div className="section-title">Shop All Shoes</div><div className="section-sub">Sole Spectrum — {products.length} styles available</div></div>
        <SecurityPanel defenses={[
          { label: "XSS-Safe Search", icon: "✓", type: "active" },
          { label: "SQLi Block", icon: "✓", type: "active" },
          { label: "JWT Auth", icon: "✓", type: "active" },
        ]} />
      </div>
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <input type="text" placeholder="Search shoes... (try typing a SQL injection)" value={search} onChange={e => handleSearch(e.target.value)}
          style={{ flex: 1, minWidth: 220, padding: "10px 14px", border: "1.5px solid var(--border)", borderRadius: 8, fontFamily: "var(--font-body)", fontSize: 14, outline: "none" }} />
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {categories.map(c => (
            <button key={c} onClick={() => setFilter(c)} style={{ padding: "8px 14px", borderRadius: 8, border: "1.5px solid", fontSize: 12, fontWeight: 600, cursor: "pointer", fontFamily: "var(--font-body)", transition: "all 0.15s",
              borderColor: filter === c ? "var(--dark)" : "var(--border)", background: filter === c ? "var(--dark)" : "white", color: filter === c ? "white" : "var(--gray)" }}>
              {c}
            </button>
          ))}
        </div>
      </div>
      {searchWarning && <div className="alert alert-red" style={{ marginBottom: 16 }}>{searchWarning}</div>}
      {loadingProducts ? (
        <div style={{ textAlign: "center", padding: 80, color: "var(--gray)" }}>Loading products from database...</div>
      ) : (
        <div className="product-grid">
          {filtered.map(p => (
            <div className="product-card" key={p.id}>
              <div className="product-img" style={{ background: `${p.color}18` }}>{p.image}</div>
              <div className="product-body">
                <div className="product-brand">{p.brand}</div>
                <div className="product-name">{p.name}</div>
                <div className="product-cat">{p.category}</div>
                <div className="product-footer">
                  <div>
                    <div className="product-price">₱{Number(p.price).toLocaleString()}</div>
                    <div className={`product-stock ${p.stock > 5 ? "stock-ok" : p.stock > 0 ? "stock-low" : "stock-out"}`}>
                      {p.stock > 5 ? `✓ In stock` : p.stock > 0 ? `⚡ Only ${p.stock} left` : "✕ Out of stock"}
                    </div>
                  </div>
                  <button className="add-btn" onClick={() => handleAdd(p)} disabled={p.stock === 0}>{addedId === p.id ? "✓ Added" : "+ Cart"}</button>
                </div>
              </div>
            </div>
          ))}
          {filtered.length === 0 && <div className="empty-state" style={{ gridColumn: "1/-1" }}><div className="icon">🔍</div><h3>No results found</h3></div>}
        </div>
      )}
    </div>
  );
}

// ─── CART PAGE ────────────────────────────────────────────────────────────────

function CartPage({ cart, onUpdate, onRemove, onCheckout }) {
  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  if (cart.length === 0) return (
    <div className="page"><div className="empty-state"><div className="icon">🛒</div><h3>Your cart is empty</h3><p>Go browse some shoes!</p></div></div>
  );
  return (
    <div className="page">
      <div className="section-title">Your Cart</div>
      <div className="section-sub">{cart.length} item(s) in your bag</div>
      {cart.map(item => (
        <div className="cart-item" key={item.id}>
          <div className="cart-item-icon">{item.image}</div>
          <div className="cart-item-info">
            <div className="cart-item-name">{item.name}</div>
            <div className="cart-item-brand">{item.brand} · {item.category}</div>
            <div style={{ marginTop: 8, fontWeight: 700, fontSize: 15 }}>₱{(item.price * item.qty).toLocaleString()}</div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 8 }}>
            <div className="qty-ctrl">
              <button className="qty-btn" onClick={() => onUpdate(item.id, item.qty - 1)}>−</button>
              <span style={{ fontWeight: 600, minWidth: 20, textAlign: "center" }}>{item.qty}</span>
              <button className="qty-btn" onClick={() => onUpdate(item.id, item.qty + 1)}>+</button>
            </div>
            <button className="btn btn-outline btn-sm" onClick={() => onRemove(item.id)} style={{ color: "var(--red)", borderColor: "var(--red)" }}>Remove</button>
          </div>
        </div>
      ))}
      <div className="cart-summary">
        <div className="summary-row"><span>Subtotal</span><span>₱{total.toLocaleString()}</span></div>
        <div className="summary-row"><span>Shipping</span><span style={{ color: "var(--green)" }}>Free</span></div>
        <div className="summary-row"><span>Tax (12% VAT)</span><span>₱{Math.round(total * 0.12).toLocaleString()}</span></div>
        <div className="summary-total"><span>Total</span><span>₱{Math.round(total * 1.12).toLocaleString()}</span></div>
        <button className="btn btn-primary" onClick={onCheckout} style={{ marginTop: 20 }}>Proceed to Checkout →</button>
      </div>
    </div>
  );
}

// ─── RECEIPT PAGE ─────────────────────────────────────────────────────────────

function ReceiptPage({ receipt, onDone }) {
  return (
    <div className="page" style={{ maxWidth: 600 }}>
      <div style={{ textAlign: "center", marginBottom: 32 }}>
        <div style={{ fontSize: 56 }}>🧾</div>
        <div className="section-title" style={{ fontSize: 28 }}>Order Receipt</div>
        <div style={{ fontSize: 13, color: "var(--gray)" }}>Thank you for shopping at Sole Spectrum!</div>
      </div>
      <div style={{ background: "white", border: "1px solid var(--border)", borderRadius: 16, overflow: "hidden" }}>
        <div style={{ background: "var(--dark)", color: "white", padding: "20px 24px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontFamily: "var(--font-head)", fontSize: 20, fontWeight: 800 }}>Sole<span style={{ color: "var(--orange)" }}>Spectrum</span></div>
            <div style={{ fontSize: 11, opacity: 0.6, marginTop: 2 }}>Online Shoe Store</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 11, opacity: 0.6 }}>Order ID</div>
            <div style={{ fontWeight: 700, fontSize: 16 }}>#{receipt.orderId}</div>
          </div>
        </div>
        <div style={{ padding: "24px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24, padding: "16px", background: "var(--bg)", borderRadius: 8 }}>
            {[
              { label: "Date", value: receipt.date },
              { label: "Payment", value: receipt.paymentMethod === "gcash" ? "💙 GCash" : "💳 Credit Card" },
              { label: "Customer", value: receipt.name },
              { label: "Status", value: <span className="badge badge-green">✓ Confirmed</span> },
            ].map(({ label, value }) => (
              <div key={label}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "var(--gray)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>{label}</div>
                <div style={{ fontWeight: 600 }}>{value}</div>
              </div>
            ))}
          </div>
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--gray)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>Ship To</div>
            <div style={{ fontSize: 14 }}>{receipt.address}</div>
          </div>
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: "var(--gray)", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>Items Ordered</div>
            {receipt.items.map((i, idx) => (
              <div key={idx} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 24 }}>{i.image}</span>
                  <div><div style={{ fontWeight: 600, fontSize: 14 }}>{i.name}</div><div style={{ fontSize: 12, color: "var(--gray)" }}>{i.brand} · Qty: {i.qty}</div></div>
                </div>
                <div style={{ fontWeight: 700 }}>₱{(i.price * i.qty).toLocaleString()}</div>
              </div>
            ))}
          </div>
          <div style={{ background: "var(--bg)", borderRadius: 8, padding: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 6 }}><span style={{ color: "var(--gray)" }}>Subtotal</span><span>₱{receipt.subtotal.toLocaleString()}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 6 }}><span style={{ color: "var(--gray)" }}>Shipping</span><span style={{ color: "var(--green)" }}>Free</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 12 }}><span style={{ color: "var(--gray)" }}>VAT (12%)</span><span>₱{receipt.vat.toLocaleString()}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 800, fontSize: 18, borderTop: "2px solid var(--border)", paddingTop: 12 }}>
              <span>Total Paid</span><span style={{ color: "var(--orange)" }}>₱{receipt.total.toLocaleString()}</span>
            </div>
          </div>
          <div style={{ marginTop: 20, padding: "12px 16px", background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "var(--green)", textTransform: "uppercase", letterSpacing: 0.5 }}>Reference Number</div>
              <div style={{ fontWeight: 700, fontSize: 15, fontFamily: "monospace" }}>{receipt.reference}</div>
            </div>
            <span style={{ fontSize: 24 }}>✅</span>
          </div>
        </div>
      </div>
      <button className="btn btn-primary" onClick={onDone} style={{ marginTop: 24, fontSize: 15 }}>Continue Shopping →</button>
    </div>
  );
}

// ─── CHECKOUT PAGE ────────────────────────────────────────────────────────────

function CheckoutPage({ cart, user, csrfToken, onSuccess }) {
  const [paymentMethod, setPaymentMethod] = useState("card");
  const [form, setForm] = useState({
    name: user?.name || "", email: user?.email || "", phone: "",
    address: "", city: "", zip: "",
    card: "", expiry: "", cvv: "",
    gcashNumber: "", gcashName: "",
  });
  const [errors, setErrors] = useState({});
  const [blocked, setBlocked] = useState([]);
  const [loading, setLoading] = useState(false);
  const [receipt, setReceipt] = useState(null);

  const subtotal = cart.reduce((s, i) => s + i.price * i.qty, 0);
  const vat = Math.round(subtotal * 0.12);
  const total = subtotal + vat;
  const update = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const generateRef = () => "SS" + Date.now().toString().slice(-8).toUpperCase();

  const validate = () => {
    const errs = {};
    const threats = [];
    const fieldsToCheck = { name: form.name, email: form.email, phone: form.phone, address: form.address, city: form.city };
    Object.entries(fieldsToCheck).forEach(([k, v]) => {
      if (hasSQLInjection(v)) { errs[k] = "⛔ SQL Injection detected"; threats.push(`SQLi in ${k}`); }
    });
    if (!validators.name(form.name)) errs.name = errs.name || "Enter your full name";
    if (!validators.email(form.email)) errs.email = errs.email || "Enter a valid email";
    if (!validators.address(form.address)) errs.address = errs.address || "Enter a valid address (min 5 chars)";
    if (!form.city.trim()) errs.city = "City is required";
    if (paymentMethod === "card") {
      if (!validators.cardNumber(form.card)) errs.card = errs.card || "Enter a valid 16-digit card number";
      if (!validators.expiry(form.expiry)) errs.expiry = errs.expiry || "Format: MM/YY";
      if (!validators.cvv(form.cvv)) errs.cvv = errs.cvv || "3 or 4 digits";
    } else {
      if (!/^09\d{9}$/.test(form.gcashNumber)) errs.gcashNumber = "Enter a valid GCash number (09XXXXXXXXX)";
      if (!validators.name(form.gcashName)) errs.gcashName = "Enter the account name";
    }
    setBlocked(threats); setErrors(errs);
    return Object.keys(errs).length === 0 && threats.length === 0;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    setLoading(true);
    try {
      const token = localStorage.getItem("token");
      const res = await fetch(`${API}/orders`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ items: cart, shipping_address: `${sanitizeInput(form.address)}, ${sanitizeInput(form.city)} ${form.zip}`, total }),
      });
      const data = await res.json();
      if (!res.ok) { setErrors({ general: data.error || "Failed to place order." }); }
      else {
        setReceipt({
          orderId: data.orderId,
          date: new Date().toLocaleString("en-PH", { dateStyle: "long", timeStyle: "short" }),
          name: form.name, email: form.email,
          address: `${form.address}, ${form.city} ${form.zip}`,
          paymentMethod, items: cart, subtotal, vat, total,
          reference: generateRef(),
        });
      }
    } catch { setErrors({ general: "Cannot connect to server." }); }
    finally { setLoading(false); }
  };

  if (receipt) return <ReceiptPage receipt={receipt} onDone={onSuccess} />;

  return (
    <div className="page">
      <div className="section-title">Checkout</div>
      <div className="section-sub">Secure & protected payment</div>
      {blocked.length > 0 && <div className="alert alert-red">⛔ Threat Blocked: {blocked.join(", ")}</div>}
      {errors.general && <div className="alert alert-red">⚠ {errors.general}</div>}
      <div className="checkout-grid">
        <div>
          <SecurityPanel defenses={[
            { label: "XSS Sanitized", icon: "✓", type: "active" },
            { label: "SQLi Protected", icon: "✓", type: "active" },
            { label: "CSRF Token", icon: "✓", type: "active" },
            { label: "JWT Auth", icon: "✓", type: "active" },
            { label: "Payment Secured", icon: "✓", type: "active" },
          ]} />

          {/* Shipping */}
          <div className="checkout-section">
            <h3>📦 Shipping Information</h3>
            {[
              { key: "name", label: "Full Name", placeholder: "Juan dela Cruz" },
              { key: "email", label: "Email", placeholder: "you@email.com" },
              { key: "phone", label: "Phone", placeholder: "+63 912 345 6789" },
              { key: "address", label: "Address", placeholder: "123 Rizal St., Barangay..." },
            ].map(({ key, label, placeholder }) => (
              <div className="field" key={key}>
                <label>{label}</label>
                <input type="text" placeholder={placeholder} value={form[key]} onChange={e => update(key, e.target.value)} className={errors[key] ? "error" : ""} />
                {errors[key] && <div className="field-err">{errors[key]}</div>}
              </div>
            ))}
            <div className="form-row">
              <div className="field">
                <label>City</label>
                <input type="text" placeholder="Quezon City" value={form.city} onChange={e => update("city", e.target.value)} className={errors.city ? "error" : ""} />
                {errors.city && <div className="field-err">{errors.city}</div>}
              </div>
              <div className="field">
                <label>ZIP Code</label>
                <input type="text" placeholder="1100" value={form.zip} onChange={e => update("zip", e.target.value)} />
              </div>
            </div>
          </div>

          {/* Payment Method */}
          <div className="checkout-section">
            <h3>💳 Payment Method</h3>
            <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
              {[{ id: "card", label: "💳 Credit Card" }, { id: "gcash", label: "💙 GCash" }].map(m => (
                <button key={m.id} onClick={() => setPaymentMethod(m.id)}
                  style={{ flex: 1, padding: "12px", border: "2px solid", borderRadius: 10, cursor: "pointer", fontFamily: "var(--font-body)", fontWeight: 600, fontSize: 14, transition: "all 0.15s",
                    borderColor: paymentMethod === m.id ? "var(--dark)" : "var(--border)",
                    background: paymentMethod === m.id ? "var(--dark)" : "white",
                    color: paymentMethod === m.id ? "white" : "var(--gray)" }}>
                  {m.label}
                </button>
              ))}
            </div>

            {paymentMethod === "card" && (
              <>
                <div className="field">
                  <label>Card Number</label>
                  <input type="text" placeholder="1234 5678 9012 3456" value={form.card}
                    onChange={e => update("card", e.target.value.replace(/[^\d\s]/g, "").slice(0, 19))} className={errors.card ? "error" : ""} />
                  {errors.card && <div className="field-err">{errors.card}</div>}
                </div>
                <div className="form-row">
                  <div className="field">
                    <label>Expiry (MM/YY)</label>
                    <input type="text" placeholder="12/27" value={form.expiry} onChange={e => update("expiry", e.target.value)} className={errors.expiry ? "error" : ""} />
                    {errors.expiry && <div className="field-err">{errors.expiry}</div>}
                  </div>
                  <div className="field">
                    <label>CVV</label>
                    <input type="password" placeholder="•••" maxLength={4} value={form.cvv} onChange={e => update("cvv", e.target.value.replace(/\D/g, ""))} className={errors.cvv ? "error" : ""} />
                    {errors.cvv && <div className="field-err">{errors.cvv}</div>}
                  </div>
                </div>
              </>
            )}

            {paymentMethod === "gcash" && (
              <div style={{ background: "#f0f7ff", border: "1px solid #bfdbfe", borderRadius: 10, padding: 20 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                  <div style={{ width: 48, height: 48, background: "#007bff", borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>💙</div>
                  <div><div style={{ fontWeight: 700, fontSize: 16 }}>GCash Payment</div><div style={{ fontSize: 12, color: "var(--gray)" }}>Enter your GCash registered number</div></div>
                </div>
                <div className="field">
                  <label>GCash Number</label>
                  <input type="text" placeholder="09XXXXXXXXX" value={form.gcashNumber}
                    onChange={e => update("gcashNumber", e.target.value.replace(/\D/g, "").slice(0, 11))} className={errors.gcashNumber ? "error" : ""} />
                  {errors.gcashNumber && <div className="field-err">{errors.gcashNumber}</div>}
                </div>
                <div className="field">
                  <label>GCash Account Name</label>
                  <input type="text" placeholder="Juan dela Cruz" value={form.gcashName} onChange={e => update("gcashName", e.target.value)} className={errors.gcashName ? "error" : ""} />
                  {errors.gcashName && <div className="field-err">{errors.gcashName}</div>}
                </div>
                <div style={{ background: "white", borderRadius: 8, padding: 12, fontSize: 12, color: "var(--gray)", border: "1px dashed var(--border)" }}>
                  🔒 Your GCash number is encrypted and never stored.
                </div>
              </div>
            )}
          </div>

          <input type="hidden" value={csrfToken} readOnly />
          <button className="btn btn-primary" onClick={handleSubmit} disabled={loading} style={{ fontSize: 16, padding: "14px" }}>
            {loading ? <span className="spinner" /> : `🔒 Place Order — ₱${total.toLocaleString()}`}
          </button>
        </div>

        <div>
          <div className="checkout-section">
            <h3>🛒 Order Summary</h3>
            {cart.map(i => (
              <div key={i.id} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid var(--border)", fontSize: 13 }}>
                <span>{i.image} {i.name} × {i.qty}</span>
                <span style={{ fontWeight: 600 }}>₱{(i.price * i.qty).toLocaleString()}</span>
              </div>
            ))}
            <div style={{ marginTop: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 4 }}><span style={{ color: "var(--gray)" }}>Subtotal</span><span>₱{subtotal.toLocaleString()}</span></div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 4 }}><span style={{ color: "var(--gray)" }}>Shipping</span><span style={{ color: "var(--green)" }}>Free</span></div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 8 }}><span style={{ color: "var(--gray)" }}>VAT (12%)</span><span>₱{vat.toLocaleString()}</span></div>
              <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 800, fontSize: 18, borderTop: "2px solid var(--border)", paddingTop: 10 }}>
                <span>Total</span><span style={{ color: "var(--orange)" }}>₱{total.toLocaleString()}</span>
              </div>
            </div>
          </div>
          <div style={{ background: "#f0fdf4", border: "1px solid #bbf7d0", borderRadius: 10, padding: 14, fontSize: 12, color: "var(--green)" }}>
            🛡 Your payment is protected by SSL encryption and our security defenses.
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── ADMIN PAGE (Full CRUD) ───────────────────────────────────────────────────

function AdminPage({ user }) {
  const [activeTab, setActiveTab] = useState("overview");
  const [stats, setStats] = useState({ totalUsers: 0, totalOrders: 0, totalRevenue: 0, totalProducts: 0 });
  const [products, setProducts] = useState([]);
  const [users, setUsers] = useState([]);
  const [orders, setOrders] = useState([]);
  const [secLog, setSecLog] = useState([
    { time: "09:12", event: "Failed login attempt", user: "unknown@evil.com", type: "blocked" },
    { time: "09:14", event: "SQL Injection attempt blocked", user: "attacker", type: "blocked" },
    { time: "09:15", event: "XSS attempt blocked in search", user: "anonymous", type: "blocked" },
    { time: "09:20", event: "Admin login successful", user: user?.email, type: "ok" },
    { time: "09:21", event: "CSRF token validated", user: user?.email, type: "ok" },
  ]);
  const [modal, setModal] = useState(null);
  const [modalForm, setModalForm] = useState({});
  const [modalErrors, setModalErrors] = useState({});
  const [modalLoading, setModalLoading] = useState(false);
  const [confirm, setConfirm] = useState(null);
  const [toast, setToast] = useState(null);

  const token = localStorage.getItem("token");
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  const showToast = (msg, type = "green") => { setToast({ msg, type }); setTimeout(() => setToast(null), 3000); };
  const logEvent = (event, type = "ok") => setSecLog(l => [...l, { time: new Date().toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit" }), event, user: user?.email, type }]);

  const fetchAll = async () => {
    try {
      const [pRes, sRes, oRes, uRes] = await Promise.all([
        fetch(`${API}/products`),
        fetch(`${API}/admin/stats`, { headers }),
        fetch(`${API}/orders`, { headers }),
        fetch(`${API}/admin/users`, { headers }),
      ]);
      setProducts(await pRes.json());
      setStats(await sRes.json());
      setOrders(await oRes.json());
      setUsers(await uRes.json());
    } catch (err) { console.error("Admin fetch error:", err); }
  };

  useEffect(() => { fetchAll(); }, []);

  const openCreate = (type) => {
    const defaults = {
      product: { name: "", brand: "", price: "", category: "Running", stock: "0", image: "👟", color: "#ff6b35" },
      user: { name: "", email: "", password: "", phone: "", role: "customer" },
      order: { status: "pending" },
    };
    setModalForm(defaults[type]); setModalErrors({}); setModal({ type, mode: "create" });
  };

  const openEdit = (type, data) => {
    const formData = type === "product"
      ? { name: data.name, brand: data.brand, price: data.price, category: data.category, stock: data.stock, image: data.image, color: data.color }
      : type === "user" ? { name: data.name, email: data.email, phone: data.phone || "", role: data.role }
      : { status: data.status };
    setModalForm(formData); setModalErrors({}); setModal({ type, mode: "edit", id: data.id });
  };

  const closeModal = () => { setModal(null); setModalForm({}); setModalErrors({}); };
  const updateForm = (k, v) => setModalForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    if (!modal) return;
    setModalLoading(true); setModalErrors({});
    try {
      let res;
      if (modal.type === "product") {
        const body = { ...modalForm, price: parseFloat(modalForm.price), stock: parseInt(modalForm.stock) };
        if (!body.name || !body.brand || !body.price || !body.category) { setModalErrors({ general: "Name, brand, price, and category are required." }); setModalLoading(false); return; }
        res = modal.mode === "create"
          ? await fetch(`${API}/products`, { method: "POST", headers, body: JSON.stringify(body) })
          : await fetch(`${API}/products/${modal.id}`, { method: "PUT", headers, body: JSON.stringify(body) });
      } else if (modal.type === "user") {
        const body = { ...modalForm };
        if (!body.name || !body.email) { setModalErrors({ general: "Name and email are required." }); setModalLoading(false); return; }
        if (modal.mode === "create" && !body.password) { setModalErrors({ general: "Password is required." }); setModalLoading(false); return; }
        res = modal.mode === "create"
          ? await fetch(`${API}/admin/users`, { method: "POST", headers, body: JSON.stringify(body) })
          : await fetch(`${API}/admin/users/${modal.id}`, { method: "PUT", headers, body: JSON.stringify(body) });
      } else {
        res = await fetch(`${API}/orders/${modal.id}`, { method: "PUT", headers, body: JSON.stringify({ status: modalForm.status }) });
      }
      const data = await res.json();
      if (!res.ok) { setModalErrors({ general: data.error || "Operation failed." }); }
      else {
        await fetchAll(); closeModal();
        const action = modal.mode === "create" ? "created" : "updated";
        showToast(`✅ ${modal.type.charAt(0).toUpperCase() + modal.type.slice(1)} ${action} successfully!`);
        logEvent(`${modal.type} ${action}: ${modalForm.name || modal.id}`);
      }
    } catch { setModalErrors({ general: "Cannot connect to server." }); }
    finally { setModalLoading(false); }
  };

  const handleDelete = (type, id, label) => {
    setConfirm({
      message: `Delete ${type} "${label}"? This cannot be undone.`,
      onConfirm: async () => {
        setConfirm(null);
        try {
          const endpoint = type === "product" ? `${API}/products/${id}` : type === "user" ? `${API}/admin/users/${id}` : `${API}/orders/${id}`;
          const res = await fetch(endpoint, { method: "DELETE", headers });
          const data = await res.json();
          if (!res.ok) { showToast(`⛔ ${data.error}`, "red"); return; }
          await fetchAll();
          showToast(`✅ ${type.charAt(0).toUpperCase() + type.slice(1)} deleted.`);
          logEvent(`${type} deleted: ${label}`, "blocked");
        } catch { showToast("⛔ Cannot connect to server.", "red"); }
      },
    });
  };

  const renderModalForm = () => {
    if (!modal) return null;
    const isEdit = modal.mode === "edit";
    if (modal.type === "product") return (
      <>
        {modalErrors.general && <div className="alert alert-red">{modalErrors.general}</div>}
        <div className="form-row">
          <div className="field"><label>Name</label><input value={modalForm.name || ""} onChange={e => updateForm("name", e.target.value)} placeholder="AirStride Pro" /></div>
          <div className="field"><label>Brand</label><input value={modalForm.brand || ""} onChange={e => updateForm("brand", e.target.value)} placeholder="Nike" /></div>
        </div>
        <div className="form-row">
          <div className="field"><label>Price (₱)</label><input type="number" value={modalForm.price || ""} onChange={e => updateForm("price", e.target.value)} placeholder="4999" /></div>
          <div className="field"><label>Stock</label><input type="number" value={modalForm.stock || ""} onChange={e => updateForm("stock", e.target.value)} placeholder="10" /></div>
        </div>
        <div className="form-row">
          <div className="field">
            <label>Category</label>
            <select value={modalForm.category || "Running"} onChange={e => updateForm("category", e.target.value)}>
              {["Running", "Casual", "Boots", "Basketball", "Sandals", "Formal"].map(c => <option key={c}>{c}</option>)}
            </select>
          </div>
          <div className="field"><label>Emoji Icon</label><input value={modalForm.image || "👟"} onChange={e => updateForm("image", e.target.value)} placeholder="👟" /></div>
        </div>
        <div className="field"><label>Color</label><input type="color" value={modalForm.color || "#ff6b35"} onChange={e => updateForm("color", e.target.value)} style={{ width: 60, height: 38, padding: 4, cursor: "pointer" }} /></div>
      </>
    );
    if (modal.type === "user") return (
      <>
        {modalErrors.general && <div className="alert alert-red">{modalErrors.general}</div>}
        <div className="form-row">
          <div className="field"><label>Full Name</label><input value={modalForm.name || ""} onChange={e => updateForm("name", e.target.value)} placeholder="Juan dela Cruz" /></div>
          <div className="field"><label>Phone</label><input value={modalForm.phone || ""} onChange={e => updateForm("phone", e.target.value)} placeholder="+63 912..." /></div>
        </div>
        <div className="field"><label>Email</label><input type="email" value={modalForm.email || ""} onChange={e => updateForm("email", e.target.value)} placeholder="user@email.com" /></div>
        {!isEdit && <div className="field"><label>Password</label><input type="password" value={modalForm.password || ""} onChange={e => updateForm("password", e.target.value)} placeholder="Min 8 chars, 1 uppercase, 1 number" /></div>}
        <div className="field">
          <label>Role</label>
          <select value={modalForm.role || "customer"} onChange={e => updateForm("role", e.target.value)}>
            <option value="customer">Customer</option>
            <option value="admin">Admin</option>
          </select>
        </div>
      </>
    );
    if (modal.type === "order") return (
      <>
        {modalErrors.general && <div className="alert alert-red">{modalErrors.general}</div>}
        <div className="field">
          <label>Order Status</label>
          <select value={modalForm.status || "pending"} onChange={e => updateForm("status", e.target.value)}>
            {["pending", "processing", "shipped", "delivered"].map(s => <option key={s}>{s}</option>)}
          </select>
        </div>
      </>
    );
  };

  const statusBadge = (s) => {
    const map = { pending: "badge-orange", processing: "badge-blue", shipped: "badge-purple", delivered: "badge-green" };
    return <span className={`badge ${map[s] || "badge-orange"}`}>{s}</span>;
  };

  return (
    <div className="page">
      {toast && (
        <div style={{ position: "fixed", bottom: 24, right: 24, zIndex: 400, padding: "12px 20px", borderRadius: 10,
          background: toast.type === "red" ? "#fef2f2" : "#f0fdf4",
          border: `1px solid ${toast.type === "red" ? "#fecaca" : "#bbf7d0"}`,
          color: toast.type === "red" ? "#b91c1c" : "#15803d",
          fontWeight: 600, fontSize: 14, boxShadow: "var(--shadow-lg)" }}>
          {toast.msg}
        </div>
      )}
      {confirm && <ConfirmDialog message={confirm.message} onConfirm={confirm.onConfirm} onCancel={() => setConfirm(null)} />}
      {modal && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-title">{modal.mode === "create" ? "➕ Add " : "✏️ Edit "}{modal.type.charAt(0).toUpperCase() + modal.type.slice(1)}</div>
            {renderModalForm()}
            <div className="modal-actions">
              <button className="btn btn-outline btn-sm" onClick={closeModal}>Cancel</button>
              <button className="btn btn-success btn-sm" onClick={handleSave} disabled={modalLoading}>
                {modalLoading ? <span className="spinner" style={{ borderTopColor: "white" }} /> : modal.mode === "create" ? "Create" : "Save Changes"}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="admin-header">
        <div><div className="section-title">Admin Dashboard</div><div className="section-sub">Sole Spectrum — System Management</div></div>
        <div style={{ display: "flex", gap: 8 }}>
          <span className="badge badge-green">🟢 System Online</span>
          <span className="badge badge-blue">🛡 All Defenses Active</span>
        </div>
      </div>

      <div className="admin-tabs">
        {[["overview", "📊 Overview"], ["products", "📦 Products"], ["users", "👥 Users"], ["orders", "📋 Orders"], ["security", "🔐 Security"]].map(([id, label]) => (
          <button key={id} className={`admin-tab ${activeTab === id ? "active" : ""}`} onClick={() => setActiveTab(id)}>{label}</button>
        ))}
      </div>

      {activeTab === "overview" && (
        <>
          <div className="stats-grid">
            {[
              { label: "Total Products", value: stats.totalProducts, sub: "In catalog" },
              { label: "Total Customers", value: stats.totalUsers, sub: "Registered users" },
              { label: "Total Orders", value: stats.totalOrders, sub: "Placed orders" },
              { label: "Revenue", value: `₱${Number(stats.totalRevenue || 0).toLocaleString()}`, sub: "Total sales" },
            ].map(s => (
              <div className="stat-card" key={s.label}>
                <div className="stat-label">{s.label}</div>
                <div className="stat-value">{s.value}</div>
                <div className="stat-sub">{s.sub}</div>
              </div>
            ))}
          </div>
          <div className="table-wrap">
            <div className="table-head"><h3>📋 Recent Orders</h3></div>
            <table>
              <thead><tr><th>Order ID</th><th>Customer</th><th>Total</th><th>Status</th><th>Date</th></tr></thead>
              <tbody>
                {orders.length === 0
                  ? <tr><td colSpan={5} style={{ textAlign: "center", color: "var(--gray)" }}>No orders yet</td></tr>
                  : orders.slice(0, 5).map(o => (
                    <tr key={o.id}>
                      <td style={{ fontWeight: 600 }}>#{o.id}</td>
                      <td>{o.customer_name || "Customer"}</td>
                      <td>₱{Number(o.total).toLocaleString()}</td>
                      <td>{statusBadge(o.status)}</td>
                      <td style={{ fontSize: 12, color: "var(--gray)" }}>{new Date(o.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === "products" && (
        <div className="table-wrap">
          <div className="table-head">
            <h3>📦 Products ({products.length})</h3>
            <button className="btn btn-success btn-sm" onClick={() => openCreate("product")}>+ Add Product</button>
          </div>
          <table>
            <thead><tr><th>Product</th><th>Brand</th><th>Category</th><th>Price</th><th>Stock</th><th>Actions</th></tr></thead>
            <tbody>
              {products.map(p => (
                <tr key={p.id}>
                  <td><span style={{ marginRight: 6 }}>{p.image}</span>{p.name}</td>
                  <td>{p.brand}</td>
                  <td><span className="badge badge-blue">{p.category}</span></td>
                  <td style={{ fontWeight: 600 }}>₱{Number(p.price).toLocaleString()}</td>
                  <td><span className={`badge ${p.stock > 5 ? "badge-green" : p.stock > 0 ? "badge-orange" : "badge-red"}`}>{p.stock} units</span></td>
                  <td>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn btn-outline btn-sm" onClick={() => openEdit("product", p)}>✏️ Edit</button>
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete("product", p.id, p.name)}>🗑 Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === "users" && (
        <div className="table-wrap">
          <div className="table-head">
            <h3>👥 Users ({users.length})</h3>
            <button className="btn btn-success btn-sm" onClick={() => openCreate("user")}>+ Add User</button>
          </div>
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Role</th><th>Joined</th><th>Actions</th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ fontWeight: 600 }}>{u.name}</td>
                  <td style={{ color: "var(--gray)" }}>{u.email}</td>
                  <td style={{ fontSize: 13 }}>{u.phone || "—"}</td>
                  <td><span className={`badge ${u.role === "admin" ? "badge-purple" : "badge-blue"}`}>{u.role}</span></td>
                  <td style={{ fontSize: 12, color: "var(--gray)" }}>{new Date(u.created_at).toLocaleDateString()}</td>
                  <td>
                    <div style={{ display: "flex", gap: 6 }}>
                      <button className="btn btn-outline btn-sm" onClick={() => openEdit("user", u)}>✏️ Edit</button>
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete("user", u.id, u.name)}>🗑 Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === "orders" && (
        <div className="table-wrap">
          <div className="table-head"><h3>📋 Orders ({orders.length})</h3></div>
          <table>
            <thead><tr><th>Order ID</th><th>Customer</th><th>Total</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead>
            <tbody>
              {orders.length === 0
                ? <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--gray)", padding: 32 }}>No orders yet</td></tr>
                : orders.map(o => (
                  <tr key={o.id}>
                    <td style={{ fontWeight: 600 }}>#{o.id}</td>
                    <td>{o.customer_name || "Customer"}</td>
                    <td>₱{Number(o.total).toLocaleString()}</td>
                    <td>{statusBadge(o.status)}</td>
                    <td style={{ fontSize: 12, color: "var(--gray)" }}>{new Date(o.created_at).toLocaleDateString()}</td>
                    <td>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn btn-outline btn-sm" onClick={() => openEdit("order", o)}>✏️ Status</button>
                        <button className="btn btn-danger btn-sm" onClick={() => handleDelete("order", o.id, `#${o.id}`)}>🗑 Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === "security" && (
        <div className="table-wrap">
          <div className="table-head"><h3>🔐 Security Event Log</h3></div>
          <table>
            <thead><tr><th>Time</th><th>Event</th><th>User/Source</th><th>Status</th></tr></thead>
            <tbody>
              {[...secLog].reverse().map((log, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: "monospace", fontSize: 12 }}>{log.time}</td>
                  <td>{log.event}</td>
                  <td style={{ color: "var(--gray)", fontSize: 13 }}>{log.user}</td>
                  <td><span className={`badge ${log.type === "ok" ? "badge-green" : "badge-red"}`}>{log.type === "ok" ? "✓ OK" : "⛔ Blocked"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────

export default function SoleSpectrum() {
  const [page, setPage] = useState("login");
  const [user, setUser] = useState(null);
  const [cart, setCart] = useState([]);
  const [csrfToken] = useState(generateCSRFToken);
  const [inactivityWarning, setInactivityWarning] = useState(false);

  const INACTIVITY_LIMIT = 10 * 60 * 1000; // 10 minutes
  const WARNING_BEFORE = 60 * 1000; // warn 1 min before
  const inactivityTimer = useRef(null);
  const warningTimer = useRef(null);

  const resetInactivityTimer = () => {
    if (!user) return;
    clearTimeout(inactivityTimer.current);
    clearTimeout(warningTimer.current);
    setInactivityWarning(false);
    warningTimer.current = setTimeout(() => setInactivityWarning(true), INACTIVITY_LIMIT - WARNING_BEFORE);
    inactivityTimer.current = setTimeout(() => {
      handleLogout();
      alert("You have been logged out due to inactivity.");
    }, INACTIVITY_LIMIT);
  };

  useEffect(() => {
    if (!user) return;
    const events = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    events.forEach(e => window.addEventListener(e, resetInactivityTimer));
    resetInactivityTimer();
    return () => {
      events.forEach(e => window.removeEventListener(e, resetInactivityTimer));
      clearTimeout(inactivityTimer.current);
      clearTimeout(warningTimer.current);
    };
  }, [user]);

  const handleLogin = (u) => { setUser(u); setPage("browse"); };
  const handleRegister = (u) => { setUser(u); setPage("browse"); };
  const handleLogout = () => { setUser(null); setCart([]); localStorage.removeItem("token"); setPage("login"); };

  const addToCart = (product) => {
    setCart(c => {
      const ex = c.find(i => i.id === product.id);
      return ex ? c.map(i => i.id === product.id ? { ...i, qty: i.qty + 1 } : i) : [...c, { ...product, qty: 1 }];
    });
  };

  const updateCart = (id, qty) => {
    if (qty <= 0) setCart(c => c.filter(i => i.id !== id));
    else setCart(c => c.map(i => i.id === id ? { ...i, qty } : i));
  };

  const cartCount = cart.reduce((s, i) => s + i.qty, 0);
  const navPages = user ? (user.role === "admin" ? ["browse", "admin"] : ["browse"]) : [];
  const labels = { browse: "Shop", admin: "Admin" };

  return (
    <>
      <style>{css}</style>

      {/* Inactivity Warning Banner */}
      {inactivityWarning && user && (
        <div className="inactivity-banner">
          <span>⚠️ You will be logged out due to inactivity in 1 minute.</span>
          <button className="btn btn-outline btn-sm" onClick={resetInactivityTimer} style={{ borderColor: "var(--orange)", color: "var(--orange)" }}>
            Stay Logged In
          </button>
        </div>
      )}
      {user && (
        <nav className="nav">
          <div className="nav-logo" onClick={() => setPage("browse")}>Sole<span>Spectrum</span></div>
          <div className="nav-links">
            {navPages.map(p => (
              <button key={p} className={`nav-link ${page === p ? "active" : ""}`} onClick={() => setPage(p)}>{labels[p]}</button>
            ))}
          </div>
          <div className="nav-right">
            <span className="user-chip">👤 {user.name}</span>
            <button className="cart-btn" onClick={() => setPage("cart")}>
              🛒 Cart {cartCount > 0 && <span className="cart-badge">{cartCount}</span>}
            </button>
            <button className="btn btn-outline btn-sm" onClick={handleLogout}>Logout</button>
          </div>
        </nav>
      )}
      {page === "login" && <LoginPage onLogin={handleLogin} onGoRegister={() => setPage("register")} csrfToken={csrfToken} />}
      {page === "register" && <RegisterPage onRegister={handleRegister} onGoLogin={() => setPage("login")} />}
      {page === "browse" && <BrowsePage onAddToCart={addToCart} />}
      {page === "cart" && <CartPage cart={cart} onUpdate={updateCart} onRemove={id => setCart(c => c.filter(i => i.id !== id))} onCheckout={() => setPage("checkout")} />}
      {page === "checkout" && <CheckoutPage cart={cart} user={user} csrfToken={csrfToken} onSuccess={() => { setCart([]); setPage("browse"); }} />}
      {page === "admin" && user?.role === "admin" && <AdminPage user={user} />}
    </>
  );
}