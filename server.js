require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { Resend } = require('resend');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Clients ───────────────────────────────────────────
// Gumroad Product ID — set in Render env vars as GUMROAD_PRODUCT_ID
// Get it from your Gumroad product URL: gumroad.com/l/YOUR_PRODUCT_ID

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const resend = new Resend(process.env.RESEND_API_KEY);

// ─── Middleware ─────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json({ limit: '2mb' }));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' }
});
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { error: 'Too many OTP requests. Please try again in 1 hour.' }
});

// ─── Auth Middleware ────────────────────────────────────
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ─── OTP helpers ────────────────────────────────────────
function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendOTPEmail(email, otp, name) {
  const html = `
  <!DOCTYPE html>
  <html>
  <head><meta charset="UTF-8"></head>
  <body style="margin:0;padding:0;background:#f8f7f4;font-family:'Segoe UI',sans-serif">
    <div style="max-width:480px;margin:40px auto;background:#ffffff;border-radius:20px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
      <div style="background:linear-gradient(135deg,#1a56db,#4a7eff);padding:36px 40px;text-align:center">
        <div style="font-size:32px;margin-bottom:8px">🎯</div>
        <div style="font-size:22px;font-weight:800;color:white;letter-spacing:-0.5px">HabitWise Pro</div>
        <div style="font-size:13px;color:rgba(255,255,255,0.75);margin-top:4px">Password Reset Request</div>
      </div>
      <div style="padding:40px">
        <p style="font-size:16px;color:#111;margin-bottom:8px">Hi <strong>${name || 'there'}</strong>,</p>
        <p style="font-size:14px;color:#5a5750;line-height:1.6;margin-bottom:28px">
          We received a request to reset your HabitWise Pro password. Use the OTP code below. It expires in <strong>10 minutes</strong>.
        </p>
        <div style="background:#f0f4ff;border:2px dashed #1a56db;border-radius:16px;padding:28px;text-align:center;margin-bottom:28px">
          <div style="font-size:11px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;color:#5a5750;margin-bottom:10px">Your OTP Code</div>
          <div style="font-size:42px;font-weight:800;letter-spacing:12px;color:#1a56db;font-family:'Courier New',monospace">${otp}</div>
        </div>
        <p style="font-size:13px;color:#9a9690;line-height:1.6">
          If you didn't request this, you can safely ignore this email. Your password won't change.
        </p>
        <hr style="border:none;border-top:1px solid #e4e1db;margin:28px 0">
        <p style="font-size:12px;color:#9a9690;text-align:center">© 2026 Dinesh R · HabitWise Pro · All rights reserved</p>
      </div>
    </div>
  </body>
  </html>`;

  await resend.emails.send({
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
    to: email,
    subject: `${otp} is your HabitWise Pro reset code`,
    html
  });
}

// ════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════

// Health check
app.get('/', (req, res) => res.json({ status: 'HabitWise Pro API running ✓' }));

// ─── SIGNUP ──────────────────────────────────
app.post('/auth/signup', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Please fill in all fields.' });
  if (name.trim().length < 2)
    return res.status(400).json({ error: 'Please enter your full name.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email))
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  // Check existing
  const { data: existing } = await supabase
    .from('users')
    .select('id')
    .eq('email', email.toLowerCase())
    .single();

  if (existing)
    return res.status(409).json({ error: 'An account already exists with this email.' });

  const passwordHash = await bcrypt.hash(password, 12);

  const { data: user, error } = await supabase
    .from('users')
    .insert({ name: name.trim(), email: email.toLowerCase(), password_hash: passwordHash })
    .select('id, name, email')
    .single();

  if (error) return res.status(500).json({ error: 'Failed to create account. Please try again.' });

  const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// ─── LOGIN ───────────────────────────────────
app.post('/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Please fill in both fields.' });

  const { data: user } = await supabase
    .from('users')
    .select('id, name, email, password_hash')
    .eq('email', email.toLowerCase())
    .single();

  if (!user)
    return res.status(401).json({ error: 'No account found with this email.' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match)
    return res.status(401).json({ error: 'Wrong password. Please try again.' });

  const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
});

// ─── FORGOT PASSWORD — Send OTP ──────────────
app.post('/auth/forgot-password', otpLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const { data: user } = await supabase
    .from('users')
    .select('id, name, email')
    .eq('email', email.toLowerCase())
    .single();

  // Always return success (don't reveal if email exists)
  if (!user) return res.json({ message: 'If that email exists, an OTP has been sent.' });

  const otp = generateOTP();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min

  // Store OTP
  await supabase.from('otp_codes').upsert({
    user_id: user.id,
    email: user.email,
    otp_hash: await bcrypt.hash(otp, 10),
    expires_at: expiresAt,
    used: false
  }, { onConflict: 'email' });

  try {
    await sendOTPEmail(user.email, otp, user.name);
  } catch (err) {
    console.error('Email send failed:', err);
    return res.status(500).json({ error: 'Failed to send OTP email. Please try again.' });
  }

  res.json({ message: 'OTP sent to your email. Check your inbox (and spam folder).' });
});

// ─── VERIFY OTP ──────────────────────────────
app.post('/auth/verify-otp', authLimiter, async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP are required.' });

  const { data: record } = await supabase
    .from('otp_codes')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();

  if (!record) return res.status(400).json({ error: 'No OTP request found. Please request a new one.' });
  if (record.used) return res.status(400).json({ error: 'This OTP has already been used.' });
  if (new Date(record.expires_at) < new Date()) return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });

  const match = await bcrypt.compare(otp, record.otp_hash);
  if (!match) return res.status(400).json({ error: 'Incorrect OTP. Please check and try again.' });

  // Mark used
  await supabase.from('otp_codes').update({ used: true }).eq('email', email.toLowerCase());

  // Issue a short-lived reset token
  const resetToken = jwt.sign({ userId: record.user_id, email: record.email, type: 'reset' }, process.env.JWT_SECRET, { expiresIn: '15m' });
  res.json({ resetToken });
});

// ─── RESET PASSWORD ──────────────────────────
app.post('/auth/reset-password', authLimiter, async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) return res.status(400).json({ error: 'Missing required fields.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  let decoded;
  try {
    decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
    if (decoded.type !== 'reset') throw new Error('Invalid token type');
  } catch {
    return res.status(400).json({ error: 'Reset link has expired. Please start over.' });
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);
  const { error } = await supabase
    .from('users')
    .update({ password_hash: passwordHash })
    .eq('id', decoded.userId);

  if (error) return res.status(500).json({ error: 'Failed to update password. Please try again.' });

  res.json({ message: 'Password updated successfully! You can now sign in.' });
});

// ─── GET HABITS ──────────────────────────────
app.get('/habits', authRequired, async (req, res) => {
  const { data, error } = await supabase
    .from('habits')
    .select('*')
    .eq('user_id', req.userId)
    .order('created_at', { ascending: true });

  if (error) return res.status(500).json({ error: 'Failed to load habits.' });
  res.json(data || []);
});

// ─── SAVE ALL HABITS (full sync) ─────────────
app.put('/habits', authRequired, async (req, res) => {
  const { habits } = req.body;
  if (!Array.isArray(habits)) return res.status(400).json({ error: 'Invalid data.' });

  // Delete all existing and re-insert (simple full sync)
  await supabase.from('habits').delete().eq('user_id', req.userId);

  if (habits.length > 0) {
    const rows = habits.map(h => ({
      user_id: req.userId,
      habit_id: h.id,
      name: h.name,
      emoji: h.emoji,
      color: h.color,
      category: h.category,
      completions: h.completions || {},
      note: h.note || '',
      created_on: h.createdOn || new Date().toISOString().slice(0, 10),
      goal_num: h.goalNum || 0,
      goal_unit: h.goalUnit || '',
      goal_progress: h.goalProgress || {}
    }));

    const { error } = await supabase.from('habits').insert(rows);
    if (error) return res.status(500).json({ error: 'Failed to save habits.' });
  }

  res.json({ message: 'Habits saved.' });
});

// ─── GET USER SETTINGS ───────────────────────
app.get('/settings', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('user_settings')
    .select('*')
    .eq('user_id', req.userId)
    .single();

  res.json(data || { dark_mode: false, reminder_dismissed: '' });
});

// ─── SAVE USER SETTINGS ──────────────────────
app.put('/settings', authRequired, async (req, res) => {
  const { darkMode, reminderDismissed } = req.body;

  await supabase.from('user_settings').upsert({
    user_id: req.userId,
    dark_mode: darkMode ?? false,
    reminder_dismissed: reminderDismissed || ''
  }, { onConflict: 'user_id' });

  res.json({ message: 'Settings saved.' });
});

// ─── VERIFY GUMROAD LICENSE KEY ──────────────
app.post('/auth/verify-license', authLimiter, async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ error: 'License key is required.' });

  const key = licenseKey.trim().toUpperCase();

  // Check if already used in our DB
  const { data: existing } = await supabase
    .from('license_keys')
    .select('*')
    .eq('key', key)
    .single();

  if (existing && existing.activated) {
    return res.status(400).json({ error: 'This license key has already been activated on another account.' });
  }

  // Verify with Gumroad API
  try {
    const gumRes = await fetch('https://api.gumroad.com/v2/licenses/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        product_id: process.env.GUMROAD_PRODUCT_ID,
        license_key: key,
        increment_uses_count: 'false'
      })
    });
    const gumData = await gumRes.json();

    if (!gumData.success) {
      return res.status(400).json({ error: 'Invalid license key. Please check and try again.' });
    }

    // Check not refunded
    if (gumData.purchase?.refunded) {
      return res.status(400).json({ error: 'This license key belongs to a refunded purchase.' });
    }

    // Store in DB as valid (not yet activated — activated on signup)
    await supabase.from('license_keys').upsert({
      key,
      gumroad_sale_id: gumData.purchase?.sale_id || '',
      buyer_email: gumData.purchase?.email || '',
      activated: false
    }, { onConflict: 'key' });

    res.json({ valid: true, buyerEmail: gumData.purchase?.email || '' });

  } catch (err) {
    console.error('Gumroad verify error:', err);
    return res.status(500).json({ error: 'Could not verify license. Please try again.' });
  }
});

// ─── ACTIVATE LICENSE ON SIGNUP ──────────────
// Called after successful signup to mark key as used
app.post('/auth/activate-license', authRequired, async (req, res) => {
  const { licenseKey } = req.body;
  if (!licenseKey) return res.status(400).json({ error: 'License key required.' });

  const key = licenseKey.trim().toUpperCase();

  await supabase.from('license_keys').update({
    activated: true,
    activated_by: req.userId,
    activated_at: new Date().toISOString()
  }).eq('key', key);

  // Also save on user record
  await supabase.from('users').update({ license_key: key }).eq('id', req.userId);

  res.json({ message: 'License activated.' });
});

// ─── START ───────────────────────────────────
app.listen(PORT, () => console.log(`HabitWise API running on port ${PORT}`));
