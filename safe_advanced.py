# app.py  —  SecureTx Complete App
# ================================================
# SETUP:
#   pip install flask flask-sqlalchemy flask-login flask-wtf cryptography bcrypt
#
# RUN:
#   python app.py
#
# OPEN:
#   http://127.0.0.1:5000
#
# ADMIN LOGIN:
#   admin@example.com  /  adminpass
# USER LOGIN:
#   user@example.com   /  password
# ================================================

from flask import Flask, render_template_string, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import os, secrets, hashlib, hmac, bcrypt

# ── App setup ────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY']                  = 'securetx-secret-2024'
app.config['SQLALCHEMY_DATABASE_URI']     = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED']            = True

db       = SQLAlchemy(app)
csrf     = CSRFProtect(app)
lm       = LoginManager(app)
lm.login_view = 'login'

KEY    = Fernet.generate_key()
fernet = Fernet(KEY)

# ── Attack detection config ──────────────────────────────────────
MAX_FAILED_LOGINS    = 5
LOCKOUT_SECONDS      = 300
MAX_TX_PER_MINUTE    = 5
AMOUNT_ANOMALY_MULT  = 5.0
AMOUNT_HARD_LIMIT    = 50000
MAX_OTP_REQUESTS     = 3
OTP_BOMB_WINDOW      = 120
REPLAY_WINDOW        = 30

# In-memory trackers
_failed   = defaultdict(list)
_ip_fail  = defaultdict(list)
_velocity = defaultdict(list)
_otpreq   = defaultdict(list)
_hashes   = defaultdict(list)
_otps     = {}

# ════════════════════════════════════════════════════════════════
# MODELS
# ════════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(160), unique=True, nullable=False)
    password   = db.Column(db.LargeBinary, nullable=False)
    is_admin   = db.Column(db.Boolean, default=False)
    is_locked  = db.Column(db.Boolean, default=False)
    lock_until = db.Column(db.DateTime, nullable=True)

class Transaction(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(160), nullable=False)
    token      = db.Column(db.String(64), unique=True, nullable=False)
    pan_enc    = db.Column(db.LargeBinary, nullable=False)
    amt_enc    = db.Column(db.LargeBinary, nullable=False)
    pan_mask   = db.Column(db.String(32), nullable=False)
    status     = db.Column(db.String(20), default='Pending')
    risk_score = db.Column(db.Integer, default=0)
    risk_flags = db.Column(db.String(256), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    alert_type  = db.Column(db.String(64), nullable=False)
    severity    = db.Column(db.String(16), nullable=False)
    email       = db.Column(db.String(160), nullable=True)
    ip          = db.Column(db.String(64), nullable=True)
    description = db.Column(db.String(512), nullable=False)
    resolved    = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(160), nullable=False)
    action     = db.Column(db.String(80), nullable=False)
    detail     = db.Column(db.String(255), nullable=True)
    ip         = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# ════════════════════════════════════════════════════════════════
# ATTACK DETECTION ENGINE
# ════════════════════════════════════════════════════════════════
def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()

def prune(lst, seconds):
    cut = datetime.utcnow() - timedelta(seconds=seconds)
    return [t for t in lst if t > cut]

def save_alert(atype, severity, desc, email=None, ip=None):
    em = email or (current_user.email if current_user.is_authenticated else None)
    a  = Alert(alert_type=atype, severity=severity,
                email=em, ip=ip or get_ip(), description=desc)
    db.session.add(a)
    db.session.add(AuditLog(email=em or 'anon', action='ALERT:'+atype,
                             detail=desc, ip=ip or get_ip()))
    db.session.commit()
    print(f'[🚨 {severity}] {atype}: {desc}')

# 1. Brute force
def check_brute(email):
    ip = get_ip()
    _ip_fail[ip] = prune(_ip_fail[ip], 600)
    if len(_ip_fail[ip]) >= 10:
        return True, 600, 'IP_BLOCKED'
    u = User.query.filter_by(email=email).first()
    if u and u.is_locked and u.lock_until:
        if datetime.utcnow() < u.lock_until:
            rem = int((u.lock_until - datetime.utcnow()).total_seconds())
            return True, rem, 'LOCKED'
        u.is_locked = False
        u.lock_until = None
        db.session.commit()
    return False, 0, None

def record_fail(email):
    ip  = get_ip()
    now = datetime.utcnow()
    _failed[email] = prune(_failed[email], LOCKOUT_SECONDS)
    _failed[email].append(now)
    _ip_fail[ip].append(now)
    n = len(_failed[email])
    if n >= MAX_FAILED_LOGINS:
        u = User.query.filter_by(email=email).first()
        if u:
            u.is_locked  = True
            u.lock_until = now + timedelta(seconds=LOCKOUT_SECONDS)
            db.session.commit()
        save_alert('BRUTE_FORCE_LOGIN', 'CRITICAL',
            f'Account {email} locked after {n} failed attempts from {ip}',
            email=email, ip=ip)
    elif n >= 3:
        save_alert('SUSPICIOUS_LOGIN', 'HIGH',
            f'{n} failed attempts for {email} from {ip}',
            email=email, ip=ip)

def clear_fails(email):
    _failed[email] = []

# 2. Velocity
def check_velocity(email):
    _velocity[email] = prune(_velocity[email], 60)
    n = len(_velocity[email])
    if n >= MAX_TX_PER_MINUTE:
        save_alert('TX_VELOCITY', 'HIGH',
            f'{n} transactions in 60s for {email}', email=email)
        return True
    _velocity[email].append(datetime.utcnow())
    return False

# 3. Amount anomaly
def check_amount(email, amount):
    flags = []
    if amount >= AMOUNT_HARD_LIMIT:
        flags.append('LARGE_TX')
        save_alert('LARGE_TRANSACTION', 'HIGH',
            f'Transaction ₹{amount:.0f} exceeds limit for {email}', email=email)
    txs = Transaction.query.filter_by(email=email).all()
    if txs:
        amts = []
        for t in txs:
            try: amts.append(float(fernet.decrypt(t.amt_enc).decode()))
            except: pass
        if amts:
            avg = sum(amts) / len(amts)
            if avg > 0 and amount > avg * AMOUNT_ANOMALY_MULT:
                flags.append('AMOUNT_ANOMALY')
                save_alert('AMOUNT_ANOMALY', 'MEDIUM',
                    f'₹{amount:.0f} is {amount/avg:.1f}x above avg ₹{avg:.0f} for {email}',
                    email=email)
    return flags

# 4. OTP bombing
def check_otp_bomb(email):
    _otpreq[email] = prune(_otpreq[email], OTP_BOMB_WINDOW)
    if len(_otpreq[email]) >= MAX_OTP_REQUESTS:
        save_alert('OTP_BOMBING', 'HIGH',
            f'{len(_otpreq[email])} OTP requests in {OTP_BOMB_WINDOW}s for {email}',
            email=email)
        return True
    _otpreq[email].append(datetime.utcnow())
    return False

# 5. Replay attack
def check_replay(email, pan, amount):
    h   = hashlib.sha256(f'{email}:{pan}:{amount}'.encode()).hexdigest()
    now = datetime.utcnow()
    _hashes[email] = [(x,t) for x,t in _hashes[email]
                      if t > now - timedelta(seconds=REPLAY_WINDOW)]
    for x, _ in _hashes[email]:
        if x == h:
            save_alert('REPLAY_ATTACK', 'CRITICAL',
                f'Duplicate tx PAN ...{pan[-4:]} ₹{amount} for {email}', email=email)
            return True
    _hashes[email].append((h, now))
    return False

# 6. Risk score
def calc_risk(flags):
    w = {'VELOCITY_FRAUD':40,'LARGE_TX':35,'AMOUNT_ANOMALY':25,'REPLAY_ATTACK':50}
    return min(100, sum(w.get(f, 10) for f in flags))

def risk_label(score):
    if score >= 70: return 'CRITICAL', '#dc2626'
    if score >= 40: return 'HIGH',     '#ea580c'
    if score >= 20: return 'MEDIUM',   '#d97706'
    return 'LOW', '#16a34a'

# ════════════════════════════════════════════════════════════════
# OTP
# ════════════════════════════════════════════════════════════════
def send_otp(email, purpose, ident=''):
    check_otp_bomb(email)
    k   = f'{email}:{purpose}:{ident}'
    rec = _otps.get(k)
    now = datetime.utcnow()
    if rec and (now - rec[2]).total_seconds() < 15:
        return False
    code = f'{secrets.randbelow(10**6):06d}'
    _otps[k] = (code, now + timedelta(seconds=300), now)
    print(f'[OTP] {email} => {code}  (purpose={purpose})')
    return True

def verify_otp(email, purpose, ident, code):
    k   = f'{email}:{purpose}:{ident}'
    rec = _otps.get(k)
    if not rec:
        return False
    real, exp, _ = rec
    if datetime.utcnow() > exp:
        del _otps[k]
        return False
    if hmac.compare_digest(code, real):
        del _otps[k]
        return True
    return False

# ════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════
def enc(s):  return fernet.encrypt(s.encode())
def dec(b):  return fernet.decrypt(b).decode()
def mask(p): return '**** **** **** ' + p.strip()[-4:]

def admin_only(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return fn(*a, **kw)
    return w

@lm.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))

# ════════════════════════════════════════════════════════════════
# FORMS
# ════════════════════════════════════════════════════════════════
class LoginForm(FlaskForm):
    email    = StringField('Email',    validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    email    = StringField('Email',    validators=[DataRequired(), Length(max=160)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class TxForm(FlaskForm):
    pan    = StringField('Card / PAN', validators=[DataRequired(),
               Regexp(r'^\d{12,19}$', message='12-19 digits')])
    amount = StringField('Amount ₹',   validators=[DataRequired(),
               Regexp(r'^\d+(?:\.\d{1,2})?$', message='e.g. 1500.00')])

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Regexp(r'^\d{6}$')])

# ════════════════════════════════════════════════════════════════
# BASE HTML TEMPLATE  (white theme)
# ════════════════════════════════════════════════════════════════
BASE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecureTx</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  body { background:#f1f5f9; font-family:'Inter',sans-serif; color:#1e293b; }
  .mono { font-family:'JetBrains Mono',monospace; }

  /* SIDEBAR */
  .sidebar {
    position:fixed; top:0; left:0; bottom:0; width:230px;
    background:linear-gradient(180deg,#1e3a5f,#0f2744);
    padding:24px 14px; overflow-y:auto; z-index:100;
    box-shadow:4px 0 20px rgba(0,0,0,0.15);
  }
  .sidebar .brand { font-size:1.1rem; font-weight:700; color:#fff; margin-bottom:2px; }
  .sidebar .brand-sub { font-size:.72rem; color:#94a3b8; margin-bottom:24px; padding-left:4px; }
  .sidebar .sec-label { font-size:.65rem; color:#64748b; text-transform:uppercase;
    letter-spacing:1.5px; padding:10px 8px 4px; }
  .sidebar a {
    display:flex; align-items:center; gap:9px; color:#cbd5e1;
    text-decoration:none; padding:8px 10px; border-radius:8px;
    font-size:.86rem; font-weight:500; margin-bottom:2px;
    transition:all .15s;
  }
  .sidebar a:hover { background:rgba(255,255,255,.1); color:#fff; }
  .sidebar a.active { background:rgba(59,130,246,.25); color:#93c5fd; font-weight:600; }
  .sidebar a.logout { color:#fca5a5; }
  .sidebar a.logout:hover { background:rgba(239,68,68,.15); }
  .sidebar a.alert-nav {
    background:rgba(239,68,68,.12); color:#fca5a5;
    border:1px solid rgba(239,68,68,.3);
    animation:blink-border 2s infinite;
  }
  @keyframes blink-border {
    0%,100% { border-color:rgba(239,68,68,.3); }
    50%      { border-color:rgba(239,68,68,.7); }
  }
  .alert-count {
    margin-left:auto; background:#ef4444; color:#fff;
    border-radius:10px; padding:1px 7px;
    font-size:.68rem; font-family:'JetBrains Mono',monospace;
  }
  .sidebar-user {
    margin-top:20px; padding-top:14px;
    border-top:1px solid rgba(255,255,255,.1);
    font-size:.75rem; color:#64748b;
  }
  .sidebar-user strong { display:block; color:#e2e8f0; font-size:.8rem; margin-top:3px; }

  /* MAIN */
  .main { margin-left:230px; padding:28px 32px; }

  /* CARDS */
  .card-white {
    background:#fff; border:1px solid #e2e8f0; border-radius:12px;
    padding:20px; box-shadow:0 1px 3px rgba(0,0,0,.05);
  }
  .stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:14px; margin-bottom:24px; }
  .stat-card {
    background:#fff; border:1px solid #e2e8f0; border-radius:12px;
    padding:18px; box-shadow:0 1px 3px rgba(0,0,0,.04);
    transition:all .2s;
  }
  .stat-card:hover { border-color:#3b82f6; box-shadow:0 4px 12px rgba(59,130,246,.1); transform:translateY(-2px); }
  .stat-card .lbl { font-size:.7rem; color:#64748b; font-weight:600; text-transform:uppercase; letter-spacing:.8px; margin-bottom:8px; }
  .stat-card .val { font-family:'JetBrains Mono',monospace; font-size:1.8rem; font-weight:700; color:#2563eb; }
  .stat-card .sub { font-size:.75rem; color:#94a3b8; margin-top:4px; }
  .stat-card.red   .val { color:#dc2626; }
  .stat-card.amber .val { color:#d97706; }
  .stat-card.green .val { color:#16a34a; }

  /* ATTACK BANNER */
  .attack-banner {
    display:flex; align-items:center; gap:12px;
    background:#fff5f5; border:1px solid #fecaca; border-radius:10px;
    padding:12px 16px; margin-bottom:20px; font-size:.87rem;
    box-shadow:0 2px 8px rgba(220,38,38,.08);
    animation:glow 2s infinite;
  }
  @keyframes glow {
    0%,100% { box-shadow:0 2px 8px rgba(220,38,38,.08); }
    50%      { box-shadow:0 4px 16px rgba(220,38,38,.2); }
  }
  .attack-banner .icon { font-size:1.3rem; }
  .attack-banner .msg  { flex:1; color:#dc2626; font-weight:600; }
  .attack-banner .cnt  {
    background:#fee2e2; color:#dc2626; border:1px solid #fecaca;
    padding:2px 9px; border-radius:20px; font-size:.72rem;
    font-family:'JetBrains Mono',monospace;
  }
  .attack-banner a {
    color:#dc2626; font-size:.78rem; text-decoration:none;
    border:1px solid #fecaca; border-radius:6px; padding:3px 10px;
    background:#fff5f5;
  }
  .attack-banner a:hover { background:#fee2e2; }

  /* FORMS */
  .form-box {
    background:#fff; border:1px solid #e2e8f0; border-radius:14px;
    padding:28px; max-width:420px;
    box-shadow:0 2px 12px rgba(0,0,0,.06);
  }
  .form-label { font-size:.82rem; font-weight:600; color:#475569; margin-bottom:4px; }
  .form-control {
    border:1px solid #e2e8f0 !important; background:#f8fafc !important;
    color:#1e293b !important; border-radius:8px;
  }
  .form-control:focus {
    border-color:#3b82f6 !important; background:#fff !important;
    box-shadow:0 0 0 3px rgba(59,130,246,.12) !important;
  }
  .btn-primary { background:#2563eb; border-color:#2563eb; border-radius:8px; font-weight:600; }
  .btn-primary:hover { background:#1d4ed8; border-color:#1d4ed8; }
  .btn-success { border-radius:8px; font-weight:600; }
  .btn-danger  { border-radius:8px; font-weight:600; }
  .btn-sm      { border-radius:6px; }

  /* RISK BADGES */
  .risk { display:inline-flex; align-items:center; gap:4px; padding:3px 9px;
    border-radius:20px; font-size:.7rem; font-weight:700;
    font-family:'JetBrains Mono',monospace; }
  .risk-CRITICAL { background:#fee2e2; color:#dc2626; border:1px solid #fecaca; }
  .risk-HIGH     { background:#fff7ed; color:#ea580c; border:1px solid #fed7aa; }
  .risk-MEDIUM   { background:#fffbeb; color:#d97706; border:1px solid #fde68a; }
  .risk-LOW      { background:#f0fdf4; color:#16a34a; border:1px solid #bbf7d0; }

  /* SECURITY ALERT CARDS */
  .sec-card {
    background:#fff; border:1px solid #e2e8f0; border-radius:10px;
    padding:14px 16px; margin-bottom:10px;
    border-left:3px solid; box-shadow:0 1px 4px rgba(0,0,0,.04);
  }
  .sec-CRITICAL { background:#fff5f5; border-left-color:#dc2626; }
  .sec-HIGH     { background:#fff7ed; border-left-color:#ea580c; }
  .sec-MEDIUM   { background:#fffbeb; border-left-color:#d97706; }
  .sec-LOW      { background:#f0fdf4; border-left-color:#16a34a; }
  .sec-resolved { opacity:.45; }

  /* TABLE */
  .table { color:#1e293b !important; font-size:.84rem; }
  .table thead th {
    background:#f8fafc; color:#64748b; font-weight:700;
    font-size:.72rem; text-transform:uppercase; letter-spacing:.8px;
    border-color:#e2e8f0 !important;
  }
  .table td { border-color:#f1f5f9 !important; vertical-align:middle; }
  .table tbody tr:hover { background:#f8fafc !important; }

  /* PAGE HEADER */
  .ph { margin-bottom:22px; padding-bottom:14px; border-bottom:1px solid #e2e8f0; }
  .ph h2 { font-size:1.3rem; font-weight:700; margin-bottom:3px; }
  .ph p  { color:#64748b; font-size:.86rem; margin:0; }

  /* QUICK ACTION BUTTONS */
  .qa { display:flex; gap:12px; flex-wrap:wrap; }
  .qa-btn {
    display:flex; align-items:center; gap:9px; flex:1; min-width:140px;
    background:#fff; border:1px solid #e2e8f0; border-radius:10px;
    padding:13px 18px; font-weight:600; font-size:.88rem; color:#1e293b;
    text-decoration:none; transition:all .15s;
    box-shadow:0 1px 3px rgba(0,0,0,.04);
  }
  .qa-btn:hover { border-color:#3b82f6; color:#2563eb; background:#eff6ff; text-decoration:none; }
  .qa-btn.red   { border-color:#fecaca; color:#dc2626; background:#fff5f5; }
  .qa-btn.red:hover { background:#fee2e2; }

  /* FLASH */
  .alert-info    { background:#eff6ff; border-color:#bfdbfe; color:#1d4ed8; border-radius:8px; }
  .alert-warning { background:#fffbeb; border-color:#fde68a; color:#92400e; border-radius:8px; }
  .alert-danger  { background:#fff5f5; border-color:#fecaca; color:#991b1b; border-radius:8px; }

  /* CHATBOX */
  .chatbox {
    height:280px; overflow-y:auto; padding:14px;
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px;
    font-size:.86rem;
  }
  .you { color:#2563eb; margin-bottom:6px; }
  .bot { color:#16a34a; margin-bottom:6px; }
</style>
</head>
<body>

<div class="sidebar">
  <div class="brand">🔐 SecureTx</div>
  <div class="brand-sub">Secure Transaction System</div>

  {% if current_user.is_authenticated %}
    <div class="sec-label">Menu</div>
    <a href="{{ url_for('dashboard') }}"     class="{{ 'active' if request.endpoint=='dashboard' }}">🏠 Dashboard</a>
    <a href="{{ url_for('new_tx') }}"        class="{{ 'active' if request.endpoint=='new_tx' }}">💳 New Transaction</a>
    <a href="{{ url_for('history') }}"       class="{{ 'active' if request.endpoint=='history' }}">📜 My Transactions</a>
    <a href="{{ url_for('chatbot') }}"       class="{{ 'active' if request.endpoint=='chatbot' }}">🤖 Chatbot</a>

    {% if current_user.is_admin %}
      <div class="sec-label">Admin</div>
      <a href="{{ url_for('security') }}"
         class="alert-nav {{ 'active' if request.endpoint=='security' }}">
        🚨 Security Alerts
        {% if open_count %}<span class="alert-count">{{ open_count }}</span>{% endif %}
      </a>
      <a href="{{ url_for('audit') }}"       class="{{ 'active' if request.endpoint=='audit' }}">🧾 Audit Logs</a>
    {% endif %}

    <div class="sidebar-user">
      Logged in as
      <strong>{{ current_user.email }}</strong>
    </div>
    <a href="{{ url_for('logout') }}" class="logout" style="margin-top:10px">🚪 Logout</a>
  {% else %}
    <a href="{{ url_for('login') }}">🔑 Login</a>
    <a href="{{ url_for('register') }}">📝 Register</a>
  {% endif %}
</div>

<div class="main">
  {% with msgs = get_flashed_messages() %}
    {% for m in msgs %}
      <div class="alert alert-info mb-3">{{ m }}</div>
    {% endfor %}
  {% endwith %}

  {% if current_user.is_authenticated and banners %}
  <div class="attack-banner">
    <span class="icon">🚨</span>
    <span class="msg">{{ banners[0].alert_type.replace('_',' ') }}: {{ banners[0].description[:80] }}{% if banners[0].description|length > 80 %}…{% endif %}</span>
    <span class="cnt">{{ banners|length }} alert{{ 's' if banners|length != 1 }}</span>
    {% if current_user.is_admin %}
    <a href="{{ url_for('security') }}">View All →</a>
    {% endif %}
  </div>
  {% endif %}

  {{ body|safe }}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""


def render(body):
    banners    = []
    open_count = 0
    if current_user.is_authenticated:
        q = Alert.query.filter_by(resolved=False)
        if not current_user.is_admin:
            q = q.filter_by(email=current_user.email)
        banners    = q.order_by(Alert.created_at.desc()).limit(5).all()
        open_count = Alert.query.filter_by(resolved=False).count() if current_user.is_admin else 0
    return render_template_string(BASE, body=body, banners=banners, open_count=open_count)


# ════════════════════════════════════════════════════════════════
# ROUTES — AUTH
# ════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.')
            return redirect(url_for('register'))
        pw = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt())
        db.session.add(User(email=form.email.data, password=pw))
        db.session.commit()
        flash('Registered! Please log in.')
        return redirect(url_for('login'))
    body = render_template_string("""
    <div class='ph'><h2>Create Account</h2><p>Register to use SecureTx.</p></div>
    <div class='form-box'>
      <form method='post'>{{ form.hidden_tag() }}
        <div class='mb-3'><label class='form-label'>Email</label>
          {{ form.email(class='form-control', placeholder='you@example.com') }}</div>
        <div class='mb-3'><label class='form-label'>Password</label>
          {{ form.password(class='form-control') }}</div>
        <button class='btn btn-primary w-100'>Register</button>
      </form>
      <p class='mt-3 text-center' style='font-size:.83rem;color:#64748b'>
        Have an account? <a href='{{ url_for("login") }}'>Login</a></p>
    </div>""", form=form)
    return render(body)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        blocked, rem, reason = check_brute(email)
        if blocked:
            flash(f'{"IP blocked" if reason=="IP_BLOCKED" else "Account locked"}. Try again in {rem}s.')
            return redirect(url_for('login'))
        u = User.query.filter_by(email=email).first()
        if u and bcrypt.checkpw(form.password.data.encode(), u.password):
            clear_fails(email)
            login_user(u)
            db.session.add(AuditLog(email=email, action='LOGIN', ip=get_ip()))
            db.session.commit()
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        record_fail(email)
        flash('Invalid email or password.')
        return redirect(url_for('login'))
    body = render_template_string("""
    <div class='ph'><h2>Login</h2><p>Sign in to your account.</p></div>
    <div class='form-box'>
      <form method='post'>{{ form.hidden_tag() }}
        <div class='mb-3'><label class='form-label'>Email</label>
          {{ form.email(class='form-control', placeholder='admin@example.com') }}</div>
        <div class='mb-3'><label class='form-label'>Password</label>
          {{ form.password(class='form-control') }}</div>
        <button class='btn btn-primary w-100'>Sign In</button>
      </form>
      <p class='mt-3 text-center' style='font-size:.83rem;color:#64748b'>
        No account? <a href='{{ url_for("register") }}'>Register</a></p>
    </div>""", form=form)
    return render(body)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('login'))


# ════════════════════════════════════════════════════════════════
# ROUTES — DASHBOARD
# ════════════════════════════════════════════════════════════════
@app.route('/dashboard')
@login_required
def dashboard():
    txs  = Transaction.query.filter_by(email=current_user.email).all()
    amts = []
    for t in txs:
        try: amts.append(float(dec(t.amt_enc)))
        except: pass
    total    = sum(amts)
    pending  = sum(1 for t in txs if t.status == 'Pending')
    approved = sum(1 for t in txs if t.status == 'Approved')
    my_alerts = Alert.query.filter_by(email=current_user.email, resolved=False).count()

    body = render_template_string("""
    <div class='ph'><h2>Dashboard</h2><p>Welcome back, {{ email }}</p></div>

    <div class='stat-grid'>
      <div class='stat-card'>
        <div class='lbl'>Total Spending</div>
        <div class='val'>₹{{ "%.0f"|format(total) }}</div>
        <div class='sub'>{{ count }} transaction(s)</div>
      </div>
      <div class='stat-card amber'>
        <div class='lbl'>Pending</div>
        <div class='val'>{{ pending }}</div>
        <div class='sub'>Awaiting OTP confirmation</div>
      </div>
      <div class='stat-card green'>
        <div class='lbl'>Approved</div>
        <div class='val'>{{ approved }}</div>
        <div class='sub'>Confirmed transactions</div>
      </div>
      {% if my_alerts %}
      <div class='stat-card red'>
        <div class='lbl'>Security Alerts</div>
        <div class='val'>{{ my_alerts }}</div>
        <div class='sub'>On your account</div>
      </div>
      {% endif %}
    </div>

    <div class='ph' style='margin-top:8px'><h2 style='font-size:1rem'>Quick Actions</h2></div>
    <div class='qa'>
      <a href='{{ url_for("new_tx") }}'   class='qa-btn'>💳 New Transaction</a>
      <a href='{{ url_for("history") }}'  class='qa-btn'>📜 View History</a>
      <a href='{{ url_for("chatbot") }}'  class='qa-btn'>🤖 Chatbot</a>
      {% if is_admin %}
      <a href='{{ url_for("security") }}' class='qa-btn red'>🚨 Security Dashboard</a>
      {% endif %}
    </div>
    """, email=current_user.email, total=total, count=len(amts),
         pending=pending, approved=approved, my_alerts=my_alerts,
         is_admin=current_user.is_admin)
    return render(body)


# ════════════════════════════════════════════════════════════════
# ROUTES — TRANSACTIONS
# ════════════════════════════════════════════════════════════════
@app.route('/transaction', methods=['GET', 'POST'])
@login_required
def new_tx():
    form = TxForm()
    if form.validate_on_submit():
        pan    = form.pan.data.strip()
        amtstr = form.amount.data.strip()
        amt    = float(amtstr)
        email  = current_user.email
        flags  = []

        if check_velocity(email):
            flags.append('VELOCITY_FRAUD')
            flash('⚡ Velocity alert: Too many transactions in a short time!')

        if check_replay(email, pan, amtstr):
            flags.append('REPLAY_ATTACK')
            flash('🔁 Replay attack detected: Duplicate transaction!')

        flags += check_amount(email, amt)
        if 'AMOUNT_ANOMALY' in flags:
            flash('📊 Amount anomaly: Unusually high transaction detected!')
        if 'LARGE_TX' in flags:
            flash('🚨 Large transaction alert: Exceeds safe limit!')

        score = calc_risk(flags)
        tx = Transaction(
            email=email, token=secrets.token_hex(16),
            pan_enc=enc(pan), amt_enc=enc(amtstr),
            pan_mask=mask(pan), status='Pending',
            risk_score=score, risk_flags=','.join(flags)
        )
        db.session.add(tx)
        db.session.commit()

        send_otp(email, 'tx', str(tx.id))
        flash(f'OTP sent! Check terminal for the OTP code.')
        return redirect(url_for('confirm', tx_id=tx.id))

    body = render_template_string("""
    <div class='ph'><h2>New Transaction</h2>
      <p>Enter card details. Attack detection runs automatically.</p></div>
    <div class='form-box'>
      <form method='post'>{{ form.hidden_tag() }}
        <div class='mb-3'>
          <label class='form-label'>Card / PAN Number</label>
          {{ form.pan(class='form-control mono', placeholder='1234567812345678') }}
          <div class='form-text' style='color:#94a3b8;font-size:.76rem'>12–19 digits, numbers only</div>
        </div>
        <div class='mb-3'>
          <label class='form-label'>Amount (₹)</label>
          {{ form.amount(class='form-control mono', placeholder='1500.00') }}
        </div>
        <button class='btn btn-primary w-100'>Create & Send OTP</button>
      </form>
    </div>""", form=form)
    return render(body)


@app.route('/confirm/<int:tx_id>', methods=['GET', 'POST'])
@login_required
def confirm(tx_id):
    tx   = Transaction.query.get_or_404(tx_id)
    form = OTPForm()

    if tx.email != current_user.email and not current_user.is_admin:
        abort(403)

    if form.validate_on_submit():
        if verify_otp(current_user.email, 'tx', str(tx.id), form.otp.data):
            tx.status = 'Approved'
            db.session.add(AuditLog(email=current_user.email,
                                    action='TX_APPROVED',
                                    detail=f'tx_id={tx.id}', ip=get_ip()))
            db.session.commit()
            flash('✅ Transaction approved!')
            return redirect(url_for('history'))
        flash('❌ Invalid or expired OTP.')
        return redirect(url_for('confirm', tx_id=tx_id))

    lbl, color = risk_label(tx.risk_score)

    body = render_template_string("""
    <div class='ph'><h2>Confirm Transaction #{{ tx.id }}</h2>
      <p>Enter the OTP shown in the terminal to confirm.</p></div>
    <div class='form-box'>
      <div class='mb-3 p-3' style='background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0'>
        <div style='font-size:.75rem;color:#64748b;margin-bottom:2px'>Masked Card</div>
        <div class='mono' style='font-size:1rem;letter-spacing:2px'>{{ tx.pan_mask }}</div>
      </div>

      <div class='mb-3' style='display:flex;align-items:center;gap:10px'>
        <div style='font-size:.75rem;color:#64748b'>Risk Level</div>
        <span class='risk risk-{{ lbl }}'>● {{ lbl }} ({{ tx.risk_score }}/100)</span>
      </div>

      {% if tx.risk_flags %}
      <div class='mb-3 p-3' style='background:#fff5f5;border-radius:8px;border:1px solid #fecaca;font-size:.82rem;color:#dc2626'>
        ⚠️ Flags detected: <strong>{{ tx.risk_flags }}</strong>
      </div>
      {% endif %}

      <form method='post'>{{ form.hidden_tag() }}
        <div class='mb-3'>
          <label class='form-label'>6-Digit OTP</label>
          {{ form.otp(class='form-control mono', placeholder='000000', maxlength=6,
             style='letter-spacing:4px;font-size:1.1rem;text-align:center') }}
          <div class='form-text' style='color:#94a3b8;font-size:.76rem'>Check your terminal for the OTP</div>
        </div>
        <button class='btn btn-success w-100'>✓ Verify & Approve</button>
      </form>
      <a href='{{ url_for("resend", tx_id=tx.id) }}'
         style='display:block;text-align:center;margin-top:12px;font-size:.82rem;color:#64748b'>
        Resend OTP</a>
    </div>""", tx=tx, form=form, lbl=lbl, color=color)
    return render(body)


@app.route('/resend/<int:tx_id>')
@login_required
def resend(tx_id):
    tx = Transaction.query.get_or_404(tx_id)
    if tx.email != current_user.email:
        abort(403)
    ok = send_otp(current_user.email, 'tx', str(tx.id))
    flash('OTP resent. Check terminal.' if ok else 'Rate limited. Wait 15 seconds.')
    return redirect(url_for('confirm', tx_id=tx_id))


@app.route('/history')
@login_required
def history():
    txs  = Transaction.query.filter_by(email=current_user.email)\
                            .order_by(Transaction.created_at.desc()).all()
    rows = ''
    for t in txs:
        try:    amt = '₹' + dec(t.amt_enc)
        except: amt = '[ERR]'
        lbl, _ = risk_label(t.risk_score)
        status_color = '#16a34a' if t.status == 'Approved' else '#ea580c'
        rows += f"""<tr>
          <td class='mono'>{t.id}</td>
          <td class='mono'>{t.pan_mask}</td>
          <td class='mono'>{amt}</td>
          <td><span style='background:{"#f0fdf4" if t.status=="Approved" else "#fff7ed"};
            color:{status_color};border:1px solid {"#bbf7d0" if t.status=="Approved" else "#fed7aa"};
            padding:2px 8px;border-radius:20px;font-size:.72rem;font-weight:600'>{t.status}</span></td>
          <td><span class='risk risk-{lbl}'>● {lbl} {t.risk_score}</span></td>
          <td style='font-size:.78rem;color:#64748b'>{t.created_at.strftime('%d-%b %H:%M')}</td>
        </tr>"""

    body = render_template_string("""
    <div class='ph'><h2>My Transactions</h2>
      <p>All transactions with risk scores.</p></div>
    {% if rows %}
    <div class='card-white'>
      <table class='table table-hover mb-0'>
        <thead><tr><th>ID</th><th>Card</th><th>Amount</th>
          <th>Status</th><th>Risk</th><th>Date</th></tr></thead>
        <tbody>{{ rows|safe }}</tbody>
      </table>
    </div>
    {% else %}
    <div class='card-white text-center' style='padding:60px;color:#94a3b8'>
      No transactions yet.
      <a href='{{ url_for("new_tx") }}' style='color:#2563eb'>Create one →</a>
    </div>
    {% endif %}""", rows=rows)
    return render(body)


# ════════════════════════════════════════════════════════════════
# ROUTES — SECURITY DASHBOARD
# ════════════════════════════════════════════════════════════════
@app.route('/security')
@login_required
@admin_only
def security():
    sev  = request.args.get('sev')
    show = request.args.get('resolved', '0') == '1'

    q = Alert.query
    if sev:  q = q.filter_by(severity=sev)
    if not show: q = q.filter_by(resolved=False)
    alerts = q.order_by(Alert.created_at.desc()).limit(200).all()

    def cnt(s): return Alert.query.filter_by(severity=s, resolved=False).count()
    c_crit = cnt('CRITICAL')
    c_high = cnt('HIGH')
    c_med  = cnt('MEDIUM')
    c_all  = Alert.query.filter_by(resolved=False).count()

    # type breakdown
    types = db.session.query(Alert.alert_type, db.func.count(Alert.id))\
                      .filter_by(resolved=False)\
                      .group_by(Alert.alert_type).all()

    cards = ''
    for a in alerts:
        res_btn = ''
        if not a.resolved:
            res_btn = (f'<a href="/security/resolve/{a.id}" '
                       f'style="font-size:.72rem;padding:2px 9px;background:#f0fdf4;'
                       f'color:#16a34a;border:1px solid #bbf7d0;border-radius:6px;'
                       f'text-decoration:none">✓ Resolve</a>')
        done = '<span style="font-size:.72rem;color:#16a34a">✓ resolved</span>' if a.resolved else ''
        cards += f"""
        <div class='sec-card sec-{a.severity} {"sec-resolved" if a.resolved else ""}'>
          <div style='display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:5px'>
            <span class='risk risk-{a.severity}'>● {a.severity}</span>
            <strong style='font-size:.88rem'>{a.alert_type.replace("_"," ")}</strong>
            {done}
            <span style='margin-left:auto'>{res_btn}</span>
          </div>
          <div style='font-size:.84rem;color:#475569;margin-bottom:5px'>{a.description}</div>
          <div style='font-size:.72rem;color:#94a3b8;font-family:"JetBrains Mono",monospace'>
            🕐 {a.created_at.strftime('%d-%b-%Y %H:%M:%S')}
            {"&nbsp;|&nbsp; 👤 "+a.email if a.email else ""}
            {"&nbsp;|&nbsp; 🌐 "+a.ip if a.ip else ""}
          </div>
        </div>"""

    breakdown = ''.join(
        f'<div style="display:flex;justify-content:space-between;padding:8px 0;'
        f'border-bottom:1px solid #f1f5f9;font-size:.84rem">'
        f'<span style="color:#64748b">{t.replace("_"," ")}</span>'
        f'<span class="mono" style="font-weight:600">{c}</span></div>'
        for t, c in types
    ) or '<div style="color:#94a3b8;font-size:.82rem">No active threats ✅</div>'

    body = render_template_string("""
    <div class='ph'><h2>🚨 Security Dashboard</h2>
      <p>Real-time attack detection and alerts.</p></div>

    <div class='stat-grid' style='margin-bottom:20px'>
      <div class='stat-card red'><div class='lbl'>Critical</div>
        <div class='val'>{{ c_crit }}</div><div class='sub'>Unresolved</div></div>
      <div class='stat-card amber'><div class='lbl'>High</div>
        <div class='val'>{{ c_high }}</div><div class='sub'>Unresolved</div></div>
      <div class='stat-card'><div class='lbl'>Medium</div>
        <div class='val' style='color:#d97706'>{{ c_med }}</div><div class='sub'>Unresolved</div></div>
      <div class='stat-card'><div class='lbl'>Total Open</div>
        <div class='val'>{{ c_all }}</div><div class='sub'>All severities</div></div>
    </div>

    <div style='display:grid;grid-template-columns:1fr 240px;gap:18px'>
      <div>
        <div style='display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px'>
          <a href='/security'              class='btn btn-sm btn-outline-secondary'>All Open</a>
          <a href='/security?sev=CRITICAL' class='btn btn-sm btn-danger'>Critical</a>
          <a href='/security?sev=HIGH'     class='btn btn-sm btn-warning'>High</a>
          <a href='/security?resolved=1'   class='btn btn-sm btn-outline-secondary'>Show Resolved</a>
          <a href='/security/resolve-all'  class='btn btn-sm'
             style='background:#f0fdf4;color:#16a34a;border:1px solid #bbf7d0'>✓ Resolve All</a>
        </div>
        {% if cards %}{{ cards|safe }}
        {% else %}
          <div class='card-white text-center' style='padding:40px;color:#94a3b8'>
            ✅ No alerts for this filter.
          </div>
        {% endif %}
      </div>

      <div>
        <div class='card-white' style='margin-bottom:14px'>
          <div style='font-size:.7rem;color:#64748b;text-transform:uppercase;
            letter-spacing:1px;font-weight:700;margin-bottom:10px'>Attack Types</div>
          {{ breakdown|safe }}
        </div>
        <div class='card-white'>
          <div style='font-size:.7rem;color:#64748b;text-transform:uppercase;
            letter-spacing:1px;font-weight:700;margin-bottom:10px'>Quick Links</div>
          <a href='{{ url_for("audit") }}'     class='qa-btn' style='margin-bottom:8px;font-size:.82rem;padding:10px 14px'>🧾 Audit Logs</a>
          <a href='{{ url_for("dashboard") }}' class='qa-btn' style='font-size:.82rem;padding:10px 14px'>🏠 Dashboard</a>
        </div>
      </div>
    </div>
    """, cards=cards, c_crit=c_crit, c_high=c_high, c_med=c_med,
         c_all=c_all, breakdown=breakdown)
    return render(body)


@app.route('/security/resolve/<int:aid>')
@login_required
@admin_only
def resolve(aid):
    a = Alert.query.get_or_404(aid)
    a.resolved = True
    db.session.commit()
    flash(f'Alert #{aid} resolved.')
    return redirect(url_for('security'))


@app.route('/security/resolve-all')
@login_required
@admin_only
def resolve_all():
    Alert.query.filter_by(resolved=False).update({'resolved': True})
    db.session.commit()
    flash('All alerts resolved.')
    return redirect(url_for('security'))


# ════════════════════════════════════════════════════════════════
# ROUTES — AUDIT
# ════════════════════════════════════════════════════════════════
@app.route('/audit')
@login_required
@admin_only
def audit():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    rows = ''.join(
        f"<tr><td class='mono' style='font-size:.75rem'>{l.created_at.strftime('%d-%b %H:%M:%S')}</td>"
        f"<td>{l.email}</td><td><span style='background:#f1f5f9;padding:2px 7px;"
        f"border-radius:4px;font-size:.75rem;font-family:monospace'>{l.action}</span></td>"
        f"<td style='color:#64748b;font-size:.82rem'>{l.detail or ''}</td>"
        f"<td class='mono' style='font-size:.75rem;color:#94a3b8'>{l.ip or ''}</td></tr>"
        for l in logs
    )
    body = render_template_string("""
    <div class='ph'><h2>Audit Logs</h2><p>Full activity trail.</p></div>
    <div class='card-white'>
      <table class='table table-hover mb-0'>
        <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead>
        <tbody>{{ rows|safe }}</tbody>
      </table>
    </div>""", rows=rows)
    return render(body)


# ════════════════════════════════════════════════════════════════
# ROUTES — CHATBOT
# ════════════════════════════════════════════════════════════════
@app.route('/chatbot', methods=['GET', 'POST'])
@login_required
def chatbot():
    if request.method == 'POST':
        msg  = request.form.get('message', '').lower().strip()
        txs  = Transaction.query.filter_by(email=current_user.email).all()
        amts = []
        for t in txs:
            try: amts.append((t, float(dec(t.amt_enc))))
            except: pass

        reply = "I did not understand. Try typing: total, biggest, pending, last, average, security, risk"

        if 'total' in msg or 'spend' in msg:
            total_amt = sum(a for _,a in amts)
            reply = f"Total spending is Rs.{total_amt:.2f} across {len(amts)} transaction(s)."
        elif 'biggest' in msg or 'highest' in msg or 'largest' in msg:
            if amts:
                t, a = max(amts, key=lambda x: x[1])
                reply = f"Biggest transaction: Rs.{a:.2f} on card {t.pan_mask}."
            else:
                reply = "No transactions found."
        elif 'pending' in msg:
            n = sum(1 for t,_ in amts if t.status == 'Pending')
            reply = f"You have {n} pending transaction(s) awaiting confirmation."
        elif 'last' in msg or 'recent' in msg or 'latest' in msg:
            if amts:
                t, a = max(amts, key=lambda x: x[0].created_at)
                reply = f"Last transaction: Rs.{a:.2f} on {t.created_at.strftime('%d-%b %H:%M')}."
            else:
                reply = "No transactions found."
        elif 'average' in msg or 'avg' in msg:
            if amts:
                avg = sum(a for _,a in amts) / len(amts)
                reply = f"Average transaction amount is Rs.{avg:.2f}."
            else:
                reply = "No transactions found."
        elif 'security' in msg or 'alert' in msg or 'attack' in msg or 'fraud' in msg:
            if current_user.is_admin:
                n = Alert.query.filter_by(resolved=False).count()
                reply = f"There are {n} total unresolved security alerts in the system." if n else "No open security alerts in the system."
            else:
                n = Alert.query.filter_by(email=current_user.email, resolved=False).count()
                reply = f"Warning: {n} unresolved security alert(s) on your account!" if n else "Good news: No security alerts on your account."
        elif 'risk' in msg or 'risky' in msg or 'flagged' in msg:
            hi = [t for t,_ in amts if t.risk_score >= 40]
            reply = f"Warning: {len(hi)} high-risk transaction(s) flagged on your account." if hi else "All clear: No high-risk transactions on your account."
        elif 'count' in msg or 'how many' in msg:
            reply = f"You have {len(amts)} total transaction(s)."
        elif 'hello' in msg or 'hi' in msg or 'help' in msg:
            reply = "Hello! Ask me: total spending, biggest, pending, last transaction, average, security alerts, or risk."

        return jsonify({'reply': reply})

    body = """
    <div class='ph'><h2>Finance Chatbot</h2>
      <p>Ask about your transactions and security status.</p></div>
    <div class='card-white' style='max-width:540px'>
      <div id='box' class='chatbox mb-3'></div>
      <div class='input-group'>
        <input id='msg' class='form-control' placeholder='total, security, risk, biggest...'/>
        <button class='btn btn-primary' onclick='send()'>Send</button>
      </div>
      <div style='margin-top:8px;font-size:.75rem;color:#94a3b8'>
        total · biggest · pending · last · average · security · risk
      </div>
    </div>
    <script>
    let msgCount = 0;
    async function send() {
      const input = document.getElementById('msg');
      const m = input.value.trim();
      if (!m) return;
      const box = document.getElementById('box');
      box.innerHTML += '<p class="you"><b>You:</b> ' + m + '</p>';
      input.value = '';
      input.disabled = true;
      try {
        const r = await fetch('/chatbot', {
          method:'POST',
          headers:{'Content-Type':'application/x-www-form-urlencoded'},
          body:'message='+encodeURIComponent(m)
        });
        const d = await r.json();
        const uid = 'msg_' + (++msgCount);
        const p = document.createElement('p');
        p.className = 'bot';
        p.innerHTML = '<b>Bot:</b> <span id="' + uid + '"></span>';
        box.appendChild(p);
        box.scrollTop = box.scrollHeight;
        const el = document.getElementById(uid);
        const text = d.reply || '';
        /* Array.from splits by Unicode code points so emoji render correctly */
        const chars = Array.from(text);
        let i = 0;
        const iv = setInterval(() => {
          if (i < chars.length) {
            el.textContent += chars[i++];
            box.scrollTop = box.scrollHeight;
          } else {
            clearInterval(iv);
          }
        }, 18);
      } catch(e) {
        box.innerHTML += '<p class="bot"><b>Bot:</b> Error contacting server.</p>';
      }
      input.disabled = false;
      input.focus();
    }
    document.getElementById('msg').addEventListener('keydown', e => {
      if (e.key === 'Enter') send();
    });
    </script>"""
    return render(body)

csrf.exempt(chatbot)


# ════════════════════════════════════════════════════════════════
# DEMO ATTACK ENDPOINT (used by attack_demo.py)
# ════════════════════════════════════════════════════════════════
@app.route('/demo/attack', methods=['POST'])
def demo_attack():
    data  = request.get_json(force=True)
    atype = data.get('type', '')
    email = data.get('email', 'user@example.com')
    ip    = data.get('ip', '192.168.1.100')

    if atype == 'brute_force':
        u = User.query.filter_by(email=email).first()
        if u:
            u.is_locked  = True
            u.lock_until = datetime.utcnow() + timedelta(seconds=300)
            db.session.commit()
        save_alert('BRUTE_FORCE_LOGIN', 'CRITICAL',
            f'[DEMO] Account {email} locked after 6 failed attempts from {ip}',
            email=email, ip=ip)

    elif atype == 'velocity':
        save_alert('TX_VELOCITY', 'HIGH',
            f'[DEMO] 6 rapid transactions in 60s detected for {email}', email=email)

    elif atype == 'replay':
        save_alert('REPLAY_ATTACK', 'CRITICAL',
            f'[DEMO] Duplicate transaction PAN ...9999 ₹9999 resubmitted within 30s for {email}',
            email=email, ip=ip)

    elif atype == 'amount':
        save_alert('AMOUNT_ANOMALY', 'MEDIUM',
            f'[DEMO] ₹75000 is 12.5x above avg ₹6000 for {email}', email=email)

    elif atype == 'otp_bomb':
        save_alert('OTP_BOMBING', 'HIGH',
            f'[DEMO] 4 OTP requests in 120s for {email} from {ip}',
            email=email, ip=ip)

    elif atype == 'large_tx':
        save_alert('LARGE_TRANSACTION', 'HIGH',
            f'[DEMO] ₹85000 exceeds hard limit ₹50000 for {email}', email=email)

    return jsonify({'status': 'ok', 'triggered': atype})

csrf.exempt(demo_attack)


# ════════════════════════════════════════════════════════════════
# STARTUP
# ════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            pw = bcrypt.hashpw(b'adminpass', bcrypt.gensalt())
            db.session.add(User(email='admin@example.com', password=pw, is_admin=True))
            print('[INIT] Created admin:  admin@example.com / adminpass')
        if not User.query.filter_by(email='user@example.com').first():
            pw = bcrypt.hashpw(b'password', bcrypt.gensalt())
            db.session.add(User(email='user@example.com', password=pw))
            print('[INIT] Created user:   user@example.com / password')
        db.session.commit()
    app.run(debug=True, port=5000)