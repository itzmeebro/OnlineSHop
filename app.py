import os
import re
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, date
from pathlib import Path

import bcrypt
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import extra_streamlit_components as stx


# ============================================================
# StoreFlow â€” Streamlit demo
# ============================================================
# Features:
# - Registration/login with email OR phone
# - bcrypt password hashing
# - Persistent "remember me" cookie
# - SQLite database
# - Dashboard: income / expenses / profit
# - 7 days / 1 month / 3 months / 1 year chart
# - Order creation with live profit
# - Order pipeline: Created -> Arrived -> Delivered
# - Delivery fee is tracked separately and never counted as expense
# - Notifications
# - 10-day order follow-up reminders (generated when the app is opened)
# - Profile editing with confirmation step
#
# IMPORTANT FOR REAL PRODUCTION:
# SQLite + local uploads are ideal for a demo/MVP. On Streamlit Cloud,
# local files can be replaced when the app is redeployed/restarted.
# For production use PostgreSQL/Supabase + object storage for images.


APP_NAME = "StoreFlow"
DB_PATH = Path("storeflow.db")
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

BUSINESS_TYPES = [
    "áƒáƒœáƒšáƒáƒ˜áƒœ áƒ›áƒáƒ¦áƒáƒ–áƒ˜áƒ",
    "áƒáƒ¯áƒáƒ®áƒ˜áƒ¡ áƒ›áƒáƒ¦áƒáƒ–áƒ˜áƒ",
    "áƒ¨áƒ˜áƒ“áƒ áƒ’áƒáƒ§áƒ˜áƒ“áƒ•áƒ”áƒ‘áƒ˜",
    "Instagram / Facebook áƒ›áƒáƒ¦áƒáƒ–áƒ˜áƒ",
    "áƒ¡áƒáƒ‘áƒ˜áƒ—áƒ£áƒ›áƒ áƒ’áƒáƒ§áƒ˜áƒ“áƒ•áƒ”áƒ‘áƒ˜",
    "áƒ¡áƒ”áƒ áƒ•áƒ˜áƒ¡áƒ˜ / áƒ›áƒáƒ›áƒ¡áƒáƒ®áƒ£áƒ áƒ”áƒ‘áƒ",
    "áƒ¡áƒ®áƒ•áƒ",
]


# -----------------------------
# Page setup
# -----------------------------
st.set_page_config(
    page_title="StoreFlow",
    page_icon="ðŸ“Š",
    layout="wide",
    initial_sidebar_state="expanded",
)


# -----------------------------
# Database
# -----------------------------
def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            business_name TEXT NOT NULL,
            business_type TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            logo_path TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            price REAL NOT NULL,
            cost REAL NOT NULL,
            address TEXT NOT NULL,
            phone TEXT NOT NULL,
            product TEXT NOT NULL,
            photo_path TEXT,
            transport_fee REAL NOT NULL DEFAULT 0,
            stage TEXT NOT NULL DEFAULT 'áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜',
            transport_paid INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            arrived_at TEXT,
            delivered_at TEXT,
            reminder_created INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'info',
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    conn.commit()
    conn.close()


init_db()


# -----------------------------
# Cookie / persistent login
# -----------------------------
cookie_manager = stx.CookieManager(key="storeflow_cookie_manager")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: int, days: int = 30) -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hash_token(token)
    expires = datetime.now() + timedelta(days=days)

    conn = db()
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ? OR expires_at < ?",
        (user_id, datetime.now().isoformat()),
    )
    conn.execute(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
        (user_id, token_hash, expires.isoformat()),
    )
    conn.commit()
    conn.close()

    cookie_manager.set(
        "storeflow_session",
        token,
        expires_at=expires,
    )
    return token


def get_user_from_cookie():
    try:
        token = cookie_manager.get("storeflow_session")
    except Exception:
        return None

    if not token:
        return None

    token_hash = hash_token(token)
    conn = db()
    row = conn.execute(
        """
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ? AND s.expires_at > ?
        """,
        (token_hash, datetime.now().isoformat()),
    ).fetchone()
    conn.close()

    if row:
        return row
    return None


def logout():
    try:
        token = cookie_manager.get("storeflow_session")
    except Exception:
        token = None

    if token:
        conn = db()
        conn.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (hash_token(token),),
        )
        conn.commit()
        conn.close()

    try:
        cookie_manager.delete("storeflow_session")
    except Exception:
        pass

    st.session_state.clear()
    st.rerun()


# -----------------------------
# Helpers
# -----------------------------
def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def normalize_email(value: str) -> str:
    return value.strip().lower()


def normalize_phone(value: str) -> str:
    return re.sub(r"\s+", "", value.strip())


def valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def valid_phone(phone: str) -> bool:
    cleaned = normalize_phone(phone)
    return bool(re.match(r"^\+?[0-9]{8,15}$", cleaned))


def password_ok(password: str) -> bool:
    return len(password) >= 8


def save_uploaded_file(uploaded, prefix: str) -> str | None:
    if uploaded is None:
        return None

    suffix = Path(uploaded.name).suffix.lower()
    if suffix not in [".png", ".jpg", ".jpeg", ".webp"]:
        return None

    filename = f"{prefix}_{secrets.token_hex(8)}{suffix}"
    path = UPLOAD_DIR / filename
    path.write_bytes(uploaded.getbuffer())
    return str(path)


def money(v):
    return f"â‚¾{float(v):,.2f}"


def add_notification(user_id, title, body, kind="info"):
    conn = db()
    conn.execute(
        """
        INSERT INTO notifications
        (user_id, title, body, kind, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, title, body, kind, now_iso()),
    )
    conn.commit()
    conn.close()


def get_user(user_id):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def get_orders(user_id):
    conn = db()
    rows = conn.execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY datetime(created_at) DESC",
        (user_id,),
    ).fetchall()
    conn.close()
    return rows


def create_due_reminders(user_id):
    # Streamlit does not run background jobs while the page is closed.
    # This check creates the reminder as soon as the user opens the app
    # after 10 days have passed.
    cutoff = datetime.now() - timedelta(days=10)

    conn = db()
    rows = conn.execute(
        """
        SELECT * FROM orders
        WHERE user_id = ?
          AND datetime(created_at) <= ?
          AND reminder_created = 0
          AND stage != 'áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜'
        """,
        (user_id, cutoff.isoformat()),
    ).fetchall()

    for order in rows:
        add_notification(
            user_id,
            "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ’áƒáƒ“áƒáƒ›áƒáƒ¬áƒ›áƒ”áƒ‘áƒ",
            f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ #{order['id']} áƒ£áƒ™áƒ•áƒ” 10 áƒ“áƒ¦áƒ˜áƒ¡áƒáƒ. áƒ’áƒáƒ“áƒáƒáƒ›áƒáƒ¬áƒ›áƒ”, áƒ áƒ áƒ”áƒ¢áƒáƒžáƒ–áƒ”áƒ áƒáƒ›áƒáƒœáƒáƒ—áƒ˜.",
            "reminder",
        )
        conn.execute(
            "UPDATE orders SET reminder_created = 1 WHERE id = ?",
            (order["id"],),
        )

    conn.commit()
    conn.close()


# -----------------------------
# Styling
# -----------------------------
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+Georgian:wght@400;500;600;700;800&display=swap');

:root{
 --bg:#070a12; --panel:#0d1220; --panel2:#101727; --line:#202a42;
 --text:#f7f7ff; --muted:#8d96ad; --purple:#7b4dff; --pink:#ff3f88;
 --green:#16e3a0; --orange:#ff9b4a;
}
html,body,[class*="css"]{font-family:'Noto Sans Georgian',sans-serif!important}
.stApp{background:
 radial-gradient(circle at 82% 3%,rgba(124,77,255,.15),transparent 28%),
 radial-gradient(circle at 45% 38%,rgba(255,63,136,.035),transparent 30%),#070a12;
 color:var(--text)}
.block-container{max-width:1480px;padding:22px 34px 45px}
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#090d16,#080b12);border-right:1px solid #182137}
section[data-testid="stSidebar"]>div{padding:20px 14px}
section[data-testid="stSidebar"] .stButton>button{background:transparent!important;border:1px solid transparent!important;color:#9da6bb!important;text-align:left!important;justify-content:flex-start!important;border-radius:11px!important;box-shadow:none!important;font-size:14px!important;padding:10px 12px!important}
section[data-testid="stSidebar"] .stButton>button:hover{background:#151a2b!important;color:#fff!important}
section[data-testid="stSidebar"] .stButton>button:focus{border-color:#6242d9!important}
.stButton>button{border:1px solid rgba(255,255,255,.07)!important;border-radius:12px!important;background:linear-gradient(135deg,#7848ff,#a84eff)!important;color:#fff!important;font-weight:700!important;min-height:42px;box-shadow:0 8px 25px rgba(110,66,255,.16);transition:.18s}
.stButton>button:hover{transform:translateY(-1px);filter:brightness(1.07)}
.stButton>button[kind="secondary"]{background:#121827!important;border-color:#2a3652!important}
.stButton>button[kind="secondary"]:hover{background:#191f32!important}
.stTextInput input,.stTextArea textarea,.stNumberInput input{background:#0c1220!important;color:#fff!important;border:1px solid #26314b!important;border-radius:12px!important}
.stTextInput input:focus,.stTextArea textarea:focus,.stNumberInput input:focus{border-color:#704cff!important;box-shadow:0 0 0 1px #704cff!important}
[data-baseweb="select"]>div{background:#0c1220!important;color:#fff!important;border:1px solid #26314b!important;border-radius:12px!important}
.stFileUploader section{background:#0c1220!important;border:1px dashed #33405f!important;border-radius:14px!important}
.stApp p,.stApp label,.stApp [data-testid="stMarkdownContainer"]{color:#f0f2fa}
[data-testid="stWidgetLabel"] p{color:#cdd3e2!important;font-weight:600}
.stTabs [data-baseweb="tab-list"]{background:#0c1220;border:1px solid #202b43;border-radius:13px;padding:4px;gap:3px}
.stTabs [data-baseweb="tab"]{color:#909ab0!important;border-radius:9px;padding:8px 14px}
.stTabs [aria-selected="true"]{color:#fff!important;background:linear-gradient(135deg,#7045ef,#a24af2)!important}
[data-testid="stSegmentedControl"]{background:#0c1220!important;border:1px solid #222e48!important;border-radius:12px!important;padding:4px!important}
[data-testid="stSegmentedControl"] button{color:#98a1b5!important;border-radius:9px!important}
[data-testid="stSegmentedControl"] button[aria-checked="true"]{background:#7547ef!important;color:#fff!important}

.sf-topbar{display:flex;align-items:center;gap:14px;margin-bottom:22px}
.sf-search{flex:1;background:#0c1220;border:1px solid #202b43;border-radius:12px;padding:11px 15px;color:#707b93;font-size:13px}
.sf-top-icon{width:42px;height:42px;border-radius:12px;background:#0c1220;border:1px solid #202b43;display:flex;align-items:center;justify-content:center;font-size:18px}
.sf-user{display:flex;align-items:center;gap:9px;background:#0c1220;border:1px solid #202b43;border-radius:12px;padding:6px 10px;color:#fff;font-size:13px}
.sf-avatar{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,#7b4dff,#ff3f88);display:flex;align-items:center;justify-content:center;font-weight:800}
.sf-hero{background:linear-gradient(110deg,rgba(15,20,34,.98),rgba(12,17,30,.9));border:1px solid #202b43;border-radius:20px;padding:23px 25px;margin-bottom:16px;position:relative;overflow:hidden}
.sf-hero:after{content:'';position:absolute;right:-80px;top:-100px;width:300px;height:300px;border-radius:50%;background:radial-gradient(circle,rgba(130,72,255,.25),transparent 67%);pointer-events:none}
.sf-hero h1{font-size:27px!important;margin:0 0 5px!important;color:#fff!important;letter-spacing:-.7px}
.sf-hero p{color:#8f99af!important;margin:0!important;font-size:13px}
.sf-card{background:linear-gradient(145deg,rgba(14,19,32,.98),rgba(9,13,23,.98));border:1px solid #202b43;border-radius:18px;padding:20px;box-shadow:0 16px 45px rgba(0,0,0,.17);margin-bottom:16px}
.sf-card h3,.sf-card h2{color:#fff!important;margin-top:0}
.sf-metric{position:relative;min-height:128px;padding:18px 20px;border-radius:18px;border:1px solid #202b43;background:#0d1422;overflow:hidden;margin-bottom:15px}
.sf-metric:after{content:'';position:absolute;right:-70px;top:-75px;width:180px;height:180px;border-radius:50%;filter:blur(5px);opacity:.18}
.sf-metric.income{border-color:rgba(0,226,160,.36)} .sf-metric.income:after{background:#00e2a0}
.sf-metric.expense{border-color:rgba(255,63,136,.34)} .sf-metric.expense:after{background:#ff3f88}
.sf-metric.profit{border-color:rgba(124,77,255,.4)} .sf-metric.profit:after{background:#7c4dff}
.metric-icon{width:38px;height:38px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-weight:800;margin-bottom:10px}
.income .metric-icon{background:rgba(0,226,160,.13);color:#00e2a0}.expense .metric-icon{background:rgba(255,63,136,.13);color:#ff5d98}.profit .metric-icon{background:rgba(124,77,255,.16);color:#a981ff}
.metric-label{color:#9ca5b8;font-size:12px;margin-bottom:2px}.metric-value{color:#fff;font-size:28px;font-weight:800;letter-spacing:-.5px}.metric-foot{font-size:10px;margin-top:8px}.positive{color:#18dfa1}.negative{color:#ff5c95}
.chart-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:8px}.chart-head h3{margin:0;color:#fff!important;font-size:17px}.chart-head p{margin:3px 0 0;color:#7f899f!important;font-size:11px}
.sf-feature{background:#0d1422;border:1px solid #202b43;border-radius:16px;padding:18px;min-height:120px}.sf-feature h4{color:#fff!important;margin:8px 0 4px;font-size:14px}.sf-feature p{color:#858fa5!important;font-size:11px;line-height:1.55;margin:0}.feature-icon{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;background:rgba(124,77,255,.16);color:#a981ff;font-size:17px}
.order-card{background:#0d1422;border:1px solid #202b43;border-radius:14px;padding:15px;margin-bottom:10px}.small-muted{color:#858fa5!important;font-size:12px}.badge{display:inline-block;padding:5px 9px;border-radius:999px;background:rgba(124,77,255,.13);border:1px solid rgba(124,77,255,.22);color:#bda9ff!important;font-size:11px}
.profile-danger{border:1px solid rgba(255,63,136,.45);background:rgba(255,63,136,.06);border-radius:14px;padding:14px;margin-bottom:10px}.profile-danger h4{color:#ff6a9d!important;margin:0 0 5px}.auth-wrap{max-width:540px;margin:45px auto}.auth-wrap .sf-card{padding:28px}
hr{border-color:#1d263a!important}
@media(max-width:900px){.block-container{padding:14px 14px 35px}.sf-topbar{gap:8px}.sf-user span{display:none}.sf-hero h1{font-size:22px!important}.metric-value{font-size:24px}}
</style>
""",
    unsafe_allow_html=True,
)


# -----------------------------
# Authentication
# -----------------------------
def registration_page():
    st.markdown('<div class="auth-wrap">', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="sf-card" style="text-align:center">
            <div class="sf-logo">
                <span class="sf-gradient">StoreFlow</span>
            </div>
            <h1>áƒ¨áƒ”áƒ¥áƒ›áƒ”áƒœáƒ˜ áƒ¨áƒ”áƒœáƒ˜ áƒ¡áƒáƒ›áƒ£áƒ¨áƒáƒ áƒ¡áƒ˜áƒ•áƒ áƒªáƒ”</h1>
            <p class="small-muted">áƒ›áƒáƒ áƒ—áƒ” áƒáƒœáƒšáƒáƒ˜áƒœ-áƒ›áƒáƒ¦áƒáƒ–áƒ˜áƒ áƒ”áƒ áƒ—áƒ˜ áƒ›áƒáƒ áƒ¢áƒ˜áƒ•áƒ˜ áƒžáƒáƒœáƒ”áƒšáƒ˜áƒ“áƒáƒœ.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("register_form"):
        email = st.text_input("áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ")
        phone = st.text_input("áƒ¡áƒáƒ™áƒáƒœáƒ¢áƒáƒ¥áƒ¢áƒ áƒœáƒáƒ›áƒ”áƒ áƒ˜")
        business_name = st.text_input("áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒ“áƒáƒ¡áƒáƒ®áƒ”áƒšáƒ”áƒ‘áƒ")
        business_type = st.selectbox("áƒ áƒ áƒ¡áƒáƒ®áƒ˜áƒ¡ áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ?", BUSINESS_TYPES)
        password = st.text_input("áƒžáƒáƒ áƒáƒšáƒ˜", type="password")
        password2 = st.text_input("áƒ’áƒáƒ˜áƒ›áƒ”áƒáƒ áƒ” áƒžáƒáƒ áƒáƒšáƒ˜", type="password")
        logo = st.file_uploader(
            "áƒšáƒáƒ’áƒ (áƒ¡áƒ£áƒ áƒ•áƒ˜áƒšáƒ˜áƒ¡áƒáƒ›áƒ”áƒ‘áƒ )",
            type=["png", "jpg", "jpeg", "webp"],
        )

        agree = st.checkbox("áƒ•áƒ”áƒ—áƒáƒœáƒ®áƒ›áƒ”áƒ‘áƒ˜, áƒ áƒáƒ› áƒ©áƒ”áƒ›áƒ˜ áƒ›áƒáƒœáƒáƒªáƒ”áƒ›áƒ”áƒ‘áƒ˜ áƒ’áƒáƒ›áƒáƒ˜áƒ§áƒ”áƒœáƒ”áƒ‘áƒ áƒáƒ› áƒáƒžáƒ¨áƒ˜.")
        submitted = st.form_submit_button("áƒ áƒ”áƒ’áƒ˜áƒ¡áƒ¢áƒ áƒáƒªáƒ˜áƒ", use_container_width=True)

        if submitted:
            email = normalize_email(email)
            phone = normalize_phone(phone)

            if not valid_email(email):
                st.error("áƒ¨áƒ”áƒ˜áƒ§áƒ•áƒáƒœáƒ” áƒ¡áƒ¬áƒáƒ áƒ˜ áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ.")
            elif not valid_phone(phone):
                st.error("áƒ¨áƒ”áƒ˜áƒ§áƒ•áƒáƒœáƒ” áƒ¡áƒ¬áƒáƒ áƒ˜ áƒ¡áƒáƒ™áƒáƒœáƒ¢áƒáƒ¥áƒ¢áƒ áƒœáƒáƒ›áƒ”áƒ áƒ˜.")
            elif not business_name.strip():
                st.error("áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒ“áƒáƒ¡áƒáƒ®áƒ”áƒšáƒ”áƒ‘áƒ áƒáƒ£áƒªáƒ˜áƒšáƒ”áƒ‘áƒ”áƒšáƒ˜áƒ.")
            elif not password_ok(password):
                st.error("áƒžáƒáƒ áƒáƒšáƒ˜ áƒ£áƒœáƒ“áƒ áƒ¨áƒ”áƒ˜áƒªáƒáƒ•áƒ“áƒ”áƒ¡ áƒ›áƒ˜áƒœáƒ˜áƒ›áƒ£áƒ› 8 áƒ¡áƒ˜áƒ›áƒ‘áƒáƒšáƒáƒ¡.")
            elif password != password2:
                st.error("áƒžáƒáƒ áƒáƒšáƒ”áƒ‘áƒ˜ áƒ”áƒ áƒ—áƒ›áƒáƒœáƒ”áƒ—áƒ¡ áƒáƒ  áƒ”áƒ›áƒ—áƒ®áƒ•áƒ”áƒ•áƒ.")
            elif not agree:
                st.error("áƒ’áƒ—áƒ®áƒáƒ•, áƒ›áƒáƒœáƒ˜áƒ¨áƒœáƒ” áƒ—áƒáƒœáƒ®áƒ›áƒáƒ‘áƒ.")
            else:
                conn = db()
                exists = conn.execute(
                    "SELECT id FROM users WHERE email = ? OR phone = ?",
                    (email, phone),
                ).fetchone()

                if exists:
                    conn.close()
                    st.error("áƒ”áƒ¡ áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ áƒáƒœ áƒœáƒáƒ›áƒ”áƒ áƒ˜ áƒ£áƒ™áƒ•áƒ” áƒ áƒ”áƒ’áƒ˜áƒ¡áƒ¢áƒ áƒ˜áƒ áƒ”áƒ‘áƒ£áƒšáƒ˜áƒ.")
                else:
                    password_hash = bcrypt.hashpw(
                        password.encode("utf-8"),
                        bcrypt.gensalt(),
                    ).decode("utf-8")

                    logo_path = save_uploaded_file(
                        logo,
                        f"logo_{email.replace('@', '_')}",
                    )

                    cur = conn.execute(
                        """
                        INSERT INTO users
                        (email, phone, business_name, business_type,
                         password_hash, logo_path, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            email,
                            phone,
                            business_name.strip(),
                            business_type,
                            password_hash,
                            logo_path,
                            now_iso(),
                        ),
                    )
                    conn.commit()
                    user_id = cur.lastrowid
                    conn.close()

                    create_session(user_id, 30)
                    st.session_state.user_id = user_id
                    st.session_state.page = "áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜"
                    st.success("áƒ áƒ”áƒ’áƒ˜áƒ¡áƒ¢áƒ áƒáƒªáƒ˜áƒ áƒ¬áƒáƒ áƒ›áƒáƒ¢áƒ”áƒ‘áƒ˜áƒ— áƒ“áƒáƒ¡áƒ áƒ£áƒšáƒ“áƒ!")
                    st.rerun()

    if st.button("áƒ£áƒ™áƒ•áƒ” áƒ›áƒáƒ¥áƒ•áƒ¡ áƒáƒœáƒ’áƒáƒ áƒ˜áƒ¨áƒ˜ â†’ áƒ¨áƒ”áƒ¡áƒ•áƒšáƒ", use_container_width=True):
        st.session_state.auth_mode = "login"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


def login_page():
    st.markdown('<div class="auth-wrap">', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="sf-card" style="text-align:center">
            <div class="sf-logo">
                <span class="sf-gradient">StoreFlow</span>
            </div>
            <h1>áƒ™áƒ”áƒ—áƒ˜áƒšáƒ˜ áƒ˜áƒ§áƒáƒ¡ áƒ¨áƒ”áƒœáƒ˜ áƒ“áƒáƒ‘áƒ áƒ£áƒœáƒ”áƒ‘áƒ</h1>
            <p class="small-muted">áƒ¨áƒ”áƒ“áƒ˜ áƒ¨áƒ”áƒœáƒ˜ áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ˜áƒ— áƒáƒœ áƒœáƒáƒ›áƒ áƒ˜áƒ—.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("login_form"):
        identifier = st.text_input("áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ áƒáƒœ áƒœáƒáƒ›áƒ”áƒ áƒ˜")
        password = st.text_input("áƒžáƒáƒ áƒáƒšáƒ˜", type="password")
        remember = st.checkbox("áƒ“áƒáƒ›áƒ˜áƒ›áƒáƒ®áƒ¡áƒáƒ•áƒ áƒ” áƒáƒ› áƒ›áƒáƒ¬áƒ§áƒáƒ‘áƒ˜áƒšáƒáƒ‘áƒáƒ–áƒ”", value=True)

        submitted = st.form_submit_button("áƒ¨áƒ”áƒ¡áƒ•áƒšáƒ", use_container_width=True)

        if submitted:
            identifier_clean = identifier.strip()
            conn = db()
            user = conn.execute(
                """
                SELECT * FROM users
                WHERE lower(email) = lower(?) OR phone = ?
                """,
                (identifier_clean, normalize_phone(identifier_clean)),
            ).fetchone()
            conn.close()

            if not user or not bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8"),
            ):
                st.error("áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ/áƒœáƒáƒ›áƒ”áƒ áƒ˜ áƒáƒœ áƒžáƒáƒ áƒáƒšáƒ˜ áƒáƒ áƒáƒ¡áƒ¬áƒáƒ áƒ˜áƒ.")
            else:
                days = 30 if remember else 1
                create_session(user["id"], days)
                st.session_state.user_id = user["id"]
                st.session_state.page = "áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜"
                st.rerun()

    if st.button("áƒáƒ  áƒ›áƒáƒ¥áƒ•áƒ¡ áƒáƒœáƒ’áƒáƒ áƒ˜áƒ¨áƒ˜ â†’ áƒ áƒ”áƒ’áƒ˜áƒ¡áƒ¢áƒ áƒáƒªáƒ˜áƒ", use_container_width=True):
        st.session_state.auth_mode = "register"
        st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)


# -----------------------------
# Dashboard
# -----------------------------
def dashboard(user):
    user_id = user["id"]
    create_due_reminders(user_id)
    orders = get_orders(user_id)

    total_income = sum(float(o["price"]) for o in orders)
    total_expense = sum(float(o["cost"]) for o in orders)
    total_profit = total_income - total_expense

    conn = db()
    unread = conn.execute(
        "SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0",
        (user_id,),
    ).fetchone()["c"]
    conn.close()

    initials = (user["business_name"] or "S")[:1].upper()
    st.markdown(
        f'''<div class="sf-topbar">
            <div class="sf-search">âŒ•&nbsp;&nbsp; áƒ«áƒ”áƒ‘áƒœáƒ...</div>
            <div class="sf-top-icon">â™§</div>
            <div class="sf-user"><span class="sf-avatar">{initials}</span><span>{user["business_name"]}</span>âŒ„</div>
        </div>''', unsafe_allow_html=True)

    st.markdown(
        f'''<div class="sf-hero">
            <h1>áƒ’áƒáƒ›áƒáƒ áƒ¯áƒáƒ‘áƒ, {user["business_name"]} ðŸ‘‹</h1>
            <p>áƒ¨áƒ”áƒœáƒ˜ áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒ›áƒáƒ áƒ—áƒ•áƒ áƒáƒ®áƒšáƒ áƒ‘áƒ”áƒ•áƒ áƒáƒ“ áƒ£áƒ¤áƒ áƒ áƒ›áƒáƒ áƒ¢áƒ˜áƒ•áƒ˜áƒ.</p>
        </div>''', unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3, gap="medium")
    cards = [
        (c1, "income", "â†—", "áƒ¨áƒ”áƒ›áƒáƒ¡áƒáƒ•áƒáƒšáƒ˜", total_income, "áƒ‘áƒáƒšáƒ áƒžáƒ”áƒ áƒ˜áƒáƒ“áƒ˜áƒ¡ áƒ¨áƒ”áƒ›áƒáƒ¡áƒáƒ•áƒšáƒ”áƒ‘áƒ˜", "+12.5%"),
        (c2, "expense", "â–£", "áƒ®áƒáƒ áƒ¯áƒ˜", total_expense, "áƒ‘áƒáƒšáƒ áƒžáƒ”áƒ áƒ˜áƒáƒ“áƒ˜áƒ¡ áƒ®áƒáƒ áƒ¯áƒ”áƒ‘áƒ˜", "+8.3%"),
        (c3, "profit", "â†—", "áƒ›áƒáƒ’áƒ”áƒ‘áƒ", total_profit, "áƒ¨áƒ”áƒ›áƒáƒ¡áƒáƒ•áƒáƒšáƒ˜ âˆ’ áƒžáƒ áƒáƒ“áƒ£áƒ¥áƒ¢áƒ˜áƒ¡ áƒ¦áƒ˜áƒ áƒ”áƒ‘áƒ£áƒšáƒ”áƒ‘áƒ", "+18.7%"),
    ]
    for col, cls, icon, label, value, foot, change in cards:
        with col:
            st.markdown(
                f'''<div class="sf-metric {cls}">
                    <div class="metric-icon">{icon}</div>
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{money(value)}</div>
                    <div class="metric-foot positive">â†‘ {change} &nbsp;Â·&nbsp; {foot}</div>
                </div>''', unsafe_allow_html=True)

    st.markdown('<div class="sf-card">', unsafe_allow_html=True)
    st.markdown('<div class="chart-head"><div><h3>áƒ¨áƒ”áƒ›áƒáƒ¡áƒáƒ•áƒáƒšáƒ˜, áƒ®áƒáƒ áƒ¯áƒ˜ áƒ“áƒ áƒ›áƒáƒ’áƒ”áƒ‘áƒ</h3><p>áƒ’áƒ áƒáƒ¤áƒ˜áƒ™áƒ–áƒ” áƒáƒ˜áƒ áƒ©áƒ˜áƒ” áƒ¡áƒáƒ¡áƒ£áƒ áƒ•áƒ”áƒšáƒ˜ áƒžáƒ”áƒ áƒ˜áƒáƒ“áƒ˜</p></div></div>', unsafe_allow_html=True)
    period = st.segmented_control(
        "áƒžáƒ”áƒ áƒ˜áƒáƒ“áƒ˜",
        ["áƒ‘áƒáƒšáƒ 7 áƒ“áƒ¦áƒ”", "áƒ‘áƒáƒšáƒ 1 áƒ—áƒ•áƒ”", "áƒ‘áƒáƒšáƒ 3 áƒ—áƒ•áƒ”", "áƒ‘áƒáƒšáƒ 1 áƒ¬áƒ”áƒšáƒ˜"],
        default="áƒ‘áƒáƒšáƒ 7 áƒ“áƒ¦áƒ”",
        label_visibility="collapsed",
    ) or "áƒ‘áƒáƒšáƒ 7 áƒ“áƒ¦áƒ”"

    days = {"áƒ‘áƒáƒšáƒ 7 áƒ“áƒ¦áƒ”": 7, "áƒ‘áƒáƒšáƒ 1 áƒ—áƒ•áƒ”": 30, "áƒ‘áƒáƒšáƒ 3 áƒ—áƒ•áƒ”": 90, "áƒ‘áƒáƒšáƒ 1 áƒ¬áƒ”áƒšáƒ˜": 365}[period]
    end_day = datetime.now().date()
    start_day = end_day - timedelta(days=days - 1)
    dates = pd.date_range(start_day, end_day, freq="D")
    df = pd.DataFrame({"date": dates})

    order_df = pd.DataFrame([
        {"date": pd.Timestamp(datetime.fromisoformat(o["created_at"]).date()),
         "income": float(o["price"]), "expense": float(o["cost"])}
        for o in orders
        if o["created_at"]
    ])
    if not order_df.empty:
        grouped = order_df.groupby("date", as_index=False)[["income", "expense"]].sum()
        df = df.merge(grouped, on="date", how="left")
    else:
        df["income"] = 0.0
        df["expense"] = 0.0
    df[["income", "expense"]] = df[["income", "expense"]].fillna(0.0)
    df["profit"] = df["income"] - df["expense"]

    fig = go.Figure()
    for key, name, color in [("income","áƒ¨áƒ”áƒ›áƒáƒ¡áƒáƒ•áƒáƒšáƒ˜","#12e3a0"),("expense","áƒ®áƒáƒ áƒ¯áƒ˜","#ff3f88"),("profit","áƒ›áƒáƒ’áƒ”áƒ‘áƒ","#8b5cf6")]:
        fig.add_trace(go.Scatter(x=df["date"], y=df[key], name=name, mode="lines", line=dict(width=2.5,color=color), fill="tozeroy" if key=="profit" else None, fillcolor="rgba(139,92,246,.06)" if key=="profit" else None))
    fig.update_layout(height=300, margin=dict(l=5,r=5,t=5,b=5), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#dfe4ef",family="Noto Sans Georgian, Arial"), legend=dict(orientation="h",y=-.18,font=dict(size=10,color="#9aa4b8")), xaxis=dict(showgrid=False,zeroline=False,tickfont=dict(color="#78849b",size=9)), yaxis=dict(gridcolor="rgba(255,255,255,.05)",zeroline=False,tickfont=dict(color="#78849b",size=9)), hovermode="x unified", hoverlabel=dict(bgcolor="#111827",bordercolor="#33415e",font=dict(color="#fff")))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("### áƒ áƒ áƒ¨áƒ”áƒ’áƒ˜áƒ«áƒšáƒ˜áƒ áƒáƒ¥?")
    f1, f2, f3, f4 = st.columns(4, gap="medium")
    features = [
        (f1,"â–£","áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜áƒ¡ áƒ›áƒáƒ áƒ—áƒ•áƒ","áƒ›áƒáƒáƒ¬áƒ”áƒ¡áƒ áƒ˜áƒ’áƒ” áƒ§áƒ•áƒ”áƒšáƒ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ áƒ”áƒ áƒ— áƒ¡áƒ˜áƒ•áƒ áƒªáƒ”áƒ¨áƒ˜."),
        (f2,"â–¤","áƒ®áƒáƒ áƒ¯áƒ”áƒ‘áƒ˜áƒ¡ áƒ™áƒáƒœáƒ¢áƒ áƒáƒšáƒ˜","áƒ“áƒáƒáƒ™áƒ•áƒ˜áƒ áƒ“áƒ˜ áƒ®áƒáƒ áƒ¯áƒ”áƒ‘áƒ¡ áƒ“áƒ áƒ áƒ”áƒáƒšáƒ£áƒ  áƒ›áƒáƒ’áƒ”áƒ‘áƒáƒ¡."),
        (f3,"â†—","áƒ›áƒáƒ’áƒ”áƒ‘áƒ˜áƒ¡ áƒ’áƒáƒ–áƒ áƒ“áƒ","áƒáƒœáƒáƒšáƒ˜áƒ¢áƒ˜áƒ™áƒ˜áƒ— áƒ“áƒáƒ˜áƒœáƒáƒ®áƒ” áƒ¡áƒáƒ“ áƒ˜áƒ–áƒ áƒ“áƒ”áƒ‘áƒ áƒ¨áƒ”áƒ“áƒ”áƒ’áƒ˜."),
        (f4,"â—«","áƒ›áƒáƒ‘áƒ˜áƒšáƒ£áƒ áƒ˜ áƒáƒžáƒšáƒ˜áƒ™áƒáƒªáƒ˜áƒ","áƒ›áƒáƒ áƒ—áƒ” áƒ¨áƒ”áƒœáƒ˜ áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜ áƒœáƒ”áƒ‘áƒ˜áƒ¡áƒ›áƒ˜áƒ”áƒ áƒ˜ áƒáƒ“áƒ’áƒ˜áƒšáƒ˜áƒ“áƒáƒœ."),
    ]
    for col,icon,title,desc in features:
        with col:
            st.markdown(f'<div class="sf-feature"><div class="feature-icon">{icon}</div><h4>{title}</h4><p>{desc}</p></div>',unsafe_allow_html=True)

    st.markdown("### áƒ‘áƒáƒšáƒ áƒ¢áƒ áƒáƒœáƒ–áƒáƒ¥áƒªáƒ˜áƒ”áƒ‘áƒ˜")
    if orders:
        rows=[]
        for o in orders[:6]:
            rows.append({"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ":f'#{o["id"]} Â· {o["product"]}',"áƒ›áƒáƒ›áƒ®áƒ›áƒáƒ áƒ”áƒ‘áƒ”áƒšáƒ˜":o["customer_name"],"áƒ¡áƒ¢áƒáƒ¢áƒ£áƒ¡áƒ˜":o["stage"],"áƒ—áƒáƒœáƒ®áƒ":money(float(o["price"]))})
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.markdown('<div class="sf-card"><span class="small-muted">áƒ¯áƒ”áƒ  áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜ áƒáƒ  áƒ’áƒáƒ¥áƒ•áƒ¡.</span></div>',unsafe_allow_html=True)


# -----------------------------
# New order
# -----------------------------
def new_order_page(user):
    st.title("áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ")
    st.caption("áƒ¨áƒ”áƒáƒ•áƒ¡áƒ” áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ˜áƒœáƒ¤áƒáƒ áƒ›áƒáƒªáƒ˜áƒ â€” áƒ›áƒáƒ’áƒ”áƒ‘áƒ áƒáƒ•áƒ¢áƒáƒ›áƒáƒ¢áƒ£áƒ áƒáƒ“ áƒ“áƒáƒ˜áƒ—áƒ•áƒšáƒ”áƒ‘áƒ.")

    left, right = st.columns([1.5, 1])

    with left:
        customer_name = st.text_input("áƒ¡áƒáƒ®áƒ”áƒšáƒ˜")
        phone = st.text_input("áƒœáƒáƒ›áƒ”áƒ áƒ˜")
        address = st.text_area("áƒ›áƒ˜áƒ¡áƒáƒ›áƒáƒ áƒ—áƒ˜", height=90)
        product = st.text_input("áƒžáƒ áƒáƒ“áƒ£áƒ¥áƒ¢áƒ˜")
        product_photo = st.file_uploader(
            "áƒžáƒ áƒáƒ“áƒ£áƒ¥áƒ¢áƒ˜áƒ¡ áƒ¤áƒáƒ¢áƒ (áƒ¡áƒ£áƒ áƒ•áƒ˜áƒšáƒ˜áƒ¡áƒáƒ›áƒ”áƒ‘áƒ )",
            type=["png", "jpg", "jpeg", "webp"],
        )

    with right:
        price = st.number_input("áƒ¤áƒáƒ¡áƒ˜", min_value=0.0, step=1.0, format="%.2f")
        cost = st.number_input("áƒ¦áƒ˜áƒ áƒ”áƒ‘áƒ£áƒšáƒ”áƒ‘áƒ", min_value=0.0, step=1.0, format="%.2f")
        transport_fee = st.number_input(
            "áƒ¢áƒ áƒáƒœáƒ¡áƒžáƒáƒ áƒ¢áƒ˜áƒ áƒ”áƒ‘áƒ˜áƒ¡ áƒ—áƒáƒœáƒ®áƒ",
            min_value=0.0,
            step=1.0,
            format="%.2f",
            help="áƒ”áƒ¡ áƒ—áƒáƒœáƒ®áƒ áƒ®áƒáƒ áƒ¯áƒ”áƒ‘áƒ¨áƒ˜ áƒáƒ  áƒ©áƒáƒ˜áƒ—áƒ•áƒšáƒ”áƒ‘áƒ.",
        )

        profit = price - cost

        st.markdown(
            f"""
            <div class="sf-card" style="margin-top:15px;text-align:center">
                <div class="small-muted">áƒáƒ› áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ›áƒáƒ’áƒ”áƒ‘áƒ</div>
                <div style="font-size:34px;font-weight:800;color:#7CFFB2">
                    {money(profit)}
                </div>
                <div class="small-muted">áƒ¤áƒáƒ¡áƒ˜ âˆ’ áƒžáƒ áƒáƒ“áƒ£áƒ¥áƒ¢áƒ˜áƒ¡ áƒ¦áƒ˜áƒ áƒ”áƒ‘áƒ£áƒšáƒ”áƒ‘áƒ</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.button("áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ â†’", use_container_width=True):
        if not customer_name.strip():
            st.error("áƒ¡áƒáƒ®áƒ”áƒšáƒ˜ áƒáƒ£áƒªáƒ˜áƒšáƒ”áƒ‘áƒ”áƒšáƒ˜áƒ.")
            return
        if not valid_phone(normalize_phone(phone)):
            st.error("áƒ¨áƒ”áƒ˜áƒ§áƒ•áƒáƒœáƒ” áƒ¡áƒ¬áƒáƒ áƒ˜ áƒœáƒáƒ›áƒ”áƒ áƒ˜.")
            return
        if not address.strip():
            st.error("áƒ›áƒ˜áƒ¡áƒáƒ›áƒáƒ áƒ—áƒ˜ áƒáƒ£áƒªáƒ˜áƒšáƒ”áƒ‘áƒ”áƒšáƒ˜áƒ.")
            return
        if not product.strip():
            st.error("áƒžáƒ áƒáƒ“áƒ£áƒ¥áƒ¢áƒ˜ áƒáƒ£áƒªáƒ˜áƒšáƒ”áƒ‘áƒ”áƒšáƒ˜áƒ.")
            return
        if price <= 0:
            st.error("áƒ¤áƒáƒ¡áƒ˜ áƒ£áƒœáƒ“áƒ áƒ˜áƒ§áƒáƒ¡ 0-áƒ–áƒ” áƒ›áƒ”áƒ¢áƒ˜.")
            return
        if cost < 0:
            st.error("áƒ¦áƒ˜áƒ áƒ”áƒ‘áƒ£áƒšáƒ”áƒ‘áƒ áƒáƒ áƒáƒ¡áƒ¬áƒáƒ áƒ˜áƒ.")
            return

        photo_path = save_uploaded_file(product_photo, f"product_{user['id']}")

        conn = db()
        cur = conn.execute(
            """
            INSERT INTO orders
            (user_id, customer_name, price, cost, address, phone, product,
             photo_path, transport_fee, stage, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜', ?)
            """,
            (
                user["id"],
                customer_name.strip(),
                price,
                cost,
                address.strip(),
                normalize_phone(phone),
                product.strip(),
                photo_path,
                transport_fee,
                now_iso(),
            ),
        )
        order_id = cur.lastrowid
        conn.commit()
        conn.close()

        add_notification(
            user["id"],
            "áƒáƒ®áƒáƒšáƒ˜ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ",
            f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ #{order_id} â€” {product} áƒ¬áƒáƒ áƒ›áƒáƒ¢áƒ”áƒ‘áƒ˜áƒ— áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ“áƒ.",
            "order",
        )

        st.success(f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ #{order_id} áƒ¬áƒáƒ áƒ›áƒáƒ¢áƒ”áƒ‘áƒ˜áƒ— áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ“áƒ!")
        st.rerun()


# -----------------------------
# Orders pipeline
# -----------------------------
def render_order_card(order, stage):
    profit = float(order["price"]) - float(order["cost"])

    st.markdown(
        f"""
        <div class="order-card">
            <div style="display:flex;justify-content:space-between;gap:10px">
                <div>
                    <b>#{order["id"]} â€” {order["product"]}</b><br>
                    <span class="small-muted">
                        {order["customer_name"]} Â· {order["phone"]}
                    </span>
                </div>
                <div style="text-align:right">
                    <b>{money(order["price"])}</b><br>
                    <span style="color:#7CFFB2">áƒ›áƒáƒ’áƒ”áƒ‘áƒ {money(profit)}</span>
                </div>
            </div>
            <hr>
            <div class="small-muted">
                ðŸ“ {order["address"]}<br>
                ðŸ’° áƒ¦áƒ˜áƒ áƒ”áƒ‘áƒ£áƒšáƒ”áƒ‘áƒ: {money(order["cost"])}<br>
                ðŸšš áƒ¢áƒ áƒáƒœáƒ¡áƒžáƒáƒ áƒ¢áƒ˜áƒ áƒ”áƒ‘áƒ: {money(order["transport_fee"])}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if order["photo_path"] and Path(order["photo_path"]).exists():
        st.image(order["photo_path"], width=160)

    if stage == "áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜":
        if st.button(
            f"áƒ’áƒáƒ“áƒáƒ•áƒ˜áƒ“áƒ â€žáƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒâ€œ-áƒ¨áƒ˜ #{order['id']}",
            key=f"arrive_{order['id']}",
            use_container_width=True,
        ):
            conn = db()
            conn.execute(
                """
                UPDATE orders
                SET stage = 'áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ', arrived_at = ?
                WHERE id = ?
                """,
                (now_iso(), order["id"]),
            )
            conn.commit()
            conn.close()

            add_notification(
                order["user_id"],
                "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ¡áƒ¢áƒáƒ¢áƒ£áƒ¡áƒ˜ áƒ¨áƒ”áƒ˜áƒªáƒ•áƒáƒšáƒ",
                f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ #{order['id']} áƒ’áƒáƒ“áƒáƒ•áƒ˜áƒ“áƒ â€žáƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒâ€œ-áƒ¨áƒ˜.",
                "order",
            )
            st.rerun()

    elif stage == "áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ":
        paid = st.checkbox(
            "áƒ›áƒáƒ›áƒ®áƒ›áƒáƒ áƒ”áƒ‘áƒ”áƒšáƒ›áƒ áƒ¢áƒ áƒáƒœáƒ¡áƒžáƒáƒ áƒ¢áƒ˜áƒ áƒ”áƒ‘áƒ˜áƒ¡ áƒ—áƒáƒœáƒ®áƒ áƒ’áƒáƒ“áƒáƒ˜áƒ®áƒáƒ“áƒ",
            value=bool(order["transport_paid"]),
            key=f"transport_paid_{order['id']}",
        )

        if paid and not order["transport_paid"]:
            conn = db()
            conn.execute(
                "UPDATE orders SET transport_paid = 1 WHERE id = ?",
                (order["id"],),
            )
            conn.commit()
            conn.close()
            st.rerun()

        if st.button(
            f"áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ¨áƒ˜ áƒ’áƒáƒ“áƒáƒ¢áƒáƒœáƒ #{order['id']}",
            key=f"deliver_{order['id']}",
            use_container_width=True,
            disabled=not paid,
        ):
            conn = db()
            conn.execute(
                """
                UPDATE orders
                SET stage = 'áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜', delivered_at = ?
                WHERE id = ?
                """,
                (now_iso(), order["id"]),
            )
            conn.commit()
            conn.close()

            add_notification(
                order["user_id"],
                "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ áƒ©áƒáƒ‘áƒáƒ áƒ“áƒ",
                f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ #{order['id']} áƒ›áƒáƒœáƒ˜áƒ¨áƒœáƒ£áƒšáƒ˜áƒ áƒ áƒáƒ’áƒáƒ áƒª áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜.",
                "order",
            )
            st.rerun()

    else:
        st.success("áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜áƒ.")


def orders_page(user):
    st.title("áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜")

    orders = get_orders(user["id"])
    stages = ["áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜", "áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ", "áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜"]

    counts = {
        stage: sum(o["stage"] == stage for o in orders)
        for stage in stages
    }

    a, b, c = st.columns(3)
    a.metric("áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜", counts["áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜"])
    b.metric("áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ", counts["áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ"])
    c.metric("áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜", counts["áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜"])

    st.markdown("")

    tabs = st.tabs(
        [
            f"áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜ Â· {counts['áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ£áƒšáƒ˜']}",
            f"áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ Â· {counts['áƒ©áƒáƒ›áƒáƒ¡áƒ£áƒšáƒ˜áƒ']}",
            f"áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜ Â· {counts['áƒ©áƒáƒ‘áƒáƒ áƒ”áƒ‘áƒ£áƒšáƒ˜']}",
        ]
    )

    for tab, stage in zip(tabs, stages):
        with tab:
            matching = [o for o in orders if o["stage"] == stage]
            if not matching:
                st.info("áƒáƒ› áƒ”áƒ¢áƒáƒžáƒ–áƒ” áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜ áƒáƒ  áƒáƒ áƒ˜áƒ¡.")
            for order in matching:
                render_order_card(order, stage)


# -----------------------------
# Notifications
# -----------------------------
def notifications_page(user):
    st.title("áƒ¨áƒ”áƒ¢áƒ§áƒáƒ‘áƒ˜áƒœáƒ”áƒ‘áƒ”áƒ‘áƒ˜")

    create_due_reminders(user["id"])

    conn = db()
    rows = conn.execute(
        """
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY datetime(created_at) DESC
        """,
        (user["id"],),
    ).fetchall()

    conn.execute(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
        (user["id"],),
    )
    conn.commit()
    conn.close()

    if not rows:
        st.info("áƒ¨áƒ”áƒ¢áƒ§áƒáƒ‘áƒ˜áƒœáƒ”áƒ‘áƒ”áƒ‘áƒ˜ áƒ¯áƒ”áƒ  áƒáƒ  áƒáƒ áƒ˜áƒ¡.")
        return

    for n in rows:
        icon = {
            "order": "ðŸ“¦",
            "reminder": "â°",
            "profile": "ðŸ‘¤",
            "security": "ðŸ”",
            "info": "ðŸ””",
        }.get(n["kind"], "ðŸ””")

        st.markdown(
            f"""
            <div class="order-card">
                <div style="font-size:20px">{icon} <b>{n["title"]}</b></div>
                <div style="margin-top:5px">{n["body"]}</div>
                <div class="small-muted" style="margin-top:8px">
                    {n["created_at"][:16].replace("T", " ")}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# -----------------------------
# Profile
# -----------------------------
def profile_page(user):
    st.title("áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜")
    st.caption("áƒªáƒ•áƒšáƒ˜áƒšáƒ”áƒ‘áƒáƒ›áƒ“áƒ” áƒ’áƒáƒ“áƒáƒáƒ›áƒáƒ¬áƒ›áƒ” áƒ˜áƒœáƒ¤áƒáƒ áƒ›áƒáƒªáƒ˜áƒ áƒ§áƒ£áƒ áƒáƒ“áƒ¦áƒ”áƒ‘áƒ˜áƒ—.")

    with st.form("profile_form"):
        business_name = st.text_input(
            "áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒ“áƒáƒ¡áƒáƒ®áƒ”áƒšáƒ”áƒ‘áƒ",
            value=user["business_name"],
        )
        email = st.text_input("áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ", value=user["email"] or "")
        phone = st.text_input("áƒœáƒáƒ›áƒ”áƒ áƒ˜", value=user["phone"] or "")
        business_type = st.selectbox(
            "áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒ¢áƒ˜áƒžáƒ˜",
            BUSINESS_TYPES,
            index=(
                BUSINESS_TYPES.index(user["business_type"])
                if user["business_type"] in BUSINESS_TYPES
                else 0
            ),
        )
        logo = st.file_uploader(
            "áƒáƒ®áƒáƒšáƒ˜ áƒšáƒáƒ’áƒ",
            type=["png", "jpg", "jpeg", "webp"],
        )

        confirm = st.checkbox(
            "áƒ•áƒáƒ“áƒáƒ¡áƒ¢áƒ£áƒ áƒ”áƒ‘, áƒ áƒáƒ› áƒªáƒ•áƒšáƒ˜áƒšáƒ”áƒ‘áƒ”áƒ‘áƒ˜áƒ¡ áƒ¨áƒ”áƒœáƒáƒ®áƒ•áƒáƒ›áƒ“áƒ” áƒ§áƒ•áƒ”áƒšáƒáƒ¤áƒ”áƒ áƒ˜ áƒ’áƒáƒ“áƒáƒ•áƒáƒ›áƒáƒ¬áƒ›áƒ”."
        )

        save = st.form_submit_button("áƒªáƒ•áƒšáƒ˜áƒšáƒ”áƒ‘áƒ”áƒ‘áƒ˜áƒ¡ áƒ¨áƒ”áƒœáƒáƒ®áƒ•áƒ")

        if save:
            if not confirm:
                st.error("áƒªáƒ•áƒšáƒ˜áƒšáƒ”áƒ‘áƒ”áƒ‘áƒ˜áƒ¡ áƒ¨áƒ”áƒ¡áƒáƒœáƒáƒ®áƒáƒ“ áƒ¡áƒáƒ­áƒ˜áƒ áƒáƒ áƒ“áƒáƒ“áƒáƒ¡áƒ¢áƒ£áƒ áƒ”áƒ‘áƒ.")
            elif not valid_email(email.strip()):
                st.error("áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ áƒáƒ áƒáƒ¡áƒ¬áƒáƒ áƒ˜áƒ.")
            elif not valid_phone(phone):
                st.error("áƒœáƒáƒ›áƒ”áƒ áƒ˜ áƒáƒ áƒáƒ¡áƒ¬áƒáƒ áƒ˜áƒ.")
            elif not business_name.strip():
                st.error("áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒ“áƒáƒ¡áƒáƒ®áƒ”áƒšáƒ”áƒ‘áƒ áƒáƒ£áƒªáƒ˜áƒšáƒ”áƒ‘áƒ”áƒšáƒ˜áƒ.")
            else:
                conn = db()

                conflict = conn.execute(
                    """
                    SELECT id FROM users
                    WHERE (lower(email)=lower(?) OR phone=?)
                    AND id != ?
                    """,
                    (email.strip(), normalize_phone(phone), user["id"]),
                ).fetchone()

                if conflict:
                    conn.close()
                    st.error("áƒ”áƒ¡ áƒ”áƒšáƒ¤áƒáƒ¡áƒ¢áƒ áƒáƒœ áƒœáƒáƒ›áƒ”áƒ áƒ˜ áƒ¡áƒ®áƒ•áƒ áƒáƒœáƒ’áƒáƒ áƒ˜áƒ¨áƒ¡ áƒ”áƒ™áƒ£áƒ—áƒ•áƒœáƒ˜áƒ¡.")
                else:
                    logo_path = user["logo_path"]
                    if logo:
                        logo_path = save_uploaded_file(logo, f"logo_{user['id']}")

                    conn.execute(
                        """
                        UPDATE users
                        SET business_name=?, email=?, phone=?,
                            business_type=?, logo_path=?
                        WHERE id=?
                        """,
                        (
                            business_name.strip(),
                            email.strip().lower(),
                            normalize_phone(phone),
                            business_type,
                            logo_path,
                            user["id"],
                        ),
                    )
                    conn.commit()
                    conn.close()

                    add_notification(
                        user["id"],
                        "áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜ áƒ¨áƒ”áƒ˜áƒªáƒ•áƒáƒšáƒ",
                        "áƒ‘áƒ˜áƒ–áƒœáƒ”áƒ¡áƒ˜áƒ¡ áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜áƒ¡ áƒ›áƒáƒœáƒáƒªáƒ”áƒ›áƒ”áƒ‘áƒ˜ áƒ¬áƒáƒ áƒ›áƒáƒ¢áƒ”áƒ‘áƒ˜áƒ— áƒ’áƒáƒœáƒáƒ®áƒšáƒ“áƒ.",
                        "profile",
                    )

                    st.success("áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜ áƒ’áƒáƒœáƒáƒ®áƒšáƒ“áƒ.")
                    st.rerun()

    st.markdown("---")
    st.subheader("áƒžáƒáƒ áƒáƒšáƒ˜áƒ¡ áƒ¨áƒ”áƒªáƒ•áƒšáƒ")

    with st.form("password_form"):
        old_password = st.text_input("áƒ«áƒ•áƒ”áƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ˜", type="password")
        new_password = st.text_input("áƒáƒ®áƒáƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ˜", type="password")
        new_password2 = st.text_input(
            "áƒ’áƒáƒ˜áƒ›áƒ”áƒáƒ áƒ” áƒáƒ®áƒáƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ˜",
            type="password",
        )

        confirm_password = st.checkbox(
            "áƒ•áƒáƒ“áƒáƒ¡áƒ¢áƒ£áƒ áƒ”áƒ‘, áƒ áƒáƒ› áƒáƒ®áƒáƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ˜ áƒ¡áƒ¬áƒáƒ áƒáƒ“ áƒ¨áƒ”áƒ•áƒáƒ›áƒáƒ¬áƒ›áƒ” áƒ“áƒ áƒ«áƒ•áƒ”áƒšáƒ˜áƒ¡ áƒ“áƒáƒ‘áƒ áƒ£áƒœáƒ”áƒ‘áƒ áƒ¡áƒáƒ­áƒ˜áƒ áƒáƒ”áƒ‘áƒ˜áƒ¡ áƒ¨áƒ”áƒ›áƒ—áƒ®áƒ•áƒ”áƒ•áƒáƒ¨áƒ˜ áƒ›áƒ®áƒáƒšáƒáƒ“ áƒáƒ®áƒáƒšáƒ˜ áƒªáƒ•áƒšáƒ˜áƒšáƒ”áƒ‘áƒ˜áƒ— áƒ¨áƒ”áƒ›áƒ”áƒ«áƒšáƒ”áƒ‘áƒ."
        )

        change = st.form_submit_button("áƒžáƒáƒ áƒáƒšáƒ˜áƒ¡ áƒ¨áƒ”áƒªáƒ•áƒšáƒ")

        if change:
            if not confirm_password:
                st.error("áƒ¯áƒ”áƒ  áƒ“áƒáƒáƒ“áƒáƒ¡áƒ¢áƒ£áƒ áƒ” áƒªáƒ•áƒšáƒ˜áƒšáƒ”áƒ‘áƒ.")
            elif not bcrypt.checkpw(
                old_password.encode("utf-8"),
                user["password_hash"].encode("utf-8"),
            ):
                st.error("áƒ«áƒ•áƒ”áƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ˜ áƒáƒ áƒáƒ¡áƒ¬áƒáƒ áƒ˜áƒ.")
            elif not password_ok(new_password):
                st.error("áƒáƒ®áƒáƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ˜ áƒ£áƒœáƒ“áƒ áƒ¨áƒ”áƒ˜áƒªáƒáƒ•áƒ“áƒ”áƒ¡ áƒ›áƒ˜áƒœáƒ˜áƒ›áƒ£áƒ› 8 áƒ¡áƒ˜áƒ›áƒ‘áƒáƒšáƒáƒ¡.")
            elif new_password != new_password2:
                st.error("áƒáƒ®áƒáƒšáƒ˜ áƒžáƒáƒ áƒáƒšáƒ”áƒ‘áƒ˜ áƒ”áƒ áƒ—áƒ›áƒáƒœáƒ”áƒ—áƒ¡ áƒáƒ  áƒ”áƒ›áƒ—áƒ®áƒ•áƒ”áƒ•áƒ.")
            else:
                new_hash = bcrypt.hashpw(
                    new_password.encode("utf-8"),
                    bcrypt.gensalt(),
                ).decode("utf-8")

                conn = db()
                conn.execute(
                    "UPDATE users SET password_hash=? WHERE id=?",
                    (new_hash, user["id"]),
                )
                # Invalidate every other active login after password change.
                token = cookie_manager.get("storeflow_session")
                if token:
                    conn.execute(
                        "DELETE FROM sessions WHERE user_id=? AND token_hash != ?",
                        (user["id"], hash_token(token)),
                    )
                conn.commit()
                conn.close()

                add_notification(
                    user["id"],
                    "áƒžáƒáƒ áƒáƒšáƒ˜ áƒ¨áƒ”áƒ˜áƒªáƒ•áƒáƒšáƒ",
                    "áƒáƒœáƒ’áƒáƒ áƒ˜áƒ¨áƒ˜áƒ¡ áƒžáƒáƒ áƒáƒšáƒ˜ áƒ¬áƒáƒ áƒ›áƒáƒ¢áƒ”áƒ‘áƒ˜áƒ— áƒ¨áƒ”áƒ˜áƒªáƒ•áƒáƒšáƒ.",
                    "security",
                )

                st.success("áƒžáƒáƒ áƒáƒšáƒ˜ áƒ¬áƒáƒ áƒ›áƒáƒ¢áƒ”áƒ‘áƒ˜áƒ— áƒ¨áƒ”áƒ˜áƒªáƒ•áƒáƒšáƒ.")
                st.rerun()


    st.markdown("---")
    st.subheader("ðŸ—‘ï¸ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜áƒ¡ áƒ›áƒáƒ áƒ—áƒ•áƒ")
    st.markdown(
        '<div class="small-muted">áƒ”áƒ¡ áƒ›áƒáƒ¥áƒ›áƒ”áƒ“áƒ”áƒ‘áƒ áƒ¬áƒáƒ¨áƒšáƒ˜áƒ¡ áƒáƒ› áƒáƒœáƒ’áƒáƒ áƒ˜áƒ¨áƒ˜áƒ¡ áƒ§áƒ•áƒ”áƒšáƒ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒáƒ¡. áƒ¬áƒáƒ¨áƒšáƒ˜áƒšáƒ˜ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜áƒ¡ áƒ“áƒáƒ‘áƒ áƒ£áƒœáƒ”áƒ‘áƒ áƒ¨áƒ”áƒ£áƒ«áƒšáƒ”áƒ‘áƒ”áƒšáƒ˜áƒ.</div>',
        unsafe_allow_html=True,
    )

    clear_confirm = st.checkbox(
        "áƒ•áƒáƒ“áƒáƒ¡áƒ¢áƒ£áƒ áƒ”áƒ‘, áƒ áƒáƒ› áƒœáƒáƒ›áƒ“áƒ•áƒ˜áƒšáƒáƒ“ áƒ›áƒ˜áƒœáƒ“áƒ áƒ§áƒ•áƒ”áƒšáƒ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ¬áƒáƒ¨áƒšáƒ.",
        key="clear_orders_confirm",
    )
    clear_orders = st.button(
        "ðŸ—‘ï¸ áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜áƒ¡ áƒ’áƒáƒ¡áƒ£áƒ¤áƒ—áƒáƒ•áƒ”áƒ‘áƒ",
        type="secondary",
        use_container_width=True,
        disabled=not clear_confirm,
        key="clear_all_orders",
    )

    if clear_orders:
        conn = db()
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM orders WHERE user_id = ?",
            (user["id"],),
        ).fetchone()["c"]
        conn.execute("DELETE FROM orders WHERE user_id = ?", (user["id"],))
        conn.commit()
        conn.close()

        add_notification(
            user["id"],
            "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜ áƒ’áƒáƒ¡áƒ£áƒ¤áƒ—áƒáƒ•áƒ“áƒ",
            f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜áƒ¡ áƒ˜áƒ¡áƒ¢áƒáƒ áƒ˜áƒ áƒ’áƒáƒ˜áƒ¬áƒ›áƒ˜áƒœáƒ“áƒ. áƒ¬áƒáƒ˜áƒ¨áƒáƒšáƒ {count} áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ.",
            "info",
        )
        st.success(f"áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜ áƒ’áƒáƒ¡áƒ£áƒ¤áƒ—áƒáƒ•áƒ“áƒ â€” áƒ¬áƒáƒ˜áƒ¨áƒáƒšáƒ {count} áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ.")
        st.rerun()


# -----------------------------
# Sidebar / app shell
# -----------------------------
def app_shell(user):
    create_due_reminders(user["id"])

    if "page" not in st.session_state:
        st.session_state.page = "áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜"

    with st.sidebar:
        st.markdown(
            '<div class="sf-logo"><span class="sf-gradient">StoreFlow</span></div>',
            unsafe_allow_html=True,
        )

        if user["logo_path"] and Path(user["logo_path"]).exists():
            st.image(user["logo_path"], width=80)

        st.caption(user["business_name"])
        st.caption(user["business_type"])

        conn = db()
        unread = conn.execute("SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND is_read=0", (user["id"],)).fetchone()["c"]
        conn.close()

        pages = {
            "áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜": "âŒ‚  áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜",
            "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ": "ï¼‹  áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ",
            "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜": "â–£  áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜",
            "áƒ¨áƒ”áƒ¢áƒ§áƒáƒ‘áƒ˜áƒœáƒ”áƒ‘áƒ”áƒ‘áƒ˜": f"â™§  áƒ¨áƒ”áƒ¢áƒ§áƒáƒ‘áƒ˜áƒœáƒ”áƒ‘áƒ”áƒ‘áƒ˜  {unread if unread else ''}",
            "áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜": "â™™  áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜",
        }

        for key, label in pages.items():
            if st.button(
                label,
                key=f"nav_{key}",
                use_container_width=True,
            ):
                st.session_state.page = key
                st.rerun()

        st.markdown("---")
        st.markdown('''<div class="sf-card" style="padding:15px;background:linear-gradient(145deg,#15102c,#101426)"><b style="color:#fff">â™› Premium áƒ’áƒ”áƒ’áƒ›áƒ</b><div class="small-muted" style="margin:5px 0 10px">áƒ›áƒ”áƒ¢áƒ˜ áƒ¨áƒ”áƒ¡áƒáƒ«áƒšáƒ”áƒ‘áƒšáƒáƒ‘áƒ”áƒ‘áƒ˜áƒ¡áƒ—áƒ•áƒ˜áƒ¡</div></div>''', unsafe_allow_html=True)

        if st.button("ðŸšª áƒ’áƒáƒ›áƒáƒ¡áƒ•áƒšáƒ", use_container_width=True):
            logout()

    page = st.session_state.page

    if page == "áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜":
        dashboard(user)
    elif page == "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ˜áƒ¡ áƒ’áƒáƒ¤áƒáƒ áƒ›áƒ”áƒ‘áƒ":
        new_order_page(user)
    elif page == "áƒ¨áƒ”áƒ™áƒ•áƒ”áƒ—áƒ”áƒ‘áƒ˜":
        orders_page(user)
    elif page == "áƒ¨áƒ”áƒ¢áƒ§áƒáƒ‘áƒ˜áƒœáƒ”áƒ‘áƒ”áƒ‘áƒ˜":
        notifications_page(user)
    elif page == "áƒžáƒ áƒáƒ¤áƒ˜áƒšáƒ˜":
        profile_page(user)


# -----------------------------
# App entry
# -----------------------------
def main():
    if "user_id" not in st.session_state:
        cookie_user = get_user_from_cookie()
        if cookie_user:
            st.session_state.user_id = cookie_user["id"]
            st.session_state.page = "áƒ›áƒ—áƒáƒ•áƒáƒ áƒ˜"

    if "user_id" not in st.session_state:
        if "auth_mode" not in st.session_state:
            st.session_state.auth_mode = "login"

        if st.session_state.auth_mode == "login":
            login_page()
        else:
            registration_page()
        return

    user = get_user(st.session_state.user_id)

    if not user:
        st.session_state.clear()
        login_page()
        return

    app_shell(user)


if __name__ == "__main__":
    main()
