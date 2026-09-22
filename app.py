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
# StoreFlow — Streamlit demo
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
    "ონლაინ მაღაზია",
    "ოჯახის მაღაზია",
    "შიდა გაყიდვები",
    "Instagram / Facebook მაღაზია",
    "საბითუმო გაყიდვები",
    "სერვისი / მომსახურება",
    "სხვა",
]


# -----------------------------
# Page setup
# -----------------------------
st.set_page_config(
    page_title="StoreFlow",
    page_icon="📊",
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
            stage TEXT NOT NULL DEFAULT 'გაფორმებული',
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
    return f"₾{float(v):,.2f}"


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
          AND stage != 'ჩაბარებული'
        """,
        (user_id, cutoff.isoformat()),
    ).fetchall()

    for order in rows:
        add_notification(
            user_id,
            "შეკვეთის გადამოწმება",
            f"შეკვეთა #{order['id']} უკვე 10 დღისაა. გადაამოწმე, რა ეტაპზეა ამანათი.",
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

html, body, [class*="css"] {
    font-family: 'Noto Sans Georgian', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 85% 0%, rgba(143, 76, 255, .13), transparent 30%),
        radial-gradient(circle at 20% 10%, rgba(255, 69, 132, .07), transparent 24%),
        #070910;
    color: #f4f3fb;
}

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b0e17 0%, #090b12 100%);
    border-right: 1px solid rgba(255,255,255,.06);
}

.block-container {
    padding-top: 1.6rem;
    max-width: 1450px;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, rgba(25,28,40,.96), rgba(13,16,25,.96));
    border: 1px solid rgba(255,255,255,.07);
    padding: 18px;
    border-radius: 22px;
    box-shadow: 0 18px 60px rgba(0,0,0,.18);
}

div[data-testid="stMetricLabel"] {
    color: #a9a8b8;
}

div[data-testid="stMetricValue"] {
    color: #fff;
}

.stButton > button {
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 13px;
    background: linear-gradient(135deg, #8b5cf6, #c04cf2);
    color: white;
    font-weight: 700;
    padding: .55rem 1rem;
    transition: .2s ease;
}

.stButton > button:hover {
    transform: translateY(-1px);
    filter: brightness(1.08);
}

input, textarea, [data-baseweb="select"] > div {
    border-radius: 12px !important;
}

.sf-card {
    background: linear-gradient(145deg, rgba(20,23,34,.96), rgba(11,14,23,.96));
    border: 1px solid rgba(255,255,255,.07);
    border-radius: 22px;
    padding: 22px;
    margin-bottom: 18px;
    box-shadow: 0 18px 60px rgba(0,0,0,.16);
}

.sf-logo {
    font-size: 25px;
    font-weight: 800;
    letter-spacing: -.7px;
    margin-bottom: 22px;
}

.sf-gradient {
    background: linear-gradient(90deg, #ff4d91, #9b5cff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.small-muted {
    color: #9293a3;
    font-size: 13px;
}

.order-card {
    background: #10131d;
    border: 1px solid rgba(255,255,255,.07);
    border-radius: 18px;
    padding: 16px;
    margin-bottom: 12px;
}

.badge {
    display:inline-block;
    padding:5px 10px;
    border-radius:999px;
    background:rgba(139,92,246,.14);
    color:#c7b5ff;
    font-size:12px;
}

div[data-testid="stFileUploader"] {
    border-radius: 16px;
}

hr {
    border-color: rgba(255,255,255,.07);
}

.auth-wrap {
    max-width: 540px;
    margin: 50px auto;
}
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
            <h1>შექმენი შენი სამუშაო სივრცე</h1>
            <p class="small-muted">მართე ონლაინ-მაღაზია ერთი მარტივი პანელიდან.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("register_form"):
        email = st.text_input("ელფოსტა")
        phone = st.text_input("საკონტაქტო ნომერი")
        business_name = st.text_input("ბიზნესის დასახელება")
        business_type = st.selectbox("რა სახის ბიზნესია?", BUSINESS_TYPES)
        password = st.text_input("პაროლი", type="password")
        password2 = st.text_input("გაიმეორე პაროლი", type="password")
        logo = st.file_uploader(
            "ლოგო (სურვილისამებრ)",
            type=["png", "jpg", "jpeg", "webp"],
        )

        agree = st.checkbox("ვეთანხმები, რომ ჩემი მონაცემები გამოიყენება ამ აპში.")
        submitted = st.form_submit_button("რეგისტრაცია", use_container_width=True)

        if submitted:
            email = normalize_email(email)
            phone = normalize_phone(phone)

            if not valid_email(email):
                st.error("შეიყვანე სწორი ელფოსტა.")
            elif not valid_phone(phone):
                st.error("შეიყვანე სწორი საკონტაქტო ნომერი.")
            elif not business_name.strip():
                st.error("ბიზნესის დასახელება აუცილებელია.")
            elif not password_ok(password):
                st.error("პაროლი უნდა შეიცავდეს მინიმუმ 8 სიმბოლოს.")
            elif password != password2:
                st.error("პაროლები ერთმანეთს არ ემთხვევა.")
            elif not agree:
                st.error("გთხოვ, მონიშნე თანხმობა.")
            else:
                conn = db()
                exists = conn.execute(
                    "SELECT id FROM users WHERE email = ? OR phone = ?",
                    (email, phone),
                ).fetchone()

                if exists:
                    conn.close()
                    st.error("ეს ელფოსტა ან ნომერი უკვე რეგისტრირებულია.")
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
                    st.session_state.page = "მთავარი"
                    st.success("რეგისტრაცია წარმატებით დასრულდა!")
                    st.rerun()

    if st.button("უკვე მაქვს ანგარიში → შესვლა", use_container_width=True):
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
            <h1>კეთილი იყოს შენი დაბრუნება</h1>
            <p class="small-muted">შედი შენი ელფოსტით ან ნომრით.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("login_form"):
        identifier = st.text_input("ელფოსტა ან ნომერი")
        password = st.text_input("პაროლი", type="password")
        remember = st.checkbox("დამიმახსოვრე ამ მოწყობილობაზე", value=True)

        submitted = st.form_submit_button("შესვლა", use_container_width=True)

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
                st.error("ელფოსტა/ნომერი ან პაროლი არასწორია.")
            else:
                days = 30 if remember else 1
                create_session(user["id"], days)
                st.session_state.user_id = user["id"]
                st.session_state.page = "მთავარი"
                st.rerun()

    if st.button("არ მაქვს ანგარიში → რეგისტრაცია", use_container_width=True):
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

    unread = db().execute(
        "SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0",
        (user_id,),
    ).fetchone()["c"]

    st.markdown(
        f"""
        <div class="sf-card">
            <div style="font-size:14px;color:#9698a9">მთავარი</div>
            <h1 style="margin:4px 0 5px">გამარჯობა, {user["business_name"]} 👋</h1>
            <div class="small-muted">აქედან აკონტროლებ შენს გაყიდვებს, ხარჯებს და მოგებას.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    c1.metric("შემოსავალი", money(total_income))
    c2.metric("გასავალი", money(total_expense))
    c3.metric("მოგება", money(total_profit))

    st.markdown("### ფინანსური დინამიკა")

    period = st.segmented_control(
        "პერიოდი",
        ["ბოლო 7 დღე", "ბოლო 1 თვე", "ბოლო 3 თვე", "ბოლო 1 წელი"],
        default="ბოლო 7 დღე",
        label_visibility="collapsed",
    )

    if period is None:
        period = "ბოლო 7 დღე"

    days_map = {
        "ბოლო 7 დღე": 7,
        "ბოლო 1 თვე": 30,
        "ბოლო 3 თვე": 90,
        "ბოლო 1 წელი": 365,
    }
    days = days_map[period]
    start = datetime.now() - timedelta(days=days - 1)

    dates = pd.date_range(start.date(), datetime.now().date(), freq="D")
    df = pd.DataFrame({"date": dates})

    order_df = pd.DataFrame(
        [
            {
                "date": datetime.fromisoformat(o["created_at"]).date(),
                "income": float(o["price"]),
                "expense": float(o["cost"]),
            }
            for o in orders
        ]
    )

    if len(order_df):
        grouped = order_df.groupby("date")[["income", "expense"]].sum().reset_index()
        df = df.merge(grouped, on="date", how="left")
    else:
        df["income"] = 0
        df["expense"] = 0

    df = df.fillna(0)
    df["profit"] = df["income"] - df["expense"]

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=df["date"],
            y=df["income"],
            name="შემოსავალი",
            mode="lines",
            line=dict(width=3, color="#7CFFB2"),
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["date"],
            y=df["expense"],
            name="გასავალი",
            mode="lines",
            line=dict(width=3, color="#FF5D8F"),
        )
    )
    fig.add_trace(
        go.Scatter(
            x=df["date"],
            y=df["profit"],
            name="მოგება",
            mode="lines",
            line=dict(width=3, color="#A875FF"),
        )
    )

    fig.update_layout(
        height=310,
        margin=dict(l=10, r=10, t=15, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c8c7d2"),
        legend=dict(orientation="h", y=-0.2),
        xaxis=dict(showgrid=False),
        yaxis=dict(gridcolor="rgba(255,255,255,.06)"),
        hovermode="x unified",
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown(
            """
            <div class="sf-card">
                <h3>ბოლო შეკვეთები</h3>
            </div>
            """,
            unsafe_allow_html=True,
        )

        for o in orders[:5]:
            profit = float(o["price"]) - float(o["cost"])
            st.markdown(
                f"""
                <div class="order-card">
                    <b>#{o["id"]} — {o["product"]}</b><br>
                    <span class="small-muted">{o["customer_name"]} · {o["phone"]}</span>
                    <div style="margin-top:8px">
                        <span class="badge">{o["stage"]}</span>
                        <span style="float:right;color:#7CFFB2">
                            მოგება {money(profit)}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        if not orders:
            st.info("ჯერ შეკვეთები არ გაქვს. დაამატე პირველი შეკვეთა.")

    with col2:
        st.markdown(
            f"""
            <div class="sf-card">
                <h3>სწრაფი ინფორმაცია</h3>
                <p>📦 ყველა შეკვეთა: <b>{len(orders)}</b></p>
                <p>📝 გაფორმებული: <b>{sum(o["stage"]=="გაფორმებული" for o in orders)}</b></p>
                <p>🚚 ჩამოსული: <b>{sum(o["stage"]=="ჩამოსულია" for o in orders)}</b></p>
                <p>✅ ჩაბარებული: <b>{sum(o["stage"]=="ჩაბარებული" for o in orders)}</b></p>
                <p>🔔 ახალი შეტყობინება: <b>{unread}</b></p>
            </div>
            """,
            unsafe_allow_html=True,
        )


# -----------------------------
# New order
# -----------------------------
def new_order_page(user):
    st.title("შეკვეთის გაფორმება")
    st.caption("შეავსე შეკვეთის ინფორმაცია — მოგება ავტომატურად დაითვლება.")

    left, right = st.columns([1.5, 1])

    with left:
        customer_name = st.text_input("სახელი")
        phone = st.text_input("ნომერი")
        address = st.text_area("მისამართი", height=90)
        product = st.text_input("პროდუქტი")
        product_photo = st.file_uploader(
            "პროდუქტის ფოტო (სურვილისამებრ)",
            type=["png", "jpg", "jpeg", "webp"],
        )

    with right:
        price = st.number_input("ფასი", min_value=0.0, step=1.0, format="%.2f")
        cost = st.number_input("ღირებულება", min_value=0.0, step=1.0, format="%.2f")
        transport_fee = st.number_input(
            "ტრანსპორტირების თანხა",
            min_value=0.0,
            step=1.0,
            format="%.2f",
            help="ეს თანხა ხარჯებში არ ჩაითვლება.",
        )

        profit = price - cost

        st.markdown(
            f"""
            <div class="sf-card" style="margin-top:15px;text-align:center">
                <div class="small-muted">ამ შეკვეთის მოგება</div>
                <div style="font-size:34px;font-weight:800;color:#7CFFB2">
                    {money(profit)}
                </div>
                <div class="small-muted">ფასი − პროდუქტის ღირებულება</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if st.button("შეკვეთის გაფორმება →", use_container_width=True):
        if not customer_name.strip():
            st.error("სახელი აუცილებელია.")
            return
        if not valid_phone(normalize_phone(phone)):
            st.error("შეიყვანე სწორი ნომერი.")
            return
        if not address.strip():
            st.error("მისამართი აუცილებელია.")
            return
        if not product.strip():
            st.error("პროდუქტი აუცილებელია.")
            return
        if price <= 0:
            st.error("ფასი უნდა იყოს 0-ზე მეტი.")
            return
        if cost < 0:
            st.error("ღირებულება არასწორია.")
            return

        photo_path = save_uploaded_file(product_photo, f"product_{user['id']}")

        conn = db()
        cur = conn.execute(
            """
            INSERT INTO orders
            (user_id, customer_name, price, cost, address, phone, product,
             photo_path, transport_fee, stage, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'გაფორმებული', ?)
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
            "ახალი შეკვეთა",
            f"შეკვეთა #{order_id} — {product} წარმატებით გაფორმდა.",
            "order",
        )

        st.success(f"შეკვეთა #{order_id} წარმატებით გაფორმდა!")
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
                    <b>#{order["id"]} — {order["product"]}</b><br>
                    <span class="small-muted">
                        {order["customer_name"]} · {order["phone"]}
                    </span>
                </div>
                <div style="text-align:right">
                    <b>{money(order["price"])}</b><br>
                    <span style="color:#7CFFB2">მოგება {money(profit)}</span>
                </div>
            </div>
            <hr>
            <div class="small-muted">
                📍 {order["address"]}<br>
                💰 ღირებულება: {money(order["cost"])}<br>
                🚚 ტრანსპორტირება: {money(order["transport_fee"])}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if order["photo_path"] and Path(order["photo_path"]).exists():
        st.image(order["photo_path"], width=160)

    if stage == "გაფორმებული":
        if st.button(
            f"გადავიდა „ჩამოსულია“-ში #{order['id']}",
            key=f"arrive_{order['id']}",
            use_container_width=True,
        ):
            conn = db()
            conn.execute(
                """
                UPDATE orders
                SET stage = 'ჩამოსულია', arrived_at = ?
                WHERE id = ?
                """,
                (now_iso(), order["id"]),
            )
            conn.commit()
            conn.close()

            add_notification(
                order["user_id"],
                "შეკვეთის სტატუსი შეიცვალა",
                f"შეკვეთა #{order['id']} გადავიდა „ჩამოსულია“-ში.",
                "order",
            )
            st.rerun()

    elif stage == "ჩამოსულია":
        paid = st.checkbox(
            "მომხმარებელმა ტრანსპორტირების თანხა გადაიხადა",
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
            f"ჩაბარებულში გადატანა #{order['id']}",
            key=f"deliver_{order['id']}",
            use_container_width=True,
            disabled=not paid,
        ):
            conn = db()
            conn.execute(
                """
                UPDATE orders
                SET stage = 'ჩაბარებული', delivered_at = ?
                WHERE id = ?
                """,
                (now_iso(), order["id"]),
            )
            conn.commit()
            conn.close()

            add_notification(
                order["user_id"],
                "შეკვეთა ჩაბარდა",
                f"შეკვეთა #{order['id']} მონიშნულია როგორც ჩაბარებული.",
                "order",
            )
            st.rerun()

    else:
        st.success("შეკვეთა ჩაბარებულია.")


def orders_page(user):
    st.title("შეკვეთები")

    orders = get_orders(user["id"])
    stages = ["გაფორმებული", "ჩამოსულია", "ჩაბარებული"]

    counts = {
        stage: sum(o["stage"] == stage for o in orders)
        for stage in stages
    }

    a, b, c = st.columns(3)
    a.metric("გაფორმებული", counts["გაფორმებული"])
    b.metric("ჩამოსულია", counts["ჩამოსულია"])
    c.metric("ჩაბარებული", counts["ჩაბარებული"])

    st.markdown("")

    tabs = st.tabs(
        [
            f"გაფორმებული · {counts['გაფორმებული']}",
            f"ჩამოსულია · {counts['ჩამოსულია']}",
            f"ჩაბარებული · {counts['ჩაბარებული']}",
        ]
    )

    for tab, stage in zip(tabs, stages):
        with tab:
            matching = [o for o in orders if o["stage"] == stage]
            if not matching:
                st.info("ამ ეტაპზე შეკვეთები არ არის.")
            for order in matching:
                render_order_card(order, stage)


# -----------------------------
# Notifications
# -----------------------------
def notifications_page(user):
    st.title("შეტყობინებები")

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
        st.info("შეტყობინებები ჯერ არ არის.")
        return

    for n in rows:
        icon = {
            "order": "📦",
            "reminder": "⏰",
            "profile": "👤",
            "security": "🔐",
            "info": "🔔",
        }.get(n["kind"], "🔔")

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
    st.title("პროფილი")
    st.caption("ცვლილებამდე გადაამოწმე ინფორმაცია ყურადღებით.")

    with st.form("profile_form"):
        business_name = st.text_input(
            "ბიზნესის დასახელება",
            value=user["business_name"],
        )
        email = st.text_input("ელფოსტა", value=user["email"] or "")
        phone = st.text_input("ნომერი", value=user["phone"] or "")
        business_type = st.selectbox(
            "ბიზნესის ტიპი",
            BUSINESS_TYPES,
            index=(
                BUSINESS_TYPES.index(user["business_type"])
                if user["business_type"] in BUSINESS_TYPES
                else 0
            ),
        )
        logo = st.file_uploader(
            "ახალი ლოგო",
            type=["png", "jpg", "jpeg", "webp"],
        )

        confirm = st.checkbox(
            "ვადასტურებ, რომ ცვლილებების შენახვამდე ყველაფერი გადავამოწმე."
        )

        save = st.form_submit_button("ცვლილებების შენახვა")

        if save:
            if not confirm:
                st.error("ცვლილებების შესანახად საჭიროა დადასტურება.")
            elif not valid_email(email.strip()):
                st.error("ელფოსტა არასწორია.")
            elif not valid_phone(phone):
                st.error("ნომერი არასწორია.")
            elif not business_name.strip():
                st.error("ბიზნესის დასახელება აუცილებელია.")
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
                    st.error("ეს ელფოსტა ან ნომერი სხვა ანგარიშს ეკუთვნის.")
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
                        "პროფილი შეიცვალა",
                        "ბიზნესის პროფილის მონაცემები წარმატებით განახლდა.",
                        "profile",
                    )

                    st.success("პროფილი განახლდა.")
                    st.rerun()

    st.markdown("---")
    st.subheader("პაროლის შეცვლა")

    with st.form("password_form"):
        old_password = st.text_input("ძველი პაროლი", type="password")
        new_password = st.text_input("ახალი პაროლი", type="password")
        new_password2 = st.text_input(
            "გაიმეორე ახალი პაროლი",
            type="password",
        )

        confirm_password = st.checkbox(
            "ვადასტურებ, რომ ახალი პაროლი სწორად შევამოწმე და ძველის დაბრუნება საჭიროების შემთხვევაში მხოლოდ ახალი ცვლილებით შემეძლება."
        )

        change = st.form_submit_button("პაროლის შეცვლა")

        if change:
            if not confirm_password:
                st.error("ჯერ დაადასტურე ცვლილება.")
            elif not bcrypt.checkpw(
                old_password.encode("utf-8"),
                user["password_hash"].encode("utf-8"),
            ):
                st.error("ძველი პაროლი არასწორია.")
            elif not password_ok(new_password):
                st.error("ახალი პაროლი უნდა შეიცავდეს მინიმუმ 8 სიმბოლოს.")
            elif new_password != new_password2:
                st.error("ახალი პაროლები ერთმანეთს არ ემთხვევა.")
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
                    "პაროლი შეიცვალა",
                    "ანგარიშის პაროლი წარმატებით შეიცვალა.",
                    "security",
                )

                st.success("პაროლი წარმატებით შეიცვალა.")
                st.rerun()


# -----------------------------
# Sidebar / app shell
# -----------------------------
def app_shell(user):
    create_due_reminders(user["id"])

    if "page" not in st.session_state:
        st.session_state.page = "მთავარი"

    with st.sidebar:
        st.markdown(
            '<div class="sf-logo"><span class="sf-gradient">StoreFlow</span></div>',
            unsafe_allow_html=True,
        )

        if user["logo_path"] and Path(user["logo_path"]).exists():
            st.image(user["logo_path"], width=80)

        st.caption(user["business_name"])
        st.caption(user["business_type"])

        pages = {
            "მთავარი": "🏠 მთავარი",
            "შეკვეთის გაფორმება": "＋ შეკვეთის გაფორმება",
            "შეკვეთები": "📦 შეკვეთები",
            "შეტყობინებები": "🔔 შეტყობინებები",
            "პროფილი": "⚙️ პროფილი",
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

        if st.button("🚪 გამოსვლა", use_container_width=True):
            logout()

    page = st.session_state.page

    if page == "მთავარი":
        dashboard(user)
    elif page == "შეკვეთის გაფორმება":
        new_order_page(user)
    elif page == "შეკვეთები":
        orders_page(user)
    elif page == "შეტყობინებები":
        notifications_page(user)
    elif page == "პროფილი":
        profile_page(user)


# -----------------------------
# App entry
# -----------------------------
def main():
    if "user_id" not in st.session_state:
        cookie_user = get_user_from_cookie()
        if cookie_user:
            st.session_state.user_id = cookie_user["id"]
            st.session_state.page = "მთავარი"

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
