import os
import json
import re
import sqlite3
import logging
import hashlib
import requests  # Telegram Bot API
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_DOWN

import csv
import io

# ✅ (NEW) for link code generation
import secrets
import string

# ===== Postgres (Neon) Support =====
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:
    psycopg2 = None
    RealDictCursor = None

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    g,
    abort,
    Response,
)
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

from currency_converter.converter import convert_currency

# ==============================
# تحميل الإعدادات من .env
# ==============================
load_dotenv()

EXCHANGE_API_KEY = os.getenv("EXCHANGE_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "changeme")
DB_PATH = os.getenv("DB_PATH", "database_v2.db")
BINANCE_UID = os.getenv("BINANCE_UID", "YOUR_BINANCE_UID_HERE")

# Neon / Postgres
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL)

# رابط الشحن الأوتوماتيكي 100 USDT
BINANCE_AUTO_100_URL = os.getenv("BINANCE_AUTO_100_URL", "").strip()
if not BINANCE_AUTO_100_URL:
    BINANCE_AUTO_100_URL = "https://s.binance.com/nLrZHHvJ"

# إعدادات بوت تيليجرام
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_API_URL = (
    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
    if TELEGRAM_BOT_TOKEN
    else None
)

# رابط المنصة (للاستخدام داخل البوت)
SITE_PUBLIC_URL = os.getenv(
    "SITE_PUBLIC_URL",
    "https://currency-exchange-app-2ymh.onrender.com"
)

# ==============================
# Telegram Linking + Bot Wallet settings
# ==============================
LINK_CODE_PREFIX = os.getenv("LINK_CODE_PREFIX", "LNK-").strip().upper()
BOT_TOPUP_FIXED_USD = float(os.getenv("BOT_TOPUP_FIXED_USD", "10"))
BOT_MIN_CASHOUT_USD = float(os.getenv("BOT_MIN_CASHOUT_USD", "1"))

# مكافآت الإحالات (Telegram)
REF_L1_BONUS_USD = float(os.getenv("REF_L1_BONUS_USD", "0.01"))   # مباشر
REF_L2_BONUS_USD = float(os.getenv("REF_L2_BONUS_USD", "0.003"))  # غير مباشر مستوى واحد فقط

# ✅ (NEW) تحويل تلقائي عندما يصل رصيد الإحالات 1$
REF_AUTO_CASHOUT_THRESHOLD = float(os.getenv("REF_AUTO_CASHOUT_THRESHOLD", "1.0"))

# ==============================
# إنشاء التطبيق
# ==============================
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ==============================
# الترجمة (translations.json + t)
# ==============================
TRANSLATIONS_FILE = "translations.json"

try:
    with open(TRANSLATIONS_FILE, "r", encoding="utf-8") as f:
        TRANSLATIONS = json.load(f)
except FileNotFoundError:
    TRANSLATIONS = {"ar": {}, "en": {}}


def translate(key, lang=None):
    if lang is None:
        lang = session.get("lang", "ar")
    lang_map = TRANSLATIONS.get(lang, {})
    return lang_map.get(key, key)


@app.context_processor
def inject_t():
    return {"t": translate}


# ==============================
# إعداد اللوج
# ==============================
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# ==============================
# إعدادات العملات
# ==============================
CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR", "EGP"]

CURRENCY_TO_COUNTRY = {
    "USD": "us",
    "EUR": "eu",
    "GBP": "gb",
    "MAD": "ma",
    "AED": "ae",
    "SAR": "sa",
    "EGP": "eg",
}

# ==============================
# أدوات SQL مشتركة
# ==============================
def _sql(sql: str) -> str:
    """تحويل placeholders من ? إلى %s عند Postgres."""
    return sql.replace("?", "%s") if USE_POSTGRES else sql


class PGConnectionWrapper:
    """
    Wrapper ليتصرف psycopg2 مثل sqlite:
      db.execute(...).fetchone()
      db.execute(...).fetchall()
      db.commit()
    """
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        cur = self._conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(_sql(sql), params or ())
        return cur

    def cursor(self):
        return self._conn.cursor(cursor_factory=RealDictCursor)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()    

    def close(self):
        return self._conn.close()


# ==============================
# دوال التعامل مع قاعدة البيانات
# ==============================
def get_db():
    if "db" not in g:
        if USE_POSTGRES:
            if psycopg2 is None:
                raise RuntimeError(
                    "psycopg2 is not installed. Add psycopg2-binary to requirements.txt"
                )
            g.db = PGConnectionWrapper(psycopg2.connect(DATABASE_URL))
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db

def _pg_column_exists(cur, table_name: str, column_name: str) -> bool:
    """
    Postgres: يتحقق هل عمود موجود داخل جدول أم لا.
    مهم لتوافق السكيما القديمة والجديدة بدون كسر.
    """
    cur.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        LIMIT 1
        """,
        (table_name, column_name),
    )
    return cur.fetchone() is not None


def _now_str() -> str:
    # UTC time string ثابتة
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# ==============================
# Helpers: Postgres column check
# ==============================
def _pg_column_exists(cur, table_name: str, column_name: str) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        LIMIT 1
        """,
        (table_name, column_name),
    )
    return cur.fetchone() is not None

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    # ===== Postgres schema (Neon) =====
    if USE_POSTGRES:
        if psycopg2 is None:
            raise RuntimeError(
                "psycopg2 is not installed. Add psycopg2-binary to requirements.txt"
            )

        db = psycopg2.connect(DATABASE_URL)
        cur = db.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            phone TEXT,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP::text
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS balances (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            currency TEXT NOT NULL,
            amount DOUBLE PRECISION NOT NULL DEFAULT 0,
            UNIQUE(user_id, currency)
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            amount DOUBLE PRECISION NOT NULL,
            currency TEXT,
            details TEXT,
            timestamp TEXT NOT NULL
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_deposits (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount DOUBLE PRECISION NOT NULL,
            fiat_currency TEXT NOT NULL,
            pay_method TEXT,
            status TEXT DEFAULT 'pending',
            txid TEXT,
            timestamp TEXT NOT NULL,
            processed_by TEXT,
            processed_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS pending_withdrawals (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount DOUBLE PRECISION NOT NULL,
            currency TEXT NOT NULL,
            payout_info TEXT,
            status TEXT DEFAULT 'pending',
            timestamp TEXT NOT NULL,
            processed_by TEXT,
            processed_at TEXT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            type TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            ref_type TEXT,
            ref_id BIGINT
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS telegram_users (
            id BIGSERIAL PRIMARY KEY,
            telegram_id BIGINT UNIQUE NOT NULL,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            referred_by_telegram_id BIGINT,
            referral_credits_usd DOUBLE PRECISION DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP::text
        );
        """)

        # ✅ (NEW) platform ↔ telegram linking (Postgres upgrades)

        # 1) telegram_users: أعمدة الربط + رصيد البوت
        cur.execute("ALTER TABLE telegram_users ADD COLUMN IF NOT EXISTS platform_user_id BIGINT;")
        cur.execute("ALTER TABLE telegram_users ADD COLUMN IF NOT EXISTS linked_at TEXT;")
        cur.execute("ALTER TABLE telegram_users ADD COLUMN IF NOT EXISTS bot_balance_usd DOUBLE PRECISION DEFAULT 0;")

        # 2) telegram_link_codes: إنشاء الجدول إن لم يوجد (بأقل قيود حتى لا نكسر سكيما قديمة)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS telegram_link_codes (
            id BIGSERIAL PRIMARY KEY,
            platform_user_id BIGINT,
            code TEXT,
            code_hash TEXT,
            expires_at TEXT,
            used_at TEXT,
            used_by_telegram_id BIGINT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP::text
        );
        """)

        # 3) ترقية الجدول إن كان موجود بسكيما قديمة
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS platform_user_id BIGINT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS code TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS code_hash TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS expires_at TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS used_at TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS used_by_telegram_id BIGINT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS created_at TEXT;")

        # 4) Unique/Indexes (ضرورية لسرعة البحث + منع تكرارات)
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tlc_code ON telegram_link_codes(code);")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tlc_code_hash ON telegram_link_codes(code_hash);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tlc_platform_user_id ON telegram_link_codes(platform_user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tlc_expires_at ON telegram_link_codes(expires_at);")

    # ✅ (NEW) platform ↔ telegram linking (Postgres upgrades)
        # 1) telegram_users: أعمدة الربط
        cur.execute("ALTER TABLE telegram_users ADD COLUMN IF NOT EXISTS platform_user_id BIGINT;")
        cur.execute("ALTER TABLE telegram_users ADD COLUMN IF NOT EXISTS linked_at TEXT;")

        # 2) telegram_link_codes: إنشاء الجدول إن لم يوجد (سكيما جديدة)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS telegram_link_codes (
            id BIGSERIAL PRIMARY KEY,
            platform_user_id BIGINT,
            user_id BIGINT,
            code TEXT,
            expires_at TEXT,
            used_at TEXT,
            used_by_telegram_id BIGINT
        );
        """)

        # 3) ترقية إن كان موجود بسكيما قديمة
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS platform_user_id BIGINT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS user_id BIGINT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS code TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS expires_at TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS used_at TEXT;")
        cur.execute("ALTER TABLE telegram_link_codes ADD COLUMN IF NOT EXISTS used_by_telegram_id BIGINT;")

        # 4) قيود/فهارس
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_tlc_code ON telegram_link_codes(code);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tlc_platform_user_id ON telegram_link_codes(platform_user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tlc_user_id ON telegram_link_codes(user_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_tlc_expires_at ON telegram_link_codes(expires_at);")

        # ✅ (NEW) telegram_users: رصيد البوت (يخصم منه أولا قبل رصيد الإحالات)
        cur.execute("ALTER TABLE telegram_users ADD COLUMN IF NOT EXISTS bot_balance_usd DOUBLE PRECISION DEFAULT 0;")
        # ✅ (NEW) SQLite: bot_balance_usd

        # ✅ (NEW) SQLite: bot_balance_usd
        try:
            cur.execute("ALTER TABLE telegram_users ADD COLUMN bot_balance_usd REAL DEFAULT 0;")
        except Exception:
            pass

        db.commit()
        db.close()
        return    

    # ==== ترقية الجداول لو كانت قديمة ====

    # pending_deposits
    cols_dep = {c["name"] for c in cur.execute("PRAGMA table_info(pending_deposits)").fetchall()}
    if "status" not in cols_dep:
        cur.execute("ALTER TABLE pending_deposits ADD COLUMN status TEXT DEFAULT 'pending'")
    if "processed_by" not in cols_dep:
        cur.execute("ALTER TABLE pending_deposits ADD COLUMN processed_by TEXT")
    if "processed_at" not in cols_dep:
        cur.execute("ALTER TABLE pending_deposits ADD COLUMN processed_at TEXT")

    # pending_withdrawals
    cols_w = {c["name"] for c in cur.execute("PRAGMA table_info(pending_withdrawals)").fetchall()}
    if "status" not in cols_w:
        cur.execute("ALTER TABLE pending_withdrawals ADD COLUMN status TEXT DEFAULT 'pending'")
    if "processed_by" not in cols_w:
        cur.execute("ALTER TABLE pending_withdrawals ADD COLUMN processed_by TEXT")
    if "processed_at" not in cols_w:
        cur.execute("ALTER TABLE pending_withdrawals ADD COLUMN processed_at TEXT")

    # notifications
    cols_not = {c["name"] for c in cur.execute("PRAGMA table_info(notifications)").fetchall()}

    if "body" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN body TEXT")
        if "message" in cols_not:
            try:
                cur.execute("UPDATE notifications SET body = message WHERE body IS NULL")
            except Exception:
                pass

    if "type" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN type TEXT")

    if "is_read" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN is_read INTEGER DEFAULT 0")

    if "created_at" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN created_at TEXT")

    if "ref_type" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN ref_type TEXT")
    if "ref_id" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN ref_id INTEGER")

    # telegram_users: add referral_credits_usd
    cols_tg = {c["name"] for c in cur.execute("PRAGMA table_info(telegram_users)").fetchall()}
    if "referral_credits_usd" not in cols_tg:
        cur.execute("ALTER TABLE telegram_users ADD COLUMN referral_credits_usd REAL DEFAULT 0")

    # ✅ (NEW) telegram_users: add platform_user_id + linked_at
    cols_tg = {c["name"] for c in cur.execute("PRAGMA table_info(telegram_users)").fetchall()}
    if "platform_user_id" not in cols_tg:
        cur.execute("ALTER TABLE telegram_users ADD COLUMN platform_user_id INTEGER")
    if "linked_at" not in cols_tg:
        cur.execute("ALTER TABLE telegram_users ADD COLUMN linked_at TEXT")

    # ✅ (NEW) telegram_link_codes table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS telegram_link_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform_user_id INTEGER NOT NULL,
            code TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            used_by_telegram_id INTEGER
        );
    """)

    db.commit()
    db.close()


def ensure_default_admin():
    """
    إنشاء حساب أدمن افتراضي مرة واحدة فقط:
    - username: admin
    - password: Admin123!  (غيّره بعد أول دخول)
    - balance: 1000 USD
    """
    # نستخدم اتصال مباشر لأن هذه الدالة تُستدعى عند تحميل الملف
    if USE_POSTGRES:
        if psycopg2 is None:
            raise RuntimeError("psycopg2 missing. Add psycopg2-binary to requirements.txt")
        db = PGConnectionWrapper(psycopg2.connect(DATABASE_URL))
    else:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row

    row = db.execute(_sql("SELECT id FROM users WHERE username = ?"), ("admin",)).fetchone()
    if row:
        db.close()
        return

    password_hash = generate_password_hash("Admin123!")

    if USE_POSTGRES:
        admin_id = db.execute(
            _sql("""
                INSERT INTO users (username, email, phone, password_hash, is_admin)
                VALUES (?, ?, ?, ?, TRUE)
                RETURNING id
            """),
            ("admin", "admin@example.com", "", password_hash),
        ).fetchone()["id"]
    else:
        cur = db.execute(
            """
            INSERT INTO users (username, email, phone, password_hash, is_admin)
            VALUES (?, ?, ?, ?, 1)
            """,
            ("admin", "admin@example.com", "", password_hash),
        )
        admin_id = cur.lastrowid

    # إنشاء أرصدة 0 لكل العملات
    for c in CURRENCIES:
        db.execute(
            _sql("INSERT INTO balances (user_id, currency, amount) VALUES (?, ?, 0) ON CONFLICT DO NOTHING")
            if USE_POSTGRES
            else "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, 0)",
            (admin_id, c),
        )

    # شحن 1000 USD
    db.execute(
        _sql("UPDATE balances SET amount = amount + ? WHERE user_id = ? AND currency = ?"),
        (1000.0, admin_id, "USD"),
    )

    # تسجيل العملية
    db.execute(
        _sql("""
            INSERT INTO transactions (user_id, type, amount, currency, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """),
        (
            admin_id,
            "Initial Admin Balance",
            1000.0,
            "USD",
            "Initial admin credit",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )

    db.commit()
    db.close()
    print("✅ Default admin created with 1000 USD.")


# استدعاء الإنشاء + إنشاء الأدمن الافتراضي مرة واحدة عند تحميل الملف
init_db()
ensure_default_admin()

# ==============================
# دوال مساعدة على مستوى المستخدمين
# ==============================
def create_user(username, email, phone, password_hash, is_admin=False):
    db = get_db()

    if USE_POSTGRES:
        user_id = db.execute(
            _sql("""
                INSERT INTO users (username, email, phone, password_hash, is_admin)
                VALUES (?, ?, ?, ?, ?)
                RETURNING id
            """),
            (username, email, phone, password_hash, bool(is_admin)),
        ).fetchone()["id"]
    else:
        cur = db.execute(
            """
            INSERT INTO users (username, email, phone, password_hash, is_admin)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, email, phone, password_hash, 1 if is_admin else 0),
        )
        user_id = cur.lastrowid

    # إنشاء رصيد 0 لكل عملة
    for c in CURRENCIES:
        db.execute(
            _sql("INSERT INTO balances (user_id, currency, amount) VALUES (?, ?, 0) ON CONFLICT DO NOTHING")
            if USE_POSTGRES
            else "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, 0)",
            (user_id, c),
        )

    db.commit()
    return user_id


def get_user(username):
    db = get_db()
    row = db.execute(_sql("SELECT * FROM users WHERE username = ?"), (username,)).fetchone()
    if not row:
        return None

    user_id = row["id"]

    # الأرصدة
    balances_rows = db.execute(
        _sql("SELECT currency, amount FROM balances WHERE user_id = ?"),
        (user_id,),
    ).fetchall()
    balance = {c: 0.0 for c in CURRENCIES}
    for b in balances_rows:
        balance[b["currency"]] = float(b["amount"] or 0.0)

    # المعاملات
    tx_rows = db.execute(
        _sql("""
            SELECT type, amount, currency, details, timestamp
            FROM transactions
            WHERE user_id = ?
            ORDER BY timestamp DESC
        """),
        (user_id,),
    ).fetchall()

    transactions = [
        {
            "type": t["type"],
            "amount": float(t["amount"]),
            "currency": t["currency"],
            "details": t["details"],
            "timestamp": t["timestamp"],
        }
        for t in tx_rows
    ]

    return {
        "id": user_id,
        "username": row["username"],
        "email": row.get("email") if isinstance(row, dict) else row["email"],
        "phone": row.get("phone") if isinstance(row, dict) else row["phone"],
        "password_hash": row["password_hash"],
        "is_admin": bool(row["is_admin"]),
        "balance": balance,
        "transactions": transactions,
    }


def change_balance(user_id, currency, delta):
    db = get_db()

    if USE_POSTGRES:
        db.execute(
            _sql("INSERT INTO balances (user_id, currency, amount) VALUES (?, ?, 0) ON CONFLICT DO NOTHING"),
            (user_id, currency),
        )
    else:
        db.execute(
            "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, 0)",
            (user_id, currency),
        )

    db.execute(
        _sql("UPDATE balances SET amount = amount + ? WHERE user_id = ? AND currency = ?"),
        (float(delta), user_id, currency),
    )
    db.commit()


def log_transaction(user_id, tx_type, amount, currency, details=""):
    db = get_db()
    db.execute(
        _sql("""
            INSERT INTO transactions (user_id, type, amount, currency, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """),
        (
            user_id,
            tx_type,
            float(amount),
            currency,
            details,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    db.commit()


# ==============================
# دوال الإشعارات
# ==============================
def create_notification(user_id, kind, title, message, ref_id=None):
    db = get_db()
    try:
        db.execute(
            _sql("""
                INSERT INTO notifications
                    (user_id, title, body, type, is_read, created_at, ref_type, ref_id)
                VALUES
                    (?,      ?,     ?,    ?,    0,       ?,          NULL,    ?)
            """),
            (
                user_id,
                title,
                message,
                kind,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ref_id,
            ),
        )
        db.commit()
    except Exception as e:
        logging.warning("create_notification error: %s", e)


def count_unread_notifications(user_id: int) -> int:
    db = get_db()
    try:
        row = db.execute(
            _sql("SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ? AND is_read = 0"),
            (user_id,),
        ).fetchone()
        return int(row["cnt"] if row else 0)
    except Exception as e:
        logging.warning("count_unread_notifications error: %s", e)
        return 0


# ==============================
# ✅ (NEW) Platform ↔ Telegram linking helpers
# ==============================

def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _generate_link_code(length=8):
    alphabet = string.ascii_uppercase + string.digits
    return LINK_CODE_PREFIX + "".join(secrets.choice(alphabet) for _ in range(length))

def create_telegram_link_code(platform_user_id: int, minutes_valid: int = 10) -> str:
    db = get_db()

    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=minutes_valid)
    ).strftime("%Y-%m-%d %H:%M:%S")

    alphabet = string.ascii_uppercase + string.digits
    attempts = 25
    last_err = None

    for _ in range(attempts):
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

        try:
            if USE_POSTGRES:
                # اكتشاف اسم عمود المستخدم (user_id القديم أو platform_user_id الجديد)
                cur = db.cursor()
                has_user_id = _pg_column_exists(cur, "telegram_link_codes", "user_id")
                user_col = "user_id" if has_user_id else "platform_user_id"

                # اكتشاف الأعمدة الموجودة (code / code_hash)
                has_code = _pg_column_exists(cur, "telegram_link_codes", "code")
                has_code_hash = _pg_column_exists(cur, "telegram_link_codes", "code_hash")

                cols = [user_col, "expires_at"]
                vals = [platform_user_id, expires_at]

                if has_code:
                    cols.append("code")
                    vals.append(code)

                if has_code_hash:
                    cols.append("code_hash")
                    vals.append(code_hash)

                cols_sql = ", ".join(cols)
                ph_sql = ", ".join(["?"] * len(vals))

                # بدون تحديد target داخل ON CONFLICT حتى يشتغل مع UNIQUE(code) أو UNIQUE(code_hash)
                row = db.execute(
                    _sql(f"""
                        INSERT INTO telegram_link_codes ({cols_sql})
                        VALUES ({ph_sql})
                        ON CONFLICT DO NOTHING
                        RETURNING id
                    """),
                    tuple(vals),
                ).fetchone()

                if row:
                    db.commit()
                    return code

                db.commit()
                continue

            # SQLite
            cur2 = db.execute(
                """
                INSERT OR IGNORE INTO telegram_link_codes (platform_user_id, code, expires_at)
                VALUES (?, ?, ?)
                """,
                (platform_user_id, code, expires_at),
            )
            db.commit()
            if cur2.rowcount and cur2.rowcount > 0:
                return code

        except Exception as e:
            last_err = str(e)
            logging.warning("create_telegram_link_code attempt failed: %s", e)

            # Postgres: لازم rollback على الاتصال الحقيقي
            try:
                if USE_POSTGRES and hasattr(db, "_conn"):
                    db._conn.rollback()
            except Exception:
                pass

    raise RuntimeError(f"Failed to generate a unique link code. Last error: {last_err}")

def redeem_telegram_link_code(telegram_id: int, code_raw: str):
    """
    ربط telegram_id بحساب منصة عبر كود الربط.
    يقبل:
      - LNK-XXXXXXXX
      - XXXXXXXX (8 حروف/أرقام)
    يرجع:
      (True, platform_user_id_as_str) عند النجاح
      (False, message) عند الفشل
    """
    if not telegram_id or not code_raw:
        return False, "بيانات غير مكتملة."

    raw = (code_raw or "").strip().upper()

    # يقبل الكود مع أو بدون prefix (LNK-XXXXXXXX أو XXXXXXXX)
    raw = (code_raw or "").strip().upper()

    if raw.startswith(LINK_CODE_PREFIX):
        code_clean = raw[len(LINK_CODE_PREFIX):].strip()
    else:
        code_clean = raw

    # لازم 8 أحرف/أرقام بالضبط
    if not re.fullmatch(r"[A-Z0-9]{8}", code_clean):
        return False, "صيغة الكود غير صحيحة. يجب أن يكون 8 أحرف/أرقام."

    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()

    try:
        # تأكد أن صف telegram_users موجود
        if USE_POSTGRES:
            db.execute(
                _sql("""
                    INSERT INTO telegram_users (telegram_id, referral_credits_usd, created_at)
                    VALUES (?, 0, ?)
                    ON CONFLICT (telegram_id) DO NOTHING
                """),
                (int(telegram_id), now_str),
            )
        else:
            db.execute(
                """
                INSERT OR IGNORE INTO telegram_users (telegram_id, referral_credits_usd, created_at)
                VALUES (?, 0, ?)
                """,
                (int(telegram_id), now_str),
            )

        # --- اكتشاف الأعمدة الموجودة في telegram_link_codes (Postgres)
        if USE_POSTGRES:
            cur = db.cursor()

            has_user_id = _pg_column_exists(cur, "telegram_link_codes", "user_id")
            user_col = "user_id" if has_user_id else "platform_user_id"

            has_code = _pg_column_exists(cur, "telegram_link_codes", "code")
            has_code_hash = _pg_column_exists(cur, "telegram_link_codes", "code_hash")

            if not has_code and not has_code_hash:
                return False, "جدول أكواد الربط ينقصه code أو code_hash."

            code_hash = hashlib.sha256(code_clean.encode("utf-8")).hexdigest()

            where_parts = []
            params = []

            if has_code:
                where_parts.append("code = ?")
                params.append(code_clean)

            if has_code_hash:
                where_parts.append("code_hash = ?")
                params.append(code_hash)

            where_sql = " OR ".join(where_parts)

            # UPDATE آمن ضد الاستخدام المزدوج
            q = f"""
                UPDATE telegram_link_codes
                SET used_at = ?, used_by_telegram_id = ?
                WHERE ({where_sql})
                  AND used_at IS NULL
                  AND expires_at > ?
                RETURNING {user_col} AS platform_user_id
            """

            r = db.execute(_sql(q), (now_str, int(telegram_id), *params, now_str)).fetchone()
            if not r:
                db.commit()
                return False, "الكود غير صحيح أو منتهي أو مستعمل."

            platform_user_id = r["platform_user_id"]
            if not platform_user_id:
                db.commit()
                return False, "❌ خطأ في بيانات الكود (لا يوجد platform_user_id)."

            # اربطه في telegram_users
            db.execute(
                _sql("""
                    UPDATE telegram_users
                    SET platform_user_id = ?, linked_at = ?
                    WHERE telegram_id = ?
                """),
                (int(platform_user_id), now_str, int(telegram_id)),
            )

            db.commit()
            return True, str(int(platform_user_id))

        # --- SQLite
        row = db.execute(
            _sql("""
                SELECT platform_user_id, expires_at, used_at, code
                FROM telegram_link_codes
                WHERE code = ?
                LIMIT 1
            """),
            (code_clean,),
        ).fetchone()

        if not row:
            return False, "الكود غير صحيح."
        if row.get("used_at"):
            return False, "هذا الكود مستعمل مسبقاً."

        expires_at_raw = row.get("expires_at")
        try:
            expires_at = datetime.fromisoformat(str(expires_at_raw).replace("Z", "+00:00"))
        except Exception:
            expires_at = datetime.strptime(str(expires_at_raw)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        if expires_at < now:
            return False, "هذا الكود منتهي."

        platform_user_id = row.get("platform_user_id")
        if not platform_user_id:
            return False, "❌ خطأ في بيانات الكود."

        db.execute(
            _sql("""
                UPDATE telegram_link_codes
                SET used_at = ?, used_by_telegram_id = ?
                WHERE code = ? AND used_at IS NULL
            """),
            (now_str, int(telegram_id), code_clean),
        )

        db.execute(
            _sql("""
                UPDATE telegram_users
                SET platform_user_id = ?, linked_at = ?
                WHERE telegram_id = ?
            """),
            (int(platform_user_id), now_str, int(telegram_id)),
        )

        db.commit()
        return True, str(int(platform_user_id))

    except Exception as e:
        logging.exception("redeem_telegram_link_code error: %s", e)
        try:
            if USE_POSTGRES and hasattr(db, "_conn"):
                db._conn.rollback()
            else:
                db.rollback()
        except Exception:
            pass
        return False, "❌ حدث خطأ أثناء الربط. حاول مرة أخرى."

    # SQLite: SELECT ثم UPDATE
    try:
        row = db.execute(
            _sql("""
                SELECT platform_user_id, expires_at, used_at
                FROM telegram_link_codes
                WHERE code = ?
            """),
            (code,),
        ).fetchone()

        if not row:
            return False, "الكود غير صحيح."
        if (row.get("used_at") if isinstance(row, dict) else row["used_at"]):
            return False, "هذا الكود مستعمل مسبقاً."
        if (row.get("expires_at") if isinstance(row, dict) else row["expires_at"]) <= now:
            return False, "هذا الكود منتهي."

        platform_user_id = row["platform_user_id"] if isinstance(row, dict) else row["platform_user_id"]

        db.execute(
            _sql("""
                UPDATE telegram_link_codes
                SET used_at = ?, used_by_telegram_id = ?
                WHERE code = ? AND used_at IS NULL
            """),
            (now, telegram_id, code),
        )

        db.execute(
            """
            INSERT OR IGNORE INTO telegram_users (telegram_id, referral_credits_usd, bot_balance_usd, created_at)
            VALUES (?, 0, 0, ?)
            """,
            (telegram_id, now),
        )

        db.execute(
            _sql("""
                UPDATE telegram_users
                SET platform_user_id = ?, linked_at = ?
                WHERE telegram_id = ?
            """),
            (platform_user_id, now, telegram_id),
        )

        db.commit()
        return True, str(platform_user_id)

    except Exception as e:
        logging.error("redeem_telegram_link_code sqlite error: %s", e)
        return False, "حدث خطأ أثناء الربط."
    
def get_telegram_wallet(telegram_id: int):
    """
    يرجع: bot_balance_usd + referral_credits_usd + platform_user_id (إن وجد)
    """
    db = get_db()
    row = db.execute(
        _sql("""
            SELECT telegram_id,
                   COALESCE(bot_balance_usd, 0) AS bot_balance_usd,
                   COALESCE(referral_credits_usd, 0) AS referral_credits_usd,
                   platform_user_id
            FROM telegram_users
            WHERE telegram_id = ?
            LIMIT 1
        """),
        (telegram_id,),
    ).fetchone()

    if not row:
        return {
            "telegram_id": telegram_id,
            "bot_balance_usd": 0.0,
            "referral_credits_usd": 0.0,
            "platform_user_id": None,
        }

    return {
        "telegram_id": int(row["telegram_id"]),
        "bot_balance_usd": float(row["bot_balance_usd"] or 0.0),
        "referral_credits_usd": float(row["referral_credits_usd"] or 0.0),
        "platform_user_id": row.get("platform_user_id") if isinstance(row, dict) else row["platform_user_id"],
    }


def bot_wallet_total_usd(telegram_id: int) -> float:
    w = get_telegram_wallet(telegram_id)
    return float(w["bot_balance_usd"]) + float(w["referral_credits_usd"])


def bot_wallet_debit_usd(telegram_id: int, amount: float) -> bool:
    """
    يخصم من bot_balance_usd أولاً ثم من referral_credits_usd إذا لزم.
    يرجع True إذا نجح الخصم، False إذا الرصيد الكلي غير كافي.
    """
    amount = float(amount)
    if amount <= 0:
        return False

    db = get_db()
    w = get_telegram_wallet(telegram_id)
    bot_bal = float(w["bot_balance_usd"])
    ref_bal = float(w["referral_credits_usd"])

    total = bot_bal + ref_bal
    if total + 1e-9 < amount:
        return False

    # خصم من الأساسي أولاً
    take_from_bot = min(bot_bal, amount)
    remaining = amount - take_from_bot
    take_from_ref = remaining if remaining > 0 else 0.0

    db.execute(
        _sql("""
            UPDATE telegram_users
            SET bot_balance_usd = COALESCE(bot_balance_usd, 0) - ?,
                referral_credits_usd = COALESCE(referral_credits_usd, 0) - ?
            WHERE telegram_id = ?
        """),
        (take_from_bot, take_from_ref, telegram_id),
    )
    db.commit()
    return True


def bot_wallet_credit_usd(telegram_id: int, amount: float):
    amount = float(amount)
    if amount <= 0:
        return

    db = get_db()
    db.execute(
        _sql("""
            UPDATE telegram_users
            SET bot_balance_usd = COALESCE(bot_balance_usd, 0) + ?
            WHERE telegram_id = ?
        """),
        (amount, telegram_id),
    )
    db.commit()

# ==============================
# ✅ (NEW) Auto cashout referrals to platform when >= 1$
# ==============================
def apply_referral_auto_cashout_for_telegram(telegram_id: int):
    """
    إذا كان telegram_id مربوط بحساب منصة:
    - عند وصول referral_credits_usd إلى >= 1$:
      ننقل (بالدولار الصحيح: 1,2,3...) إلى رصيد USD في balances
      ونخصم نفس المبلغ من referral_credits_usd
    """
    db = get_db()
    now = _now_str()

    row = db.execute(
        _sql("""
            SELECT telegram_id, platform_user_id, referral_credits_usd
            FROM telegram_users
            WHERE telegram_id = ?
        """),
        (telegram_id,),
    ).fetchone()
    if not row:
        return

    platform_user_id = row.get("platform_user_id")
    credits = float(row.get("referral_credits_usd") or 0.0)
    if not platform_user_id:
        return

    transferable = int(credits // REF_AUTO_CASHOUT_THRESHOLD)
    if transferable <= 0:
        return

    # خصم من رصيد الإحالات
    db.execute(
        _sql("""
            UPDATE telegram_users
            SET referral_credits_usd = COALESCE(referral_credits_usd, 0) - ?
            WHERE telegram_id = ?
        """),
        (float(transferable), telegram_id),
    )
    db.commit()

    # إضافة للمنصة (USD)
    change_balance(int(platform_user_id), "USD", float(transferable))
    log_transaction(
        int(platform_user_id),
        "Referral Auto Cashout",
        float(transferable),
        "USD",
        details=f"Telegram referral cashout from tg_id={telegram_id}",
    )

    # إشعار داخل المنصة
    try:
        create_notification(
            int(platform_user_id),
            "referral_cashout",
            "تمت إضافة أرباح الإحالة / Referral added",
            f"تمت إضافة {transferable}$ إلى رصيدك في المنصة من أرباح الإحالة عبر تيليجرام.\n"
            f"{transferable}$ was added to your platform balance from Telegram referrals.",
            ref_id=None,
        )
    except Exception:
        pass


# ==============================
# دوال خاصة ببوت تيليجرام
# ==============================
def register_telegram_user(from_user, start_param=None):
    """
    - يسجّل/يحدّث المستخدم في telegram_users
    - إذا كان start_param = ref_<tg_id> وسجلنا مستخدم جديد لأول مرة:
        * نعطي للمُحيل (Level 1) +0.01$
        * ونعطي لمُحيل المُحيل (Level 2) +0.003$ (مرة واحدة فقط)
    """
    if not from_user:
        return 0

    tg_id = from_user.get("id")
    if not tg_id:
        return 0

    username = from_user.get("username")
    first_name = from_user.get("first_name")
    last_name = from_user.get("last_name")

    referred_by = None
    if start_param and start_param.startswith("ref_"):
        try:
            referred_by = int(start_param.split("ref_")[1])
        except ValueError:
            referred_by = None

    # منع self-referral
    if referred_by == tg_id:
        referred_by = None

    db = get_db()

    row = db.execute(
        _sql("SELECT * FROM telegram_users WHERE telegram_id = ?"),
        (tg_id,),
    ).fetchone()

    if row is None:
        # مستخدم جديد
        try:
            db.execute(
                _sql("""
                    INSERT INTO telegram_users
                        (telegram_id, username, first_name, last_name, referred_by_telegram_id, referral_credits_usd)
                    VALUES (?, ?, ?, ?, ?, 0)
                """),
                (tg_id, username, first_name, last_name, referred_by),
            )

            lvl2 = None

            # مكافآت الإحالة (فقط عند التسجيل الأول)
            if referred_by:
                # Level 1 bonus
                db.execute(
                    _sql("""
                        UPDATE telegram_users
                        SET referral_credits_usd = COALESCE(referral_credits_usd, 0) + ?
                        WHERE telegram_id = ?
                    """),
                    (REF_L1_BONUS_USD, referred_by),
                )

                # Level 2 bonus (referrer of referrer)
                ref_row = db.execute(
                    _sql("SELECT referred_by_telegram_id FROM telegram_users WHERE telegram_id = ?"),
                    (referred_by,),
                ).fetchone()
                lvl2 = ref_row["referred_by_telegram_id"] if ref_row else None
                if lvl2:
                    db.execute(
                        _sql("""
                            UPDATE telegram_users
                            SET referral_credits_usd = COALESCE(referral_credits_usd, 0) + ?
                            WHERE telegram_id = ?
                        """),
                        (REF_L2_BONUS_USD, lvl2),
                    )

            db.commit()

            # ✅ (NEW) بعد إضافة المكافآت، صرف تلقائي إذا كان الحساب مربوطاً
            try:
                if referred_by:
                    apply_referral_auto_cashout_for_telegram(referred_by)
                if lvl2:
                    apply_referral_auto_cashout_for_telegram(lvl2)
            except Exception:
                pass

        except Exception as e:
            logging.error("register_telegram_user insert error: %s", e)
            return tg_id

    else:
        # تحديث بيانات الاسم/اليوزر إذا تغيّرت
        try:
            needs_update = (
                row.get("username") != username
                or row.get("first_name") != first_name
                or row.get("last_name") != last_name
            )
            if needs_update:
                db.execute(
                    _sql("""
                        UPDATE telegram_users
                        SET username = ?, first_name = ?, last_name = ?
                        WHERE telegram_id = ?
                    """),
                    (username, first_name, last_name, tg_id),
                )
                db.commit()
        except Exception as e:
            logging.error("register_telegram_user update error: %s", e)

    return tg_id


def tg_send_message(chat_id, text, reply_markup=None):
    if not TELEGRAM_API_URL or not TELEGRAM_BOT_TOKEN:
        logging.warning("Telegram bot token not configured.")
        return

    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }
    if reply_markup:
        payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)

    try:
        requests.post(f"{TELEGRAM_API_URL}/sendMessage", data=payload, timeout=10)
    except Exception as e:
        logging.error(f"Error sending Telegram message: {e}")


def tg_answer_callback(callback_id):
    if not TELEGRAM_API_URL or not TELEGRAM_BOT_TOKEN:
        return
    try:
        requests.post(
            f"{TELEGRAM_API_URL}/answerCallbackQuery",
            data={"callback_query_id": callback_id},
            timeout=10,
        )
    except Exception as e:
        logging.error(f"Error answering callback: {e}")

def get_telegram_balances(telegram_id: int):
    db = get_db()
    row = db.execute(
        _sql("SELECT bot_balance_usd, referral_credits_usd, platform_user_id FROM telegram_users WHERE telegram_id = ?"),
        (telegram_id,),
    ).fetchone()
    if not row:
        return None
    bot_bal = float(row.get("bot_balance_usd") or 0)
    ref_bal = float(row.get("referral_credits_usd") or 0)
    platform_user_id = row.get("platform_user_id")
    return bot_bal, ref_bal, platform_user_id


def get_total_bot_balance(telegram_id: int) -> float:
    info = get_telegram_balances(telegram_id)
    if not info:
        return 0.0
    bot_bal, ref_bal, _ = info
    return float(bot_bal + ref_bal)


def add_to_bot_balance(telegram_id: int, amount: float) -> bool:
    if not telegram_id or amount <= 0:
        return False
    db = get_db()
    db.execute(
        _sql("UPDATE telegram_users SET bot_balance_usd = COALESCE(bot_balance_usd, 0) + ? WHERE telegram_id = ?"),
        (amount, telegram_id),
    )
    db.commit()
    return True


def deduct_from_bot_balance_wallet_first(telegram_id: int, amount: float) -> tuple[bool, str]:
    """
    يخصم من bot_balance_usd أولا، ثم من referral_credits_usd إن لم يكفِ.
    يرجع (ok, msg)
    """
    if not telegram_id or amount <= 0:
        return False, "مبلغ غير صالح."

    info = get_telegram_balances(telegram_id)
    if not info:
        return False, "حساب Telegram غير موجود."

    bot_bal, ref_bal, _ = info
    total = bot_bal + ref_bal
    if total + 1e-9 < amount:
        return False, "الرصيد غير كافٍ."

    use_bot = min(bot_bal, amount)
    remaining = amount - use_bot
    use_ref = remaining  # الباقي نخصمه من الإحالات

    db = get_db()
    if use_bot > 0:
        db.execute(
            _sql("UPDATE telegram_users SET bot_balance_usd = COALESCE(bot_balance_usd, 0) - ? WHERE telegram_id = ?"),
            (use_bot, telegram_id),
        )
    if use_ref > 0:
        db.execute(
            _sql("UPDATE telegram_users SET referral_credits_usd = COALESCE(referral_credits_usd, 0) - ? WHERE telegram_id = ?"),
            (use_ref, telegram_id),
        )
    db.commit()
    return True, "ok"

def transfer_bot_to_platform_by_telegram_id(telegram_id: int, amount: float) -> tuple[bool, str]:
    if not telegram_id or amount <= 0:
        return False, "مبلغ غير صالح."

    info = get_telegram_balances(telegram_id)
    if not info:
        return False, "هذا المستخدم غير موجود في telegram_users."

    bot_bal, ref_bal, platform_user_id = info
    if not platform_user_id:
        return False, "هذا الحساب غير مربوط بحساب منصة."

    ok, msg = deduct_from_bot_balance_wallet_first(telegram_id, amount)
    if not ok:
        return False, msg

    db = get_db()

    # إضافة للمنصة (USD): نضمن وجود السطر
    db.execute(
        _sql("""
            INSERT INTO balances (user_id, currency, amount)
            VALUES (?, ?, ?)
            ON CONFLICT (user_id, currency) DO UPDATE SET amount = balances.amount + EXCLUDED.amount
        """),
        (int(platform_user_id), "USD", amount),
    )

    # Transaction
    db.execute(
        _sql("""
            INSERT INTO transactions (user_id, type, amount, currency, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """),
        (int(platform_user_id), "transfer_from_bot", amount, "USD", f"from telegram_id={telegram_id}", _now_str()),
    )

    db.commit()
    return True, "✅ تم تحويل الرصيد إلى المنصة."

# ==============================
# المسارات الأساسية (المستخدم)
# ==============================
@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    unread_notifications = count_unread_notifications(user["id"])

    return render_template(
        "index.html",
        username=user["username"],
        user=user,
        currencies=CURRENCIES,
        currency_to_country=CURRENCY_TO_COUNTRY,
        binance_uid=BINANCE_UID,
        binance_auto_100_url=BINANCE_AUTO_100_URL,
        unread_notifications=unread_notifications,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)
        if user and check_password_hash(user.get("password_hash", ""), password):
            session["username"] = username
            session["is_admin"] = bool(user.get("is_admin", False))
            return redirect(url_for("index"))

        flash("❌ اسم المستخدم أو كلمة المرور غير صحيحة", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            flash("❌ يجب إدخال اسم مستخدم وكلمة مرور", "error")
            return render_template("register.html")

        if password != confirm:
            flash("❌ كلمتا المرور غير متطابقتين", "error")
            return render_template("register.html")

        if get_user(username):
            flash("❌ اسم المستخدم موجود بالفعل", "error")
            return render_template("register.html")

        hashed_pw = generate_password_hash(password)

        try:
            create_user(username, email, phone, hashed_pw, is_admin=False)
        except Exception:
            flash("❌ اسم المستخدم موجود بالفعل", "error")
            return render_template("register.html")

        flash("✅ تم إنشاء الحساب بنجاح", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/convert_currency", methods=["POST"])
def convert_currency_route():
    if "username" not in session:
        return jsonify({"success": False, "message": "يجب تسجيل الدخول أولاً"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "بيانات غير صحيحة"}), 400

    from_currency = data.get("from")
    to_currency = data.get("to")
    amount_str = str(data.get("amount"))

    if not from_currency or not to_currency or not amount_str:
        return jsonify({"success": False, "message": "جميع الحقول مطلوبة"}), 400

    if from_currency not in CURRENCIES or to_currency not in CURRENCIES:
        return jsonify({"success": False, "message": "عملة غير مدعومة"}), 400

    try:
        amount = Decimal(amount_str)
        if amount <= 0:
            return jsonify({"success": False, "message": "المبلغ يجب أن يكون أكبر من صفر"}), 400
    except Exception:
        return jsonify({"success": False, "message": "المبلغ غير صالح"}), 400

    username = session["username"]
    user = get_user(username)
    if not user:
        session.clear()
        return jsonify({"success": False, "message": "المستخدم غير موجود"}), 400

    current_from_balance = user["balance"].get(from_currency, 0.0)
    if current_from_balance < float(amount):
        return jsonify({"success": False, "message": f"الرصيد غير كافٍ في {from_currency}"}), 400

    try:
        converted_raw = convert_currency(amount, from_currency, to_currency)
        converted_dec = Decimal(str(converted_raw)).quantize(Decimal("0.01"), rounding=ROUND_DOWN)
        rate_dec = (converted_dec / amount).quantize(Decimal("0.0001"))

        change_balance(user["id"], from_currency, -float(amount))
        change_balance(user["id"], to_currency, float(converted_dec))

        details = f"{amount} {from_currency} → {converted_dec} {to_currency}"
        log_transaction(user["id"], "Currency Conversion", float(amount), from_currency, details)

        updated_user = get_user(username)
        balances = updated_user["balance"] if updated_user and "balance" in updated_user else {}

        return jsonify(
            {
                "success": True,
                "converted_amount": f"{converted_dec}",
                "rate": f"{rate_dec:.4f}",
                "balances": balances,
            }
        )

    except RuntimeError as e:
        logging.error(f"Currency API error: {e}")
        return jsonify(
            {"success": False, "message": "تعذر جلب سعر الصرف من مزوّد الأسعار الخارجي، يرجى المحاولة لاحقاً."}
        ), 502

    except Exception as e:
        logging.error(f"Currency conversion error: {e}")
        return jsonify({"success": False, "message": "خطأ أثناء تحويل العملات"}), 500


# ==============================
# Binance Pay Top-up (UID + Proof)
# ==============================
@app.route("/binance_topup", methods=["POST"])
def binance_topup():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً", "error")
        return redirect(url_for("login"))

    username = session["username"]
    user = get_user(username)
    if not user:
        session.clear()
        flash("حصل خطأ في بيانات المستخدم", "error")
        return redirect(url_for("login"))

    amount_str = request.form.get("amount", "0").strip()
    fiat_currency = request.form.get("fiat_currency")
    txid = (request.form.get("txid") or "").strip()

    try:
        amount = Decimal(amount_str)
    except Exception:
        flash("❌ يرجى إدخال مبلغ صحيح", "error")
        return redirect(url_for("index"))

    if amount <= 0:
        flash("❌ المبلغ يجب أن يكون أكبر من صفر", "error")
        return redirect(url_for("index"))

    if fiat_currency not in CURRENCIES:
        flash("❌ عملة غير مدعومة", "error")
        return redirect(url_for("index"))

    if not txid:
        flash("❌ يجب إدخال TxID أو ملاحظة عن التحويل", "error")
        return redirect(url_for("index"))

    db = get_db()
    db.execute(
        _sql("""
            INSERT INTO pending_deposits
            (user_id, amount, fiat_currency, pay_method, status, txid, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """),
        (
            user["id"],
            float(amount),
            fiat_currency,
            "Binance Pay",
            "pending",
            txid,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    db.commit()

    log_transaction(user["id"], "Binance Topup Request", amount, fiat_currency, details=f"UID={BINANCE_UID}, txid={txid}")
    flash("✅ تم تسجيل طلب الشحن، سيتم التحقق من التحويل وإضافة الرصيد يدويًا.", "success")
    return redirect(url_for("index"))


@app.route("/binance_deposit_proof", methods=["POST"])
def binance_deposit_proof():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً", "error")
        return redirect(url_for("login"))

    from decimal import InvalidOperation

    amount_raw = request.form.get("amount", "0")
    currency = request.form.get("currency")
    txid = (request.form.get("txid") or "").strip()

    try:
        amount = Decimal(str(amount_raw))
    except InvalidOperation:
        flash("❌ مبلغ غير صالح", "error")
        return redirect(url_for("index"))

    if amount <= 0 or currency not in CURRENCIES or not txid:
        flash("❌ يرجى إدخال بيانات صحيحة للشحن", "error")
        return redirect(url_for("index"))

    username = session["username"]
    user = get_user(username)
    if not user:
        session.clear()
        flash("خطأ في بيانات المستخدم", "error")
        return redirect(url_for("login"))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()

    db.execute(
        _sql("""
            INSERT INTO pending_deposits
            (user_id, amount, fiat_currency, pay_method, status, txid, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """),
        (user["id"], float(amount), currency, "Binance Pay", "pending", txid, now_str),
    )

    log_transaction(user["id"], "Binance Deposit Proof", amount, currency, details=f"TXID/Proof: {txid}")
    db.commit()

    flash("✅ تم إرسال إثبات الشحن، سيقوم الأدمن بمراجعته وإضافة الرصيد بعد التحقق.", "success")
    return redirect(url_for("index"))


@app.route("/withdraw_request", methods=["POST"])
def withdraw_request():
    if "username" not in session:
        flash("يجب تسجيل الدخول أولاً", "error")
        return redirect(url_for("login"))

    from decimal import InvalidOperation

    amount_raw = request.form.get("amount", "0")
    currency = request.form.get("currency")
    payout_info = (request.form.get("payout_info") or "").strip()

    try:
        amount = Decimal(str(amount_raw))
    except InvalidOperation:
        flash("❌ مبلغ غير صالح", "error")
        return redirect(url_for("index"))

    if amount <= 0 or currency not in CURRENCIES or not payout_info:
        flash("❌ يرجى إدخال بيانات صحيحة لطلب السحب", "error")
        return redirect(url_for("index"))

    username = session["username"]
    user = get_user(username)
    if not user:
        session.clear()
        flash("خطأ في بيانات المستخدم", "error")
        return redirect(url_for("login"))

    if user["balance"].get(currency, 0.0) < float(amount):
        flash("❌ الرصيد غير كافٍ", "error")
        return redirect(url_for("index"))

    change_balance(user["id"], currency, -float(amount))

    db = get_db()
    db.execute(
        _sql("""
            INSERT INTO pending_withdrawals
            (user_id, amount, currency, payout_info, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """),
        (
            user["id"],
            float(amount),
            currency,
            payout_info,
            "pending",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    db.commit()

    log_transaction(user["id"], "Withdraw Request", amount, currency, details=f"Payout info: {payout_info}")
    flash("📤 تم إرسال طلب السحب، سيتم معالجته يدويًا.", "success")
    return redirect(url_for("index"))


# ==============================
# أدوات مساعدة للأدمن
# ==============================
def _ensure_admin():
    if "username" not in session:
        return None
    user = get_user(session["username"])
    if not user or not user["is_admin"]:
        return None
    return user


@app.route("/admin/export/transactions")
def export_transactions_csv():
    admin = _ensure_admin()
    if not admin:
        abort(403)

    db = get_db()

    username_f = (request.args.get("username") or "").strip() or None
    currency_f = (request.args.get("currency") or "").strip().upper() or None
    start_date = request.args.get("start_date") or None
    end_date = request.args.get("end_date") or None

    conditions = []
    params = []

    if username_f:
        conditions.append("u.username = ?")
        params.append(username_f)
    if currency_f:
        conditions.append("t.currency = ?")
        params.append(currency_f)
    if start_date:
        conditions.append("date(t.timestamp) >= date(?)")
        params.append(start_date)
    if end_date:
        conditions.append("date(t.timestamp) <= date(?)")
        params.append(end_date)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    rows = db.execute(
        _sql(f"""
            SELECT u.username, t.type, t.amount, t.currency, t.details, t.timestamp
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            {where_clause}
            ORDER BY t.timestamp DESC
        """),
        params,
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "type", "amount", "currency", "details", "timestamp"])
    for r in rows:
        writer.writerow([r["username"], r["type"], r["amount"], r["currency"], r["details"], r["timestamp"]])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=transactions.csv"},
    )


@app.route("/admin/export/balances")
def export_balances_csv():
    admin = _ensure_admin()
    if not admin:
        abort(403)

    db = get_db()
    username_f = (request.args.get("username") or "").strip() or None

    if username_f:
        rows = db.execute(
            _sql("""
                SELECT u.username, b.currency, b.amount
                FROM balances b
                JOIN users u ON b.user_id = u.id
                WHERE u.username = ?
                ORDER BY u.username, b.currency
            """),
            (username_f,),
        ).fetchall()
    else:
        rows = db.execute(
            _sql("""
                SELECT u.username, b.currency, b.amount
                FROM balances b
                JOIN users u ON b.user_id = u.id
                ORDER BY u.username, b.currency
            """)
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "currency", "amount"])
    for r in rows:
        writer.writerow([r["username"], r["currency"], r["amount"]])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=balances.csv"},
    )


@app.route("/admin/withdrawals", methods=["GET", "POST"])
def admin_withdrawals():
    admin = _ensure_admin()
    if not admin:
        flash("🚫 غير مسموح بالدخول إلى لوحة الإدارة", "error")
        return redirect(url_for("index"))

    db = get_db()

    if request.method == "POST":
        wid = request.form.get("withdrawal_id")
        action = request.form.get("action")

        if not wid or not action:
            flash("⚠️ بيانات الطلب غير كاملة", "error")
            return redirect(url_for("admin_withdrawals"))

        w = db.execute(_sql("SELECT * FROM pending_withdrawals WHERE id = ?"), (wid,)).fetchone()
        if not w:
            flash("⚠️ الطلب غير موجود", "error")
            return redirect(url_for("admin_withdrawals"))

        if w["status"] != "pending":
            flash("ℹ️ هذا الطلب تمّت معالجته مسبقاً.", "info")
            return redirect(url_for("admin_withdrawals"))

        user_id = w["user_id"]
        amount = float(w["amount"])
        currency = w["currency"]
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if action == "approve":
            db.execute(
                _sql("""
                    UPDATE pending_withdrawals
                    SET status = 'completed', processed_by = ?, processed_at = ?
                    WHERE id = ?
                """),
                (admin["username"], now_str, wid),
            )

            log_transaction(user_id, "Withdrawal Approved", amount, currency, f"تم تنفيذ طلب السحب بقيمة {amount} {currency}")

            title = "تم تنفيذ طلب السحب / Withdrawal executed"
            body = f"تم تنفيذ طلب السحب بقيمة {amount} {currency} بنجاح.\nWithdrawal of {amount} {currency} has been processed successfully."

            db.execute(
                _sql("""
                    INSERT INTO notifications (user_id, title, body, type, is_read, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                """),
                (user_id, title, body, "withdraw_approved", now_str),
            )

            db.commit()
            flash("✅ تم اعتماد طلب السحب وإرسال إشعار للمستخدم.", "success")
            return redirect(url_for("admin_withdrawals"))

        if action == "reject":
            change_balance(user_id, currency, amount)

            db.execute(
                _sql("""
                    UPDATE pending_withdrawals
                    SET status = 'rejected', processed_by = ?, processed_at = ?
                    WHERE id = ?
                """),
                (admin["username"], now_str, wid),
            )

            log_transaction(user_id, "Withdrawal Rejected", amount, currency, "تم رفض طلب السحب وإرجاع المبلغ إلى الرصيد.")

            title = "تم رفض طلب السحب / Withdrawal rejected"
            body = (
                f"تم رفض طلب السحب بقيمة {amount} {currency} وتم إرجاع المبلغ إلى رصيد حسابك.\n"
                f"Withdrawal of {amount} {currency} has been rejected and the amount has been returned to your balance."
            )

            db.execute(
                _sql("""
                    INSERT INTO notifications (user_id, title, body, type, is_read, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                """),
                (user_id, title, body, "withdraw_rejected", now_str),
            )

            db.commit()
            flash("✅ تم رفض طلب السحب وإرجاع المبلغ للمستخدم.", "success")
            return redirect(url_for("admin_withdrawals"))

        flash("⚠️ إجراء غير معروف", "error")
        return redirect(url_for("admin_withdrawals"))

    withdrawals = db.execute(
        _sql("""
            SELECT w.*, u.username, u.email
            FROM pending_withdrawals w
            JOIN users u ON w.user_id = u.id
            WHERE w.status = 'pending'
            ORDER BY w.timestamp DESC
        """)
    ).fetchall()

    return render_template("admin_withdrawals.html", withdrawals=withdrawals)


@app.route("/admin/deposits", methods=["GET", "POST"])
def admin_deposits():
    admin = _ensure_admin()
    if not admin:
        flash("🚫 غير مسموح بالدخول إلى لوحة الإدارة", "error")
        return redirect(url_for("index"))

    db = get_db()

    if request.method == "POST":
        did = request.form.get("deposit_id")
        action = request.form.get("action")

        if not did or not action:
            flash("⚠️ بيانات الطلب غير كاملة", "error")
            return redirect(url_for("admin_deposits"))

        dep = db.execute(_sql("SELECT * FROM pending_deposits WHERE id = ?"), (did,)).fetchone()
        if not dep:
            flash("⚠️ الطلب غير موجود", "error")
            return redirect(url_for("admin_deposits"))

        if dep["status"] != "pending":
            flash("ℹ️ هذا الطلب تمّت معالجته مسبقاً.", "info")
            return redirect(url_for("admin_deposits"))

        new_status = "completed" if action == "approve" else "rejected"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        user_id = dep["user_id"]
        amount = float(dep["amount"])
        fiat_currency = dep["fiat_currency"]

        if new_status == "completed":
            change_balance(user_id, fiat_currency, amount)
            log_transaction(user_id, "Binance Topup", amount, fiat_currency, details=f"Approved topup #{dep['id']} via Binance Pay")

            title = "تم قبول طلب الشحن / Top-up approved"
            body = f"تم شحن حسابك بمبلغ {amount} {fiat_currency} بنجاح.\nYour account has been credited with {amount} {fiat_currency} successfully."
            notif_type = "deposit_approved"
        else:
            title = "تم رفض طلب الشحن / Top-up rejected"
            body = (
                f"تم رفض طلب شحن بقيمة {amount} {fiat_currency}. يرجى التأكد من التحويل أو التواصل مع الدعم.\n"
                f"Top-up request of {amount} {fiat_currency} has been rejected. Please verify your transfer or contact support."
            )
            notif_type = "deposit_rejected"

        db.execute(
            _sql("""
                UPDATE pending_deposits
                SET status = ?, processed_by = ?, processed_at = ?
                WHERE id = ?
            """),
            (new_status, admin["username"], now_str, did),
        )

        try:
            db.execute(
                _sql("""
                    INSERT INTO notifications
                        (user_id, title, body, type, is_read, created_at, ref_type, ref_id)
                    VALUES (?, ?, ?, ?, 0, ?, 'pending_deposits', ?)
                """),
                (user_id, title, body, notif_type, now_str, dep["id"]),
            )
        except Exception:
            db.execute(
                _sql("""
                    INSERT INTO notifications
                        (user_id, title, body, type, is_read, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                """),
                (user_id, title, body, notif_type, now_str),
            )

        db.commit()
        flash("✅ تم تحديث حالة طلب الشحن.", "success")
        return redirect(url_for("admin_deposits"))

    deposits = db.execute(
        _sql("""
            SELECT d.*, u.username, u.email
            FROM pending_deposits d
            JOIN users u ON d.user_id = u.id
            WHERE d.status = 'pending'
            ORDER BY d.timestamp DESC
        """)
    ).fetchall()

    return render_template("admin_deposits.html", deposits=deposits)

@app.route("/admin/bot_balance", methods=["GET", "POST"])
def admin_bot_balance():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user or not user.get("is_admin"):
        return redirect(url_for("index"))

    if request.method == "POST":
        telegram_id = request.form.get("telegram_id", "").strip()
        amount = request.form.get("amount", "").strip()
        action = request.form.get("action", "").strip()  # add / deduct

        try:
            tid = int(telegram_id)
            amt = float(amount)
        except Exception:
            flash("❌ بيانات غير صالحة.", "error")
            return redirect(url_for("admin_bot_balance"))

        if amt <= 0:
            flash("❌ المبلغ يجب أن يكون أكبر من 0.", "error")
            return redirect(url_for("admin_bot_balance"))

        if action == "add":
            ok = add_to_bot_balance(tid, amt)
            flash("✅ تمت الإضافة." if ok else "❌ فشلت العملية.", "success" if ok else "error")
            return redirect(url_for("admin_bot_balance"))

        if action == "deduct":
            ok, msg = deduct_from_bot_balance_wallet_first(tid, amt)
            flash("✅ تم الخصم." if ok else f"❌ {msg}", "success" if ok else "error")
            return redirect(url_for("admin_bot_balance"))

        flash("❌ اختيار غير معروف.", "error")
        return redirect(url_for("admin_bot_balance"))

    # GET: عرض بسيط
    return render_template("admin_bot_balance.html")

# ==============================
# صفحة الإشعارات للمستخدم
# ==============================
@app.route("/notifications")
def notifications():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    db = get_db()

    try:
        rows = db.execute(
            _sql("""
                SELECT id, title, body, type, ref_type, ref_id, is_read, created_at
                FROM notifications
                WHERE user_id = ?
                ORDER BY created_at DESC, id DESC
            """),
            (user["id"],),
        ).fetchall()
    except Exception as e:
        logging.error("notifications select error: %s", e)
        rows = []

    try:
        db.execute(
            _sql("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0"),
            (user["id"],),
        )
        db.commit()
    except Exception as e:
        logging.error("notifications update error: %s", e)

    return render_template("notifications.html", notifications=rows)


# ==============================
# صفحات إضافية
# ==============================
TRANSACTIONS_PER_PAGE = 5


@app.route("/transactions")
def recent_transactions():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    db = get_db()

    try:
        page = int(request.args.get("page", 1) or 1)
    except ValueError:
        page = 1
    if page < 1:
        page = 1

    per_page = TRANSACTIONS_PER_PAGE
    offset = (page - 1) * per_page

    rows = db.execute(
        _sql("""
            SELECT type, amount, currency, details, timestamp
            FROM transactions
            WHERE user_id = ?
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
        """),
        (user["id"], per_page, offset),
    ).fetchall()

    next_row = db.execute(
        _sql("""
            SELECT 1
            FROM transactions
            WHERE user_id = ?
            LIMIT 1 OFFSET ?
        """),
        (user["id"], offset + per_page),
    ).fetchone()

    has_next = next_row is not None
    has_prev = page > 1

    return render_template("transactions.html", transactions=rows, page=page, has_next=has_next, has_prev=has_prev)


@app.route("/toggle_language")
def toggle_language():
    current_lang = session.get("lang", "ar")
    session["lang"] = "en" if current_lang == "ar" else "ar"
    return redirect(request.referrer or url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/support")
def support():
    return render_template("support.html")


# ==============================
# Webhook الخاص ببوت تيليجرام
# ==============================
@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    if not TELEGRAM_BOT_TOKEN:
        return "Bot token not configured", 200

    try:
        update = request.get_json(force=True)
    except Exception:
        return "invalid json", 400

    if not update:
        return "no update", 200

    # رسالة نصية
    if "message" in update:
        message = update["message"]
        text = message.get("text", "") or ""
        chat_id = message["chat"]["id"]
        from_user = message.get("from", {})

        start_param = None
        if text.startswith("/start") and " " in text:
            start_param = text.split(" ", 1)[1].strip()

        register_telegram_user(from_user, start_param)

        # ✅ (NEW) إذا أرسل كود ربط (LNK-XXXXXXX أو XXXXXXXX)
        raw = (text or "").strip().upper()
        is_prefixed = raw.startswith(LINK_CODE_PREFIX)
        is_plain = bool(re.fullmatch(r"[A-Z0-9]{8}", raw))  # مثل: 5CE92V5R

        if is_prefixed or is_plain:
            code_to_redeem = raw if is_prefixed else f"{LINK_CODE_PREFIX}{raw}"

            ok, info = redeem_telegram_link_code(from_user.get("id"), code_to_redeem)
            if ok:
                platform_user_id = int(info)
                uname = ""
                try:
                    db = get_db()
                    urow = db.execute(
                        _sql("SELECT username FROM users WHERE id = ?"),
                        (platform_user_id,),
                    ).fetchone()
                    if urow:
                        uname = urow["username"]
                except Exception:
                    pass

                tg_send_message(
                    chat_id,
                    "✅ تم ربط حسابك بنجاح.\n"
                    + (f"👤 حساب المنصة: <b>{uname}</b>" if uname else ""),
                )

                try:
                    apply_referral_auto_cashout_for_telegram(from_user.get("id"))
                except Exception:
                    pass
            else:
                tg_send_message(chat_id, f"❌ {info}")

            return "ok", 200

        if text.startswith("/start"):
            tg_id = from_user.get("id")
            ref_link = f"https://t.me/Currencyexchangedh_bot?start=ref_{tg_id}"

            welcome_text = (
                "👋 أهلاً بك في بوت المنصة.\n\n"
                "يمكنك من هنا الدخول إلى المنصة، استخدام نظام الإحالات، "
                "أو الوصول إلى بعض الخدمات الفرعية.\n\n"
                "🔗 رابط المنصة:\n"
                f"{SITE_PUBLIC_URL}\n\n"
                "✅ رابط إحالتك:\n"
                f"{ref_link}"
            )

            keyboard = {
        "inline_keyboard": [
            [{"text": "🌐 المنصة / Platform", "url": SITE_PUBLIC_URL}],
            [{"text": "🔗 ربط الحساب / Link account", "callback_data": "link_account"}],
            [{"text": "👥 نظام الإحالات / Referrals", "callback_data": "referrals"}],
            [{"text": "💰 الرصيد / Wallet", "callback_data": "wallet"}],
            [{"text": "💸 تحويل الرصيد / Transfer balance", "callback_data": "transfer_balance"}],
            [{"text": "🧰 الخدمات الفرعية / Services", "callback_data": "services"}],
        ]
    }

            tg_send_message(chat_id, welcome_text, reply_markup=keyboard)
            return "ok", 200

        tg_send_message(chat_id, "استخدم الأمر /start للحصول على القائمة الرئيسية للبوت.")
        return "ok", 200

    # أزرار Inline
    if "callback_query" in update:
        cq = update["callback_query"]
        data = cq.get("data")
        chat_id = cq["message"]["chat"]["id"]
        from_user = cq.get("from", {})
        tg_id = from_user.get("id")
        callback_id = cq.get("id")

        if callback_id:
            tg_answer_callback(callback_id)

        # 👥 نظام الإحالات + عرض الرصيد
        if data == "referrals":
            ref_link = f"https://t.me/Currencyexchangedh_bot?start=ref_{tg_id}"

            db = get_db()
            referral_credits = 0.0
            try:
                row = db.execute(
                    _sql("SELECT referral_credits_usd FROM telegram_users WHERE telegram_id = ?"),
                    (tg_id,),
                ).fetchone()
                if row and row.get("referral_credits_usd") is not None:
                    referral_credits = float(row["referral_credits_usd"])
            except Exception as e:
                logging.warning("referrals select error: %s", e)

            # إجمالي الرصيد في البوت (إن عندك دالة ثانية استخدمها)
            try:
                total_wallet = get_total_bot_balance(tg_id)
            except Exception:
                # fallback لو ما تشتغل
                total_wallet = referral_credits

            msg = (
                "👥 <b>نظام الإحالات</b>\n\n"
                f"رصيد مكافآت الإحالة الخاص بك: <b>{referral_credits:.3f}$</b>\n"
                f"إجمالي رصيد البوت (البوت + الإحالات): <b>{total_wallet:.3f}$</b>\n\n"
                "هذا هو رابط الإحالة الخاص بك:\n"
                f"{ref_link}\n\n"
                f"🎁 مكافأة الإحالة المباشرة: {REF_L1_BONUS_USD}$\n"
                f"🎁 مكافأة الإحالة غير المباشرة (Level 2): {REF_L2_BONUS_USD}$\n\n"
                "ℹ️ عند وصول أرباح الإحالة إلى 1$ سيتم تحويلها تلقائياً إلى رصيدك في المنصة (USD) إذا كان حسابك مربوطاً."
            )
            tg_send_message(chat_id, msg)
            return "ok", 200

        # 🧰 خدمات فرعية
        elif data == "services":
            msg = (
                "🧰 <b>الخدمات الفرعية</b>\n\n"
                "سيتم هنا لاحقًا إضافة أزرار لخدمات إضافية "
                "مثل: أسعار الصرف، شروحات، أو أدوات أخرى مرتبطة بالمنصة."
            )
            tg_send_message(chat_id, msg)
            return "ok", 200

        # 💸 شاشة تحويل الرصيد (تظهر الرصيد + زر تحويل الكل)
        elif data == "transfer_balance":
            try:
                total_wallet = get_total_bot_balance(tg_id)
            except Exception:
                total_wallet = 0.0

            msg = (
                "💸 <b>تحويل الرصيد إلى المنصة</b>\n\n"
                f"إجمالي الرصيد المتاح في البوت (رصيد البوت + الإحالات): <b>{total_wallet:.3f}$</b>\n\n"
                "يمكنك هنا تحويل <b>كامل</b> الرصيد المتاح إلى حسابك في المنصة (USD).\n"
                f"الحد الأدنى للتحويل: <b>{BOT_MIN_CASHOUT_USD}$</b>.\n\n"
                "سيتم إضافة المبلغ إلى رصيدك بالدولار داخل المنصة، "
                "ويمكنك بعدها تحويله إلى أي عملة من داخل الموقع."
            )

            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": f"✅ تحويل كل الرصيد ({total_wallet:.2f}$) إلى المنصة",
                            "callback_data": "transfer_all_to_platform",
                        }
                    ],
                    [
                        {
                            "text": "⬅️ رجوع للقائمة",
                            "callback_data": "start_menu",
                        }
                    ],
                ]
            }

            tg_send_message(chat_id, msg, reply_markup=keyboard)
            return "ok", 200

        # ✅ تنفيذ تحويل كل الرصيد إلى المنصة
        elif data == "transfer_all_to_platform":
            try:
                total_wallet = get_total_bot_balance(tg_id)
            except Exception:
                total_wallet = 0.0

            if total_wallet <= 0:
                tg_send_message(chat_id, "❌ لا يوجد رصيد متاح للتحويل.")
                return "ok", 200

            if total_wallet + 1e-9 < BOT_MIN_CASHOUT_USD:
                tg_send_message(
                    chat_id,
                    f"❌ الحد الأدنى للتحويل هو {BOT_MIN_CASHOUT_USD}$، "
                    f"ورصيدك الحالي هو {total_wallet:.3f}$ فقط."
                )
                return "ok", 200

            ok, msg_res = transfer_bot_to_platform_by_telegram_id(tg_id, total_wallet)
            if ok:
                tg_send_message(
                    chat_id,
                    "✅ تم تحويل كل رصيدك في البوت إلى حسابك في المنصة.\n"
                    f"المبلغ المحوَّل: <b>{total_wallet:.3f}$</b>\n\n"
                    "يمكنك الآن الدخول إلى المنصة ورؤية الرصيد في USD."
                )
            else:
                tg_send_message(
                    chat_id,
                    f"❌ لم يتم التحويل:\n{msg_res}"
                )
            return "ok", 200

        # 🔗 شرح وزر ربط الحساب
        elif data == "link_account":
            link_url = f"{SITE_PUBLIC_URL}/link_telegram"
            msg = (
                "🔗 <b>ربط الحساب</b>\n\n"
                "1) افتح صفحة الربط من الزر بالأسفل.\n"
                "2) اضغط: توليد كود.\n"
                "3) انسخ الكود.\n"
                "4) أرسله هنا في البوت (مثال: LNK-ABC12345)\n\n"
                "📌 الكود صالح لمدة 10 دقائق."
            )
            kb = {"inline_keyboard": [[{"text": "🔗 فتح صفحة الربط", "url": link_url}]]}
            tg_send_message(chat_id, msg, reply_markup=kb)
            return "ok", 200

        # 🔁 رجوع للقائمة الرئيسية (نفس محتوى /start تقريباً)
        elif data == "start_menu":
            tg_id = from_user.get("id")
            ref_link = f"https://t.me/Currencyexchangedh_bot?start=ref_{tg_id}"

            welcome_text = (
                "👋 أهلاً بك في بوت المنصة.\n\n"
                "يمكنك من هنا الدخول إلى المنصة، استخدام نظام الإحالات، "
                "أو الوصول إلى بعض الخدمات الفرعية.\n\n"
                "🔗 رابط المنصة:\n"
                f"{SITE_PUBLIC_URL}\n\n"
                "✅ رابط إحالتك:\n"
                f"{ref_link}"
            )

            keyboard = {
                "inline_keyboard": [
                    [{"text": "🌐 المنصة / Platform", "url": SITE_PUBLIC_URL}],
                    [{"text": "🔗 ربط الحساب / Link account", "callback_data": "link_account"}],
                    [{"text": "👥 نظام الإحالات / Referrals", "callback_data": "referrals"}],
                    [{"text": "💸 تحويل الرصيد / Transfer balance", "callback_data": "transfer_balance"}],
                    [{"text": "🧰 الخدمات الفرعية / Services", "callback_data": "services"}],
                ]
            }

            tg_send_message(chat_id, welcome_text, reply_markup=keyboard)
            return "ok", 200

        else:
            tg_send_message(chat_id, "الخيار غير معروف حالياً.")
            return "ok", 200
# ==============================
# ✅ (NEW) ربط الحساب من المنصة (routes)
# ==============================
@app.route("/link_telegram")
def link_telegram():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    db = get_db()

    tg_link = None
    try:
        tg_link = db.execute(
            _sql("""
                SELECT telegram_id, username, first_name, last_name, linked_at
                FROM telegram_users
                WHERE platform_user_id = ?
                LIMIT 1
            """),
            (user["id"],),
        ).fetchone()
    except Exception:
        tg_link = None

    # جلب آخر كود صالح (غير مستخدم وغير منتهي) إن وجد
    active_code = None
    try:
        active_code = db.execute(
            _sql("""
                SELECT code, expires_at
                FROM telegram_link_codes
                WHERE COALESCE(platform_user_id, user_id) = ?
                  AND used_at IS NULL
                  AND expires_at::timestamptz > now()
                ORDER BY id DESC
                LIMIT 1
            """) if USE_POSTGRES else _sql("""
                SELECT code, expires_at
                FROM telegram_link_codes
                WHERE platform_user_id = ?
                  AND used_at IS NULL
                  AND expires_at > ?
                ORDER BY id DESC
                LIMIT 1
            """),
            (user["id"],) if USE_POSTGRES else (user["id"], datetime.now(timezone.utc).isoformat()),
        ).fetchone()
    except Exception:
        active_code = None

    # إذا غير مربوط ومافيش كود صالح => لا نولّد تلقائياً، فقط نعرض زر التوليد
    return render_template(
        "link_telegram.html",
        user=user,
        tg_link=tg_link,
        active_code=active_code,
        link_code_prefix=LINK_CODE_PREFIX,
    )

@app.route("/unlink_telegram", methods=["POST"])
def unlink_telegram():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    db = get_db()

    db.execute(
        _sql("""
            UPDATE telegram_users
            SET platform_user_id = NULL, linked_at = NULL
            WHERE platform_user_id = ?
        """),
        (user["id"],),
    )

    try:
        if USE_POSTGRES:
            db.execute(
                _sql("""
                    UPDATE telegram_link_codes
                    SET used_by_telegram_id = NULL
                    WHERE COALESCE(platform_user_id, user_id) = ?
                """),
                (user["id"],),
            )
        else:
            db.execute(
                """
                UPDATE telegram_link_codes
                SET used_by_telegram_id = NULL
                WHERE platform_user_id = ?
                """,
                (user["id"],),
            )
    except Exception:
        pass

    db.commit()
    flash("✅ تم إلغاء ربط حساب Telegram.", "success")
    return redirect(url_for("link_telegram"))

@app.route("/generate_telegram_link_code", methods=["POST"])
def generate_telegram_link_code():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    try:
        create_telegram_link_code(user["id"], minutes_valid=10)
        flash("✅ تم توليد كود ربط جديد.", "success")
    except Exception as e:
        logging.error("generate_telegram_link_code error: %s", e)
        flash("❌ تعذر توليد كود الربط. حاول مرة أخرى.", "error")

    return redirect(url_for("link_telegram"))    

@app.route("/transfer_to_bot_10", methods=["POST"])
def transfer_to_bot_10():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    db = get_db()

    # لازم يكون الحساب مربوط
    row = db.execute(
        _sql("""
            SELECT telegram_id
            FROM telegram_users
            WHERE platform_user_id = ?
            LIMIT 1
        """),
        (user["id"],),
    ).fetchone()

    if not row:
        flash("❌ يجب ربط تيليجرام أولاً.", "error")
        return redirect(url_for("link_telegram"))

    telegram_id = int(row["telegram_id"])
    amount = float(BOT_TOPUP_FIXED_USD)  # غالباً 10

    # التأكد من رصيد USD في المنصة
    bal_row = db.execute(
        _sql("SELECT amount FROM balances WHERE user_id = ? AND currency = ?"),
        (user["id"], "USD"),
    ).fetchone()

    current = float(bal_row["amount"]) if bal_row else 0.0
    if current + 1e-9 < amount:
        flash("❌ رصيد USD في المنصة غير كافٍ لإضافة 10$ للبوت.", "error")
        return redirect(url_for("link_telegram"))

    # خصم من المنصة
    db.execute(
        _sql("UPDATE balances SET amount = amount - ? WHERE user_id = ? AND currency = ?"),
        (amount, user["id"], "USD"),
    )

    # إضافة للبوت
    db.execute(
        _sql("""
            UPDATE telegram_users
            SET bot_balance_usd = COALESCE(bot_balance_usd, 0) + ?
            WHERE telegram_id = ?
        """),
        (amount, telegram_id),
    )

    # تسجيل معاملة
    db.execute(
        _sql("""
            INSERT INTO transactions (user_id, type, amount, currency, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """),
        (user["id"], "transfer_to_bot", amount, "USD", f"to telegram_id={telegram_id}", _now_str()),
    )

    db.commit()
    flash("✅ تم تحويل 10$ إلى رصيد البوت بنجاح.", "success")
    return redirect(url_for("link_telegram"))    

# ==============================
# توافق قديم: ensure_admin (بدون تكرار)
# ==============================
def ensure_admin():
    ensure_default_admin()


ensure_admin()

# ==============================
# تشغيل التطبيق
# ==============================
if __name__ == "__main__":
    app.run(debug=True)