import os
import json
import sqlite3
import logging
import requests  # لإرسال طلبات إلى Telegram Bot API
from datetime import datetime
from decimal import Decimal, ROUND_DOWN

import csv
import io

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

# رابط الشحن الأوتوماتيكي 100 USDT
BINANCE_AUTO_100_URL = os.getenv("BINANCE_AUTO_100_URL", "").strip()
if not BINANCE_AUTO_100_URL:
    # fallback ثابت لو ما كانش موجود في .env
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
    "https://currency-exchange-app-2ymh.onrender.com"  # ✅ تم تحديث الرابط الافتراضي هنا
)

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
    """
    استخدام داخل القوالب:
      {{ t('home') }}

    يرجع النص حسب اللغة الحالية في session['lang']،
    وإذا لم يجد المفتاح يرجع نفس الـ key.
    """
    if lang is None:
        lang = session.get("lang", "ar")
    lang_map = TRANSLATIONS.get(lang, {})
    return lang_map.get(key, key)


@app.context_processor
def inject_t():
    """
    يجعل الدالة t متاحة في جميع القوالب:
      {{ t('some_key') }}
    """
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
# دوال التعامل مع قاعدة البيانات
# ==============================
def get_db():
    """إرجاع اتصال SQLite مخزَّن في g لكل طلب."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    cur.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            phone TEXT,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            currency TEXT NOT NULL,
            amount REAL NOT NULL DEFAULT 0,
            UNIQUE(user_id, currency),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS pending_deposits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            fiat_currency TEXT NOT NULL,
            pay_method TEXT,
            status TEXT DEFAULT 'pending',
            txid TEXT,
            timestamp TEXT NOT NULL,
            processed_by TEXT,
            processed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS pending_withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            payout_info TEXT,
            status TEXT DEFAULT 'pending',
            timestamp TEXT NOT NULL,
            processed_by TEXT,
            processed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            type TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            ref_type TEXT,
            ref_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS telegram_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE NOT NULL,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            referred_by_telegram_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # ==== ترقية الجداول لو كانت قديمة (على DB موجودة من قبل) ====

    # ترقية جدول pending_deposits
    cols_dep = {
        c["name"] for c in cur.execute("PRAGMA table_info(pending_deposits)").fetchall()
    }
    if "status" not in cols_dep:
        cur.execute("ALTER TABLE pending_deposits ADD COLUMN status TEXT DEFAULT 'pending'")
    if "processed_by" not in cols_dep:
        cur.execute("ALTER TABLE pending_deposits ADD COLUMN processed_by TEXT")
    if "processed_at" not in cols_dep:
        cur.execute("ALTER TABLE pending_deposits ADD COLUMN processed_at TEXT")

    # ترقية جدول pending_withdrawals
    cols_w = {
        c["name"] for c in cur.execute("PRAGMA table_info(pending_withdrawals)").fetchall()
    }
    if "status" not in cols_w:
        cur.execute("ALTER TABLE pending_withdrawals ADD COLUMN status TEXT DEFAULT 'pending'")
    if "processed_by" not in cols_w:
        cur.execute("ALTER TABLE pending_withdrawals ADD COLUMN processed_by TEXT")
    if "processed_at" not in cols_w:
        cur.execute("ALTER TABLE pending_withdrawals ADD COLUMN processed_at TEXT")

    # ترقية جدول notifications
    cols_not = {
        c["name"] for c in cur.execute("PRAGMA table_info(notifications)").fetchall()
    }

    # body
    if "body" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN body TEXT")
        if "message" in cols_not:
            try:
                cur.execute("UPDATE notifications SET body = message WHERE body IS NULL")
            except Exception:
                pass

    # type
    if "type" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN type TEXT")

    # is_read
    if "is_read" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN is_read INTEGER DEFAULT 0")

    # created_at
    if "created_at" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN created_at TEXT")

    # ref_type / ref_id
    if "ref_type" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN ref_type TEXT")
    if "ref_id" not in cols_not:
        cur.execute("ALTER TABLE notifications ADD COLUMN ref_id INTEGER")

    db.commit()
    db.close()


def ensure_default_admin():
    """
    إنشاء حساب أدمن افتراضي مرة واحدة فقط:
    - username: admin
    - password: Admin123!  (غيّره بعد أول دخول)
    - balance: 1000 USD
    """
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    cur = db.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    row = cur.fetchone()
    if row:
        db.close()
        return  # الأدمن موجود مسبقًا

    password_hash = generate_password_hash("Admin123!")

    # إنشاء المستخدم كأدمن
    cur.execute(
        """
        INSERT INTO users (username, email, phone, password_hash, is_admin)
        VALUES (?, ?, ?, ?, 1)
        """,
        ("admin", "admin@example.com", "", password_hash),
    )
    admin_id = cur.lastrowid

    # إنشاء أرصدة 0 لكل العملات
    for c in CURRENCIES:
        cur.execute(
            "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, ?)",
            (admin_id, c, 0.0),
        )

    # شحن 1000 USD
    cur.execute(
        "UPDATE balances SET amount = amount + ? WHERE user_id = ? AND currency = ?",
        (1000.0, admin_id, "USD"),
    )

    # تسجيل العملية في سجلّ المعاملات
    cur.execute(
        """
        INSERT INTO transactions (user_id, type, amount, currency, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
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
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO users (username, email, phone, password_hash, is_admin)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, email, phone, password_hash, 1 if is_admin else 0),
    )
    user_id = cur.lastrowid

    # إنشاء رصيد 0 لكل عملة
    for c in CURRENCIES:
        cur.execute(
            "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, ?)",
            (user_id, c, 0.0),
        )

    db.commit()
    return user_id


def get_user(username):
    """إرجاع dict يمثل المستخدم مع الأرصدة + المعاملات."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row:
        return None

    user_id = row["id"]

    # الأرصدة
    balances_rows = db.execute(
        "SELECT currency, amount FROM balances WHERE user_id = ?", (user_id,)
    ).fetchall()
    balance = {c: 0.0 for c in CURRENCIES}
    for b in balances_rows:
        balance[b["currency"]] = float(b["amount"] or 0.0)

    # المعاملات
    tx_rows = db.execute(
        """
        SELECT type, amount, currency, details, timestamp
        FROM transactions
        WHERE user_id = ?
        ORDER BY timestamp DESC
        """,
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
        "email": row["email"],
        "phone": row["phone"],
        "password_hash": row["password_hash"],
        "is_admin": bool(row["is_admin"]),
        "balance": balance,
        "transactions": transactions,
    }


def change_balance(user_id, currency, delta):
    """زيادة/إنقاص رصيد عملة معينة للمستخدم."""
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, 0)",
        (user_id, currency),
    )
    db.execute(
        "UPDATE balances SET amount = amount + ? WHERE user_id = ? AND currency = ?",
        (float(delta), user_id, currency),
    )
    db.commit()


def log_transaction(user_id, tx_type, amount, currency, details=""):
    db = get_db()
    db.execute(
        """
        INSERT INTO transactions (user_id, type, amount, currency, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
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
    """
    kind: نوع الإشعار (مثال: 'deposit_approved', 'deposit_rejected',
          'withdraw_approved', 'withdraw_rejected' ...)
    - يتم دائماً إنشاء الإشعار بحالة غير مقروءة is_read = 0
    - نخزّن kind في عمود type، ونصّ الإشعار في body
    """
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO notifications
                (user_id, title, body, type, is_read, created_at, ref_type, ref_id)
            VALUES
                (?,      ?,     ?,    ?,    0,       ?,          NULL,    ?)
            """,
            (
                user_id,
                title,
                message,
                kind,  # نخزّن kind في عمود type
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ref_id,
            ),
        )
        db.commit()
    except sqlite3.OperationalError as e:
        logging.warning("create_notification schema error: %s", e)


def count_unread_notifications(user_id: int) -> int:
    """
    إرجاع عدد الإشعارات غير المقروءة للمستخدم.
    لو كان هناك مشكلة في سكيمة قاعدة البيانات على السيرفر
    لا نُسقط الموقع، بل نعيد 0 ونكتب تحذير في اللوج.
    """
    db = get_db()
    try:
        row = db.execute(
            "SELECT COUNT(*) AS cnt FROM notifications WHERE user_id = ? AND is_read = 0",
            (user_id,),
        ).fetchone()
        return int(row["cnt"] if row else 0)
    except sqlite3.OperationalError as e:
        logging.warning("count_unread_notifications schema error: %s", e)
        return 0


# ==============================
# دوال خاصة ببوت تيليجرام
# ==============================
def register_telegram_user(from_user, start_param=None):
    """
    يسجّل/يحدّث مستخدم تلجرام في جدول telegram_users.
    start_param قد تحتوي على كود الإحالة: مثال 'ref_123456789'
    ترجع telegram_id أو 0 لو فشل.
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

    db = get_db()
    cur = db.cursor()

    row = cur.execute(
        "SELECT * FROM telegram_users WHERE telegram_id = ?",
        (tg_id,),
    ).fetchone()

    if row is None:
        # مستخدم جديد
        cur.execute(
            """
            INSERT INTO telegram_users
                (telegram_id, username, first_name, last_name, referred_by_telegram_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tg_id, username, first_name, last_name, referred_by),
        )
        db.commit()
    else:
        # تحديث بيانات الاسم/اليوزر إذا تغيّرت
        if (
            row["username"] != username
            or row["first_name"] != first_name
            or row["last_name"] != last_name
        ):
            cur.execute(
                """
                UPDATE telegram_users
                SET username = ?, first_name = ?, last_name = ?
                WHERE telegram_id = ?
                """,
                (username, first_name, last_name, tg_id),
            )
            db.commit()

    return tg_id


def tg_send_message(chat_id, text, reply_markup=None):
    """إرسال رسالة نصية بسيطة عبر Telegram API."""
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
    """إزالة حالة الـ Loading عند الضغط على الأزرار المضمنة."""
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

        # تحقق أساسي من المدخلات
        if not username or not password:
            flash("❌ يجب إدخال اسم مستخدم وكلمة مرور", "error")
            return render_template("register.html")

        if password != confirm:
            flash("❌ كلمتا المرور غير متطابقتين", "error")
            return render_template("register.html")

        # اسم المستخدم موجود؟
        if get_user(username):
            flash("❌ اسم المستخدم موجود بالفعل", "error")
            return render_template("register.html")

        hashed_pw = generate_password_hash(password)

        try:
            create_user(username, email, phone, hashed_pw, is_admin=False)
        except sqlite3.IntegrityError:
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

    # تحويل المبلغ إلى Decimal
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

    # رصيد العملة المرسِل منها
    current_from_balance = user["balance"].get(from_currency, 0.0)
    if current_from_balance < float(amount):
        return jsonify({"success": False, "message": f"الرصيد غير كافٍ في {from_currency}"}), 400

    try:
        # استخدام الدالة من currency_converter.converter (سعر صرف حقيقي + كاش داخلي)
        converted_raw = convert_currency(amount, from_currency, to_currency)
        converted_dec = Decimal(str(converted_raw)).quantize(
            Decimal("0.01"), rounding=ROUND_DOWN
        )

        # حساب سعر الصرف الفعلي
        rate_dec = (converted_dec / amount).quantize(Decimal("0.0001"))

        # تحديث الأرصدة في قاعدة البيانات
        change_balance(user["id"], from_currency, -float(amount))
        change_balance(user["id"], to_currency, float(converted_dec))

        # تسجيل تحويل واحد فقط (بدون تكرار)
        details = f"{amount} {from_currency} → {converted_dec} {to_currency}"
        log_transaction(
            user["id"],
            "Currency Conversion",
            float(amount),
            from_currency,
            details,
        )

        # جلب الأرصدة الجديدة بعد التحديث
        updated_user = get_user(username)
        balances = updated_user["balance"] if updated_user and "balance" in updated_user else {}

        return jsonify(
            {
                "success": True,
                "converted_amount": f"{converted_dec}",
                "rate": f"{rate_dec:.4f}",
                "balances": balances,  # لتحديث الواجهة فوراً
            }
        )

    except RuntimeError as e:
        # مشكلة في مزود أسعار الصرف (API)
        logging.error(f"Currency API error: {e}")
        return jsonify(
            {
                "success": False,
                "message": "تعذر جلب سعر الصرف من مزوّد الأسعار الخارجي، يرجى المحاولة لاحقاً.",
            }
        ), 502

    except Exception as e:
        logging.error(f"Currency conversion error: {e}")
        return jsonify(
            {"success": False, "message": "خطأ أثناء تحويل العملات"}
        ), 500


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
        """
        INSERT INTO pending_deposits
        (user_id, amount, fiat_currency, pay_method, status, txid, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
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

    log_transaction(
        user["id"],
        "Binance Topup Request",
        amount,
        fiat_currency,
        details=f"UID={BINANCE_UID}, txid={txid}",
    )

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

    # التحقق من المدخلات
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

    # ✅ إضافة طلب الشحن إلى جدول pending_deposits ليظهر في لوحة الأدمن
    db.execute(
        """
        INSERT INTO pending_deposits
        (user_id, amount, fiat_currency, pay_method, status, txid, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            float(amount),
            currency,          # تخزين العملة في حقل fiat_currency
            "Binance Pay",     # طريقة الدفع
            "pending",         # حالة الطلب المبدئية
            txid,
            now_str,
        ),
    )

    # تسجيل العملية في سجل المعاملات
    log_transaction(
        user["id"],
        "Binance Deposit Proof",
        amount,
        currency,
        details=f"TXID/Proof: {txid}",
    )

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

    # خصم الرصيد
    change_balance(user["id"], currency, -float(amount))

    # إضافة إلى جدول طلبات السحب المعلقة
    db = get_db()
    db.execute(
        """
        INSERT INTO pending_withdrawals
        (user_id, amount, currency, payout_info, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
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

    log_transaction(
        user["id"],
        "Withdraw Request",
        amount,
        currency,
        details=f"Payout info: {payout_info}",
    )

    flash("📤 تم إرسال طلب السحب، سيتم معالجته يدويًا.", "success")
    return redirect(url_for("index"))


# ==============================
# أدوات مساعدة للأدمن
# ==============================
def _ensure_admin():
    """تفقد أن المستخدم أدمن وإلا يرجع None."""
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
        f"""
        SELECT u.username, t.type, t.amount, t.currency, t.details, t.timestamp
        FROM transactions t
        JOIN users u ON t.user_id = u.id
        {where_clause}
        ORDER BY t.timestamp DESC
        """,
        params,
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "type", "amount", "currency", "details", "timestamp"])
    for r in rows:
        writer.writerow(
            [r["username"], r["type"], r["amount"], r["currency"], r["details"], r["timestamp"]]
        )

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=transactions.csv",
        },
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
            """
            SELECT u.username, b.currency, b.amount
            FROM balances b
            JOIN users u ON b.user_id = u.id
            WHERE u.username = ?
            ORDER BY u.username, b.currency
            """,
            (username_f,),
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT u.username, b.currency, b.amount
            FROM balances b
            JOIN users u ON b.user_id = u.id
            ORDER BY u.username, b.currency
            """
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
        headers={
            "Content-Disposition": "attachment; filename=balances.csv",
        },
    )


@app.route("/admin/withdrawals", methods=["GET", "POST"])
def admin_withdrawals():
    admin = _ensure_admin()
    if not admin:
        flash("🚫 غير مسموح بالدخول إلى لوحة الإدارة", "error")
        return redirect(url_for("index"))

    db = get_db()

    # ========= POST: موافقة أو رفض =========
    if request.method == "POST":
        wid = request.form.get("withdrawal_id")
        action = request.form.get("action")  # "approve" أو "reject"

        if not wid or not action:
            flash("⚠️ بيانات الطلب غير كاملة", "error")
            return redirect(url_for("admin_withdrawals"))

        # نجلب الطلب من جدول pending_withdrawals
        w = db.execute(
            "SELECT * FROM pending_withdrawals WHERE id = ?", (wid,)
        ).fetchone()

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

        # ========== حالة الموافقة ==========
        if action == "approve":
            # تحديث حالة الطلب
            db.execute(
                """
                UPDATE pending_withdrawals
                SET status = 'completed',
                    processed_by = ?,
                    processed_at = ?
                WHERE id = ?
                """,
                (admin["username"], now_str, wid),
            )

            # تسجيل معاملة
            log_transaction(
                user_id,
                "Withdrawal Approved",
                amount,
                currency,
                f"تم تنفيذ طلب السحب بقيمة {amount} {currency}",
            )

            # إشعار ثنائي اللغة للمستخدم
            title = "تم تنفيذ طلب السحب / Withdrawal executed"
            body = (
                f"تم تنفيذ طلب السحب بقيمة {amount} {currency} بنجاح.\n"
                f"Withdrawal of {amount} {currency} has been processed successfully."
            )

            db.execute(
                """
                INSERT INTO notifications (user_id, title, body, type, is_read, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (
                    user_id,
                    title,
                    body,
                    "withdraw_approved",
                    now_str,
                ),
            )

            db.commit()
            flash("✅ تم اعتماد طلب السحب وإرسال إشعار للمستخدم.", "success")
            return redirect(url_for("admin_withdrawals"))

        # ========== حالة الرفض ==========
        if action == "reject":
            # إرجاع المبلغ إلى رصيد المستخدم
            change_balance(user_id, currency, amount)

            # تحديث حالة الطلب
            db.execute(
                """
                UPDATE pending_withdrawals
                SET status = 'rejected',
                    processed_by = ?,
                    processed_at = ?
                WHERE id = ?
                """,
                (admin["username"], now_str, wid),
            )

            # تسجيل معاملة
            log_transaction(
                user_id,
                "Withdrawal Rejected",
                amount,
                currency,
                "تم رفض طلب السحب وإرجاع المبلغ إلى الرصيد.",
            )

            # إشعار ثنائي اللغة للمستخدم
            title = "تم رفض طلب السحب / Withdrawal rejected"
            body = (
                f"تم رفض طلب السحب بقيمة {amount} {currency} "
                f"وتم إرجاع المبلغ إلى رصيد حسابك.\n"
                f"Withdrawal of {amount} {currency} has been rejected and "
                f"the amount has been returned to your balance."
            )

            db.execute(
                """
                INSERT INTO notifications (user_id, title, body, type, is_read, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (
                    user_id,
                    title,
                    body,
                    "withdraw_rejected",
                    now_str,
                ),
            )

            db.commit()
            flash("✅ تم رفض طلب السحب وإرجاع المبلغ للمستخدم.", "success")
            return redirect(url_for("admin_withdrawals"))

        # لو action ليست approve أو reject
        flash("⚠️ إجراء غير معروف", "error")
        return redirect(url_for("admin_withdrawals"))

    # ========= GET: عرض الطلبات المعلقة =========
    withdrawals = db.execute(
        """
        SELECT w.*, u.username, u.email
        FROM pending_withdrawals w
        JOIN users u ON w.user_id = u.id
        WHERE w.status = 'pending'
        ORDER BY w.timestamp DESC
        """
    ).fetchall()

    return render_template("admin_withdrawals.html", withdrawals=withdrawals)


@app.route("/admin/deposits", methods=["GET", "POST"])
def admin_deposits():
    admin = _ensure_admin()
    if not admin:
        flash("🚫 غير مسموح بالدخول إلى لوحة الإدارة", "error")
        return redirect(url_for("index"))

    db = get_db()

    # ========= POST: موافقة أو رفض شحن =========
    if request.method == "POST":
        did = request.form.get("deposit_id")
        action = request.form.get("action")  # "approve" أو "reject"

        if not did or not action:
            flash("⚠️ بيانات الطلب غير كاملة", "error")
            return redirect(url_for("admin_deposits"))

        dep = db.execute(
            "SELECT * FROM pending_deposits WHERE id = ?", (did,)
        ).fetchone()

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

        # لو تم القبول: نضيف الرصيد ونُسجّل معاملة
        if new_status == "completed":
            change_balance(user_id, fiat_currency, amount)
            log_transaction(
                user_id,
                "Binance Topup",
                amount,
                fiat_currency,
                details=f"Approved topup #{dep['id']} via Binance Pay",
            )

            title = "تم قبول طلب الشحن / Top-up approved"
            body = (
                f"تم شحن حسابك بمبلغ {amount} {fiat_currency} بنجاح.\n"
                f"Your account has been credited with {amount} {fiat_currency} successfully."
            )
            notif_type = "deposit_approved"
        else:
            title = "تم رفض طلب الشحن / Top-up rejected"
            body = (
                f"تم رفض طلب شحن بقيمة {amount} {fiat_currency}. "
                "يرجى التأكد من التحويل أو التواصل مع الدعم.\n"
                f"Top-up request of {amount} {fiat_currency} has been rejected. "
                "Please verify your transfer or contact support."
            )
            notif_type = "deposit_rejected"

        # تحديث سجل الشحن (مع الأعمدة الجديدة)
        try:
            db.execute(
                """
                UPDATE pending_deposits
                SET status = ?, processed_by = ?, processed_at = ?
                WHERE id = ?
                """,
                (new_status, admin["username"], now_str, did),
            )
        except sqlite3.OperationalError:
            # قاعدة بيانات قديمة لا تحتوي الأعمدة الجديدة
            db.execute(
                "UPDATE pending_deposits SET status = ? WHERE id = ?",
                (new_status, did),
            )

        # إدخال إشعار، باستخدام ref_type / ref_id (متوافقة مع السكيمة الحالية)
        try:
            db.execute(
                """
                INSERT INTO notifications
                    (user_id, title, body, type, is_read, created_at, ref_type, ref_id)
                VALUES (?, ?, ?, ?, 0, ?, 'pending_deposits', ?)
                """,
                (user_id, title, body, notif_type, now_str, dep["id"]),
            )
        except sqlite3.OperationalError:
            db.execute(
                """
                INSERT INTO notifications
                    (user_id, title, body, type, is_read, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (user_id, title, body, notif_type, now_str),
            )

        db.commit()
        flash("✅ تم تحديث حالة طلب الشحن.", "success")
        return redirect(url_for("admin_deposits"))

    # ========= GET: عرض الطلبات المعلقة =========
    deposits = db.execute(
        """
        SELECT d.*, u.username, u.email
        FROM pending_deposits d
        JOIN users u ON d.user_id = u.id
        WHERE d.status = 'pending'
        ORDER BY d.timestamp DESC
        """
    ).fetchall()

    return render_template("admin_deposits.html", deposits=deposits)


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

    # جلب الإشعارات
    try:
        rows = db.execute(
            """
            SELECT id, title, body, type, ref_type, ref_id, is_read, created_at
            FROM notifications
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC, id DESC
            """,
            (user["id"],),
        ).fetchall()
    except sqlite3.OperationalError as e:
        logging.error("notifications select error: %s", e)
        rows = []

    # تحديث الإشعارات إلى "مقروءة"
    try:
        db.execute(
            "UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0",
            (user["id"],),
        )
        db.commit()
    except sqlite3.OperationalError as e:
        logging.error("notifications update error: %s", e)

    return render_template("notifications.html", notifications=rows)


# ==============================
# صفحات إضافية
# ==============================
# عدد المعاملات في كل صفحة
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

    # رقم الصفحة من الـ query string ?page=2
    try:
        page = int(request.args.get("page", 1) or 1)
    except ValueError:
        page = 1

    if page < 1:
        page = 1

    per_page = TRANSACTIONS_PER_PAGE
    offset = (page - 1) * per_page

    # جلب 5 سجلات فقط (مع ترتيب من الأحدث إلى الأقدم)
    rows = db.execute(
        """
        SELECT type, amount, currency, details, timestamp
        FROM transactions
        WHERE user_id = ?
        ORDER BY datetime(timestamp) DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (user["id"], per_page, offset),
    ).fetchall()

    # لمعرفة هل توجد صفحة تالية أم لا
    next_row = db.execute(
        """
        SELECT 1
        FROM transactions
        WHERE user_id = ?
        LIMIT 1 OFFSET ?
        """,
        (user["id"], offset + per_page),
    ).fetchone()

    has_next = next_row is not None
    has_prev = page > 1

    return render_template(
        "transactions.html",
        transactions=rows,
        page=page,
        has_next=has_next,
        has_prev=has_prev,
    )


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
    """
    هذا هو Webhook الذي سيستقبل رسائل البوت من Telegram.
    ضعه في BotFather:
      https://YOUR_DOMAIN/telegram/webhook
    """
    if not TELEGRAM_BOT_TOKEN:
        return "Bot token not configured", 200

    try:
        update = request.get_json(force=True)
    except Exception:
        return "invalid json", 400

    if not update:
        return "no update", 200

    # رسالة نصية عادية
    if "message" in update:
        message = update["message"]
        text = message.get("text", "") or ""
        chat_id = message["chat"]["id"]
        from_user = message.get("from", {})

        # بارامتر start (لإحالات) يأتي من الأمر /start param
        start_param = None
        if text.startswith("/start") and " " in text:
            start_param = text.split(" ", 1)[1].strip()

        register_telegram_user(from_user, start_param)

        # /start
        if text.startswith("/start"):
            tg_id = from_user.get("id")
            ref_link = f"https://t.me/Currencyexchangedh_bot?start=ref_{tg_id}"

            welcome_text = (
                "👋 أهلاً بك في بوت المنصة.\n\n"
                "يمكنك من هنا الدخول إلى المنصة، استخدام نظام الإحالات، "
                "أو الوصول إلى بعض الخدمات الفرعية.\n\n"
                "🔗 رابط المنصة:\n"
                f"{SITE_PUBLIC_URL}"
            )

            keyboard = {
                "inline_keyboard": [
                    [
                        {
                            "text": "🌐 المنصة / Platform",
                            "url": SITE_PUBLIC_URL,
                        }
                    ],
                    [
                        {
                            "text": "👥 نظام الإحالات / Referrals",
                            "callback_data": "referrals",
                        }
                    ],
                    [
                        {
                            "text": "🧰 الخدمات الفرعية / Services",
                            "callback_data": "services",
                        }
                    ],
                ]
            }

            tg_send_message(chat_id, welcome_text, reply_markup=keyboard)
            return "ok", 200

        # أي رسالة أخرى حاليًا
        tg_send_message(
            chat_id,
            "استخدم الأمر /start للحصول على القائمة الرئيسية للبوت.",
        )
        return "ok", 200

    # الضغط على زر Inline (callback_query)
    if "callback_query" in update:
        cq = update["callback_query"]
        data = cq.get("data")
        chat_id = cq["message"]["chat"]["id"]
        from_user = cq.get("from", {})
        tg_id = from_user.get("id")
        callback_id = cq.get("id")

        # إزالة الـ Loading
        if callback_id:
            tg_answer_callback(callback_id)

        if data == "referrals":
            ref_link = f"https://t.me/Currencyexchangedh_bot?start=ref_{tg_id}"
            msg = (
                "👥 <b>نظام الإحالات</b>\n\n"
                "هذا هو رابط الإحالة الخاص بك:\n"
                f"{ref_link}\n\n"
                "أي مستخدم يفتح البوت لأول مرة عبر هذا الرابط "
                "سيُسجَّل كإحالة مرتبطة بحسابك في البوت."
            )
            tg_send_message(chat_id, msg)
            return "ok", 200

        if data == "services":
            msg = (
                "🧰 <b>الخدمات الفرعية</b>\n\n"
                "سيتم هنا لاحقًا إضافة أزرار لخدمات إضافية "
                "مثل: أسعار الصرف، شروحات، أو أدوات أخرى مرتبطة بالمنصة."
            )
            tg_send_message(chat_id, msg)
            return "ok", 200

        # أي callback غير معروف
        tg_send_message(chat_id, "الخيار غير معروف حالياً.")
        return "ok", 200

    # أنواع أخرى من التحديثات نتجاهلها الآن
    return "ok", 200


# إنشاء حساب أدمن تلقائي عند التشغيل الأول (Render)
def ensure_admin():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE username='admin'")
    if not cur.fetchone():
        from werkzeug.security import generate_password_hash
        cur.execute(
            """
            INSERT INTO users (username, email, phone, password_hash, is_admin)
            VALUES ('admin', 'admin@example.com', '', ?, 1)
            """,
            (generate_password_hash("admin123"),),
        )
        db.commit()
        print("✅ Admin account created on Render (admin / admin123)")
    else:
        print("ℹ️ Admin account already exists.")
    db.close()


ensure_admin()


# ==============================
# تشغيل التطبيق
# ==============================
if __name__ == "__main__":
    app.run(debug=True)