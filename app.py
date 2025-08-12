import smtplib, ssl
from email.message import EmailMessage
import os
import json
import time
import tempfile
import sqlite3
import logging
import requests
import hmac, hashlib, secrets, string, uuid
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# -----------------------------------
# تهيئة التطبيق والسرّيات من البيئة
# -----------------------------------
load_dotenv()
app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY') or (_ for _ in ()).throw(RuntimeError('SECRET_KEY not set'))
EXCHANGE_API_KEY = os.environ.get('EXCHANGE_API_KEY') or (_ for _ in ()).throw(RuntimeError('EXCHANGE_API_KEY not set'))
DB_PATH = os.environ.get('DB_PATH', 'data.db')

# Binance Pay فقط
BINANCE_API_KEY = os.getenv('BINANCE_API_KEY')             # BinancePay-Certificate-SN
BINANCE_API_SECRET = os.getenv('BINANCE_API_SECRET')       # HMAC-SHA512 secret
BINANCE_HOST = 'https://bpay.binanceapi.com'

# حماية CSRF
csrf = CSRFProtect(app)

# تسجيل
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# -----------------------------------
# i18n بسيط
# -----------------------------------
TRANSLATIONS_FILE = os.path.join(os.path.dirname(__file__), 'translations.json')
_translations_cache = None

def get_translations():
    global _translations_cache
    if _translations_cache is None:
        try:
            with open(TRANSLATIONS_FILE, 'r', encoding='utf-8') as f:
                _translations_cache = json.load(f)
        except Exception:
            _translations_cache = {"ar": {}, "en": {}}
    return _translations_cache

def t(key):
    lang = session.get('lang', 'ar')
    trans = get_translations()
    return (trans.get(lang, {}) or {}).get(key, key)

@app.context_processor
def inject_t():
    return {"t": t}

@app.route('/set_lang')
def set_lang():
    lang = request.args.get('lang', 'ar')
    if lang not in ('ar', 'en'):
        lang = 'ar'
    session['lang'] = lang
    next_url = request.args.get('next') or url_for('index')
    return redirect(next_url)

# -----------------------------------
# قاعدة البيانات (SQLite)
# -----------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS balances (
            username TEXT,
            currency TEXT,
            amount REAL DEFAULT 0,
            PRIMARY KEY (username, currency)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp TEXT,
            type TEXT,
            amount TEXT,
            currency TEXT
        );
        CREATE TABLE IF NOT EXISTS withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp TEXT,
            amount REAL,
            currency TEXT,
            email TEXT,
            status TEXT
        );
        /* أوامر باينانس للتتبع */
        CREATE TABLE IF NOT EXISTS binance_orders (
            merchant_trade_no TEXT PRIMARY KEY,
            username TEXT,
            prepay_id TEXT,
            currency TEXT,
            amount REAL,
            status TEXT,
            created_at TEXT
        );
        """)
        db.commit()

# -----------------------------------
# إعدادات عامة
# -----------------------------------
SUPPORTED_CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR"]
RATES_CACHE_FILE = 'rates_cache.json'
RATES_TTL_SEC = 12 * 60 * 60  # 12 ساعة

def parse_amount(value, *, min_value=0.0, max_value=1_000_000.0):
    try:
        amt = float(value)
    except (TypeError, ValueError):
        raise ValueError('invalid_amount')
    if not (min_value <= amt <= max_value):
        raise ValueError('amount_out_of_range')
    return round(amt, 2)

def get_exchange_rate(from_currency, to_currency):
    # كاش
    try:
        if os.path.exists(RATES_CACHE_FILE):
            cache = json.load(open(RATES_CACHE_FILE, 'r', encoding='utf-8'))
            key = f"{from_currency}->{to_currency}"
            rec = cache.get(key)
            if rec and int(time.time()) - int(rec.get("ts", 0)) < RATES_TTL_SEC:
                return float(rec["rate"])
    except Exception as ce:
        logging.warning("Rate cache read failed: %s", ce)

    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_API_KEY}/latest/{from_currency}"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        rate = float(data["conversion_rates"][to_currency])
        # كتابة الكاش
        try:
            cache = {}
            if os.path.exists(RATES_CACHE_FILE):
                cache = json.load(open(RATES_CACHE_FILE, 'r', encoding='utf-8'))
            now = int(time.time())
            cache_key = f"{from_currency}->{to_currency}"
            cache[cache_key] = {"rate": rate, "ts": now}
            with tempfile.NamedTemporaryFile('w', delete=False, dir='.', encoding='utf-8') as tmp:
                json.dump(cache, tmp, ensure_ascii=False, indent=2)
                tmp_path = tmp.name
            os.replace(tmp_path, RATES_CACHE_FILE)
        except Exception as we:
            logging.warning("Rate cache write failed: %s", we)
        return rate
    except Exception as e:
        logging.exception("Exchange rate fetch failed: %s", e)
        return None

# --------- Binance Pay أدوات ---------
def _rand_merchant_trade_no():
    return uuid.uuid4().hex[:32]  # <= 32

def _binance_sign_headers(body: dict):
    if not BINANCE_API_KEY or not BINANCE_API_SECRET:
        return None
    ts = str(int(time.time() * 1000))
    nonce = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    body_json = json.dumps(body, separators=(',', ':'), ensure_ascii=False)
    payload = f"{ts}\n{nonce}\n{body_json}\n"
    signature = hmac.new(BINANCE_API_SECRET.encode('utf-8'),
                         payload.encode('utf-8'),
                         hashlib.sha512).hexdigest().upper()
    headers = {
        "Content-Type": "application/json",
        "BinancePay-Timestamp": ts,
        "BinancePay-Nonce": nonce,
        "BinancePay-Certificate-SN": BINANCE_API_KEY,
        "BinancePay-Signature": signature
    }
    return headers, body_json

def _binance_post(path: str, body: dict):
    hb = _binance_sign_headers(body)
    if not hb:
        raise RuntimeError("Binance Pay is not configured")
    headers, body_json = hb
    url = f"{BINANCE_HOST}{path}"
    r = requests.post(url, headers=headers, data=body_json, timeout=15)
    r.raise_for_status()
    return r.json()

def _get_btc_usd():
    try:
        r = requests.get("https://api.binance.com/api/v3/ticker/price", params={"symbol":"BTCUSDT"}, timeout=10)
        r.raise_for_status()
        return float(r.json()["price"])  # USDT لكل BTC
    except Exception as e:
        logging.warning("BTCUSDT price fetch failed: %s", e)
        return None

# -----------------------------------
# المصادقة
# -----------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    with get_db() as db:
        if request.method == 'POST':
            username = request.form['username'].strip()
            password = request.form['password']
            if not username or not password:
                flash("⚠️ يرجى إدخال اسم المستخدم وكلمة المرور", 'error')
                return redirect(url_for('register'))
            row = db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
            if row:
                flash("⚠️ اسم المستخدم موجود مسبقًا", 'error')
                return redirect(url_for('register'))
            db.execute("INSERT INTO users(username, password_hash, is_admin) VALUES(?,?,?)",
                       (username, generate_password_hash(password),
                        1 if username == (os.getenv("ADMIN_USERNAME") or "") else 0))
            for cur in SUPPORTED_CURRENCIES:
                db.execute("INSERT INTO balances(username, currency, amount) VALUES(?,?,?)", (username, cur, 0.0))
            db.commit()
            flash("✅ تم إنشاء الحساب بنجاح", 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    with get_db() as db:
        if request.method == 'POST':
            username = request.form['username'].strip()
            password = request.form['password']
            row = db.execute("SELECT password_hash, is_admin FROM users WHERE username=?", (username,)).fetchone()
            if row and check_password_hash(row["password_hash"], password):
                session['username'] = username
                session['is_admin'] = bool(row['is_admin'])
                return redirect(url_for('index'))
            flash("❌ اسم المستخدم أو كلمة المرور غير صحيح", 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))

# -----------------------------------
# الواجهة الرئيسية
# -----------------------------------
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    with get_db() as db:
        bals = db.execute("SELECT currency, amount FROM balances WHERE username=?", (session['username'],)).fetchall()
        txs = db.execute("SELECT timestamp, type, amount, currency FROM transactions WHERE username=? ORDER BY id DESC LIMIT 50",
                         (session['username'],)).fetchall()
        wcount = db.execute("SELECT COUNT(*) as c FROM withdrawals WHERE username=? AND status='pending'",
                            (session['username'],)).fetchone()["c"]
    balances = {row["currency"]: row["amount"] for row in bals}
    return render_template('index.html',
                           balances=balances,
                           transactions=txs,
                           pending_withdrawals_count=wcount,
                           supported=SUPPORTED_CURRENCIES,
                           binance_enabled=bool(BINANCE_API_KEY and BINANCE_API_SECRET))

# -----------------------------------
# تحويل الرصيد بين العملات
# -----------------------------------
@app.route('/convert_balance', methods=['POST'])
def convert_balance():
    if 'username' not in session:
        return redirect(url_for('login'))
    from_currency = (request.form.get('from_currency') or '').upper()
    to_currency = (request.form.get('to_currency') or '').upper()
    try:
        amount = parse_amount(request.form.get('amount'))
    except Exception:
        flash('❌ مبلغ غير صالح', 'error')
        return redirect(url_for('index'))
    if from_currency == to_currency:
        flash('❌ لا يمكن تحويل نفس العملة', 'error')
        return redirect(url_for('index'))

    rate = get_exchange_rate(from_currency, to_currency)
    if not rate:
        flash('❌ تعذر جلب سعر الصرف', 'error')
        return redirect(url_for('index'))

    converted = round(amount * rate, 2)
    with get_db() as db:
        bal_from = db.execute("SELECT amount FROM balances WHERE username=? AND currency=?",
                              (session['username'], from_currency)).fetchone()
        if not bal_from or bal_from['amount'] < amount:
            flash('❌ الرصيد غير كافٍ', 'error')
            return redirect(url_for('index'))
        db.execute("UPDATE balances SET amount = amount - ? WHERE username=? AND currency=?",
                   (amount, session['username'], from_currency))
        db.execute("UPDATE balances SET amount = amount + ? WHERE username=? AND currency=?",
                   (converted, session['username'], to_currency))
        db.execute("INSERT INTO transactions(username, timestamp, type, amount, currency) VALUES(?,?,?,?,?)",
                   (session['username'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    f'تحويل من {from_currency} إلى {to_currency}', f'{amount} → {converted}', to_currency))
        db.commit()
    flash('✅ تم التحويل بنجاح', 'success')
    return redirect(url_for('index'))

# -----------------------------------
# Binance Pay: إنشاء طلب + العودة + استعلام الحالة
# -----------------------------------
@app.route('/binance/create_order', methods=['POST'])
@csrf.exempt
def binance_create_order():
    if 'username' not in session:
        return jsonify({'ok': False, 'error': 'auth'}), 401
    if not (BINANCE_API_KEY and BINANCE_API_SECRET):
        return jsonify({'ok': False, 'error': 'not_configured'}), 500

    data = request.get_json(silent=True) or {}
    try:
        amount = parse_amount(data.get('amount'), min_value=0.5)
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid_amount'}), 400

    crypto = (data.get('crypto') or '').upper()
    if crypto not in ('USDT', 'BTC'):
        return jsonify({'ok': False, 'error': 'unsupported_crypto'}), 400

    trade_no = _rand_merchant_trade_no()

    body = {
        "env": {"terminalType": "WEB"},
        "merchantTradeNo": trade_no,
        "orderAmount": float(amount),
        "currency": crypto,  # USDT أو BTC
        "description": f"Top-up for {session['username']}",
        "goodsDetails": [{
            "goodsType": "02",
            "goodsCategory": "Z000",
            "referenceGoodsId": trade_no,
            "goodsName": "Account Balance Top-up"
        }],
        "returnUrl": url_for('binance_return', _external=True) + f"?mtn={trade_no}",
        "cancelUrl": url_for('index', _external=True)
    }

    try:
        res = _binance_post("/binancepay/openapi/v3/order", body)
        if not (res.get("status") == "SUCCESS" and res.get("code") == "000000"):
            logging.error("Binance create order failed: %s", res)
            return jsonify({'ok': False, 'error': 'binance_fail', 'detail': res}), 502

        data_obj = res.get("data") or {}
        checkout_url = data_obj.get("checkoutUrl") or data_obj.get("universalUrl")
        prepay_id = data_obj.get("prepayId")

        with get_db() as db:
            db.execute("""INSERT OR REPLACE INTO binance_orders
                          (merchant_trade_no, username, prepay_id, currency, amount, status, created_at)
                          VALUES (?,?,?,?,?,?,?)""",
                       (trade_no, session['username'], prepay_id, crypto, amount, "INITIAL",
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            db.commit()

        return jsonify({'ok': True, 'url': checkout_url})
    except Exception as e:
        logging.exception("Binance create order exception: %s", e)
        return jsonify({'ok': False, 'error': 'exception'}), 500

@app.route('/binance/return', methods=['GET'])
def binance_return():
    if 'username' not in session:
        return redirect(url_for('login'))
    if not (BINANCE_API_KEY and BINANCE_API_SECRET):
        flash('Binance Pay غير مُعد.', 'error')
        return redirect(url_for('index'))

    trade_no = (request.args.get('mtn') or '').strip()
    if not trade_no:
        flash('طلب غير معروف.', 'error')
        return redirect(url_for('index'))

    try:
        res = _binance_post("/binancepay/openapi/v2/order/query", {"merchantTradeNo": trade_no})
        if not (res.get("status") == "SUCCESS" and res.get("code") == "000000"):
            flash('تعذر التحقق من حالة الدفع.', 'error')
            return redirect(url_for('index'))

        data_obj = res.get("data") or {}
        status = (data_obj.get("status") or "INITIAL").upper()
        currency = (data_obj.get("currency") or "").upper()
        order_amount = float(data_obj.get("orderAmount") or 0)

        if status != "PAID":
            with get_db() as db:
                db.execute("UPDATE binance_orders SET status=? WHERE merchant_trade_no=?", (status, trade_no))
                db.commit()
            flash('الدفع قيد المعالجة أو لم يكتمل بعد. حاول لاحقاً.', 'error')
            return redirect(url_for('index'))

        # اعتماد الرصيد بـ USD
        usd_credit = 0.0
        if currency == "USDT":
            usd_credit = round(order_amount, 2)  # ~1:1
        elif currency == "BTC":
            px = _get_btc_usd()
            if not px:
                flash('تم الدفع، لكن تعذر جلب سعر BTC حالياً.', 'error')
                return redirect(url_for('index'))
            usd_credit = round(order_amount * px, 2)
        else:
            rate = get_exchange_rate(currency, "USD")
            if not rate:
                flash('تم الدفع، لكن تعذر تحويل العملة إلى USD.', 'error')
                return redirect(url_for('index'))
            usd_credit = round(order_amount * rate, 2)

        with get_db() as db:
            db.execute("UPDATE binance_orders SET status=? WHERE merchant_trade_no=?", ("PAID", trade_no))
            db.execute("UPDATE balances SET amount = amount + ? WHERE username=? AND currency=?",
                       (usd_credit, session['username'], "USD"))
            db.execute("INSERT INTO transactions(username, timestamp, type, amount, currency) VALUES(?,?,?,?,?)",
                       (session['username'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "💳 Binance Pay Deposit", f"{order_amount} {currency} → {usd_credit}", "USD"))
            db.commit()

        flash('✅ تم شحن الرصيد عبر Binance Pay بنجاح.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logging.exception("Binance return/query error: %s", e)
        flash('تعذر إكمال التحقق من الدفع.', 'error')
        return redirect(url_for('index'))

# -----------------------------------
# السحب اليدوي (احتفظنا به كما هو)
# -----------------------------------
@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        amount = parse_amount(request.form.get('withdraw_amount'), min_value=1.0)
    except Exception:
        flash('❌ مبلغ غير صالح للسحب', 'error')
        return redirect(url_for('index'))
    currency = (request.form.get('withdraw_currency') or '').upper()
    email = (request.form.get('paypal_email') or '').strip()  # يمكنك لاحقاً تغيير الاسم إلى جهة السحب
    if not email or '@' not in email:
        flash('❌ بريد غير صالح', 'error')
        return redirect(url_for('index'))
    if currency not in SUPPORTED_CURRENCIES:
        flash('❌ عملة غير مدعومة', 'error')
        return redirect(url_for('index'))

    with get_db() as db:
        bal = db.execute("SELECT amount FROM balances WHERE username=? AND currency=?",
                         (session['username'], currency)).fetchone()
        if not bal or bal['amount'] < amount:
            flash('❌ الرصيد غير كافٍ للسحب', 'error')
            return redirect(url_for('index'))
        db.execute("INSERT INTO withdrawals(username, timestamp, amount, currency, email, status) VALUES(?,?,?,?,?, 'pending')",
                   (session['username'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), amount, currency, email))
        db.commit()

    flash('✅ تم إرسال طلب السحب بنجاح. سيُعالج يدويًا.', 'success')
    return redirect(url_for('index'))

# -----------------------------------
# لوحة الإدارة (مختصر: نظرة عامة + سحوبات)
# -----------------------------------
@app.route('/admin/withdrawals', methods=['GET'])
def admin_withdrawals():
    if 'username' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin') and session.get('username') != (os.getenv('ADMIN_USERNAME') or ''):
        flash("غير مصرح.", "error")
        return redirect(url_for('index'))

    with get_db() as db:
        rows = db.execute("SELECT id, username, timestamp, amount, currency, email, status FROM withdrawals ORDER BY id DESC").fetchall()
    return render_template('admin_withdrawals.html', withdrawals=rows)

@app.route('/admin/withdrawals/<int:wid>/approve', methods=['POST'])
def approve_withdrawal(wid):
    if 'username' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin') and session.get('username') != (os.getenv('ADMIN_USERNAME') or ''):
        flash("غير مصرح.", "error")
        return redirect(url_for('index'))

    with get_db() as db:
        w = db.execute("SELECT username, amount, currency, status FROM withdrawals WHERE id=?", (wid,)).fetchone()
        if not w or w["status"] != "pending":
            flash("طلب غير صالح", "error")
            return redirect(url_for('admin_withdrawals'))
        db.execute("UPDATE balances SET amount = amount - ? WHERE username=? AND currency=?",
                   (w["amount"], w["username"], w["currency"]))
        db.execute("UPDATE withdrawals SET status='approved' WHERE id=?", (wid,))
        db.commit()
    flash("✅ تم اعتماد السحب", "success")
    return redirect(url_for('admin_withdrawals'))

@app.route('/admin/withdrawals/<int:wid>/reject', methods=['POST'])
def reject_withdrawal(wid):
    if 'username' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin') and session.get('username') != (os.getenv('ADMIN_USERNAME') or ''):
        flash("غير مصرح.", "error")
        return redirect(url_for('index'))

    with get_db() as db:
        w = db.execute("SELECT id, status FROM withdrawals WHERE id=?", (wid,)).fetchone()
        if not w or w["status"] != "pending":
            flash("طلب غير صالح", "error")
            return redirect(url_for('admin_withdrawals'))
        db.execute("UPDATE withdrawals SET status='rejected' WHERE id=?", (wid,))
        db.commit()
    flash("❌ تم رفض السحب", "success")
    return redirect(url_for('admin_withdrawals'))

@app.route('/admin/overview')
def admin_overview():
    if 'username' not in session:
        return redirect(url_for('login'))
    if not session.get('is_admin') and session.get('username') != (os.getenv('ADMIN_USERNAME') or ''):
        flash("غير مصرح.", "error")
        return redirect(url_for('index'))

    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    PER_PAGE = 50
    offset = (page - 1) * PER_PAGE

    username_f = (request.args.get('username') or '').strip()
    currency_f = (request.args.get('currency') or '').strip().upper()
    start_date = (request.args.get('start_date') or '').strip()
    end_date = (request.args.get('end_date') or '').strip()

    where, params = [], []
    if start_date: where.append("date(timestamp) >= ?"); params.append(start_date)
    if end_date:   where.append("date(timestamp) <= ?"); params.append(end_date)
    if username_f: where.append("username = ?");        params.append(username_f)
    if currency_f: where.append("currency = ?");        params.append(currency_f)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    with get_db() as db:
        users = db.execute("SELECT username, is_admin FROM users ORDER BY username").fetchall()
        balances = db.execute("SELECT username, currency, amount FROM balances ORDER BY username, currency").fetchall()

        total = db.execute(f"SELECT COUNT(*) as c FROM transactions{where_sql}", params).fetchone()["c"]
        total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
        transactions = db.execute(
            f"SELECT username, timestamp, type, amount, currency FROM transactions {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*params, PER_PAGE, offset)
        ).fetchall()

        if username_f:
            totals = db.execute("SELECT currency, SUM(amount) as total FROM balances WHERE username=? GROUP BY currency",
                                (username_f,)).fetchall()
        else:
            totals = db.execute("SELECT currency, SUM(amount) as total FROM balances GROUP BY currency").fetchall()

    prev_page = page - 1 if page > 1 else None
    next_page = page + 1 if page < total_pages else None

    return render_template('admin_overview.html',
                           users=users, balances=balances, transactions=transactions, totals=totals,
                           page=page, total_pages=total_pages, prev_page=prev_page, next_page=next_page,
                           username_f=username_f, currency_f=currency_f, start_date=start_date, end_date=end_date)

@app.route('/about')
def about():
    return "Currency Converter — Flask + SQLite (Binance Pay only)"

# تشغيل
init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
