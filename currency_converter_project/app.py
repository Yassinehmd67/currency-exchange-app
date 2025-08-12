import os
import json
import logging
from datetime import datetime
from decimal import Decimal, ROUND_DOWN
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from currency_converter.converter import convert_currency
from paypal_config import create_order, capture_order, send_payout

# تحميل القيم من ملف .env
load_dotenv()

# إعداد التطبيق
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change_me")
csrf = CSRFProtect(app)

# تسجيل الأخطاء في ملف
logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ملفات البيانات
USERS_FILE = "users.json"

# القيم الثابتة
CURRENCIES = ["USD", "EUR", "SAR", "EGP", "GBP", "AED"]
CURRENCY_TO_COUNTRY = {
    "USD": "us", "EUR": "eu", "SAR": "sa", "EGP": "eg", "GBP": "gb", "AED": "ae"
}

# ==============================
# دوال مساعدة
# ==============================
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

def get_user(username):
    users = load_users()
    return users.get(username)

def update_user(username, data):
    users = load_users()
    users[username] = data
    save_users(users)

def log_transaction(user, tx_type, amount, currency, details=""):
    user["transactions"].append({
        "type": tx_type,
        "amount": float(amount),
        "currency": currency,
        "details": details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# ==============================
# المسارات
# ==============================
@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    user = get_user(session["username"])
    return render_template("index.html",
                           username=session["username"],
                           user=user,
                           currencies=CURRENCIES,
                           currency_to_country=CURRENCY_TO_COUNTRY,
                           paypal_client_id=os.getenv("PAYPAL_CLIENT_ID"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = get_user(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return redirect(url_for("index"))
        flash("❌ اسم المستخدم أو كلمة المرور غير صحيحة", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if get_user(username):
            flash("❌ اسم المستخدم موجود بالفعل", "error")
        else:
            hashed_pw = generate_password_hash(password)
            users = load_users()
            users[username] = {"password": hashed_pw, "balance": {c: 0.0 for c in CURRENCIES}, "transactions": []}
            save_users(users)
            flash("✅ تم إنشاء الحساب بنجاح", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/paypal_capture", methods=["POST"])
def paypal_capture():
    data = request.get_json()
    amount = Decimal(data.get("amount", "0"))
    currency = data.get("currency", "USD")
    order_id = data.get("orderID")

    if amount <= 0 or currency not in CURRENCIES:
        return jsonify({"success": False, "error": "Invalid payment data"})

    if not order_id:
        return jsonify({"success": False, "error": "Missing order ID"})

    try:
        capture_result = capture_order(order_id)
        if capture_result.get("status") == "COMPLETED":
            username = session.get("username")
            user = get_user(username)
            user["balance"][currency] += float(amount)
            log_transaction(user, "Deposit", amount, currency)
            update_user(username, user)
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Payment not completed"})
    except Exception as e:
        logging.error(f"PayPal capture error: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route("/paypal_payout", methods=["POST"])
def paypal_payout():
    amount = Decimal(request.form.get("paypal_withdraw_amount", "0"))
    currency = request.form.get("paypal_withdraw_currency")
    email = request.form.get("paypal_email")

    if amount <= 0 or currency not in CURRENCIES:
        flash("❌ بيانات السحب غير صحيحة", "error")
        return redirect(url_for("index"))

    username = session.get("username")
    user = get_user(username)

    if user["balance"][currency] < float(amount):
        flash("❌ الرصيد غير كافٍ", "error")
        return redirect(url_for("index"))

    try:
        payout_result = send_payout(email, amount, currency)
        if payout_result:
            user["balance"][currency] -= float(amount)
            log_transaction(user, "Withdraw", amount, currency, details=f"Payout to {email}")
            update_user(username, user)
            flash("✅ تم إرسال طلب السحب", "success")
        else:
            flash("❌ فشل في إرسال السحب", "error")
    except Exception as e:
        logging.error(f"PayPal payout error: {e}")
        flash("❌ خطأ أثناء معالجة السحب", "error")

    return redirect(url_for("index"))

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
    except:
        return jsonify({"success": False, "message": "المبلغ غير صالح"}), 400

    username = session["username"]
    user = get_user(username)

    if user["balance"][from_currency] < float(amount):
        return jsonify({"success": False, "message": f"الرصيد غير كافٍ في {from_currency}"}), 400

    try:
        converted_amount = convert_currency(amount, from_currency, to_currency)
        converted_amount = Decimal(converted_amount).quantize(Decimal('.01'), rounding=ROUND_DOWN)

        # تحديث الأرصدة
        user["balance"][from_currency] -= float(amount)
        user["balance"][to_currency] += float(converted_amount)

        details = f"Convert {amount} {from_currency} to {converted_amount} {to_currency}"
        log_transaction(user, "Currency Conversion", amount, from_currency, details=details)
        log_transaction(user, "Currency Conversion", converted_amount, to_currency, details=details)

        update_user(username, user)

        return jsonify({
            "success": True,
            "converted_amount": f"{converted_amount}",
            "rate": f"{(converted_amount / amount):.4f}"
        })
    except Exception as e:
        logging.error(f"Currency conversion error: {e}")
        return jsonify({"success": False, "message": "خطأ أثناء تحويل العملات"}), 500

@app.route("/toggle_language")
def toggle_language():
    current_lang = session.get("lang", "ar")
    session["lang"] = "en" if current_lang == "ar" else "ar"
    return redirect(request.referrer or url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ==============================
# تشغيل التطبيق
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
