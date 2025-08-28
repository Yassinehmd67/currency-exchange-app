# create_admin.py
import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("DB_PATH", "data.db")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin12345")
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL", "")
INITIAL_USD    = float(os.environ.get("ADMIN_INITIAL_USD", "2000"))

SUPPORTED_CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR"]

def create_admin():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    # تأكد من وجود جدول users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)

    # تأكد من وجود جدول balances
    cur.execute("""
        CREATE TABLE IF NOT EXISTS balances (
            username TEXT,
            currency TEXT,
            amount REAL DEFAULT 0,
            PRIMARY KEY (username, currency)
        )
    """)

    # إنشاء/تحديث حساب الأدمن
    password_hash = generate_password_hash(ADMIN_PASSWORD)
    cur.execute("""
        INSERT OR REPLACE INTO users (username, password_hash, email, is_admin)
        VALUES (?, ?, ?, 1)
    """, (ADMIN_USERNAME, password_hash, ADMIN_EMAIL))

    # تجهيز جميع الأرصدة للمستخدم
    for cur_code in SUPPORTED_CURRENCIES:
        cur.execute("""
            INSERT OR IGNORE INTO balances (username, currency, amount)
            VALUES (?, ?, 0.0)
        """, (ADMIN_USERNAME, cur_code))

    # شحن رصيد USD
    cur.execute("""
        UPDATE balances
        SET amount = ?
        WHERE username = ? AND currency = 'USD'
    """, (INITIAL_USD, ADMIN_USERNAME))

    con.commit()
    con.close()

    print(f"[✓] Admin user '{ADMIN_USERNAME}' جاهز بكلمة مرور '{ADMIN_PASSWORD}'.")
    print(f"[✓] رصيد USD = {INITIAL_USD:.2f} تمت إضافته.")

if __name__ == "__main__":
    create_admin()
