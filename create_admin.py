import os
import sqlite3
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# تحميل متغيرات البيئة من .env
load_dotenv()

DB_PATH = os.getenv("DB_PATH", "data.db")

ADMIN_USERNAME = "admin"          # عدّل اسم الأدمن إذا رغبت
ADMIN_PASSWORD = "admin12345"     # عدّل كلمة المرور إذا رغبت
ADMIN_EMAIL    = "admin@example.com"

# نفس قائمة العملات في app.py
CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR", "EGP"]


def main():
    print(f"[i] استخدام قاعدة البيانات: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # إنشاء الجداول الأساسية إذا لم تكن موجودة (متوافقة مع الكود الحالي تقريبًا)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            currency TEXT,
            amount REAL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # هل يوجد مستخدم بنفس الاسم؟
    cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
    row = cur.fetchone()

    password_hash = generate_password_hash(ADMIN_PASSWORD)

    if row:
        user_id = row["id"]
        cur.execute(
            "UPDATE users SET password_hash = ?, email = ?, is_admin = 1 WHERE id = ?",
            (password_hash, ADMIN_EMAIL, user_id),
        )
        print(f"[+] تم تحديث حساب الأدمن '{ADMIN_USERNAME}' وكلمة مروره.")
    else:
        cur.execute(
            "INSERT INTO users (username, password_hash, email, is_admin) VALUES (?,?,?,1)",
            (ADMIN_USERNAME, password_hash, ADMIN_EMAIL),
        )
        user_id = cur.lastrowid
        print(f"[+] تم إنشاء حساب الأدمن '{ADMIN_USERNAME}'.")

    # تجهيز أرصدة كل العملات = 0
    for cur_code in CURRENCIES:
        cur.execute(
            """
            INSERT OR IGNORE INTO balances (user_id, currency, amount)
            VALUES (?,?,0)
            """,
            (user_id, cur_code),
        )

    # شحن 1000 دولار
    cur.execute(
        """
        UPDATE balances
        SET amount = 1000
        WHERE user_id = ? AND currency = 'USD'
        """,
        (user_id,),
    )

    conn.commit()
    conn.close()

    print("[✓] تم تجهيز الأدمن برصيد 1000 USD.")
    print(f"[i] يمكنك الدخول الآن بالبيانات:\n    username = {ADMIN_USERNAME}\n    password = {ADMIN_PASSWORD}")


if __name__ == "__main__":
    main()