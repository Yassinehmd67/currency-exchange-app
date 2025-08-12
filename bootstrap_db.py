# bootstrap_db.py
# يهيّئ data.db (ينشئ الجداول) ويضيف/يحدّث حساب الأدمن admin/admin12345

import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = "data.db"
ADMIN_USERNAME = "admin"        # غيّره إن أردت
ADMIN_PASSWORD = "admin12345"   # غيّرها إن أردت
SUPPORTED_CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR"]

schema = """
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
"""

def main():
    db = sqlite3.connect(DB_PATH)
    db.executescript(schema)

    # هل يوجد مستخدم بنفس الاسم؟
    cur = db.execute("SELECT username FROM users WHERE username=?", (ADMIN_USERNAME,))
    exists = cur.fetchone() is not None

    if exists:
        # تحديث كلمة المرور وتأكيد أنه أدمن
        db.execute("UPDATE users SET password_hash=?, is_admin=1 WHERE username=?",
                   (generate_password_hash(ADMIN_PASSWORD), ADMIN_USERNAME))
        print(f"[+] تم تحديث كلمة مرور الأدمن '{ADMIN_USERNAME}' وتأكيد صلاحياته.")
    else:
        # إنشاء المستخدم كأدمن
        db.execute("INSERT INTO users(username, password_hash, email, is_admin) VALUES(?,?,?,1)",
                   (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD), None))
        print(f"[+] تم إنشاء حساب الأدمن '{ADMIN_USERNAME}'.")

    # إنشاء أرصدة العملات له إن لم تكن موجودة
    for cur in SUPPORTED_CURRENCIES:
        db.execute("INSERT OR IGNORE INTO balances(username, currency, amount) VALUES(?,?,0)", (ADMIN_USERNAME, cur))

    db.commit()
    db.close()
    print("[✓] القاعدة مهيأة وجاهزة.")

if __name__ == "__main__":
    main()
