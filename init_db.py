import sqlite3
import logging

DB_PATH = "data.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # ================ جدول المستخدمين ================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        is_admin INTEGER DEFAULT 0
    )
    """)

    # ================ جدول الأرصدة ================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS balances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        currency TEXT,
        amount REAL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # يمكنك لاحقًا إضافة UNIQUE(user_id, currency) عند الحاجة
    # لكن الأفضل الآن نتركها كما هي لتجنّب مشاكل مع بيانات سابقة.

    # ================ جدول المعاملات ================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        amount REAL,
        currency TEXT,
        details TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # ================ جدول السحوبات ================
    cur.execute("""
    CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount REAL,
        currency TEXT,
        email TEXT,
        status TEXT DEFAULT 'pending',
        bank_info TEXT,
        payout_ref TEXT,
        processed_by TEXT,
        processed_at DATETIME,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # لو عندك قاعدة قديمة، نحاول نضيف الأعمدة الناقصة بلطف
    try:
        cols = cur.execute("PRAGMA table_info(withdrawals)").fetchall()
        colnames = {c["name"] for c in cols}

        if "bank_info" not in colnames:
            cur.execute("ALTER TABLE withdrawals ADD COLUMN bank_info TEXT")
            print("ℹ️ تم إضافة العمود bank_info إلى جدول withdrawals.")

        if "payout_ref" not in colnames:
            cur.execute("ALTER TABLE withdrawals ADD COLUMN payout_ref TEXT")
            print("ℹ️ تم إضافة العمود payout_ref إلى جدول withdrawals.")

        if "processed_by" not in colnames:
            cur.execute("ALTER TABLE withdrawals ADD COLUMN processed_by TEXT")
            print("ℹ️ تم إضافة العمود processed_by إلى جدول withdrawals.")

        if "processed_at" not in colnames:
            cur.execute("ALTER TABLE withdrawals ADD COLUMN processed_at DATETIME")
            print("ℹ️ تم إضافة العمود processed_at إلى جدول withdrawals.")

    except Exception as e:
        logging.warning("ALTER TABLE on withdrawals failed: %s", e)

    conn.commit()
    conn.close()
    print("✅ قاعدة البيانات أنشئت/تحدّثت بنجاح!")


if __name__ == "__main__":
    init_db()