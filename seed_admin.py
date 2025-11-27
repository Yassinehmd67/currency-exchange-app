import sqlite3
import os

DB_PATH = "data.db"

# العملات التي يجب أن يملكها كل مستخدم
CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR", "EGP"]

def main():
    if not os.path.exists(DB_PATH):
        print("❌ قاعدة البيانات غير موجودة!")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # التأكد من أن جدول المستخدمين موجود
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cur.fetchone():
        print("❌ جدول users غير موجود. شغّل التطبيق لإنشائه أولاً.")
        conn.close()
        return

    # هل يوجد مستخدم admin؟
    cur.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    row = cur.fetchone()

    if row:
        print("ℹ️ المستخدم 'admin' موجود مسبقاً، تم التأكد أنه أدمن.")
        cur.execute("UPDATE users SET is_admin = 1 WHERE username = 'admin'")
        user_id = row["id"]
    else:
        print("👤 إنشاء مستخدم أدمن جديد...")
        cur.execute(
            "INSERT INTO users (username, email, phone, password_hash, is_admin) VALUES (?, ?, ?, ?, 1)",
            ("admin", "admin@example.com", "0000000000", "admin",),
        )
        user_id = cur.lastrowid

    # إنشاء أرصدة العملات
    print("💰 التأكد من وجود أرصدة لكل العملات...")
    for c in CURRENCIES:
        cur.execute(
            "INSERT OR IGNORE INTO balances (user_id, currency, amount) VALUES (?, ?, ?)",
            (user_id, c, 0.0)
        )

    # شحن 1000 USD
    print("💵 شحن 1000 USD لحساب الأدمن...")
    cur.execute(
        "UPDATE balances SET amount = amount + 1000 WHERE user_id = ? AND currency = 'USD'",
        (user_id,)
    )

    conn.commit()
    conn.close()

    print("✅ تمت العملية بنجاح! حساب الأدمن جاهز.")

if __name__ == "__main__":
    main()