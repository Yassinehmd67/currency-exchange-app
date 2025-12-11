# seed_admin_neon.py
import os
import psycopg2
from werkzeug.security import generate_password_hash

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise SystemExit("❌ DATABASE_URL missing")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin123!")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")

CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR", "EGP"]

def main():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # تأكد أن المستخدم موجود / أنشئه
    cur.execute("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))
    row = cur.fetchone()

    if row:
        admin_id = row[0]
        cur.execute(
            "UPDATE users SET password_hash=%s, email=%s, is_admin=TRUE WHERE id=%s",
            (generate_password_hash(ADMIN_PASSWORD), ADMIN_EMAIL, admin_id),
        )
        print(f"[+] Updated admin: {ADMIN_USERNAME}")
    else:
        cur.execute(
            """
            INSERT INTO users (username, email, phone, password_hash, is_admin)
            VALUES (%s,%s,%s,%s,TRUE)
            RETURNING id
            """,
            (ADMIN_USERNAME, ADMIN_EMAIL, "", generate_password_hash(ADMIN_PASSWORD)),
        )
        admin_id = cur.fetchone()[0]
        print(f"[+] Created admin: {ADMIN_USERNAME}")

    # أرصدة العملات
    for c in CURRENCIES:
        cur.execute(
            """
            INSERT INTO balances (user_id, currency, amount)
            VALUES (%s,%s,0)
            ON CONFLICT (user_id, currency) DO NOTHING
            """,
            (admin_id, c),
        )

    # اشحن 1000 USD (مرة واحدة/أو إذا تحب دائمًا)
    cur.execute(
        "UPDATE balances SET amount = amount + 1000 WHERE user_id=%s AND currency='USD'",
        (admin_id,),
    )

    conn.commit()
    conn.close()

    print("[✓] Admin ready on Neon with +1000 USD")
    print(f"[i] login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")

if __name__ == "__main__":
    main()