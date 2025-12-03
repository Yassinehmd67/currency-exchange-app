import os
import sqlite3
import psycopg2
from psycopg2.extras import execute_values

SQLITE_PATH = os.getenv("SQLITE_PATH", "data.db")  # غيّرها إذا اسم ملفك مختلف
DATABASE_URL = os.getenv("DATABASE_URL")           # Neon connection string

if not DATABASE_URL:
    raise SystemExit("❌ DATABASE_URL is missing in .env")

def fetch_all_sqlite(conn, query, params=()):
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    return rows

def migrate_users(sqlite_conn, pg_conn):
    rows = fetch_all_sqlite(sqlite_conn, """
        SELECT id, username, email, phone, password_hash, is_admin, created_at
        FROM users
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ users: no rows")
        return

    with pg_conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO users (id, username, email, phone, password_hash, is_admin, created_at)
            VALUES %s
            ON CONFLICT (id) DO NOTHING
        """, rows)
    pg_conn.commit()
    print(f"✅ users migrated: {len(rows)}")

def migrate_balances(sqlite_conn, pg_conn):
    rows = fetch_all_sqlite(sqlite_conn, """
        SELECT id, user_id, currency, amount
        FROM balances
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ balances: no rows")
        return

    with pg_conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO balances (id, user_id, currency, amount)
            VALUES %s
            ON CONFLICT (id) DO NOTHING
        """, rows)
    pg_conn.commit()
    print(f"✅ balances migrated: {len(rows)}")

def migrate_transactions(sqlite_conn, pg_conn):
    rows = fetch_all_sqlite(sqlite_conn, """
        SELECT id, user_id, type, amount, currency, details, timestamp
        FROM transactions
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ transactions: no rows")
        return

    with pg_conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO transactions (id, user_id, type, amount, currency, details, timestamp)
            VALUES %s
            ON CONFLICT (id) DO NOTHING
        """, rows)
    pg_conn.commit()
    print(f"✅ transactions migrated: {len(rows)}")

def migrate_pending_deposits(sqlite_conn, pg_conn):
    rows = fetch_all_sqlite(sqlite_conn, """
        SELECT id, user_id, amount, fiat_currency, pay_method, status, txid, timestamp, processed_by, processed_at
        FROM pending_deposits
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ pending_deposits: no rows")
        return

    with pg_conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO pending_deposits
            (id, user_id, amount, fiat_currency, pay_method, status, txid, timestamp, processed_by, processed_at)
            VALUES %s
            ON CONFLICT (id) DO NOTHING
        """, rows)
    pg_conn.commit()
    print(f"✅ pending_deposits migrated: {len(rows)}")

def migrate_pending_withdrawals(sqlite_conn, pg_conn):
    rows = fetch_all_sqlite(sqlite_conn, """
        SELECT id, user_id, amount, currency, payout_info, status, timestamp, processed_by, processed_at
        FROM pending_withdrawals
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ pending_withdrawals: no rows")
        return

    with pg_conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO pending_withdrawals
            (id, user_id, amount, currency, payout_info, status, timestamp, processed_by, processed_at)
            VALUES %s
            ON CONFLICT (id) DO NOTHING
        """, rows)
    pg_conn.commit()
    print(f"✅ pending_withdrawals migrated: {len(rows)}")

def migrate_notifications(sqlite_conn, pg_conn):
    rows = fetch_all_sqlite(sqlite_conn, """
        SELECT id, user_id, title, body, type, is_read, created_at, ref_type, ref_id
        FROM notifications
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ notifications: no rows")
        return

    # SQLite is_read قد يكون 0/1 -> في Postgres BOOLEAN
    fixed = []
    for r in rows:
        r = list(r)
        r[5] = bool(r[5])  # is_read
        fixed.append(tuple(r))

    with pg_conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO notifications
            (id, user_id, title, body, type, is_read, created_at, ref_type, ref_id)
            VALUES %s
            ON CONFLICT (id) DO NOTHING
        """, fixed)
    pg_conn.commit()
    print(f"✅ notifications migrated: {len(rows)}")

def migrate_telegram_users(sqlite_conn, pg_conn):
    # إذا جدول SQLite ما فيه أعمدة referral_credits_usd... عادي، نعطيهم 0
    # نحاول نقرأ الأعمدة الموجودة
    cur = sqlite_conn.cursor()
    cur.execute("PRAGMA table_info(telegram_users)")
    cols = [row[1] for row in cur.fetchall()]
    cur.close()

    base_cols = ["id", "telegram_id", "username", "first_name", "last_name", "referred_by_telegram_id", "created_at"]
    has_ref = "referral_credits_usd" in cols
    has_botbal = "bot_balance_usd" in cols

    select_cols = base_cols[:]
    if has_ref: select_cols.insert(-1, "referral_credits_usd")
    if has_botbal: select_cols.insert(-1, "bot_balance_usd")

    rows = fetch_all_sqlite(sqlite_conn, f"""
        SELECT {", ".join(select_cols)}
        FROM telegram_users
        ORDER BY id
    """)
    if not rows:
        print("ℹ️ telegram_users: no rows")
        return

    # جهّز الإدخال حسب أعمدة Postgres
    with pg_conn.cursor() as pg_cur:
        if has_ref and has_botbal:
            execute_values(pg_cur, """
                INSERT INTO telegram_users
                (id, telegram_id, username, first_name, last_name, referred_by_telegram_id, referral_credits_usd, bot_balance_usd, created_at)
                VALUES %s
                ON CONFLICT (id) DO NOTHING
            """, rows)
        elif has_ref and not has_botbal:
            fixed = []
            for r in rows:
                r = list(r)
                # أضف bot_balance_usd=0 قبل created_at
                r.insert(-1, 0)
                fixed.append(tuple(r))
            execute_values(pg_cur, """
                INSERT INTO telegram_users
                (id, telegram_id, username, first_name, last_name, referred_by_telegram_id, referral_credits_usd, bot_balance_usd, created_at)
                VALUES %s
                ON CONFLICT (id) DO NOTHING
            """, fixed)
        else:
            fixed = []
            for r in rows:
                r = list(r)
                # أضف referral_credits_usd=0 و bot_balance_usd=0 قبل created_at
                r.insert(-1, 0)
                r.insert(-1, 0)
                fixed.append(tuple(r))
            execute_values(pg_cur, """
                INSERT INTO telegram_users
                (id, telegram_id, username, first_name, last_name, referred_by_telegram_id, referral_credits_usd, bot_balance_usd, created_at)
                VALUES %s
                ON CONFLICT (id) DO NOTHING
            """, fixed)

    pg_conn.commit()
    print(f"✅ telegram_users migrated: {len(rows)}")

def fix_sequences(pg_conn):
    # بعد إدخال IDs يدويًا، نعيد ضبط SEQUENCE حتى لا يحدث تعارض في INSERT لاحقًا
    with pg_conn.cursor() as cur:
        cur.execute("SELECT setval(pg_get_serial_sequence('users','id'), COALESCE((SELECT MAX(id) FROM users), 1));")
        cur.execute("SELECT setval(pg_get_serial_sequence('balances','id'), COALESCE((SELECT MAX(id) FROM balances), 1));")
        cur.execute("SELECT setval(pg_get_serial_sequence('transactions','id'), COALESCE((SELECT MAX(id) FROM transactions), 1));")
        cur.execute("SELECT setval(pg_get_serial_sequence('pending_deposits','id'), COALESCE((SELECT MAX(id) FROM pending_deposits), 1));")
        cur.execute("SELECT setval(pg_get_serial_sequence('pending_withdrawals','id'), COALESCE((SELECT MAX(id) FROM pending_withdrawals), 1));")
        cur.execute("SELECT setval(pg_get_serial_sequence('notifications','id'), COALESCE((SELECT MAX(id) FROM notifications), 1));")
        cur.execute("SELECT setval(pg_get_serial_sequence('telegram_users','id'), COALESCE((SELECT MAX(id) FROM telegram_users), 1));")
    pg_conn.commit()
    print("✅ sequences fixed")

def main():
    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    pg_conn = psycopg2.connect(DATABASE_URL)

    try:
        migrate_users(sqlite_conn, pg_conn)
        migrate_balances(sqlite_conn, pg_conn)
        migrate_transactions(sqlite_conn, pg_conn)
        migrate_pending_deposits(sqlite_conn, pg_conn)
        migrate_pending_withdrawals(sqlite_conn, pg_conn)
        migrate_notifications(sqlite_conn, pg_conn)
        migrate_telegram_users(sqlite_conn, pg_conn)
        fix_sequences(pg_conn)
        print("🎉 Migration completed.")
    finally:
        sqlite_conn.close()
        pg_conn.close()

if __name__ == "__main__":
    main()