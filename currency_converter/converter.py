import os
import json
from decimal import Decimal
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

# نحمل متغيرات البيئة (حتى لو استدعينا الملف مباشرة)
load_dotenv()

EXCHANGE_API_KEY = os.getenv("EXCHANGE_API_KEY")

# ملف كاش محلي (اختياري – يمكنك تغييره أو حذفه)
RATES_CACHE_FILE = "rates_cache.json"
CACHE_TTL_MINUTES = 10  # مدة صلاحية الكاش بالدقائق


def _load_cache():
    """قراءة الكاش من ملف JSON إن وُجد وإلا يرجع dict فارغ."""
    if not os.path.exists(RATES_CACHE_FILE):
        return {}

    try:
        with open(RATES_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data or {}
    except Exception:
        return {}


def _save_cache(cache):
    """حفظ الكاش في ملف JSON."""
    try:
        with open(RATES_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        # لو حصل خطأ في التخزين لا نوقف البرنامج
        pass


def _is_cache_valid(entry):
    """يتأكد أن بيانات الكاش ما زالت ضمن مدة الـ TTL."""
    ts_str = entry.get("timestamp")
    if not ts_str:
        return False

    try:
        ts = datetime.fromisoformat(ts_str)
    except Exception:
        return False

    return datetime.utcnow() - ts < timedelta(minutes=CACHE_TTL_MINUTES)


def get_live_rate(from_currency: str, to_currency: str, amount: Decimal) -> Decimal:
    """
    جلب المبلغ المحوَّل باستخدام Exchangerate-API.
    يرجع قيمة المبلغ المحوَّل (وليس الـ rate فقط) من API مباشرة.
    يرفع RuntimeError في حالة وجود مشكلة.
    """
    if not EXCHANGE_API_KEY:
        raise RuntimeError("EXCHANGE_API_KEY غير موجود في ملف .env")

    # نستخدم الكاش حسب (from,to,amount) إذا أحببت يمكن أن يكون حسب (from,to) فقط
    cache_key = f"{from_currency}_{to_currency}_{amount}"
    cache = _load_cache()
    entry = cache.get(cache_key)

    if entry and _is_cache_valid(entry):
        # نعيد القيمة من الكاش
        return Decimal(str(entry["converted"]))

    url = (
        f"https://v6.exchangerate-api.com/v6/"
        f"{EXCHANGE_API_KEY}/pair/{from_currency}/{to_currency}/{amount}"
    )

    try:
        resp = requests.get(url, timeout=5)
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"فشل الاتصال بمزوِّد الأسعار: {e}")

    if data.get("result") != "success":
        raise RuntimeError(f"خطأ من مزوِّد الأسعار: {data!r}")

    converted = data.get("conversion_result")
    if converted is None:
        raise RuntimeError("الرد من API لا يحتوي على conversion_result")

    converted_dec = Decimal(str(converted))

    # نخزن في الكاش
    cache[cache_key] = {
        "converted": str(converted_dec),
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
    }
    _save_cache(cache)

    return converted_dec


def convert_currency(amount: Decimal, from_currency: str, to_currency: str) -> Decimal:
    """
    دالة واجهة بسيطة تستخدمها في app.py:
        from currency_converter.converter import convert_currency

    ترجع المبلغ المحوَّل باستخدام السعر الحقيقي.
    """
    if from_currency == to_currency:
        return amount

    return get_live_rate(from_currency, to_currency, amount)