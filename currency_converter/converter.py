import os
import json
from decimal import Decimal, getcontext
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

# نحمل متغيرات البيئة
load_dotenv()

EXCHANGE_API_KEY = os.getenv("EXCHANGE_API_KEY")

# ملف كاش محلي
RATES_CACHE_FILE = "rates_cache.json"
CACHE_TTL_MINUTES = 10  # مدة صلاحية الكاش بالدقائق

# دقة أكبر للعمليات الداخلية
getcontext().prec = 28

# العملات المدعومة (طابقها مع app.py)
SUPPORTED_CURRENCIES = ["USD", "EUR", "GBP", "MAD", "AED", "SAR", "EGP"]


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


def _fetch_base_usd_rates():
    """
    يجلب أسعار كل العملات مقابل USD من Exchangerate-API.
    يرجع dict مثل:
      {"USD": Decimal("1"), "SAR": Decimal("3.75"), ...}
    """
    if not EXCHANGE_API_KEY:
        raise RuntimeError("EXCHANGE_API_KEY غير موجود في ملف .env")

    # endpoint الرسمي لـ latest/USD في v6
    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_API_KEY}/latest/USD"

    try:
        resp = requests.get(url, timeout=5)
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"فشل الاتصال بمزوِّد الأسعار: {e}")

    if data.get("result") != "success":
        raise RuntimeError(f"خطأ من مزوِّد الأسعار: {data!r}")

    conv = data.get("conversion_rates") or {}
    if "USD" not in conv:
        # نضمن أن USD موجودة كأساس
        conv["USD"] = 1.0

    rates = {}
    for cur in SUPPORTED_CURRENCIES:
        val = conv.get(cur)
        if val is None:
            raise RuntimeError(f"الرد من API لا يحتوي على سعر {cur}")
        rates[cur] = Decimal(str(val))

    return rates


def _get_base_usd_rates():
    """
    دالة تستخدم الكاش:
      - BASE_USD_RATES: { "rates": {...}, "timestamp": "..." }
    """
    cache = _load_cache()
    entry = cache.get("BASE_USD_RATES")

    if entry and _is_cache_valid(entry):
        stored = entry.get("rates") or {}
        return {k: Decimal(str(v)) for k, v in stored.items()}

    # كاش منتهي أو غير موجود → جلب جديد
    rates = _fetch_base_usd_rates()

    cache["BASE_USD_RATES"] = {
        "rates": {k: float(v) for k, v in rates.items()},
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
    }
    _save_cache(cache)

    return rates


def convert_currency(amount: Decimal, from_currency: str, to_currency: str) -> Decimal:
    """
    دالة واجهة بسيطة تستخدمها في app.py:
        from currency_converter.converter import convert_currency

    التحويل يتم عبر عملة أساس واحدة (USD) لمنع أي أربيتراج:
        A -> USD -> B
    بدون أي عمولة إضافية هنا.
    """
    from_currency = (from_currency or "").upper()
    to_currency = (to_currency or "").upper()

    if from_currency == to_currency:
        return amount

    if from_currency not in SUPPORTED_CURRENCIES:
        raise RuntimeError(f"عملة غير مدعومة: {from_currency}")
    if to_currency not in SUPPORTED_CURRENCIES:
        raise RuntimeError(f"عملة غير مدعومة: {to_currency}")

    amt = Decimal(str(amount))

    rates = _get_base_usd_rates()

    rate_from = rates.get(from_currency)
    rate_to = rates.get(to_currency)

    if rate_from is None or rate_to is None:
        raise RuntimeError("لم يتم العثور على السعر لأحد العملتين")

    # مثال: rate["SAR"] = 3.75 يعني 1 USD = 3.75 SAR
    # إذن 1 SAR = 1 / 3.75 USD
    amount_in_usd = amt / rate_from
    converted = amount_in_usd * rate_to

    return converted