# api_handler.py
# مسؤول عن جلب أسعار الصرف من Exchangerate API مع كاش موحّد
# واستخدام USD كعملة أساس لحساب جميع التحويلات.

import os
import json
from decimal import Decimal, InvalidOperation
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

# تحميل متغيرات البيئة
load_dotenv()

EXCHANGE_API_KEY = os.getenv("EXCHANGE_API_KEY")

# نستخدم USD كعملة أساس موحّدة لكل الحسابات
BASE_CURRENCY = "USD"

# ملف الكاش
RATES_CACHE_FILE = "rates_cache.json"
CACHE_TTL_MINUTES = 10  # مدة صلاحية الكاش بالدقائق


def _load_cache() -> dict:
    """قراءة الكاش من ملف JSON إن وجد."""
    if not os.path.exists(RATES_CACHE_FILE):
        return {}

    try:
        with open(RATES_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data or {}
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    """حفظ الكاش في ملف JSON."""
    try:
        with open(RATES_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        # لا نكسر التطبيق إذا فشل الحفظ
        pass


def _is_rates_cache_valid(entry: dict) -> bool:
    """
    يتحقق أن جدول الأسعار ما زال صالحاً ضمن مدة TTL.
    نتوقع شكل:
    {
      "base": "USD",
      "timestamp": "2025-12-10T12:34:56",
      "rates": { "EUR": 0.92, "SAR": 3.75, ... }
    }
    """
    ts_str = entry.get("timestamp")
    if not ts_str:
        return False

    try:
        ts = datetime.fromisoformat(ts_str)
    except Exception:
        return False

    return datetime.utcnow() - ts < timedelta(minutes=CACHE_TTL_MINUTES)


def _fetch_latest_rates() -> dict:
    """
    جلب آخر جدول أسعار من Exchangerate API بالنسبة لـ BASE_CURRENCY.
    يرجع dict بالشكل:
      {
        "base": "USD",
        "timestamp": "...",
        "rates": { "EUR": 0.92, "SAR": 3.75, ... }
      }
    يرفع RuntimeError عند الفشل.
    """
    if not EXCHANGE_API_KEY:
        raise RuntimeError("EXCHANGE_API_KEY غير موجود في ملف .env")

    url = (
        f"https://v6.exchangerate-api.com/v6/"
        f"{EXCHANGE_API_KEY}/latest/{BASE_CURRENCY}"
    )

    try:
        resp = requests.get(url, timeout=8)
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"فشل الاتصال بمزوّد الأسعار: {e}")

    if data.get("result") != "success":
        raise RuntimeError(f"خطأ من مزوّد الأسعار: {data!r}")

    rates = data.get("conversion_rates")
    if not isinstance(rates, dict):
        raise RuntimeError("الرد من API لا يحتوي على conversion_rates بشكل صحيح")

    entry = {
        "base": BASE_CURRENCY,
        "timestamp": datetime.utcnow().isoformat(timespec="seconds"),
        "rates": rates,
    }
    return entry


def get_rates() -> dict:
    """
    الحصول على جدول أسعار صالح من الكاش أو من الـ API.
    يرجع dict بالشكل:
      { "EUR": 0.92, "SAR": 3.75, ... }
    """
    cache = _load_cache()

    entry = cache.get("latest_rates")
    if entry and _is_rates_cache_valid(entry) and entry.get("base") == BASE_CURRENCY:
        return entry["rates"]

    # إن لم يكن الكاش صالحاً، جلب جديد
    entry = _fetch_latest_rates()
    cache["latest_rates"] = entry
    _save_cache(cache)
    return entry["rates"]


def get_effective_rate(from_currency: str, to_currency: str) -> Decimal:
    """
    يعيد معدل التحويل الفعلي بين عملتين باستخدام BASE_CURRENCY كوسيط:
      rate(from→to) = (1 from → BASE → to)
    """
    from_currency = (from_currency or "").upper()
    to_currency = (to_currency or "").upper()

    if from_currency == to_currency:
        return Decimal("1")

    rates = get_rates()

    if from_currency != BASE_CURRENCY and from_currency not in rates:
        raise RuntimeError(f"العملة {from_currency} غير موجودة في جدول الأسعار")
    if to_currency != BASE_CURRENCY and to_currency not in rates:
        raise RuntimeError(f"العملة {to_currency} غير موجودة في جدول الأسعار")

    # 1) نحول 1 من العملة المصدر إلى العملة الأساس
    if from_currency == BASE_CURRENCY:
        amount_in_base = Decimal("1")
    else:
        r_from = Decimal(str(rates[from_currency]))
        if r_from == 0:
            raise RuntimeError(f"معدل {from_currency}->{BASE_CURRENCY} يساوي 0 وهو غير منطقي")
        # لأن الجدول يعطي: 1 BASE = r_from FROM
        # إذن 1 FROM = 1/r_from BASE
        amount_in_base = Decimal("1") / r_from

    # 2) نحول من BASE إلى العملة الهدف
    if to_currency == BASE_CURRENCY:
        amount_to = amount_in_base
    else:
        r_to = Decimal(str(rates[to_currency]))
        # 1 BASE = r_to TO
        amount_to = amount_in_base * r_to

    return amount_to


def convert_currency(amount: Decimal, from_currency: str, to_currency: str) -> Decimal:
    """
    تحويل مبلغ معين بين عملتين باستخدام جدول أسعار واحد:
      amount(from) → BASE → to

    مثال الاستخدام في app.py:
        from api_handler import convert_currency

        converted = convert_currency(Decimal("100"), "USD", "SAR")
    """
    try:
        amount = Decimal(str(amount))
    except (InvalidOperation, TypeError):
        raise RuntimeError("قيمة المبلغ غير صالحة للتحويل.")

    if amount == 0 or from_currency == to_currency:
        return amount

    rate = get_effective_rate(from_currency, to_currency)
    converted = (amount * rate)

    # لا نعمل quantize هنا؛ نخلي app.py يحدد الدقة المناسبة
    return converted