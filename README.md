# 💱 Currency Exchange App — Flask + SQLite + Binance Pay

تطبيق ويب لتحويل العملات وإدارة الحسابات، مع إمكانية شحن الرصيد عبر **Binance Pay** (يدعم USDT و BTC)، تم تطويره باستخدام **Flask** و **SQLite**.

---

## 🚀 المزايا

- 🧾 تسجيل الدخول وإنشاء حسابات للمستخدمين
- 💰 عرض الأرصدة بكل العملات المدعومة
- 🔄 تحويل العملات بأسعار صرف حية عبر API
- 📥 شحن الرصيد بـ USDT أو BTC عبر Binance Pay
- 📜 تتبع المعاملات السابقة
- 🛡️ لوحة إدارة للتحكم بطلبات السحب
- 📧 إرسال إشعار بالبريد الإلكتروني عند طلب السحب

---

## 📦 المتطلبات

- Python **3.10+**
- حساب **Binance Pay** للحصول على API Key و Secret
- مفتاح API من خدمة أسعار الصرف (Exchange API)
- حساب بريد إلكتروني مخصص لإرسال الإشعارات

---

## ⚙️ الإعداد المحلي

### 1. استنساخ المشروع
```bash
git clone https://github.com/YOUR_USERNAME/currency-exchange-app.git
cd currency-exchange-app
```

### 2. إنشاء بيئة عمل افتراضية وتفعيلها
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / Mac
source venv/bin/activate
```

### 3. تثبيت المتطلبات
```bash
pip install -r requirements.txt
```

### 4. إعداد ملف البيئة
- أنشئ ملف `.env` من المثال `.env.example`:
```bash
copy .env.example .env  # Windows
cp .env.example .env    # Linux/Mac
```
- عدّل القيم داخله لإضافة مفاتيح Binance Pay و API الخاص بأسعار الصرف ومعلومات البريد.

### 5. تهيئة قاعدة البيانات
```bash
python bootstrap_db.py
```

### 6. تشغيل الخادم
```bash
flask run
```
أو:
```bash
python app.py
```

---

## 📂 بنية المشروع

```
currency-exchange-app/
│── app.py                 # نقطة تشغيل التطبيق
│── bootstrap_db.py        # سكريبت تهيئة قاعدة البيانات
│── requirements.txt       # المتطلبات
│── .env.example           # مثال على ملف البيئة
│── templates/             # ملفات HTML
│── static/                # ملفات CSS و JS
│── data.db                # قاعدة البيانات (تُنشأ تلقائيًا)
│── logs/                  # سجلات الأخطاء
```

---

## 🔒 ملاحظات أمنية

- لا ترفع ملف `.env` إلى GitHub أبدًا، بل فقط `.env.example` بدون البيانات الحساسة.
- لا تشارك مفاتيح API أو كلمات المرور مع أي شخص.
- في الإنتاج، استخدم HTTPS.

---

## 📜 الترخيص

هذا المشروع مفتوح المصدر ويُستخدم لأغراض تعليمية. يمكنك التعديل عليه بما يتوافق مع احتياجاتك.
