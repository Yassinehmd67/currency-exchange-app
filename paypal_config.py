import paypalrestsdk

paypalrestsdk.configure({
    "mode": "sandbox",  # أو "live" للإنتاج لاحقًا
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET"
})
