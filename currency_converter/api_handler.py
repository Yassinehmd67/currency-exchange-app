import requests
import os
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET')
MODE = os.getenv('PAYPAL_MODE', 'sandbox')

BASE_URL = "https://api-m.sandbox.paypal.com" if MODE == 'sandbox' else "https://api-m.paypal.com"

def get_access_token():
    auth = (CLIENT_ID, CLIENT_SECRET)
    headers = {'Accept': 'application/json', 'Accept-Language': 'en_US'}
    data = {'grant_type': 'client_credentials'}

    response = requests.post(f"{BASE_URL}/v1/oauth2/token", headers=headers, data=data, auth=auth)
    return response.json().get('access_token')

def capture_paypal_order(order_id):
    token = get_access_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    url = f"{BASE_URL}/v2/checkout/orders/{order_id}/capture"
    response = requests.post(url, headers=headers)
    return {'success': response.status_code == 201}

def process_paypal_payout(email, amount, currency):
    token = get_access_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    data = {
        "sender_batch_header": {
            "sender_batch_id": f"batch_{email}",
            "email_subject": "You have a payout!",
            "email_message": "You have received a payout via PayPal."
        },
        "items": [{
            "recipient_type": "EMAIL",
            "amount": {
                "value": f"{amount:.2f}",
                "currency": currency
            },
            "receiver": email,
            "note": "Thank you.",
            "sender_item_id": "item_1"
        }]
    }

    response = requests.post(f"{BASE_URL}/v1/payments/payouts", json=data, headers=headers)
    return response.status_code in [200, 201]
