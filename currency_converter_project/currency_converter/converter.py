import requests

def convert_currency(amount, from_currency, to_currency):
    if from_currency == to_currency:
        return amount

    try:
        url = f"https://api.exchangerate.host/convert?from={from_currency}&to={to_currency}&amount={amount}"
        response = requests.get(url)
        result = response.json()
        return float(result.get("result", amount))
    except Exception:
        return amount  # fallback
