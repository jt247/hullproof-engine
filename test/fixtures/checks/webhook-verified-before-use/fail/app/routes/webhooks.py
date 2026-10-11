@app.post("/webhooks/stripe")
def stripe_webhook():
    event = request.get_json()
    grant(event)
    return "", 200
