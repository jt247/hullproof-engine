@app.post("/webhooks/stripe")
def stripe_webhook():
    event = stripe.Webhook.construct_event(request.data, request.headers["Stripe-Signature"], SECRET)
    grant(event)
    return "", 200
