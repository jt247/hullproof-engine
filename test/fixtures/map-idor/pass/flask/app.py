import sqlite3
from flask import Flask, g, jsonify
from flask_login import login_required, current_user

app = Flask(__name__)


@app.get("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    row = sqlite3.connect("app.db").execute("SELECT * FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, current_user.id)).fetchone()
    return jsonify(row)
