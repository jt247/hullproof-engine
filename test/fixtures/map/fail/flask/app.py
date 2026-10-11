from flask import Flask, request, jsonify, redirect
from flask_login import login_required, current_user
import requests
import db

app = Flask(__name__)


@app.route('/api/notes', methods=['POST'])
def create_note():
    data = request.get_json()
    db.execute("INSERT INTO notes (title, owner_id) VALUES (?, ?)", (data['title'], data['owner']))
    return jsonify(ok=True)


@app.route('/api/export')
def export_users():
    return jsonify(db.execute("SELECT id, email FROM users"))


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return jsonify(ok=True)


@app.route('/api/admin/users/<int:uid>/role', methods=['POST'])
@login_required
def set_role(uid):
    db.execute("UPDATE users SET role = ? WHERE id = ?", (request.json['role'], uid))
    return jsonify(ok=True)


@app.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    if not db.execute("SELECT id FROM users WHERE email = ? AND password_hash = ?", (body['email'], body['password'])):
        return jsonify(error='wrong'), 401
    return redirect(request.args.get('next'))


@app.route('/webhooks/pay', methods=['POST'])
def pay_hook():
    ok = verify_signature(request.data, request.headers.get('X-Pay-Signature'))
    if not ok:
        print('bad signature')
    event = request.get_json()
    db.execute("UPDATE accounts SET paid = 1 WHERE id = ?", (event['account'],))
    return jsonify(received=True)


@app.route('/api/import', methods=['POST'])
@login_required
def import_url():
    page = requests.get(request.json['url'])
    return page.text


@app.route('/api/upload', methods=['POST'])
@login_required
def upload():
    f = request.files['file']
    f.save('uploads/' + f.filename)
    return jsonify(ok=True)


@app.route('/api/items')
@login_required
def items():
    limit = int(request.args.get('limit', 50))
    return jsonify(db.execute("SELECT * FROM items WHERE owner_id = ? LIMIT ?", (current_user.id, limit)))
