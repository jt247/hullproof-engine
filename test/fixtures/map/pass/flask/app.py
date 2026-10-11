import hmac
import uuid
from flask import Flask, request, jsonify, redirect, abort
from flask_login import login_required, current_user
from flask_limiter import Limiter
import requests
import db
from schemas import NoteSchema, RoleSchema
from audit import record_audit

app = Flask(__name__)
limiter = Limiter(app)
ALLOWED_HOSTS = {'example.com'}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_TYPES = {'image/png', 'image/jpeg'}


def admin_required(fn):
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.route('/api/notes', methods=['POST'])
@login_required
def create_note():
    data = NoteSchema().load(request.get_json())
    db.execute("INSERT INTO notes (title, owner_id) VALUES (?, ?)", (data['title'], current_user.id))
    return jsonify(ok=True)


@app.route('/api/export')
@login_required
def export_users():
    return jsonify(db.execute("SELECT id, email FROM users WHERE id = ?", (current_user.id,)))


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    db.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, current_user.id))
    return jsonify(ok=True)


@app.route('/api/admin/users/<int:uid>/role', methods=['POST'])
@login_required
@admin_required
def set_role(uid):
    data = RoleSchema().load(request.json)
    db.execute("UPDATE users SET role = ? WHERE id = ?", (data['role'], uid))
    record_audit(actor=current_user.id, action='set_role', target=uid)
    return jsonify(ok=True)


@app.route('/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    body = NoteSchema().load(request.get_json())
    if not db.execute("SELECT id FROM users WHERE email = ? AND password_hash = ?", (body['email'], body['password'])):
        return jsonify(error='wrong'), 401
    target = request.args.get('next', '/')
    return redirect(target if target.startswith('/') and not target.startswith('//') else '/')


@app.route('/webhooks/pay', methods=['POST'])
def pay_hook():
    ok = verify_signature(request.data, request.headers.get('X-Pay-Signature'))
    if not ok:
        abort(400)
    event = request.get_json()
    db.execute("UPDATE accounts SET paid = 1 WHERE id = ?", (event['account'],))
    return jsonify(received=True)


@app.route('/api/import', methods=['POST'])
@login_required
def import_url():
    body = NoteSchema().load(request.json)
    from urllib.parse import urlparse
    if urlparse(body['url']).hostname not in ALLOWED_HOSTS:
        abort(400)
    page = requests.get(body['url'])
    return page.text


@app.route('/api/upload', methods=['POST'])
@login_required
def upload():
    f = request.files['file']
    if request.content_length > MAX_UPLOAD_BYTES:
        abort(413)
    if f.mimetype not in ALLOWED_TYPES:
        abort(415)
    f.save('uploads/' + str(uuid.uuid4()))
    return jsonify(ok=True)


@app.route('/api/items')
@login_required
def items():
    limit = min(int(request.args.get('limit', 50)), 100)
    return jsonify(db.execute("SELECT * FROM items WHERE owner_id = ? LIMIT ?", (current_user.id, limit)))
