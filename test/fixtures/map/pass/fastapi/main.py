import uuid
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, UploadFile, Request, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter
import httpx
import db
from auth import get_current_user, require_admin
from audit import record_audit

app = FastAPI()
limiter = Limiter(key_func=lambda request: request.client.host)
ALLOWED_HOSTS = {'example.com'}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ALLOWED_TYPES = {'image/png', 'image/jpeg'}


class NoteIn(BaseModel):
    title: str


class RoleIn(BaseModel):
    id: int
    role: str


class LoginIn(BaseModel):
    email: str
    password: str


class ImportIn(BaseModel):
    url: str


@app.post('/api/notes')
def create_note(payload: NoteIn, user=Depends(get_current_user)):
    db.execute("INSERT INTO notes (title, owner_id) VALUES (?, ?)", (payload.title, user.id))
    return {'ok': True}


@app.get('/api/export')
def export_users(user=Depends(get_current_user)):
    return db.execute("SELECT id, email FROM users WHERE id = ?", (user.id,))


@app.delete('/api/notes/{note_id}')
def delete_note(note_id: int, user=Depends(get_current_user)):
    db.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, user.id))
    return {'ok': True}


@app.post('/api/admin/role')
def set_role(body: RoleIn, user=Depends(require_admin)):
    db.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, body.id))
    record_audit(actor=user.id, action='set_role', target=body.id)
    return {'ok': True}


@app.post('/login')
@limiter.limit('10/minute')
def login(request: Request, body: LoginIn, next: str = '/'):
    if not db.execute("SELECT id FROM users WHERE email = ? AND password_hash = ?", (body.email, body.password)):
        return {'error': 'wrong'}
    return RedirectResponse(next if next.startswith('/') and not next.startswith('//') else '/')


@app.post('/webhooks/pay')
async def pay_hook(request: Request):
    raw = await request.body()
    ok = verify_signature(raw, request.headers.get('x-pay-signature'))
    if not ok:
        raise HTTPException(status_code=400)
    event = await request.json()
    db.execute("UPDATE accounts SET paid = 1 WHERE id = ?", (event['account'],))
    return {'received': True}


@app.post('/api/import')
async def import_url(body: ImportIn, user=Depends(get_current_user)):
    if urlparse(body.url).hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400)
    async with httpx.AsyncClient() as client:
        page = await client.get(body.url)
    return {'text': page.text}


@app.post('/api/upload')
async def upload(file: UploadFile, user=Depends(get_current_user)):
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413)
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=415)
    open('uploads/' + str(uuid.uuid4()), 'wb').write(data)
    return {'ok': True}


@app.get('/api/items')
def items(limit: int = Query(50, le=100), user=Depends(get_current_user)):
    return db.execute("SELECT * FROM items WHERE owner_id = ? LIMIT ?", (user.id, limit))
