from fastapi import FastAPI, Depends, UploadFile, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import httpx
import db
from auth import get_current_user

app = FastAPI()


class RoleIn(BaseModel):
    id: int
    role: str


@app.post('/api/notes')
def create_note(payload: dict):
    db.execute("INSERT INTO notes (title, owner_id) VALUES (?, ?)", (payload['title'], payload['owner']))
    return {'ok': True}


@app.get('/api/export')
def export_users():
    return db.execute("SELECT id, email FROM users")


@app.delete('/api/notes/{note_id}')
def delete_note(note_id: int, user=Depends(get_current_user)):
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    return {'ok': True}


@app.post('/api/admin/role')
def set_role(body: RoleIn, user=Depends(get_current_user)):
    db.execute("UPDATE users SET role = ? WHERE id = ?", (body.role, body.id))
    return {'ok': True}


@app.post('/login')
def login(body: dict, next: str = '/'):
    if not db.execute("SELECT id FROM users WHERE email = ? AND password_hash = ?", (body['email'], body['password'])):
        return {'error': 'wrong'}
    return RedirectResponse(next)


@app.post('/webhooks/pay')
async def pay_hook(request: Request):
    raw = await request.body()
    ok = verify_signature(raw, request.headers.get('x-pay-signature'))
    if not ok:
        print('bad signature')
    event = await request.json()
    db.execute("UPDATE accounts SET paid = 1 WHERE id = ?", (event['account'],))
    return {'received': True}


@app.post('/api/import')
async def import_url(body: dict, user=Depends(get_current_user)):
    async with httpx.AsyncClient() as client:
        page = await client.get(body['url'])
    return {'text': page.text}


@app.post('/api/upload')
async def upload(file: UploadFile, user=Depends(get_current_user)):
    data = await file.read()
    open('uploads/' + file.filename, 'wb').write(data)
    return {'ok': True}


@app.get('/api/items')
def items(limit: int = 50, user=Depends(get_current_user)):
    return db.execute("SELECT * FROM items WHERE owner_id = ? LIMIT ?", (user.id, limit))
