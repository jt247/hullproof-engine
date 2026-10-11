export async function GET(req: Request, { params }) {
  const user = currentUser(req);
  const note = db.prepare("SELECT id, body FROM notes WHERE id = ? AND owner_id = ?").get(params.id, user.id);
  return json(note);
}
