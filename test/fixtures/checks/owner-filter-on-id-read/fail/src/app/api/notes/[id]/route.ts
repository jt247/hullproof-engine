export async function GET(req: Request, { params }) {
  const note = db.prepare("SELECT id, owner_id, body FROM notes WHERE id = ?").get(params.id);
  return json(note);
}
