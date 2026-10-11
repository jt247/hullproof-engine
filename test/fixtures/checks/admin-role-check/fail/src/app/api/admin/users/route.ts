export async function GET(req: Request) {
  if (!currentUser(req)) return unauthorized();
  return json(db.prepare("SELECT * FROM users").all());
}
