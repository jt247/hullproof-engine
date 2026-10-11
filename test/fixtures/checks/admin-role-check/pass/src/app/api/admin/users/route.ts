export async function GET(req: Request) {
  const user = currentUser(req);
  if (!user || user.role !== "admin") return forbidden();
  return json(db.prepare("SELECT * FROM users").all());
}
