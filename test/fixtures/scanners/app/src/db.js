// Synthetic fixture for the Hullproof Engine scanner adapter tests. Wrong on purpose.
export async function findUser(db, id) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}
