export const tools = {
  read_note: (args, ctx) => db.prepare("SELECT body FROM notes WHERE id = ? AND owner_id = ?").get(String(args.noteId), ctx.userId),
};
