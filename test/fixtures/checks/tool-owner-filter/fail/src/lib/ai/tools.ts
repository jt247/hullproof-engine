export const tools = {
  read_note: (args) => db.prepare("SELECT body FROM notes WHERE id = ?").get(String(args.noteId)),
};
