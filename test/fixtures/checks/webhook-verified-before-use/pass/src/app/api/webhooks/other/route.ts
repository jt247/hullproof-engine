export async function POST(req: Request) {
  if (!verifyWebhook(req)) throw new Error("bad signature");
  return ok();
}
