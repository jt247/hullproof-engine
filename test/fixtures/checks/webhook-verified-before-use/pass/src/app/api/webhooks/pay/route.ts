import { verifySignature } from "@/lib/pay";
export async function POST(req: Request) {
  const raw = await req.text();
  const ok = verifySignature(raw, req.headers.get("x-pay-signature"));
  if (!ok) {
    return new Response("bad signature", { status: 401 });
  }
  return grant(JSON.parse(raw));
}
