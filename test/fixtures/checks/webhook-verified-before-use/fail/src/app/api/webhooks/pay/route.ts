import { verifySignature } from "@/lib/pay";
export async function POST(req: Request) {
  const raw = await req.text();
  const ok = verifySignature(raw, req.headers.get("x-pay-signature"));
  if (!ok) console.warn("bad signature");
  return grant(JSON.parse(raw));
}
