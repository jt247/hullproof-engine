import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { verifySignature } from '@/lib/pay';

export async function POST(req: Request) {
  const raw = await req.text();
  const valid = verifySignature(raw, req.headers.get('x-pay-signature'));
  if (!valid) return NextResponse.json({ error: 'bad signature' }, { status: 400 });
  const event = JSON.parse(raw);
  db.prepare('UPDATE accounts SET paid = 1 WHERE id = ?').run(event.account);
  return NextResponse.json({ received: true });
}
