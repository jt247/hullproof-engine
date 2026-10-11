import OpenAI from 'openai';
import { createClient } from '@supabase/supabase-js';
import { helper } from '../../lib/helper';

export async function POST(): Promise<Response> {
  const supabase = createClient('url', 'key');
  const { data } = await supabase.auth.getUser();
  return Response.json({ ok: Boolean(data) && Boolean(OpenAI) && Boolean(helper) });
}
