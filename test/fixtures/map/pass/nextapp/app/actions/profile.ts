'use server';

import { z } from 'zod';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

const Input = z.object({ display_name: z.string().max(80) });

export async function updateProfile(formData: FormData) {
  const user = await currentUser();
  if (!user) throw new Error('Sign in required');
  const input = Input.parse(Object.fromEntries(formData));
  db.prepare('UPDATE profiles SET display_name = ? WHERE id = ?').run(input.display_name, user.id);
}
