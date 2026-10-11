'use server';

import { db } from '@/lib/db';

export async function updateProfile(formData: FormData) {
  const input = Object.fromEntries(formData);
  db.prepare('UPDATE profiles SET display_name = ?, role = ? WHERE id = ?').run(input.display_name, input.role, input.id);
}
