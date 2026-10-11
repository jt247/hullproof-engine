import { getServerSession } from 'next-auth';

export async function currentUser() {
  const session = await getServerSession();
  return session?.user ?? null;
}
