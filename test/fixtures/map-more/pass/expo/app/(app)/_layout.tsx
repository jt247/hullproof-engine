import { Redirect, Stack } from 'expo-router';
import { useSession } from '../../lib/session';

export default function AppLayout() {
  const { session } = useSession();
  if (!session) {
    return <Redirect href="/sign-in" />;
  }
  return <Stack />;
}
