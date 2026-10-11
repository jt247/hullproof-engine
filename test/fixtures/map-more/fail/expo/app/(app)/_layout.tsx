import { Stack } from 'expo-router';
import { useSession } from '../../lib/session';

export default function AppLayout() {
  const { session } = useSession();
  return <Stack screenOptions={{ title: session ? 'Notes' : 'Welcome' }} />;
}
