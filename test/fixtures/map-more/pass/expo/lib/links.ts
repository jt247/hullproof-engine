import * as Linking from 'expo-linking';
import { router } from 'expo-router';

const ALLOWED = ['notes', 'account'];

export function listenForLinks() {
  return Linking.addEventListener('url', ({ url }) => {
    const parsed = Linking.parse(url);
    const first = String(parsed.path ?? '').split('/')[0];
    if (ALLOWED.includes(first)) router.push(`/${first}` as never);
  });
}
