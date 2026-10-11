import * as Linking from 'expo-linking';
import { router } from 'expo-router';

export function listenForLinks() {
  return Linking.addEventListener('url', ({ url }) => {
    const parsed = Linking.parse(url);
    router.push(parsed.path as string);
  });
}
