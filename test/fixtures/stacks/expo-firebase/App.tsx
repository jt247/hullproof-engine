import { View } from 'react-native';
import { getAuth } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

export default function App() {
  return getAuth() && getFirestore() ? View : null;
}
