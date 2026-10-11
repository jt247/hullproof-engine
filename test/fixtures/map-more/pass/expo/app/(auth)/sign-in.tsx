import { Button } from 'react-native';
import { supabase } from '../../lib/supabase';

export default function SignIn() {
  return <Button title="Sign in" onPress={() => supabase.auth.signInWithOAuth({ provider: 'github' })} />;
}
