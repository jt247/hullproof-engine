import { useEffect, useState } from 'react';
import { Text } from 'react-native';
import { supabase } from '../../lib/supabase';

export default function Account() {
  const [rows, setRows] = useState<unknown[]>([]);
  useEffect(() => {
    supabase.from('profiles').select('*').then(({ data }) => setRows(data ?? []));
  }, []);
  return <Text>{rows.length}</Text>;
}
