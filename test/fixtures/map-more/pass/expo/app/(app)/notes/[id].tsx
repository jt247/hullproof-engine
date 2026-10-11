import { useEffect, useState } from 'react';
import { Text } from 'react-native';
import { useLocalSearchParams } from 'expo-router';
import { supabase } from '../../../lib/supabase';

export default function NoteScreen() {
  const { id } = useLocalSearchParams();
  const [note, setNote] = useState<{ title: string } | null>(null);
  useEffect(() => {
    supabase.from('notes').select('*').eq('id', id).single().then(({ data }) => setNote(data));
  }, [id]);
  return <Text>{note?.title}</Text>;
}
