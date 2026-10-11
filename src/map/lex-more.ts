// Masking for the languages added in the second wave: Go, Ruby and PHP. Same contract as mask() in lex.ts: a copy of the
// text with the same length in which comments and the insides of string literals are spaces, quote characters and newlines
// kept, so a position in the copy is the same position in the original.
export type MoreLang = 'go' | 'rb' | 'php';

const blank = (s: string): string => s.replace(/[^\n]/g, ' ');

export function maskMore(text: string, lang: MoreLang): string {
  const n = text.length;
  const out: string[] = [];
  const put = (from: number, to: number): void => { out.push(blank(text.slice(from, to))); };
  const keep = (from: number, to: number): void => { out.push(text.slice(from, to)); };
  let i = 0;
  let prevSig = '';
  let prevWord = '';
  // Heredoc terminators waiting for the end of the current line (Ruby and PHP).
  let pending: { id: string; squiggly: boolean }[] = [];

  const quoted = (q: string, escapes: boolean): void => {
    let j = i + 1;
    while (j < n && text[j] !== q && (text[j] !== '\n' || lang !== 'go')) { if (escapes && text[j] === '\\') j++; j++; }
    const close = j < n && text[j] === q ? j : -1;
    keep(i, i + 1);
    put(i + 1, close < 0 ? Math.min(j, n) : close);
    if (close >= 0) keep(close, close + 1);
    i = close < 0 ? Math.min(j, n) : close + 1;
    prevSig = q;
    prevWord = '';
  };

  const flushHeredocs = (): void => {
    // i is just after a newline. Blank lines until each pending terminator line.
    for (const h of pending) {
      for (;;) {
        if (i >= n) break;
        const e = text.indexOf('\n', i);
        const end = e < 0 ? n : e;
        const row = text.slice(i, end);
        const isEnd = (lang === 'rb' ? row.trim() : row.replace(/^\s+/, '').replace(/[;,)\s]+$/, '')) === h.id;
        if (isEnd) { keep(i, end); i = end; break; }
        put(i, end);
        i = end;
        if (i < n) { out.push('\n'); i++; }
      }
    }
    pending = [];
  };

  while (i < n) {
    const c = text[i];
    const c2 = text[i + 1];
    if (c === '\n') {
      keep(i, i + 1); i++;
      if (pending.length) flushHeredocs();
      // Ruby block comments
      if (lang === 'rb' && text.startsWith('=begin', i)) { const e = text.indexOf('\n=end', i); const end = e < 0 ? n : text.indexOf('\n', e + 1) < 0 ? n : text.indexOf('\n', e + 1); put(i, end); i = end; }
      continue;
    }
    if (lang === 'go') {
      if (c === '/' && c2 === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; put(i, end); i = end; continue; }
      if (c === '/' && c2 === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; put(i, end); i = end; continue; }
      if (c === '"') { quoted('"', true); continue; }
      if (c === '\'') { quoted('\'', true); continue; }
      if (c === '`') { const e = text.indexOf('`', i + 1); const end = e < 0 ? n : e; keep(i, i + 1); put(i + 1, end); if (e >= 0) keep(e, e + 1); i = e < 0 ? n : e + 1; prevSig = '`'; continue; }
    } else if (lang === 'rb') {
      if (i === 0 && text.startsWith('=begin')) { const e = text.indexOf('\n=end'); const end = e < 0 ? n : e + 5; put(0, end); i = end; continue; }
      if (c === '#') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; put(i, end); i = end; continue; }
      const hd = c === '<' && c2 === '<' ? /^<<([~-]?)(['"`]?)([A-Za-z_]\w*)\2/.exec(text.slice(i, i + 60)) : null;
      if (hd && !/[\w)\]]\s*$/.test(text.slice(Math.max(0, i - 2), i).replace(/ $/, '')) || (hd && /[=(,]\s*$/.test(text.slice(Math.max(0, i - 12), i)))) {
        pending.push({ id: hd![3], squiggly: hd![1] === '~' });
        keep(i, i + hd![0].length); i += hd![0].length; continue;
      }
      if (c === '"' || c === '\'' || c === '`') { quoted(c, true); continue; }
      if (c === '/' && /^[(,=~{|&!;]$/.test(prevSig) || (c === '/' && /^(?:when|if|unless|and|or|not|return|split|match|scan|gsub|sub)$/.test(prevWord))) {
        let j = i + 1; let cls = false;
        while (j < n && text[j] !== '\n') { if (text[j] === '\\') { j += 2; continue; } if (text[j] === '[') cls = true; else if (text[j] === ']') cls = false; else if (text[j] === '/' && !cls) break; j++; }
        if (j < n && text[j] === '/') { keep(i, i + 1); put(i + 1, j); keep(j, j + 1); i = j + 1; prevSig = '/'; prevWord = ''; continue; }
      }
    } else {
      if ((c === '/' && c2 === '/') || (c === '#' && c2 !== '[')) { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; put(i, end); i = end; continue; }
      if (c === '/' && c2 === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; put(i, end); i = end; continue; }
      const hd = c === '<' && c2 === '<' && text[i + 2] === '<' ? /^<<<\s*(['"]?)([A-Za-z_]\w*)\1/.exec(text.slice(i, i + 60)) : null;
      if (hd) { pending.push({ id: hd[2], squiggly: true }); keep(i, i + hd[0].length); i += hd[0].length; continue; }
      if (c === '"' || c === '\'') { quoted(c, true); continue; }
    }
    keep(i, i + 1);
    if (!/\s/.test(c)) {
      prevSig = c;
      if (/[A-Za-z_]/.test(c)) { const m = /^[A-Za-z_]\w*/.exec(text.slice(i, i + 20)); if (m) { prevWord = m[0]; out.pop(); keep(i, i + m[0].length); i += m[0].length; prevSig = 'w'; continue; } }
      else prevWord = '';
    }
    i++;
  }
  return out.join('');
}
