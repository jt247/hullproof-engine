// Masking for the languages added after JavaScript and Python: Go, Ruby and PHP (second wave), Java and C# (which have light profiles),
// and Kotlin, Swift and Rust (masking only). Same contract as mask() in lex.ts: a copy of the text with the same length in which
// comments and the insides of string literals are spaces, quote characters and newlines kept, so a position in the copy is the same
// position in the original.
export type MoreLang = 'go' | 'rb' | 'php' | 'java' | 'cs';       // languages with a body profile (light-profiles.ts)
export type MaskLang = MoreLang | 'kt' | 'swift' | 'rs';

// Java, C#, Kotlin, Swift and Rust: line and block comments, "strings" with escapes, text blocks and raw strings, character literals.
function maskC(text: string, lang: 'java' | 'cs' | 'kt' | 'swift' | 'rs'): string {
  const n = text.length;
  const out: string[] = [];
  let i = 0;
  const put = (from: number, to: number): void => { out.push(blank(text.slice(from, to))); };
  const keep = (from: number, to: number): void => { out.push(text.slice(from, to)); };
  const closed = (open: number, close: string, escapes: boolean, doubled = false): number => {
    // index of the closing delimiter at or after open, or -1
    let j = open;
    while (j < n) {
      if (escapes && text[j] === '\\') { j += 2; continue; }
      if (text.startsWith(close, j)) { if (doubled && text.startsWith(close + close, j)) { j += close.length * 2; continue; } return j; }
      j++;
    }
    return -1;
  };
  while (i < n) {
    const c = text[i];
    const c2 = text[i + 1];
    if (c === '/' && c2 === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; put(i, end); i = end; continue; }
    if (c === '/' && c2 === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; put(i, end); i = end; continue; }
    // C#: $"...", @"...", $@"..." ; raw strings in every language: """..."""
    let pre = 0;
    if (lang === 'cs') { while (text[i + pre] === '$' || text[i + pre] === '@') pre++; }
    if (lang === 'rs' && (c === 'r' || (c === 'b' && c2 === 'r')) && /^b?r#*"/.test(text.slice(i, i + 12))) {
      const m = /^b?r(#*)"/.exec(text.slice(i, i + 12))!;
      const start = i + m[0].length;
      const e = text.indexOf('"' + m[1], start);
      const end = e < 0 ? n : e;
      keep(i, start); put(start, end); if (e >= 0) keep(e, e + 1 + m[1].length); i = e < 0 ? n : e + 1 + m[1].length; continue;
    }
    const q = i + pre;
    if (text[q] === '"') {
      if (text.startsWith('"""', q)) {
        const e = text.indexOf('"""', q + 3);
        const end = e < 0 ? n : e;
        keep(i, q + 3); put(q + 3, end); if (e >= 0) keep(e, e + 3); i = e < 0 ? n : e + 3; continue;
      }
      const verbatim = lang === 'cs' && text.slice(i, q).includes('@');
      const e = closed(q + 1, '"', !verbatim, verbatim);
      const end = e < 0 ? n : e;
      keep(i, q + 1); put(q + 1, end); if (e >= 0) keep(e, e + 1); i = e < 0 ? n : e + 1; continue;
    }
    if (c === '\'' && lang !== 'rs' || (c === '\'' && lang === 'rs' && /^'(?:\\.[^']*|[^\\'])'/.test(text.slice(i, i + 12)))) {
      const e = closed(i + 1, '\'', true);
      if (e >= 0 && e - i <= 12) { keep(i, i + 1); put(i + 1, e); keep(e, e + 1); i = e + 1; continue; }
    }
    keep(i, i + 1);
    i++;
  }
  return out.join('');
}

const blank = (s: string): string => s.replace(/[^\n]/g, ' ');

export function maskMore(text: string, lang: MaskLang): string {
  if (lang === 'java' || lang === 'cs' || lang === 'kt' || lang === 'swift' || lang === 'rs') return maskC(text, lang);
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
