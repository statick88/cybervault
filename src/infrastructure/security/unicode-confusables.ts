export interface ConfusableMapping {
  readonly char: string;
  readonly codePoint: number;
  readonly script: string;
  readonly lookalike: string;
  readonly category: 'homograph' | 'zerowidth' | 'combining' | 'fullwidth';
}

export const UNICODE_CONFUSABLES_MAP: ReadonlyArray<ConfusableMapping> = [
  { char: 'а', codePoint: 0x0430, script: 'Cyrillic', lookalike: 'a', category: 'homograph' },
  { char: 'е', codePoint: 0x0435, script: 'Cyrillic', lookalike: 'e', category: 'homograph' },
  { char: 'о', codePoint: 0x043E, script: 'Cyrillic', lookalike: 'o', category: 'homograph' },
  { char: 'р', codePoint: 0x0440, script: 'Cyrillic', lookalike: 'p', category: 'homograph' },
  { char: 'с', codePoint: 0x0441, script: 'Cyrillic', lookalike: 'c', category: 'homograph' },
  { char: 'у', codePoint: 0x0443, script: 'Cyrillic', lookalike: 'y', category: 'homograph' },
  { char: 'х', codePoint: 0x0445, script: 'Cyrillic', lookalike: 'x', category: 'homograph' },
  { char: 'і', codePoint: 0x0456, script: 'Cyrillic', lookalike: 'i', category: 'homograph' },
  { char: 'ј', codePoint: 0x0458, script: 'Cyrillic', lookalike: 'j', category: 'homograph' },
  { char: 'ѕ', codePoint: 0x0455, script: 'Cyrillic', lookalike: 's', category: 'homograph' },

  { char: 'α', codePoint: 0x03B1, script: 'Greek', lookalike: 'a', category: 'homograph' },
  { char: 'β', codePoint: 0x03B2, script: 'Greek', lookalike: 'b', category: 'homograph' },
  { char: 'ε', codePoint: 0x03B5, script: 'Greek', lookalike: 'e', category: 'homograph' },
  { char: 'ο', codePoint: 0x03BF, script: 'Greek', lookalike: 'o', category: 'homograph' },
  { char: 'ρ', codePoint: 0x03C1, script: 'Greek', lookalike: 'p', category: 'homograph' },
  { char: 'τ', codePoint: 0x03C4, script: 'Greek', lookalike: 't', category: 'homograph' },
  { char: 'υ', codePoint: 0x03C5, script: 'Greek', lookalike: 'y', category: 'homograph' },
  { char: 'χ', codePoint: 0x03C7, script: 'Greek', lookalike: 'x', category: 'homograph' },
  { char: 'ι', codePoint: 0x03B9, script: 'Greek', lookalike: 'i', category: 'homograph' },
  { char: 'κ', codePoint: 0x03BA, script: 'Greek', lookalike: 'k', category: 'homograph' },

  { char: 'ա', codePoint: 0x0561, script: 'Armenian', lookalike: 'a', category: 'homograph' },
  { char: 'ե', codePoint: 0x0565, script: 'Armenian', lookalike: 'e', category: 'homograph' },
  { char: 'օ', codePoint: 0x0585, script: 'Armenian', lookalike: 'o', category: 'homograph' },

  { char: 'א', codePoint: 0x05D0, script: 'Hebrew', lookalike: 'a', category: 'homograph' },
  { char: 'ע', codePoint: 0x05E2, script: 'Hebrew', lookalike: 'o', category: 'homograph' },

  ...Array.from({ length: 94 }, (_, i) => ({
    char: String.fromCharCode(0xFF01 + i),
    codePoint: 0xFF01 + i,
    script: 'Fullwidth',
    lookalike: String.fromCharCode(0x21 + i),
    category: 'fullwidth' as const
  })),

  { char: '\u200B', codePoint: 0x200B, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\u200C', codePoint: 0x200C, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\u200D', codePoint: 0x200D, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\uFEFF', codePoint: 0xFEFF, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\u00AD', codePoint: 0x00AD, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\u2060', codePoint: 0x2060, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\u2061', codePoint: 0x2061, script: 'Common', lookalike: '', category: 'zerowidth' },
  { char: '\u034F', codePoint: 0x034F, script: 'Common', lookalike: '', category: 'combining' },

  { char: '𝐚', codePoint: 0x1D41A, script: 'MathBold', lookalike: 'a', category: 'homograph' },
  { char: '𝐞', codePoint: 0x1D41E, script: 'MathBold', lookalike: 'e', category: 'homograph' },
  { char: '𝐨', codePoint: 0x1D424, script: 'MathBold', lookalike: 'o', category: 'homograph' },

  { char: 'à', codePoint: 0x00E0, script: 'Latin', lookalike: 'a', category: 'homograph' },
  { char: 'á', codePoint: 0x00E1, script: 'Latin', lookalike: 'a', category: 'homograph' },
  { char: 'â', codePoint: 0x00E2, script: 'Latin', lookalike: 'a', category: 'homograph' },
  { char: 'ã', codePoint: 0x00E3, script: 'Latin', lookalike: 'a', category: 'homograph' },
  { char: 'ä', codePoint: 0x00E4, script: 'Latin', lookalike: 'a', category: 'homograph' },
  { char: 'å', codePoint: 0x00E5, script: 'Latin', lookalike: 'a', category: 'homograph' },
  { char: 'è', codePoint: 0x00E8, script: 'Latin', lookalike: 'e', category: 'homograph' },
  { char: 'é', codePoint: 0x00E9, script: 'Latin', lookalike: 'e', category: 'homograph' },
  { char: 'ê', codePoint: 0x00EA, script: 'Latin', lookalike: 'e', category: 'homograph' },
  { char: 'ë', codePoint: 0x00EB, script: 'Latin', lookalike: 'e', category: 'homograph' },
  { char: 'ì', codePoint: 0x00EC, script: 'Latin', lookalike: 'i', category: 'homograph' },
  { char: 'í', codePoint: 0x00ED, script: 'Latin', lookalike: 'i', category: 'homograph' },
  { char: 'î', codePoint: 0x00EE, script: 'Latin', lookalike: 'i', category: 'homograph' },
  { char: 'ï', codePoint: 0x00EF, script: 'Latin', lookalike: 'i', category: 'homograph' },
  { char: 'ò', codePoint: 0x00F2, script: 'Latin', lookalike: 'o', category: 'homograph' },
  { char: 'ó', codePoint: 0x00F3, script: 'Latin', lookalike: 'o', category: 'homograph' },
  { char: 'ô', codePoint: 0x00F4, script: 'Latin', lookalike: 'o', category: 'homograph' },
  { char: 'õ', codePoint: 0x00F5, script: 'Latin', lookalike: 'o', category: 'homograph' },
  { char: 'ö', codePoint: 0x00F6, script: 'Latin', lookalike: 'o', category: 'homograph' },
  { char: 'ù', codePoint: 0x00F9, script: 'Latin', lookalike: 'u', category: 'homograph' },
  { char: 'ú', codePoint: 0x00FA, script: 'Latin', lookalike: 'u', category: 'homograph' },
  { char: 'û', codePoint: 0x00FB, script: 'Latin', lookalike: 'u', category: 'homograph' },
  { char: 'ü', codePoint: 0x00FC, script: 'Latin', lookalike: 'u', category: 'homograph' },

  { char: '⁰', codePoint: 0x2070, script: 'Superscript', lookalike: '0', category: 'homograph' },
  { char: '¹', codePoint: 0x00B9, script: 'Superscript', lookalike: '1', category: 'homograph' },
  { char: '²', codePoint: 0x00B2, script: 'Superscript', lookalike: '2', category: 'homograph' },
  { char: '³', codePoint: 0x00B3, script: 'Superscript', lookalike: '3', category: 'homograph' },
];

export const CONFUSABLE_LOOKUP: ReadonlyMap<string, ConfusableMapping> = new Map(
  UNICODE_CONFUSABLES_MAP.map(m => [m.char, m])
);

export const SCRIPT_RANGES: ReadonlyArray<{ script: string; start: number; end: number }> = [
  { script: 'Cyrillic', start: 0x0400, end: 0x04FF },
  { script: 'Greek', start: 0x0370, end: 0x03FF },
  { script: 'Armenian', start: 0x0530, end: 0x058F },
  { script: 'Hebrew', start: 0x0590, end: 0x05FF },
  { script: 'Arabic', start: 0x0600, end: 0x06FF },
  { script: 'Devanagari', start: 0x0900, end: 0x097F },
  { script: 'Fullwidth', start: 0xFF00, end: 0xFFEF },
  { script: 'MathBold', start: 0x1D400, end: 0x1D7FF },
  { script: 'LatinExtendedA', start: 0x0100, end: 0x017F },
  { script: 'LatinExtendedB', start: 0x0180, end: 0x024F },
];