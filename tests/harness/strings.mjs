/**
 * Vietnamese string constants used by the §13 harness.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The harness compares against Vietnamese literals that the Rust/TS code must
 * contain verbatim (the five verdict labels, and the "not measured" string for
 * the Leak/Speed cards in IP-only mode). Writing those literals directly in
 * source made them vulnerable: a single `Set-Content -Encoding utf8` round-trip
 * through a CP1252 shell silently double-encoded them, and every §13 comparison
 * then failed while the application code was actually correct.
 *
 * So every non-ASCII string here is built from `\u` escapes. These survive any
 * encoding round-trip: they are pure ASCII in the file, and the runtime value is
 * exact. Never inline a raw Vietnamese literal into a test comparison - add it
 * here instead.
 *
 * Even the comments below avoid raw Vietnamese glyphs and name them by codepoint
 * instead, because a corrupted comment is how the corruption gets missed.
 */

/** Verdict for Clean Score >= 85. §6.5 (S-a-c-h with a dot under the a) */
export const V_SACH = 'S\u1EA1ch';

/** Verdict for Clean 65-84. §6.5 (T-a-m with a dot under the a) */
export const V_TAM = 'T\u1EA1m';

/** Verdict for Clean 40-64 or strong conflict. §6.5 (Nghi ngo with a hook) */
export const V_NGHI_NGO = 'Nghi ng\u1EDD';

/** Verdict for Clean < 40 or multi-source agreement. §6.5 (B-a-n with a hook) */
export const V_BAN = 'B\u1EA9n';

/** Verdict when quorum is missing. §6.3, §6.5 (Chua du du lieu, full diacritics) */
export const V_CHUA_DU = 'Ch\u01B0a \u0111\u1EE7 d\u1EEF li\u1EC7u';

/** Every legal verdict, in spec order. §6.5 */
export const ALL_VERDICTS = [V_SACH, V_TAM, V_NGHI_NGO, V_BAN, V_CHUA_DU];

/**
 * The exact string the Leak/Speed cards must show in IP-only mode. §1.2, §3.3
 * U+2014 EM DASH between the two clauses, one space either side.
 */
export const NOT_MEASURED_PROXY = 'Ch\u01B0a \u0111o \u0111\u01B0\u1EE3c \u2014 c\u1EA7n nh\u1EADp proxy';

/** Prefix of the stale-cache label. §3.4, §10.2 (tu cache, check luc) */
export const FROM_CACHE_LABEL = 't\u1EEB cache, check l\u00FAc';

/** The force-refresh button. §10.2 (Check lai) */
export const RECHECK_LABEL = 'Check l\u1EA1i';

/** Leak card clean state. §8.2 (khong leak) */
export const NO_LEAK_LABEL = 'kh\u00F4ng leak';

/** Per-provider error prefix. §3.4 (Loi) */
export const ERROR_LABEL = 'L\u1ED7i';

/** Quota exhausted state. §3.4 (Het quota) */
export const QUOTA_LABEL = 'H\u1EBFt quota';

/** Vietnamese-only check: proves a string was not silently mojibake'd. */
export function looksVietnamese(s) {
  return /[\u00C0-\u1EF9]/.test(s);
}

/**
 * Detect the classic double-encoding artifact (UTF-8 bytes read as CP1252).
 * A correct file returns `[]`.
 *
 * Each marker below is built from escapes on purpose: writing the artifact
 * literally in this file would itself trip the mojibake sweep.
 */
export function detectMojibake(text) {
  const markers = [
    'S\u00E1\u00BA\u00A1ch',      // "Sach" double-encoded
    'Ch\u00C6\u00B0a',            // "Chua" double-encoded
    '\u00C3\u00A2\u20AC\u2122',   // three-byte wreck
    '\u00E1\u00BA',               // generic 'a-circumflex, ordinal' pair
    '\u00C4\u2018',               // "d-stroke" double-encoded
  ];
  return markers.filter((m) => text.includes(m));
}
