const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function emailFormatError(email: string): string | null {
  if (!email) return null;
  return EMAIL_RE.test(email) ? null : 'Enter a valid email address, or leave email blank.';
}

export function phoneFormatError(phone: string): string | null {
  if (!phone) return null;
  const digits = phone.replace(/\D/g, '');
  if (digits.length >= 7 && digits.length <= 15 && /^\+?[\d\s().-]+$/.test(phone)) return null;
  return 'Enter a valid phone number, or leave phone blank.';
}

// US numbers are stored as (xxx) xxx-xxxx however they were typed
// (9515993371, 951.599.3371, +1 951-599-3371, ...). Anything that is not a
// 10-digit US number (e.g. international) is kept as entered.
export function formatPhone(phone: string): string {
  const raw = (phone || '').trim();
  if (!raw) return '';
  let d = raw.replace(/\D/g, '');
  if (d.length === 11 && d.startsWith('1')) d = d.slice(1);
  if (d.length !== 10) return raw;
  return `(${d.slice(0, 3)}) ${d.slice(3, 6)}-${d.slice(6)}`;
}
