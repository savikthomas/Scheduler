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
