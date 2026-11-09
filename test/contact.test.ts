import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { emailFormatError, phoneFormatError } from '../src/contact';

describe('optional contact format', () => {
  it('accepts a blank email or phone', () => {
    expect(emailFormatError('')).toBeNull();
    expect(phoneFormatError('')).toBeNull();
    expect(phoneFormatError('   '.trim())).toBeNull();
  });

  it('accepts a normal email and phone', () => {
    expect(emailFormatError('volunteer@example.com')).toBeNull();
    expect(phoneFormatError('(206) 555-0101')).toBeNull();
    expect(phoneFormatError('+1 206 555 0101')).toBeNull();
  });

  it('rejects a bad email or phone only when a value is present', () => {
    expect(emailFormatError('not-an-email')).toMatch(/email/i);
    expect(phoneFormatError('123')).toMatch(/phone/i);
    expect(phoneFormatError('call-me')).toMatch(/phone/i);
  });
});

describe('scheduler behavior in source', () => {
  const worker = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const wrangler = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8');

  it('lets volunteer entry save without email or phone', () => {
    expect(worker).not.toContain('Email and phone number are required');
    expect(worker).not.toContain('type="email" required');
    expect(worker).not.toContain('type="tel" required');
    expect(worker).toContain('First Name<input id="fn" required>');
    expect(worker).toContain('Gender<select id="gender" required>');
  });

  it('shows congregation captains only for a Cleaning department', () => {
    expect(app).toContain("selectedDepartment.name==='Cleaning'");
    expect(app).toContain('Congregation Captains');
    expect(app).toContain('deps.length===1');
    expect(app).toContain('>Volunteers</button><button id="nav-task">Tasks & Times</button><button id="nav-avail">Availability</button>');
    expect(app).not.toContain('>Simple Event<');
    expect(app).not.toContain('Upgrade to Full Organization</button>');
    expect(worker).toContain("d.name!=='Cleaning'");
    expect(worker).toContain('congregation_captains');
  });

  it('serves the events app at /events and leaves /ca in place', () => {
    expect(worker).toContain("p.match(/^\\/events(?:\\/([^/]+))?$/)");
    expect(worker).toContain("/^\\/events(?:\\/|$)/");
    expect(worker).toContain("p.match(/^\\/(ca|rc|sc)(?:\\/events\\/([^/]+))?$/)");
    expect(app).toContain('const eventsListHref=`/events?app=${cfg.app}`');
    expect(app).not.toContain('/${cfg.app}/events/');
  });

  it('does not add a route or replace the public homepage', () => {
    const home = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
    expect(wrangler).not.toMatch(/"routes"/);
    expect(wrangler).not.toContain('/events');
    expect(wrangler).toContain('"name": "ourportal-scheduler"');
    expect(wrangler).toContain('"database_name": "ourportal-scheduler-prod"');
    expect(home).toContain('Continue to Events.');
    expect(home).toContain('href="/events?app=ca"');
    expect(home).toContain('href="/events?app=rc"');
    expect(home).toContain('href="/events?app=sc"');
    expect(home).not.toContain('Hello World');
  });
});

import { formatPhone } from '../src/contact';
describe('phone formatting', () => {
  it('formats US numbers as (xxx) xxx-xxxx however they are typed', () => {
    for (const v of ['9515993371', '951.599.3371', '951-599-3371', '(951)599 3371', '+1 951 599 3371', '19515993371'])
      expect(formatPhone(v)).toBe('(951) 599-3371');
  });
  it('keeps blank and non-US numbers as entered', () => {
    expect(formatPhone('')).toBe('');
    expect(formatPhone('+44 20 7946 0958')).toBe('+44 20 7946 0958');
  });
});
