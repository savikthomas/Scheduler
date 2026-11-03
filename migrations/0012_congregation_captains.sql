-- Event department name, and congregation captains for the Cleaning department.
ALTER TABLE events ADD COLUMN department_name TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS congregation_captains (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  department_id TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  congregation_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
  FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_congregation_captains_department
  ON congregation_captains(event_id, department_id, congregation_name, name);
