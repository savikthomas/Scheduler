# Scheduler

OurPortal volunteer scheduler (Cloudflare Worker + D1), deployed automatically to ourportal.us on every push to `main`.

## Database changes

The Worker adds the `volunteers.congregation` and `volunteers.minor` columns itself on its first API request if they are missing (see `ensureVolunteerColumns` in `src/index.ts`), so no manual migration is needed for them.
