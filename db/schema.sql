-- ---------------------------------------------------------------------------
-- Brio — reference schema for PostgreSQL
--
-- The shipped app stores the same entities in data/db.json (see server/db.js)
-- so it runs with zero infrastructure. When you outgrow one process, create
-- this schema and port server/db.js to SQL — the column names match the JSON
-- field names one-for-one.
--
--   createdb brio && psql brio -f db/schema.sql
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,              -- scrypt$<salt>$<hash>
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at TIMESTAMPTZ
);

-- One row per (user, ebook) the user is entitled to read.
CREATE TABLE IF NOT EXISTS entitlements (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id    TEXT NOT NULL,
  source     TEXT NOT NULL DEFAULT 'checkout',   -- checkout | grant | import
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, book_id)
);

-- Reading position per user per book.
CREATE TABLE IF NOT EXISTS progress (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id     TEXT NOT NULL,
  percent     INTEGER NOT NULL DEFAULT 0 CHECK (percent BETWEEN 0 AND 100),
  minutes     INTEGER NOT NULL DEFAULT 0,
  finished    BOOLEAN NOT NULL DEFAULT false,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, book_id)
);

-- Append-only activity log; the analytics panel is a rollup of this table.
CREATE TABLE IF NOT EXISTS events (
  id      BIGSERIAL PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type    TEXT NOT NULL,                       -- read | listen
  book_id TEXT,
  minutes INTEGER NOT NULL DEFAULT 0,
  at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS purchases (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider     TEXT NOT NULL DEFAULT 'none',   -- stripe | gumroad | razorpay | none
  reference    TEXT,
  amount_cents INTEGER NOT NULL DEFAULT 0,
  currency     TEXT NOT NULL DEFAULT 'USD',
  status       TEXT NOT NULL DEFAULT 'placeholder',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS events_user_at_idx        ON events (user_id, at DESC);
CREATE INDEX IF NOT EXISTS entitlements_user_idx     ON entitlements (user_id);
CREATE INDEX IF NOT EXISTS progress_user_idx         ON progress (user_id);
CREATE INDEX IF NOT EXISTS purchases_user_idx        ON purchases (user_id);

-- Rolling 7-day reading minutes per user — the dashboard query in SQL form.
-- SELECT user_id, date_trunc('day', at) AS day, SUM(minutes) AS minutes
--   FROM events
--  WHERE user_id = $1 AND type = 'read' AND at > now() - interval '7 days'
--  GROUP BY 1, 2 ORDER BY 2;
