-- Run this once in the Supabase SQL editor.

create table if not exists scam_reports (
  id bigserial primary key,
  key text not null,                -- normalised number (n + digits) or link host (u + host)
  kind text not null check (kind in ('number','link')),
  display text not null,
  cat text not null,
  city_key text not null,           -- like "Mumbai, IN"
  reporter text not null,           -- anonymous per-browser id
  created_at timestamptz not null default now(),
  unique (key, reporter)            -- one report per person per number/link
);
create index if not exists scam_reports_key_idx on scam_reports (key);
create index if not exists scam_reports_created_idx on scam_reports (created_at desc);

create table if not exists crime_reports (
  id bigserial primary key,
  type text not null,
  lat double precision not null,    -- rounded to about 1 km
  lng double precision not null,
  hour int not null check (hour between 0 and 23),
  coarse boolean not null default false,
  occurred_at timestamptz not null,
  reporter text not null,
  created_at timestamptz not null default now()
);
create index if not exists crime_reports_geo_idx on crime_reports (lat, lng);
create index if not exists crime_reports_time_idx on crime_reports (occurred_at desc);

create table if not exists news_cache (
  key text primary key,
  payload jsonb not null,
  fetched_at timestamptz not null default now()
);

-- Only the backend (service role key) may read or write. No public policies on purpose.
alter table scam_reports enable row level security;
alter table crime_reports enable row level security;
alter table news_cache enable row level security;
