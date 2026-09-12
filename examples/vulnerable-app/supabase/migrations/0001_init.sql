create table public.documents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  title text,
  body text
);

-- "It kept returning zero rows in dev, so I turned it off."
alter table public.documents disable row level security;

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  amount_cents integer
);

alter table public.invoices enable row level security;

-- Row level security reports as enabled. It enforces nothing.
create policy "everyone can read invoices"
  on public.invoices for select
  using (true);
