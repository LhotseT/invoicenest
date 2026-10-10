-- InvoiceNest initial schema: profiles, clients, invoices, invoice_items.
-- Every table has Row Level Security (RLS) on, so a signed-in user can only
-- reach rows they own, even though the browser talks to the database directly.

-- ---------------------------------------------------------------------------
-- profiles: one row per user, holding app data that Supabase Auth doesn't.
-- ---------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  plan text not null default 'free' check (plan in ('free', 'pro')),
  stripe_customer_id text unique,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Read-only for the user. There is deliberately no update policy: if users
-- could update their own row they could set plan = 'pro' for free. Only the
-- Stripe webhook (using the service role key, which bypasses RLS) changes it.
create policy "Users can read their own profile"
  on public.profiles for select
  to authenticated
  using (id = (select auth.uid()));

-- Create the profile automatically whenever someone signs up.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- clients: the people and companies a user bills.
-- ---------------------------------------------------------------------------
create table public.clients (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 200),
  email text,
  address text,
  created_at timestamptz not null default now()
);

create index clients_user_id_idx on public.clients (user_id);

alter table public.clients enable row level security;

create policy "Users manage their own clients"
  on public.clients for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

-- ---------------------------------------------------------------------------
-- invoices: the header of an invoice. The amounts live in invoice_items.
-- ---------------------------------------------------------------------------
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  -- restrict: a client with invoices can't be deleted out from under them.
  client_id uuid not null references public.clients (id) on delete restrict,
  number text not null,
  status text not null default 'draft' check (status in ('draft', 'sent', 'paid')),
  issue_date date not null default current_date,
  due_date date,
  currency text not null default 'EUR' check (currency ~ '^[A-Z]{3}$'),
  tax_rate numeric(5, 2) not null default 0 check (tax_rate between 0 and 100),
  notes text,
  created_at timestamptz not null default now(),
  unique (user_id, number),
  check (due_date is null or due_date >= issue_date)
);

create index invoices_user_id_idx on public.invoices (user_id);
create index invoices_client_id_idx on public.invoices (client_id);

alter table public.invoices enable row level security;

-- The with check also requires the client to be the user's own, so nobody can
-- attach an invoice to another user's client by guessing its id.
create policy "Users manage their own invoices"
  on public.invoices for all
  to authenticated
  using (user_id = (select auth.uid()))
  with check (
    user_id = (select auth.uid())
    and exists (
      select 1 from public.clients c
      where c.id = client_id and c.user_id = (select auth.uid())
    )
  );

-- ---------------------------------------------------------------------------
-- invoice_items: the lines on an invoice.
-- ---------------------------------------------------------------------------
create table public.invoice_items (
  id uuid primary key default gen_random_uuid(),
  invoice_id uuid not null references public.invoices (id) on delete cascade,
  description text not null check (char_length(description) between 1 and 500),
  quantity numeric(10, 2) not null default 1 check (quantity > 0),
  -- Money is stored as whole cents (120000 = 1,200.00) to avoid float rounding.
  unit_price_cents integer not null check (unit_price_cents >= 0),
  position integer not null default 0
);

create index invoice_items_invoice_id_idx on public.invoice_items (invoice_id);

alter table public.invoice_items enable row level security;

-- Items have no user_id of their own: they belong to whoever owns the invoice.
create policy "Users manage items on their own invoices"
  on public.invoice_items for all
  to authenticated
  using (
    exists (
      select 1 from public.invoices i
      where i.id = invoice_id and i.user_id = (select auth.uid())
    )
  )
  with check (
    exists (
      select 1 from public.invoices i
      where i.id = invoice_id and i.user_id = (select auth.uid())
    )
  );

-- ---------------------------------------------------------------------------
-- Table privileges. Signed-in users only; anonymous visitors get nothing.
-- RLS above then narrows each of these to the user's own rows.
-- ---------------------------------------------------------------------------
revoke all on public.profiles, public.clients, public.invoices, public.invoice_items from anon;

grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.clients, public.invoices, public.invoice_items to authenticated;
