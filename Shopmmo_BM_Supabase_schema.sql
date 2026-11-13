-- Shopmmo.BM: Supabase PostgreSQL starter schema
-- Run this in Supabase Dashboard > SQL Editor.
-- IMPORTANT: review policies and test with separate buyer/seller/admin accounts before production.

create extension if not exists pgcrypto;

create type public.account_role as enum ('buyer','seller','admin');
create type public.product_status as enum ('pending','approved','rejected','hidden');
create type public.order_status as enum ('pending','paid','delivered','completed','cancelled','disputed','refunded');
create type public.dispute_status as enum ('open','reviewing','resolved','rejected');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null check (char_length(username) between 4 and 24),
  role public.account_role not null default 'buyer',
  display_name text,
  created_at timestamptz not null default now()
);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  seller_id uuid not null references public.profiles(id),
  name text not null check (char_length(name) between 3 and 120),
  category text not null,
  description text not null default '',
  price_vnd bigint not null check (price_vnd > 0),
  quantity integer not null default 0 check (quantity >= 0),
  status public.product_status not null default 'pending',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index products_search_idx on public.products using gin
  (to_tsvector('simple', coalesce(name,'') || ' ' || coalesce(category,'') || ' ' || coalesce(description,'')));
create index products_seller_idx on public.products(seller_id);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  buyer_id uuid not null references public.profiles(id),
  seller_id uuid not null references public.profiles(id),
  product_id uuid not null references public.products(id),
  quantity integer not null check (quantity > 0),
  unit_price_vnd bigint not null check (unit_price_vnd > 0),
  total_vnd bigint generated always as (quantity * unit_price_vnd) stored,
  status public.order_status not null default 'pending',
  buyer_note text not null default '',
  delivery_note text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index orders_buyer_idx on public.orders(buyer_id, created_at desc);
create index orders_seller_idx on public.orders(seller_id, created_at desc);

-- Ledger only. Never let a browser directly change wallet balances.
create table public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  amount_vnd bigint not null check (amount_vnd <> 0),
  kind text not null check (kind in ('deposit','withdrawal','purchase','sale','refund','adjustment')),
  status text not null default 'pending' check (status in ('pending','confirmed','rejected')),
  reference_id uuid,
  note text not null default '',
  created_at timestamptz not null default now()
);
create index wallet_user_idx on public.wallet_transactions(user_id, created_at desc);

create table public.conversations (
  id uuid primary key default gen_random_uuid(),
  buyer_id uuid not null references public.profiles(id),
  seller_id uuid not null references public.profiles(id),
  product_id uuid references public.products(id),
  created_at timestamptz not null default now(),
  unique (buyer_id, seller_id, product_id)
);
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references public.profiles(id),
  body text not null check (char_length(body) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index messages_conversation_idx on public.messages(conversation_id, created_at);

create table public.disputes (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null unique references public.orders(id),
  opened_by uuid not null references public.profiles(id),
  reason text not null check (char_length(reason) between 10 and 3000),
  evidence_urls text[] not null default '{}',
  status public.dispute_status not null default 'open',
  admin_note text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Create a buyer profile automatically. Public signup cannot self-assign seller/admin.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare requested_username text;
begin
  requested_username := coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1));
  insert into public.profiles(id, username, role)
  values (new.id, requested_username, 'buyer');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.conversations enable row level security;
alter table public.messages enable row level security;
alter table public.disputes enable row level security;

-- Profiles: members can see basic profile data; only self can edit display name.
create policy "profiles readable by authenticated" on public.profiles
for select to authenticated using (true);
-- SECURITY DEFINER helper avoids querying profiles recursively from its own RLS policy.
create or replace function public.current_profile_role()
returns public.account_role
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;

create policy "profile owner updates display fields" on public.profiles
for update to authenticated using (id = auth.uid())
with check (id = auth.uid() and role = public.current_profile_role());

-- Products: public sees approved products; sellers manage only their own listings.
create policy "approved products public read" on public.products
for select to anon, authenticated using (status = 'approved' or seller_id = auth.uid());
create policy "seller inserts own pending products" on public.products
for insert to authenticated with check (
  seller_id = auth.uid()
  and exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'seller')
  and status = 'pending'
);
create policy "seller updates own products" on public.products
for update to authenticated using (
  seller_id = auth.uid()
  and exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'seller')
) with check (
  seller_id = auth.uid()
  and exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'seller')
);

-- Orders: participants can read. Creation/status changes should be routed through trusted server RPCs.
create policy "order participants read" on public.orders
for select to authenticated using (buyer_id = auth.uid() or seller_id = auth.uid());

-- Wallet: owner can read own ledger; no client insert/update/delete policies.
create policy "wallet owner reads ledger" on public.wallet_transactions
for select to authenticated using (user_id = auth.uid());

-- Chat: only conversation participants can read; sender must be the current user.
create policy "participants read conversations" on public.conversations
for select to authenticated using (buyer_id = auth.uid() or seller_id = auth.uid());
create policy "participants read messages" on public.messages
for select to authenticated using (
  exists (select 1 from public.conversations c
          where c.id = conversation_id and (c.buyer_id = auth.uid() or c.seller_id = auth.uid()))
);
create policy "participants send messages" on public.messages
for insert to authenticated with check (
  sender_id = auth.uid()
  and exists (select 1 from public.conversations c
              where c.id = conversation_id and (c.buyer_id = auth.uid() or c.seller_id = auth.uid()))
);

create policy "dispute parties read" on public.disputes
for select to authenticated using (
  opened_by = auth.uid()
  or exists (select 1 from public.orders o where o.id = order_id and (o.buyer_id = auth.uid() or o.seller_id = auth.uid()))
);
create policy "buyer opens dispute" on public.disputes
for insert to authenticated with check (
  opened_by = auth.uid()
  and exists (select 1 from public.orders o where o.id = order_id and o.buyer_id = auth.uid())
);

-- Do not create a browser-accessible balance field or expose Supabase service_role key.
-- Add secure server-side RPC/Edge Functions for checkout, delivery, completion,
-- deposits, withdrawals, refunds, moderation and admin actions before enabling live money.
