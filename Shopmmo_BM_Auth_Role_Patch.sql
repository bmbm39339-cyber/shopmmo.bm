-- Shopmmo.BM: update signup trigger so buyer/seller choice is saved safely.
-- Run once in Supabase SQL Editor. Users can never self-register as admin.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_username text;
  requested_role public.account_role;
begin
  requested_username := coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1));
  if new.raw_user_meta_data->>'role' = 'seller' then
    requested_role := 'seller';
  else
    requested_role := 'buyer';
  end if;
  insert into public.profiles(id, username, role)
  values (new.id, requested_username, requested_role);
  return new;
end;
$$;
