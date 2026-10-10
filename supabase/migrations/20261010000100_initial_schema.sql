-- CODECORE initial schema. Apply with Supabase CLI or SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.vouchers (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  code_hint text not null,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  max_redemptions integer not null default 1 check (max_redemptions > 0),
  redemption_count integer not null default 0 check (redemption_count >= 0),
  is_disabled boolean not null default false,
  metadata jsonb not null default '{}'::jsonb
);

create table if not exists public.voucher_redemptions (
  id uuid primary key default gen_random_uuid(),
  voucher_id uuid not null references public.vouchers(id),
  user_id uuid not null references auth.users(id),
  redeemed_at timestamptz not null default now(),
  unique (voucher_id, user_id)
);

create table if not exists public.totp_factors (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  label text not null default 'CODECORE',
  secret_ciphertext text not null,
  enabled boolean not null default false,
  last_accepted_step bigint,
  created_at timestamptz not null default now(),
  enabled_at timestamptz
);

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  key_hash text not null unique,
  key_prefix text not null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  target_type text not null,
  target_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists vouchers_created_by_idx on public.vouchers(created_by);
create index if not exists redemptions_user_idx on public.voucher_redemptions(user_id);
create index if not exists audit_logs_created_at_idx on public.audit_logs(created_at desc);
create index if not exists api_keys_owner_idx on public.api_keys(owner_id);

alter table public.profiles enable row level security;
alter table public.vouchers enable row level security;
alter table public.voucher_redemptions enable row level security;
alter table public.totp_factors enable row level security;
alter table public.api_keys enable row level security;
alter table public.audit_logs enable row level security;

create policy "profile owner reads own profile" on public.profiles
 for select to authenticated using ((select auth.uid()) = user_id);
create policy "users read own redemptions" on public.voucher_redemptions
 for select to authenticated using ((select auth.uid()) = user_id);
create policy "users manage own totp factors" on public.totp_factors
 for select to authenticated using ((select auth.uid()) = user_id);
create policy "users read own api keys" on public.api_keys
 for select to authenticated using ((select auth.uid()) = owner_id);
create policy "admins read vouchers" on public.vouchers
 for select to authenticated using (
   exists (select 1 from public.profiles p where p.user_id = (select auth.uid()) and p.role = 'admin')
);
create policy "admins read all redemptions" on public.voucher_redemptions
 for select to authenticated using (
   exists (select 1 from public.profiles p where p.user_id = (select auth.uid()) and p.role = 'admin')
);
create policy "admins read audit logs" on public.audit_logs
 for select to authenticated using (
   exists (select 1 from public.profiles p where p.user_id = (select auth.uid()) and p.role = 'admin')
);

-- No direct client INSERT/UPDATE/DELETE policies for vouchers, redemption records,
-- API keys, audit logs, or TOTP secrets. Privileged operations belong in Edge Functions.
revoke all on public.vouchers, public.voucher_redemptions, public.totp_factors,
  public.api_keys, public.audit_logs from anon, authenticated;
grant select on public.voucher_redemptions, public.totp_factors, public.api_keys to authenticated;
grant select on public.vouchers to authenticated;
grant select on public.profiles to authenticated;

create or replace function public.redeem_voucher(p_code_hash text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_voucher public.vouchers%rowtype;
begin
  if v_user is null then
    return jsonb_build_object('ok', false, 'error', 'authentication_required');
  end if;
  select * into v_voucher
    from public.vouchers
   where code_hash = p_code_hash
   for update;
  if not found or v_voucher.is_disabled then
    return jsonb_build_object('ok', false, 'error', 'invalid_voucher');
  end if;
  if v_voucher.expires_at is not null and v_voucher.expires_at <= now() then
    return jsonb_build_object('ok', false, 'error', 'expired_voucher');
  end if;
  if v_voucher.redemption_count >= v_voucher.max_redemptions then
    return jsonb_build_object('ok', false, 'error', 'voucher_exhausted');
  end if;
  if exists (select 1 from public.voucher_redemptions r
             where r.voucher_id = v_voucher.id and r.user_id = v_user) then
    return jsonb_build_object('ok', false, 'error', 'already_redeemed');
  end if;
  insert into public.voucher_redemptions(voucher_id, user_id)
  values (v_voucher.id, v_user);
  update public.vouchers set redemption_count = redemption_count + 1
   where id = v_voucher.id;
  insert into public.audit_logs(actor_id, action, target_type, target_id)
  values (v_user, 'voucher.redeem', 'voucher', v_voucher.id::text);
  return jsonb_build_object('ok', true, 'message', 'voucher_redeemed');
exception when unique_violation then
  return jsonb_build_object('ok', false, 'error', 'already_redeemed');
end;
$$;

revoke all on function public.redeem_voucher(text) from public, anon;
grant execute on function public.redeem_voucher(text) to authenticated;

-- Atomic TOTP replay prevention: the factor row can accept a step only once.
create or replace function public.accept_totp_step(p_factor_id uuid, p_step bigint, p_enable boolean default false)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_user uuid := auth.uid(); v_rows integer;
begin
 if v_user is null then return false; end if;
 update public.totp_factors
 set last_accepted_step=p_step,
     enabled=enabled or p_enable,
     enabled_at=case when p_enable and not enabled then now() else enabled_at end
 where id=p_factor_id and user_id=v_user
 and (last_accepted_step is null or last_accepted_step < p_step);
 get diagnostics v_rows = row_count;
 return v_rows = 1;
end;
$$;
revoke all on function public.accept_totp_step(uuid,bigint,boolean) from public, anon;
grant execute on function public.accept_totp_step(uuid,bigint,boolean) to authenticated;
