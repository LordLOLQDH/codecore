-- CODECORE multi-tenant shop and balance-voucher migration.
-- Applied to the connected Supabase project; this file records the schema changes.
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('user','shop_admin','admin','superadmin'));
update public.profiles set role='superadmin' where role='admin';

create table if not exists public.companies (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references auth.users(id) on delete cascade,
 name text not null check (length(trim(name)) between 2 and 120),
 integration_code text not null unique,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create index if not exists companies_owner_idx on public.companies(owner_id);
alter table public.vouchers add column if not exists company_id uuid references public.companies(id) on delete cascade;
alter table public.vouchers add column if not exists balance_cents bigint not null default 0 check (balance_cents>=0);
alter table public.vouchers add column if not exists initial_balance_cents bigint not null default 0 check (initial_balance_cents>=0);
alter table public.vouchers add column if not exists currency text not null default 'EUR' check (currency ~ '^[A-Z]{3}$');
alter table public.vouchers add column if not exists discount_percent numeric(5,2) check (discount_percent is null or (discount_percent>0 and discount_percent<=100));
alter table public.vouchers add column if not exists label text not null default 'Gutschein';
alter table public.voucher_redemptions drop constraint if exists voucher_redemptions_voucher_id_user_id_key;
alter table public.voucher_redemptions alter column user_id drop not null;
alter table public.voucher_redemptions add column if not exists amount_cents bigint not null default 0 check (amount_cents>=0);
alter table public.voucher_redemptions add column if not exists company_id uuid references public.companies(id) on delete set null;
create index if not exists voucher_redemptions_voucher_time_idx on public.voucher_redemptions(voucher_id,redeemed_at desc);

create table if not exists public.notifications (
 id bigint generated always as identity primary key,
 recipient_id uuid references auth.users(id) on delete cascade,
 company_id uuid references public.companies(id) on delete cascade,
 title text not null, body text not null, kind text not null default 'info',
 read_at timestamptz, created_at timestamptz not null default now()
);
create index if not exists notifications_recipient_idx on public.notifications(recipient_id,created_at desc);
alter table public.companies enable row level security;
alter table public.notifications enable row level security;
drop policy if exists "profile owner reads own profile" on public.profiles;
create policy "users read own profile" on public.profiles for select to authenticated using ((select auth.uid())=user_id);
drop policy if exists "admins read vouchers" on public.vouchers;
create policy "admins and company owners read vouchers" on public.vouchers for select to authenticated using (
 exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and p.role in ('admin','superadmin'))
 or exists(select 1 from public.companies c where c.id=vouchers.company_id and c.owner_id=(select auth.uid()))
);
create policy "company owners read own companies" on public.companies for select to authenticated using (
 owner_id=(select auth.uid()) or exists(select 1 from public.profiles p where p.user_id=(select auth.uid()) and p.role='superadmin')
);
create policy "users read own notifications" on public.notifications for select to authenticated using (recipient_id=(select auth.uid()));
grant select on public.companies,public.notifications to authenticated;

drop function if exists public.redeem_voucher(text);
create or replace function public.redeem_voucher(p_code_hash text,p_amount_cents bigint default 0,p_company_id uuid default null)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_user uuid:=auth.uid(); v_voucher public.vouchers%rowtype; v_deduct bigint; v_remaining bigint;
begin
 if v_user is null then return jsonb_build_object('ok',false,'error','authentication_required'); end if;
 if p_amount_cents<0 then return jsonb_build_object('ok',false,'error','invalid_amount'); end if;
 select * into v_voucher from public.vouchers where code_hash=p_code_hash for update;
 if not found or v_voucher.is_disabled then return jsonb_build_object('ok',false,'error','invalid_voucher'); end if;
 if v_voucher.expires_at is not null and v_voucher.expires_at<=now() then return jsonb_build_object('ok',false,'error','expired_voucher'); end if;
 if v_voucher.company_id is not null and p_company_id is not null and v_voucher.company_id<>p_company_id then return jsonb_build_object('ok',false,'error','wrong_shop'); end if;
 if v_voucher.balance_cents>0 or v_voucher.initial_balance_cents>0 then
  if p_amount_cents<=0 then return jsonb_build_object('ok',false,'error','amount_required'); end if;
  v_deduct:=least(p_amount_cents,v_voucher.balance_cents);
  if v_deduct<=0 then return jsonb_build_object('ok',false,'error','voucher_exhausted'); end if;
  update public.vouchers set balance_cents=balance_cents-v_deduct,redemption_count=redemption_count+1 where id=v_voucher.id returning balance_cents into v_remaining;
  insert into public.voucher_redemptions(voucher_id,user_id,amount_cents,company_id) values(v_voucher.id,v_user,v_deduct,p_company_id);
  insert into public.audit_logs(actor_id,action,target_type,target_id,details) values(v_user,'voucher.redeem','voucher',v_voucher.id::text,jsonb_build_object('amount_cents',v_deduct,'remaining_cents',v_remaining));
  return jsonb_build_object('ok',true,'message','voucher_redeemed','deducted_cents',v_deduct,'remaining_cents',v_remaining,'currency',v_voucher.currency);
 end if;
 if v_voucher.redemption_count>=v_voucher.max_redemptions then return jsonb_build_object('ok',false,'error','voucher_exhausted'); end if;
 insert into public.voucher_redemptions(voucher_id,user_id,amount_cents,company_id) values(v_voucher.id,v_user,p_amount_cents,p_company_id);
 update public.vouchers set redemption_count=redemption_count+1 where id=v_voucher.id;
 insert into public.audit_logs(actor_id,action,target_type,target_id) values(v_user,'voucher.redeem','voucher',v_voucher.id::text);
 return jsonb_build_object('ok',true,'message','voucher_redeemed','remaining_cents',0,'currency',v_voucher.currency);
exception when unique_violation then return jsonb_build_object('ok',false,'error','already_redeemed');
end; $$;
revoke all on function public.redeem_voucher(text,bigint,uuid) from public,anon;
grant execute on function public.redeem_voucher(text,bigint,uuid) to authenticated;

create or replace function public.redeem_shop_voucher(p_integration_code text,p_code_hash text,p_amount_cents bigint)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_company public.companies%rowtype; v_voucher public.vouchers%rowtype; v_deduct bigint; v_remaining bigint;
begin
 if p_amount_cents is null or p_amount_cents<=0 or p_amount_cents>100000000 then return jsonb_build_object('ok',false,'error','invalid_amount'); end if;
 select * into v_company from public.companies where integration_code=p_integration_code;
 if not found then return jsonb_build_object('ok',false,'error','invalid_shop'); end if;
 select * into v_voucher from public.vouchers where code_hash=p_code_hash and company_id=v_company.id for update;
 if not found or v_voucher.is_disabled then return jsonb_build_object('ok',false,'error','invalid_voucher'); end if;
 if v_voucher.expires_at is not null and v_voucher.expires_at<=now() then return jsonb_build_object('ok',false,'error','expired_voucher'); end if;
 if v_voucher.initial_balance_cents<=0 then return jsonb_build_object('ok',false,'error','not_a_balance_voucher'); end if;
 if v_voucher.redemption_count>=v_voucher.max_redemptions then return jsonb_build_object('ok',false,'error','voucher_exhausted'); end if;
 v_deduct:=least(p_amount_cents,v_voucher.balance_cents);
 if v_deduct<=0 then return jsonb_build_object('ok',false,'error','voucher_exhausted'); end if;
 update public.vouchers set balance_cents=balance_cents-v_deduct,redemption_count=redemption_count+1 where id=v_voucher.id returning balance_cents into v_remaining;
 insert into public.voucher_redemptions(voucher_id,user_id,amount_cents,company_id) values(v_voucher.id,null,v_deduct,v_company.id);
 insert into public.audit_logs(actor_id,action,target_type,target_id,details) values(null,'shop.voucher_redeem','voucher',v_voucher.id::text,jsonb_build_object('company_id',v_company.id,'amount_cents',v_deduct,'remaining_cents',v_remaining));
 return jsonb_build_object('ok',true,'deducted_cents',v_deduct,'remaining_cents',v_remaining,'currency',v_voucher.currency);
end; $$;
revoke all on function public.redeem_shop_voucher(text,text,bigint) from public;
grant execute on function public.redeem_shop_voucher(text,text,bigint) to anon,authenticated;
