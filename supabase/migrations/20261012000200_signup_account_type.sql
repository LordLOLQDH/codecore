alter table public.profiles add column if not exists account_type text not null default 'user' check (account_type in ('user','shop'));
create or replace function public.handle_codecore_new_user()
returns trigger language plpgsql security definer set search_path=''
as $$
begin
 insert into public.profiles(user_id,display_name,role,account_type)
 values(new.id,coalesce(new.raw_user_meta_data->>'display_name',new.email,''),'user',
   case when new.raw_user_meta_data->>'account_type'='shop' then 'shop' else 'user' end)
 on conflict(user_id) do nothing;
 return new;
end; $$;
revoke all on function public.handle_codecore_new_user() from public,anon,authenticated;