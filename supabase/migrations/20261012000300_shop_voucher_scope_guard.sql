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
 if v_voucher.company_id is not null and (p_company_id is null or p_company_id<>v_voucher.company_id) then return jsonb_build_object('ok',false,'error','wrong_shop'); end if;
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