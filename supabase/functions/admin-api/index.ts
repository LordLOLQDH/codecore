import { createClient } from "npm:@supabase/supabase-js@2.57.0";
const corsHeaders={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type, x-retry-count, traceparent, tracestate, baggage","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const response=(status:number,body:unknown)=>new Response(JSON.stringify(body),{status,headers:corsHeaders});
async function currentUser(req:Request) {
 const url=Deno.env.get("SUPABASE_URL"),key=Deno.env.get("SUPABASE_ANON_KEY"),auth=req.headers.get("Authorization");
 if(!url||!key) throw new Error("server_not_configured"); if(!auth?.startsWith("Bearer ")) return null;
 const client=createClient(url,key,{global:{headers:{Authorization:auth}},auth:{persistSession:false,autoRefreshToken:false}});
 const {data,error}=await client.auth.getUser(); return error||!data.user?null:{user:data.user,client};
}
async function adminClient() {
 const url=Deno.env.get("SUPABASE_URL"),key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"); if(!url||!key) throw new Error("server_not_configured");
 return createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
}
async function isAdmin(uid:string) { const db=await adminClient(); const {data}=await db.from("profiles").select("role").eq("user_id",uid).maybeSingle(); return data?.role==="admin"; }
async function audit(actorId:string,action:string,targetType:string,targetId?:string,details:Record<string,unknown>={}) { const db=await adminClient(); await db.from("audit_logs").insert({actor_id:actorId,action,target_type:targetType,target_id:targetId??null,details}); }
Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok",{headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, x-client-info, apikey, content-type, x-retry-count, traceparent, tracestate, baggage","Access-Control-Allow-Methods":"POST, OPTIONS"}});
  if (req.method !== "POST") return response(405,{error:"method_not_allowed"});
  const session = await currentUser(req);
  if (!session) return response(401,{error:"authentication_required"});
  if (!await isAdmin(session.user.id)) return response(403,{error:"admin_required"});
  let body: Record<string,unknown>;
  try { body = await req.json(); } catch { return response(400,{error:"invalid_json"}); }
  const db = await adminClient();
  if (body.action === "overview") {
    const [v,r,p,a] = await Promise.all([
      db.from("vouchers").select("id,is_disabled,redemption_count,max_redemptions,expires_at,created_at",{count:"exact"}),
      db.from("voucher_redemptions").select("id",{count:"exact",head:true}),
      db.from("profiles").select("user_id",{count:"exact",head:true}),
      db.from("audit_logs").select("id,actor_id,action,target_type,target_id,details,created_at").order("created_at",{ascending:false}).limit(100)
    ]);
    if (v.error || r.error || p.error || a.error) return response(500,{error:"admin_query_failed"});
    return response(200,{stats:{vouchers:v.count??0,activeVouchers:(v.data??[]).filter(x=>!x.is_disabled&&(!x.expires_at||new Date(x.expires_at)>new Date())&&x.redemption_count<x.max_redemptions).length,disabledVouchers:(v.data??[]).filter(x=>x.is_disabled).length,redemptions:r.count??0,users:p.count??0},vouchers:v.data??[],activity:a.data??[]});
  }
  if (body.action === "set_role") {
    const userId = typeof body.userId==="string"?body.userId:"";
    const role = body.role;
    if (!/^[0-9a-f-]{36}$/i.test(userId) || !["admin","user"].includes(String(role))) return response(400,{error:"invalid_input"});
    if (userId === session.user.id && role === "user") return response(400,{error:"cannot_remove_own_admin_role"});
    const {error} = await db.from("profiles").upsert({user_id:userId,role},{onConflict:"user_id"});
    if (error) return response(500,{error:"role_update_failed"});
    await audit(session.user.id,"admin.role_changed","profile",userId,{role});
    return response(200,{ok:true});
  }
  return response(400,{error:"unknown_action"});
});
