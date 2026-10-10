import { createClient } from "npm:@supabase/supabase-js@2.57.0";
const corsHeaders={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS","Content-Type":"application/json"};
const response=(status:number,body:unknown)=>new Response(JSON.stringify(body),{status,headers:corsHeaders});
async function currentUser(req:Request) {
 const url=Deno.env.get("SUPABASE_URL"), key=Deno.env.get("SUPABASE_ANON_KEY"), auth=req.headers.get("Authorization");
 if(!url||!key) throw new Error("server_not_configured"); if(!auth?.startsWith("Bearer ")) return null;
 const client=createClient(url,key,{global:{headers:{Authorization:auth}},auth:{persistSession:false,autoRefreshToken:false}});
 const {data,error}=await client.auth.getUser(); return error||!data.user?null:{user:data.user,client};
}
async function adminClient() {
 const url=Deno.env.get("SUPABASE_URL"),key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"); if(!url||!key) throw new Error("server_not_configured");
 return createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
}
async function isAdmin(uid:string) { const db=await adminClient(); const {data}=await db.from("profiles").select("role").eq("user_id",uid).maybeSingle(); return data?.role==="admin"; }
async function audit(actorId:string,action:string,targetType:string,targetId?:string) { const db=await adminClient(); await db.from("audit_logs").insert({actor_id:actorId,action,target_type:targetType,target_id:targetId??null}); }

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(bytes: Uint8Array) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function decode32(s: string) {
  let bits = 0, value = 0; const out: number[] = [];
  for (const c of s.replace(/=+$/,"").toUpperCase()) { const n = ALPHABET.indexOf(c); if (n < 0) throw new Error("invalid_secret"); value = (value << 5) | n; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
async function encryptionKey() {
  const raw = Deno.env.get("TOTP_ENCRYPTION_KEY");
  if (!raw) throw new Error("totp_encryption_key_missing");
  const bytes = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
  if (bytes.length !== 32) throw new Error("TOTP_ENCRYPTION_KEY_must_be_base64_32_bytes");
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt","decrypt"]);
}
async function encryptSecret(secret: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey();
  const cipher = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(secret));
  const all = new Uint8Array(iv.length + cipher.byteLength); all.set(iv); all.set(new Uint8Array(cipher), iv.length);
  return btoa(String.fromCharCode(...all));
}
async function decryptSecret(encoded: string) {
  const all = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
  const key = await encryptionKey();
  const plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv:all.slice(0,12) }, key, all.slice(12));
  return new TextDecoder().decode(plain);
}
async function codeAt(secret: string, step: number) {
  const key = await crypto.subtle.importKey("raw", decode32(secret), {name:"HMAC",hash:"SHA-1"}, false, ["sign"]);
  const msg = new Uint8Array(8); let n = BigInt(step);
  for (let i=7;i>=0;i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
  const offset = mac[mac.length-1] & 15;
  const bin = ((mac[offset]&127)<<24)|(mac[offset+1]<<16)|(mac[offset+2]<<8)|mac[offset+3];
  return String(bin % 1_000_000).padStart(6,"0");
}
async function verifiedStep(secret: string, input: string) {
  if (!/^\d{6}$/.test(input)) return null;
  const now = Math.floor(Date.now()/30000);
  for (const step of [now, now-1, now+1]) if (await codeAt(secret, step) === input) return step;
  return null;
}
Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok",{headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"authorization, apikey, content-type","Access-Control-Allow-Methods":"POST, OPTIONS"}});
  if (req.method !== "POST") return response(405,{error:"method_not_allowed"});
  try {
    const session = await currentUser(req);
    if (!session) return response(401,{error:"authentication_required"});
    let body: Record<string,unknown>;
    try { body = await req.json(); } catch { return response(400,{error:"invalid_json"}); }
    const db = await adminClient(), uid = session.user.id, action = body.action;
    if (action === "setup") {
      const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
      const label = typeof body.label === "string" ? body.label.slice(0,60) : "CODECORE";
      const { data, error } = await db.from("totp_factors").insert({user_id:uid,label,secret_ciphertext:await encryptSecret(secret),enabled:false}).select("id,label").single();
      if (error || !data) return response(500,{error:"factor_setup_failed"});
      const account = encodeURIComponent(session.user.email ?? uid);
      const issuer = encodeURIComponent("CODECORE");
      const uri = `otpauth://totp/${issuer}:${account}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
      await audit(uid,"totp.setup_started","totp_factor",data.id);
      return response(201,{factor:{id:data.id,label:data.label,provisioningUri:uri,secret,confirmationRequired:true}});
    }
    if (action === "confirm" || action === "verify") {
      const factorId = typeof body.factorId === "string" ? body.factorId : "";
      const code = typeof body.code === "string" ? body.code : "";
      const { data: factor } = await db.from("totp_factors").select("id,user_id,secret_ciphertext,enabled,last_accepted_step").eq("id",factorId).eq("user_id",uid).maybeSingle();
      if (!factor) return response(404,{error:"factor_not_found"});
      const secret = await decryptSecret(factor.secret_ciphertext);
      const step = await verifiedStep(secret,code);
      if (step === null) return response(400,{error:"invalid_code"});
      if (factor.last_accepted_step !== null && step <= Number(factor.last_accepted_step)) return response(409,{error:"code_already_used"});
      const { data: accepted, error } = await db.rpc("accept_totp_step",{p_factor_id:factor.id,p_step:step,p_enable:action==="confirm"});
      if (error) return response(500,{error:"verification_failed"});
      if (!accepted) return response(409,{error:"code_already_used"});
      await audit(uid,action==="confirm"?"totp.enabled":"totp.verified","totp_factor",factor.id);
      return response(200,{ok:true,enabled:true});
    }
    if (action === "list") {
      const { data, error } = await db.from("totp_factors").select("id,label,enabled,created_at,enabled_at").eq("user_id",uid).order("created_at",{ascending:false});
      if (error) return response(500,{error:"factor_list_failed"});
      return response(200,{factors:data});
    }
    if (action === "remove") {
      const id = typeof body.factorId === "string" ? body.factorId : "";
      const { error } = await db.from("totp_factors").delete().eq("id",id).eq("user_id",uid);
      if (error) return response(500,{error:"factor_remove_failed"});
      await audit(uid,"totp.removed","totp_factor",id);
      return response(200,{ok:true});
    }
    if (action === "admin_stats") {
      if (!await isAdmin(uid)) return response(403,{error:"admin_required"});
      const [v,r,a,u] = await Promise.all([
        db.from("vouchers").select("id,is_disabled,redemption_count,max_redemptions",{count:"exact",head:false}),
        db.from("voucher_redemptions").select("id",{count:"exact",head:true}),
        db.from("audit_logs").select("id,actor_id,action,target_type,target_id,details,created_at").order("created_at",{ascending:false}).limit(100),
        db.from("profiles").select("user_id",{count:"exact",head:true})
      ]);
      return response(200,{stats:{vouchers:v.data?.length??0,disabledVouchers:v.data?.filter(x=>x.is_disabled).length??0,redemptions:r.count??0,users:u.count??0},recentActivity:a.data??[]});
    }
    return response(400,{error:"unknown_action"});
  } catch (e) { return response(500,{error:e instanceof Error?e.message:"internal_error"}); }
});
