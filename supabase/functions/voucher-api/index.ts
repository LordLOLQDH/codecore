import { createClient } from "npm:@supabase/supabase-js@2.57.0";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: cors });
const sha256 = async (value: string) => {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
};
const randomCode = () => {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("").match(/.{1,5}/g)!.join("-");
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  const url = Deno.env.get("SUPABASE_URL");
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anonKey || !serviceKey) return json(500, { error: "server_not_configured" });

  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return json(401, { error: "authentication_required" });

  const userClient = createClient(url, anonKey, {
    global: { headers: { Authorization: authHeader } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: userData, error: userError } = await userClient.auth.getUser();
  if (userError || !userData.user) return json(401, { error: "invalid_session" });

  const adminClient = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json(400, { error: "invalid_json" });
  }
  const action = body.action;

  if (action === "redeem") {
    const code = typeof body.code === "string" ? body.code.trim().toUpperCase() : "";
    if (!/^[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/.test(code)) {
      return json(400, { error: "invalid_voucher_format" });
    }
    const codeHash = await sha256(code);
    const { data, error } = await userClient.rpc("redeem_voucher", { p_code_hash: codeHash });
    if (error) return json(500, { error: "redemption_failed" });
    const result = data as { ok?: boolean; error?: string; message?: string };
    return json(result.ok ? 200 : 400, result);
  }

  const { data: profile, error: profileError } = await adminClient
    .from("profiles").select("role").eq("user_id", userData.user.id).maybeSingle();
  if (profileError || profile?.role !== "admin") return json(403, { error: "admin_required" });

  if (action === "create") {
    const maxRedemptions = Number(body.maxRedemptions ?? 1);
    if (!Number.isInteger(maxRedemptions) || maxRedemptions < 1 || maxRedemptions > 100000) {
      return json(400, { error: "invalid_redemption_limit" });
    }
    let expiresAt: string | null = null;
    if (body.expiresAt !== undefined && body.expiresAt !== null && body.expiresAt !== "") {
      const parsed = new Date(String(body.expiresAt));
      if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
        return json(400, { error: "invalid_expiration" });
      }
      expiresAt = parsed.toISOString();
    }
    const code = randomCode();
    const { data, error } = await adminClient.from("vouchers").insert({
      code_hash: await sha256(code),
      code_hint: code.slice(-5),
      created_by: userData.user.id,
      max_redemptions: maxRedemptions,
      expires_at: expiresAt,
    }).select("id,code_hint,expires_at,max_redemptions").single();
    if (error || !data) return json(500, { error: "voucher_creation_failed" });
    await adminClient.from("audit_logs").insert({
      actor_id: userData.user.id, action: "voucher.create", target_type: "voucher",
      target_id: data.id, details: { max_redemptions: maxRedemptions, expires_at: expiresAt },
    });
    // Raw code is returned once. The database stores only its SHA-256 hash.
    return json(201, { voucher: { ...data, code } });
  }

  if (action === "disable") {
    const id = typeof body.id === "string" ? body.id : "";
    if (!/^[0-9a-f-]{36}$/i.test(id)) return json(400, { error: "invalid_voucher_id" });
    const { data, error } = await adminClient.from("vouchers")
      .update({ is_disabled: true }).eq("id", id).select("id,is_disabled").maybeSingle();
    if (error || !data) return json(404, { error: "voucher_not_found" });
    await adminClient.from("audit_logs").insert({
      actor_id: userData.user.id, action: "voucher.disable", target_type: "voucher", target_id: id,
    });
    return json(200, { voucher: data });
  }

  return json(400, { error: "unknown_action" });
});
