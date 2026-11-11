import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (request.method !== "POST") {
    return Response.json({ error: "Method not allowed" }, { status: 405, headers: corsHeaders });
  }

  const username = Deno.env.get("ADMIN_USERNAME");
  const email = Deno.env.get("ADMIN_EMAIL");
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const publishableKey = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS") ?? Deno.env.get("SUPABASE_ANON_KEY");
  if (!username || !email || !supabaseUrl || !publishableKey) {
    return Response.json({ error: "Admin login is not configured" }, { status: 503, headers: corsHeaders });
  }

  try {
    const body = await request.json();
    if (typeof body.username !== "string" || typeof body.password !== "string" ||
        body.username.trim().toLowerCase() !== username.trim().toLowerCase() || body.password.length < 1) {
      return Response.json({ error: "Invalid credentials" }, { status: 401, headers: corsHeaders });
    }

    const supabase = createClient(supabaseUrl, publishableKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data, error } = await supabase.auth.signInWithPassword({ email, password: body.password });
    if (error || !data.session || data.user.email?.toLowerCase() !== email.toLowerCase()) {
      return Response.json({ error: "Invalid credentials" }, { status: 401, headers: corsHeaders });
    }

    return Response.json({ session: data.session }, { headers: corsHeaders });
  } catch {
    return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders });
  }
});
