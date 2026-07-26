// netlify/edge-functions/password-gate.ts
//
// Gates every page on this site behind a single shared password.
// Runs server-side on Netlify's free tier — no Pro plan needed.
//
// SETUP:
// 1. In Netlify: Site configuration → Environment variables → Add variable
//      Key:   PROTECTED_PAGE_PASSWORD
//      Value: (choose a real password)
// 2. Commit this file at exactly this path: netlify/edge-functions/password-gate.ts
// 3. Also commit the netlify.toml below (or merge into your existing one).
// 4. Push — Netlify redeploys automatically and the gate goes live.
//
// Session lasts 30 days per browser once someone enters the correct
// password — they won't be asked again until it expires or they clear
// cookies. This is meant for a small trusted internal team, not for
// anything holding sensitive financial or personal data long-term —
// when you build real logins later (Supabase), swap this out.

export default async (request: Request, context: any) => {
  const correctPassword = Deno.env.get("PROTECTED_PAGE_PASSWORD");

  // Fail closed: if the env var isn't set, block everything with a clear message
  // rather than accidentally leaving the site open.
  if (!correctPassword) {
    return new Response(
      "Site protection is misconfigured — PROTECTED_PAGE_PASSWORD is not set in Netlify environment variables.",
      { status: 500, headers: { "content-type": "text/plain" } }
    );
  }

  const cookieHeader = request.headers.get("cookie") || "";
  const isAuthed = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .includes(`sensorium_auth=${correctPassword}`);

  if (isAuthed) {
    return context.next();
  }

  // Handle password form submission
  if (request.method === "POST") {
    const form = await request.formData();
    const attempt = form.get("password");

    if (attempt === correctPassword) {
      const response = await context.next();
      const newHeaders = new Headers(response.headers);
      newHeaders.append(
        "Set-Cookie",
        `sensorium_auth=${correctPassword}; Path=/; HttpOnly; Max-Age=2592000; SameSite=Lax; Secure`
      );
      return new Response(response.body, { status: response.status, headers: newHeaders });
    }

    return new Response(renderForm(true), {
      status: 401,
      headers: { "content-type": "text/html" },
    });
  }

  return new Response(renderForm(false), {
    status: 401,
    headers: { "content-type": "text/html" },
  });
};

function renderForm(failed: boolean): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sensorium — Internal Access</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:linear-gradient(135deg,#2e1a47 0%,#4a2d6b 55%,#b1583c 130%);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
  .box{background:rgba(0,0,0,0.35);border:1px solid rgba(201,162,75,0.4);border-radius:14px;
    padding:36px 32px;max-width:340px;width:90%;text-align:center;}
  h1{color:#f4efe4;font-size:20px;margin:0 0 6px;letter-spacing:1px;}
  p{color:rgba(244,239,228,0.6);font-size:13px;margin:0 0 20px;}
  input[type=password]{width:100%;padding:11px 12px;border-radius:7px;border:1px solid rgba(201,162,75,0.4);
    background:rgba(0,0,0,0.3);color:#f4efe4;font-size:14px;box-sizing:border-box;margin-bottom:12px;}
  button{width:100%;padding:11px;border:none;border-radius:7px;background:#c9a24b;color:#1a1420;
    font-weight:700;font-size:14px;cursor:pointer;}
  button:hover{background:#e6c675;}
  .err{color:#e8a58a;font-size:12px;margin-bottom:12px;}
</style>
</head>
<body>
  <div class="box">
    <h1>SENSORIUM</h1>
    <p>Internal access only</p>
    ${failed ? '<div class="err">Incorrect password — try again.</div>' : ""}
    <form method="POST">
      <input type="password" name="password" placeholder="Password" autofocus required>
      <button type="submit">Enter</button>
    </form>
  </div>
</body>
</html>`;
}

export const config = { path: "/*" };
