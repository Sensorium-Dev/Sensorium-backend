// netlify/edge-functions/password-gate.ts
//
// Gates every page on this site behind a shared password, and logs
// who entered it and when to your Google Sheet via the same Apps
// Script backend the calculator already talks to.
//
// SETUP (same as before — nothing new to configure if you already
// have PROTECTED_PAGE_PASSWORD set):
// 1. Netlify: Site configuration → Environment variables →
//      PROTECTED_PAGE_PASSWORD = (your password)
// 2. Commit this file at exactly: netlify/edge-functions/password-gate.ts
// 3. Keep netlify.toml as-is from before.
//
// The APPS_SCRIPT_URL below is the same URL already used in the
// calculator's client-side JS — it's not a secret (it's visible in
// the page source anyway), so it's fine hardcoded here directly.

const APPS_SCRIPT_URL = 'https://script.google.com/macros/s/AKfycbzsaKmv5c6T88iKIN0rfg7QxEVQcWsbuHDxeymKZkabQ2XWch0rEIedfKi73iZop-M6/exec';

export default async (request: Request, context: any) => {
  const correctPassword = Deno.env.get("PROTECTED_PAGE_PASSWORD");

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

  // Handle password + name form submission
  if (request.method === "POST") {
    const form = await request.formData();
    const attempt = form.get("password");
    const name = String(form.get("name") || "").trim();

    if (attempt === correctPassword && name) {
      // Log the access — failures here never block login, they just don't get logged
      try {
        await fetch(APPS_SCRIPT_URL, {
          method: "POST",
          headers: { "Content-Type": "text/plain;charset=utf-8" },
          body: JSON.stringify({
            "form-name": "portal-access-log",
            name: name,
            userAgent: request.headers.get("user-agent") || "",
          }),
        });
      } catch (err) {
        console.error("Access log failed:", err);
      }

      // KEY FIX: redirect back to the same URL as a fresh GET, instead of
      // trying to hand this POST straight through. Netlify's static hosting
      // only serves pages via GET — passing the POST through caused the
      // blank "form load error" page you were seeing.
      const redirectUrl = new URL(request.url);
      return new Response(null, {
        status: 302,
        headers: {
          "Location": redirectUrl.toString(),
          "Set-Cookie": [
            `sensorium_auth=${correctPassword}; Path=/; HttpOnly; Max-Age=2592000; SameSite=Lax; Secure`,
            `sensorium_user=${encodeURIComponent(name)}; Path=/; Max-Age=2592000; SameSite=Lax; Secure`,
          ].join(", "),
        },
      });
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
  input[type=text],input[type=password]{width:100%;padding:11px 12px;border-radius:7px;
    border:1px solid rgba(201,162,75,0.4);background:rgba(0,0,0,0.3);color:#f4efe4;
    font-size:14px;box-sizing:border-box;margin-bottom:12px;}
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
    ${failed ? '<div class="err">Incorrect password or missing name — try again.</div>' : ""}
    <form method="POST">
      <input type="text" name="name" placeholder="Your name" autofocus required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Enter</button>
    </form>
  </div>
</body>
</html>`;
}

export const config = { path: "/*" };
