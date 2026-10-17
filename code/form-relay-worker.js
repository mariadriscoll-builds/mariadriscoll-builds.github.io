/**
 * Form relay — Cloudflare Worker
 * ------------------------------
 * Portfolio sample by Maria Driscoll. Production code with company-specific
 * names, domains and form names replaced by generic ones.
 *
 * Sits between a marketing website's forms and the marketing-automation
 * platform's form handlers (Salesforce Marketing Cloud Account Engagement,
 * formerly Pardot). Every submission must pass two checks before it is
 * forwarded:
 *   1. Honeypot ("company_website" must be empty), checked server-side,
 *      so bots that POST directly can no longer bypass it.
 *   2. Cloudflare Turnstile token verification (proves a real browser).
 *
 * The form-handler URLs live ONLY in this Worker's environment variables.
 * They no longer appear anywhere in the site HTML, so bots can't scrape them.
 *
 * Required environment variables (Worker > Settings > Variables):
 *   TURNSTILE_SECRET        - secret key from the Turnstile widget (encrypt it)
 *   GUIDE_HANDLER_URL       - handler for the downloadable guide form
 *   SALES_HANDLER_URL       - handler for "Talk to sales"
 *   CALCULATOR_HANDLER_URL  - handler for the ROI calculator's email gate
 *   CALC_UPDATE_HANDLER_URL - handler that only writes calculator values.
 *                             It MUST have ZERO completion actions. See below.
 *   TICKET_SECRET           - any long random string (encrypt it). Signs update tickets.
 * Optional:
 *   ALLOWED_ORIGINS         - comma-separated origins allowed to call this Worker.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE TWO-STAGE CALCULATOR CAPTURE
 * ─────────────────────────────────────────────────────────────────────────────
 * Problem: on the calculator page the email gate comes BEFORE the tool. At the
 * moment someone submits their email, the sliders are still at defaults, so
 * there is no real number to capture. Their actual figure only exists after
 * they start moving sliders, which is after the form is already submitted.
 *
 * So the page posts TWICE:
 *   Stage 1  form=calculator         -> CALCULATOR_HANDLER_URL   (Turnstile-verified)
 *            Creates the prospect. Fires ALL completion actions: autoresponder,
 *            notify the sales owner, add to list, set engagement stage.
 *            On success the Worker returns a signed TICKET.
 *
 *   Stage 2  form=calculator-update  -> CALC_UPDATE_HANDLER_URL  (ticket-verified)
 *            Sent after they've moved the sliders. Writes calc_* values onto the
 *            SAME prospect (the platform upserts on email). May fire repeatedly
 *            as they keep adjusting; the last one wins.
 *
 * WHY A SECOND HANDLER, NOT THE SAME ONE:
 * A form handler runs ALL of its completion actions on EVERY submission.
 * Re-posting to the stage-1 handler would resend the autoresponder and re-notify
 * sales every time a slider moved. The update handler exists only to write fields.
 *
 * WHY A TICKET, NOT TURNSTILE:
 * Turnstile tokens are single-use, and the widget lives inside the gate that is
 * hidden on reveal, so re-issuing a token from it is unreliable. Instead, stage 1
 * returns an HMAC of (email + expiry) signed with TICKET_SECRET. Stage 2 presents
 * it. Bots can't forge it without the secret, so no spam hole is reopened, and the
 * update route can't write arbitrary data to arbitrary prospects: the ticket binds
 * the update to ONE email address.
 *
 * Tickets expire after 2 hours. Stage 2 failing is harmless by design: the lead
 * is already captured in stage 1; we just don't learn their numbers.
 */

const TICKET_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

// Fields the calculator is allowed to write in stage 2. Anything else is dropped,
// so a leaked ticket can't be used to overwrite name, company, opt-out status, etc.
const CALC_FIELDS = new Set([
  "calc_tons",
  "calc_capture_rate",
  "calc_bonus_per_ton",
  "calc_penalties",
  "calc_total_leak",
]);

const b64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64url(sig);
}

/** Ticket format: base64url(email|expiryMs).signature */
async function issueTicket(email, secret) {
  const payload = `${email}|${Date.now() + TICKET_TTL_MS}`;
  const sig = await sign(payload, secret);
  return `${b64url(new TextEncoder().encode(payload))}.${sig}`;
}

/** Returns the email the ticket is bound to, or null if invalid/expired. */
async function readTicket(ticket, secret) {
  try {
    const [body, sig] = String(ticket).split(".");
    if (!body || !sig) return null;
    const payload = new TextDecoder().decode(
      Uint8Array.from(atob(body.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))
    );
    const expected = await sign(payload, secret);
    // Constant-time-ish compare: lengths first, then char-by-char accumulate.
    if (expected.length !== sig.length) return null;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
    if (diff !== 0) return null;

    const sep = payload.lastIndexOf("|");
    const email = payload.slice(0, sep);
    const exp = Number(payload.slice(sep + 1));
    if (!email || !Number.isFinite(exp) || Date.now() > exp) return null;
    return email;
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGINS || "https://www.example.com")
      .split(",").map((s) => s.trim()).filter(Boolean);

    const cors = {
      "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : allowed[0],
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (origin && !allowed.includes(origin)) return json({ ok: false, error: "bad_origin" }, 403);

    let form;
    try {
      form = await request.formData();
    } catch {
      return json({ ok: false, error: "bad_body" }, 400);
    }

    const formName = (form.get("form") || "").toString();

    // ───────────────────────────────────────────────────────────────────────
    // STAGE 2 — calculator value update. Ticket-verified, no Turnstile.
    // Handled BEFORE the Turnstile block, because this request has no token.
    // Writes fields only; the destination handler has no completion actions.
    // ───────────────────────────────────────────────────────────────────────
    if (formName === "calculator-update") {
      const dest = env.CALC_UPDATE_HANDLER_URL;
      // Not configured yet -> silently accept and do nothing. The lead is already
      // captured by stage 1; we simply don't learn their numbers. NEVER error here.
      if (!dest || !env.TICKET_SECRET) return json({ ok: true, stored: false });

      const email = await readTicket(form.get("ticket"), env.TICKET_SECRET);
      if (!email) return json({ ok: false, error: "bad_ticket" }, 403);

      // The ticket dictates the email. We do NOT trust an email in the request body.
      const body = new URLSearchParams();
      body.append("email", email);
      for (const [k, v] of form.entries()) {
        if (CALC_FIELDS.has(k)) body.append(k, v.toString());
      }

      const relay = await fetch(dest, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        redirect: "manual",
      });
      if (relay.status >= 200 && relay.status < 400) return json({ ok: true, stored: true });
      return json({ ok: false, error: "handler_error" }, 502);
    }

    // ───────────────────────────────────────────────────────────────────────
    // STAGE 1 — normal form submission. Unchanged behaviour.
    // ───────────────────────────────────────────────────────────────────────

    // Honeypot filled -> it's a bot. Return fake success so bots don't adapt.
    if ((form.get("company_website") || "").toString().trim() !== "") return json({ ok: true });

    // Verify the Turnstile token.
    const token = form.get("cf-turnstile-response");
    if (!token) return json({ ok: false, error: "missing_token" }, 403);
    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET,
        response: token.toString(),
        remoteip: request.headers.get("CF-Connecting-IP") || undefined,
      }),
    });
    const outcome = await verify.json();
    if (!outcome.success) return json({ ok: false, error: "verification_failed" }, 403);

    // Route to the right MCAE form handler.
    const dest = {
      "guide": env.GUIDE_HANDLER_URL,
      "talk-to-sales": env.SALES_HANDLER_URL,
      // ROI calculator. Falls back to the guide handler if CALCULATOR_HANDLER_URL
      // isn't set yet, so leads are captured rather than dropped.
      "calculator": env.CALCULATOR_HANDLER_URL || env.GUIDE_HANDLER_URL,
    }[formName];
    if (!dest) return json({ ok: false, error: "unknown_form" }, 400);

    // Forward everything except our control fields.
    const body = new URLSearchParams();
    for (const [k, v] of form.entries()) {
      if (k === "cf-turnstile-response" || k === "company_website" || k === "form" || k === "ticket") continue;
      body.append(k, v.toString());
    }
    const relay = await fetch(dest, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      redirect: "manual", // The handler replies with a redirect; we just need it accepted
    });
    if (relay.status < 200 || relay.status >= 400) return json({ ok: false, error: "handler_error" }, 502);

    // Success. For the calculator, hand back a signed ticket so the page can post
    // the slider values once the user has actually moved them (stage 2 above).
    // Wrapped so that a ticket failure can NEVER turn a successful capture into an
    // error — worst case the page just doesn't get a ticket and skips stage 2.
    if (formName === "calculator" && env.TICKET_SECRET) {
      try {
        const email = (form.get("email") || "").toString().trim();
        if (email) return json({ ok: true, ticket: await issueTicket(email, env.TICKET_SECRET) });
      } catch { /* fall through to plain ok */ }
    }
    return json({ ok: true });
  },
};
