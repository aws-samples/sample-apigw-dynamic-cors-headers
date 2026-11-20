// Browser demo for the dynamic CORS pattern.
// Renders results via textContent / DOM nodes (no raw HTML strings) so the page
// models safe DOM handling under a strict Content-Security-Policy.
//
// API_ENDPOINT is a hardcoded constant (not user input) — the recommended way to
// avoid SSRF-style findings in a static demo. Set it to your deployed /hello URL
// before serving the page.
const API_ENDPOINT =
  "https://REPLACE_WITH_API_ID.execute-api.us-east-1.amazonaws.com/prod/hello";

document.getElementById("origin").textContent = window.location.origin;
document.getElementById("endpoint").textContent = API_ENDPOINT;
const out = document.getElementById("out");

function render(cls, label, rest) {
  out.textContent = "";
  const span = document.createElement("span");
  span.className = cls;
  span.textContent = label;
  out.append(span, rest);
}

document.getElementById("go").addEventListener("click", async () => {
  if (API_ENDPOINT.includes("REPLACE_WITH_API_ID")) {
    render(
      "err",
      "NOT CONFIGURED",
      " — set API_ENDPOINT in app.js to your deployed /hello URL first."
    );
    return;
  }
  out.textContent = "Sending…";
  try {
    // A cross-origin request with a non-simple method triggers the browser's
    // CORS preflight. If this page's origin isn't allowlisted, the browser throws.
    const res = await fetch(API_ENDPOINT, {
      method: "OPTIONS",
      headers: { "Access-Control-Request-Method": "GET" },
    });
    render(
      "ok",
      "CORS ALLOWED",
      ` — this origin is on the allowlist.\nHTTP status: ${res.status}`
    );
  } catch (e) {
    render(
      "err",
      "CORS BLOCKED",
      " — this origin is NOT on the allowlist.\n" +
        "The browser refused to expose the response.\n\n" +
        `Error: ${e}`
    );
  }
});
