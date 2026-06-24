#!/usr/bin/env python3
# Reddit logged-in capture. Run by the USER (via `!`): reads the reddit jar from
# Chrome, injects it into the running tee-browser, navigates logged-in, captures
# the authenticated app traffic. Prints a REDACTED summary (no cookie values).
#
#   ! python3 test/inject-cookies-reddit.py
#
# Stack must be up: cd tee-browser && docker compose up -d --build  (assistant does this).
import browser_cookie3 as bc, json, time, urllib.request as u

BRIDGE = "http://localhost:3002"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def post(path, body):
    req = u.Request(BRIDGE + path, data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
    return json.load(u.urlopen(req, timeout=90))


cookies = []
for c in bc.chrome(domain_name=".reddit.com"):
    cookies.append({
        "name": c.name, "value": c.value, "domain": c.domain, "path": c.path or "/",
        "secure": bool(c.secure), "httpOnly": bool(c.has_nonstandard_attr("HttpOnly")),
        # valid chrome.cookies.set enums only ("None" is INVALID and gets rejected)
        "sameSite": "no_restriction" if c.secure else "lax",
        **({"expires": c.expires} if c.expires else {}),
    })
names = {c["name"] for c in cookies}
print(f"[1] read {len(cookies)} reddit cookies (reddit_session present: {'reddit_session' in names})")
if "reddit_session" not in names:
    raise SystemExit("not logged into reddit.com in Chrome — log in and retry")

post("/session", {"cookies": cookies, "userAgent": UA})
print("[2] injected session into tee-browser")

post("/navigate", {"url": "https://www.reddit.com"})
time.sleep(5)
trace = post("/capture-trace", {})
dom = trace.get("dom_html") or ""
logged_out = ("Continue with Email" in dom) or ("Join the most real place" in dom)
print(f"[3] logged-in: {not logged_out}   (title: {trace.get('title')!r})")

log = trace.get("network_log") or []
api = [e for e in log if any(h in (e.get("url") or "") for h in
       ("gql-fed.reddit.com", "/svc/shreddit", "/api/")) and e.get("type") in ("Fetch", "XHR")]
print(f"[4] captured {len(log)} requests ({len(api)} authenticated API/XHR)")
for e in api[:8]:
    print(f"     {e.get('method','?'):4} {e.get('status','?')}  {(e.get('url') or '').split('?')[0][:64]}")
print(f"[5] artifacts: /tmp/proof-artifacts/{trace.get('artifactDir')}   dom={len(dom)} chars")
print("\nLOGGED-IN BROWSER CAPTURE OK" if not logged_out else "\nSTILL LOGGED OUT — cookies not authenticating, tell the assistant")
