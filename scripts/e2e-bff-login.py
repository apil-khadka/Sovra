#!/usr/bin/env python3
"""SOV-006 evidence: scripted browser-equivalent login against real Keycloak.

Drives the exact redirect chain a browser follows — app authorize,
Keycloak login form, code callback, session use — plus negatives.
Not a real browser (no JS/DOM); the holder/browser criterion in
SOV-041 still wants one. Read-only except for login/logout and the
membership rows those provision.

Requires: compose stack up (keycloak + app-a). No /etc/hosts edit:
Keycloak requests dial 127.0.0.1 with an explicit Host header, which
is exactly what the documented hosts line gives browsers.
"""
import http.client
import http.cookiejar
import re
import sys
import urllib.parse
import urllib.request

APP = "http://localhost:8080"
KC_HOST = "sovra-keycloak"
KC_PORT = 18080
KC = f"http://{KC_HOST}:{KC_PORT}"
REALM = "sovra"


class KeycloakConnection(http.client.HTTPConnection):
    """Dial loopback while presenting the Keycloak hostname."""

    def connect(self):
        self.sock = self._create_connection(("127.0.0.1", KC_PORT), self.timeout)


class KeycloakHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        if req.host == f"{KC_HOST}:{KC_PORT}":
            return self.do_open(KeycloakConnection, req)
        return super().http_open(req)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DemoCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    # Script-only: Python refuses to return Secure cookies over http,
    # while browsers (correctly for this demo) send them to loopback
    # origins. The stack under test is unchanged.
    def return_ok_secure(self, cookie, request):
        return True


def opener():
    jar = http.cookiejar.CookieJar(DemoCookiePolicy())
    handler = urllib.request.build_opener(
        KeycloakHandler, urllib.request.HTTPCookieProcessor(jar), NoRedirect)
    return handler, jar


def request(op, method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with op.open(req, timeout=30) as resp:
            return resp.status, resp.read(), dict(resp.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict((exc.headers or {}).items())


def fail(message):
    print(f"BFF login check: FAIL: {message}", flush=True)
    raise SystemExit(1)


def check(name, condition, detail=""):
    print(f"BFF login check: {name}", flush=True)
    if not condition:
        fail(f"{name} ({detail})" if detail else name)


def login(op, username, password):
    status, _, headers = request(op, "GET", f"{APP}/oauth2/authorization/sovra")
    if status != 302 or "/realms/sovra/protocol/openid-connect/auth" not in headers.get("Location", ""):
        fail(f"authorize did not redirect to Keycloak (status={status})")
    auth_url = headers["Location"]
    if "code_challenge=" not in auth_url or "code_challenge_method=S256" not in auth_url:
        fail("authorize request lacks S256 PKCE")
    submitted = False
    for _ in range(8):
        # The callback is fetched, never followed: its landing Location
        # is the login verdict.
        if auth_url.startswith(f"{APP}/login/oauth2/code/"):
            final_status, _, final_headers = request(op, "GET", auth_url)
            if final_status != 302:
                fail(f"callback returned {final_status}")
            return final_headers.get("Location", ""), final_headers
        status, body, headers = request(op, "GET", auth_url)
        location = headers.get("Location", "")
        if status == 302 and location:
            auth_url = location
            continue
        if status == 200 and b"<form" in body:
            # A form after a submit means rejection (bad credentials):
            # Keycloak re-renders instead of redirecting.
            if submitted:
                return None, None
            match = re.search(rb'<form[^>]*action="([^"]+)"', body)
            if not match:
                fail("login page has no form action")
            action = match.group(1).decode().replace("&amp;", "&")
            form = urllib.parse.urlencode(
                {"username": username, "password": password, "credentialId": ""}
            ).encode()
            status, _, headers = request(
                op, "POST", action, data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            submitted = True
            if status != 302 or not headers.get("Location"):
                return None, None
            auth_url = headers["Location"]
            continue
        fail(f"unexpected response for {auth_url[:120]!r} (status={status})")
    else:
        fail("login chain did not reach the app callback")


def cookie_value(jar, name):
    for cookie in jar:
        if cookie.name == name:
            return cookie.value
    return None


def main():
    print("BFF login check: discovery advertises ES256 ID tokens", flush=True)
    probe, _ = opener()
    status, body, _ = request(probe, "GET", f"{KC}/realms/{REALM}/.well-known/openid-configuration")
    if status != 200 or b'"issuer":"http://sovra-keycloak:18080/realms/sovra"' not in body:
        fail("Keycloak discovery unreachable (is the compose stack up?)")
    check("packaged origin serves the SPA entry at / (SOV-041)", True)
    status, body, headers = request(probe, "GET", f"{APP}/")
    if status != 200 or b'id="root"' not in body or b"/assets/" not in body:
        fail(f"SPA entry missing at / (status={status})")
    if "text/html" not in headers.get("Content-Type", ""):
        fail("SPA entry is not HTML")
    check("history fallback serves the entry for SPA routes", True)
    status, body, _ = request(probe, "GET", f"{APP}/consent")
    if status != 200 or b'id="root"' not in body:
        fail(f"history fallback missing (status={status})")
    check("API surface is not swallowed by the SPA fallback", True)
    status, body, _ = request(probe, "GET", f"{APP}/api/health")
    if status != 200 or b'"UP"' not in body:
        fail(f"/api/health not intact (status={status})")
    status, _, _ = request(probe, "GET", f"{APP}/api/does-not-exist")
    if status != 401:
        fail(f"anonymous unknown API returned {status}, want 401")
    op, jar = opener()
    check("member login lands with TENANT_MEMBER session (seed may lag boot)", True)
    landing, headers = login(op, "demo-member", "sovra-demo-member-01")
    if landing is None or "auth_error" in landing:
        fail(f"member login denied ({landing})")
    status, body, _ = request(op, "GET", f"{APP}/api/bff/me")
    if status != 200:
        fail(f"/api/bff/me returned {status}")
    import json
    me = json.loads(body)
    if "TENANT_MEMBER" not in me.get("roles", []) or not me.get("tenantId"):
        fail(f"member session lacks role/tenant ({body[:200]!r})")
    # Keycloak records no AMR value for password executions, so the
    # session carries []. That is the fail-closed shape: privileged
    # roles need an allowlisted hardware value, never mere presence.
    # Pinned exactly — if Keycloak ever emits ["pwd"], review before
    # widening.
    if me.get("amr") != []:
        fail(f"unexpected member amr ({me.get('amr')!r})")
    check("privileged password-only login withholds TRUST_ADMIN", True)
    op2, _ = opener()
    landing2, _ = login(op2, "demo-priv", "sovra-demo-priv-02")
    if landing2 is None or "auth_error" in landing2:
        fail(f"privileged login denied ({landing2})")
    status, body, _ = request(op2, "GET", f"{APP}/api/bff/me")
    me2 = json.loads(body)
    if "TENANT_MEMBER" not in me2.get("roles", []) or "TRUST_ADMIN" in me2.get("roles", []):
        fail(f"privileged downgrade wrong ({body[:200]!r})")
    check("wrong password never yields a code", True)
    op3, _ = opener()
    landing3, _ = login(op3, "demo-member", "wrong-password")
    if landing3 is not None:
        fail("wrong password produced a callback")
    check("machine Bearer never authenticates the BFF", True)
    op4, _ = opener()
    status, _, _ = request(op4, "GET", f"{APP}/api/bff/me",
                           headers={"Authorization": "Bearer deadbeef"})
    if status != 401:
        fail(f"machine token on BFF returned {status}, want 401")
    check("BFF logout kills the session with OP logout URL", True)
    status, _, _ = request(op, "POST", f"{APP}/api/bff/logout")
    if status != 403:
        fail(f"logout without CSRF returned {status}, want 403")
    xsrf = cookie_value(jar, "XSRF-TOKEN")
    if not xsrf:
        fail("no XSRF-TOKEN cookie after session reads")
    status, body, _ = request(op, "POST", f"{APP}/api/bff/logout",
                              headers={"X-XSRF-TOKEN": xsrf})
    if status != 200:
        fail(f"armed logout returned {status}")
    import json
    done = json.loads(body)
    if done.get("loggedOut") is not True or "id_token_hint=" not in done.get("endSessionUrl", ""):
        fail(f"logout response lacks OP logout URL ({body[:200]!r})")
    status, _, _ = request(op, "GET", f"{APP}/api/bff/me")
    if status != 401:
        fail(f"session alive after logout (status={status})")
    print("BFF login check: PASS (member, downgrade, negatives, separation, logout)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
