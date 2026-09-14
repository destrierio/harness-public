"""A clean, stateful HTTP client so the model does not fight shell quoting on web
work. Cookies persist across calls (auth flows survive), redirects are followed,
and TLS is not verified (self-signed target certs are normal). HTTP Basic AND Digest
auth are auto-negotiated on a 401 when credentials are supplied (an IP camera's
digest login is common on embedded targets). An HTTP error status is returned as
data, never raised.
"""
from __future__ import annotations

import http.cookiejar
import ssl
import urllib.error
import urllib.request


class HttpClient:
    def __init__(self, *, opener=None, proxy_opener=None) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._opener = opener or urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPBasicAuthHandler(self.pwmgr),
            urllib.request.HTTPDigestAuthHandler(self.pwmgr),
        )
        # Preset/injectable opener used for ANY proxied request (tests inject a
        # recording opener); when None a real SOCKS opener is built lazily per proxy.
        self._proxy_opener = proxy_opener

    def _proxy_opener_for(self, proxy: str):
        """An opener that routes through a SOCKS5 proxy (a pivot's local port), sharing
        this client's cookie jar and auth. Raises RuntimeError if PySocks is absent."""
        if self._proxy_opener is not None:
            return self._proxy_opener
        host, _, port = str(proxy).rpartition(":")
        try:
            import socks  # PySocks, baked in the image
            from sockshandler import SocksiPyHandler
        except ImportError as exc:  # not baked in a bare test env
            raise RuntimeError("SOCKS proxy needs PySocks (baked in the image)") from exc
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.build_opener(
            SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, host or "127.0.0.1", int(port or 1080)),
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPBasicAuthHandler(self.pwmgr),
            urllib.request.HTTPDigestAuthHandler(self.pwmgr),
        )

    def _add_auth(self, url: str, auth) -> None:
        user = pw = None
        if isinstance(auth, dict):
            user = auth.get("username", auth.get("user"))
            pw = auth.get("password", auth.get("pass"))
        elif isinstance(auth, (list, tuple)) and len(auth) >= 2:
            user, pw = auth[0], auth[1]
        if user is not None and pw is not None:
            # realm=None with the default-realm manager covers both Basic and Digest.
            self.pwmgr.add_password(None, url, str(user), str(pw))

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str | bytes | None = None,
        timeout: float = 20.0,
        auth: dict | None = None,
        proxy: str | None = None,
    ) -> dict:
        if auth:
            self._add_auth(url, auth)
        try:
            opener = self._proxy_opener_for(proxy) if proxy else self._opener
        except RuntimeError as exc:
            return {"status": 0, "headers": {}, "body": f"proxy error: {exc}"}
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers or {})
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": raw.decode(errors="replace"),
                }
        except urllib.error.HTTPError as exc:
            return {
                "status": exc.code,
                "headers": dict(exc.headers or {}),
                "body": exc.read().decode(errors="replace"),
            }
        except Exception as exc:  # noqa: BLE001 - a failed request is data for the model
            return {"status": 0, "headers": {}, "body": f"request error: {exc}"}

    def get_bytes(self, url: str, timeout: float = 30.0) -> tuple[int, bytes]:
        """Fetch raw bytes (for binaries/artifacts) rather than decoded text."""
        req = urllib.request.Request(url, method="GET")
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except Exception:  # noqa: BLE001
            return 0, b""
