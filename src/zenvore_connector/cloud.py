from __future__ import annotations
import json
import socket
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler
from . import __version__


class CloudError(Exception):
    def __init__(self, code, status=0):
        super().__init__(code)
        self.code, self.status = code, status
        self.transient = status == 0 or status == 429 or status >= 500


class NoRedirect(HTTPRedirectHandler):
    # Do not forward installation credentials or bearer tokens to redirects.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Cloud:
    def __init__(self, config, credentials):
        self.config, self.credentials = config, credentials
        self.token = None
        self.expires = 0
        self.lock = threading.RLock()
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        self.rotate_needed = False
        self.installation = None

    def raw(self, method, route, body=None, token=None, timeout=None):
        headers = {"Accept": "application/json", "User-Agent": "ZenvoreConnector/" + __version__}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.config.api_url + route, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=timeout or self.config.timeout_seconds) as response:
                data = response.read(2 * 1024 * 1024 + 1)
                if len(data) > 2 * 1024 * 1024:
                    raise CloudError("CLOUD_SERVER", 502)
                return json.loads(data)
        except HTTPError as exc:
            # Server error bodies may contain secrets or PII. Never log them.
            raise CloudError("CLOUD_AUTH" if exc.code in (401, 403) else "CLOUD_SERVER", exc.code) from None
        except (URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            code = "CLOUD_DNS" if isinstance(reason, socket.gaierror) else "CLOUD_TLS" if isinstance(reason, ssl.SSLError) else "CLOUD_NETWORK"
            raise CloudError(code) from None
        except (ValueError, UnicodeError):
            raise CloudError("CLOUD_SERVER", 502) from None

    def pair(self, code):
        result = self.raw("POST", "/connectors/pair", {"code": code.strip().upper(), "appVersion": __version__})
        self.credentials.save(result)
        self.token, self.expires = None, 0
        return result["connectorId"]

    def access_token(self):
        with self.lock:
            credential = self.credentials.load()
            if not credential:
                raise CloudError("CLOUD_AUTH", 401)
            if credential != self.installation:
                self.token, self.expires = None, 0
                self.installation = credential
            if self.token and time.monotonic() < self.expires:
                return self.token
            result = self.raw("POST", "/connectors/token", credential)
            self.token = result["accessToken"]
            self.expires = time.monotonic() + min(result["expiresIn"], 900) - 60
            self.rotate_needed = result.get("rotateCredential", False)
            return self.token

    def request(self, method, route, body=None, timeout=None):
        for attempt in range(2):
            token = self.access_token()
            try:
                return self.raw(method, route, body, token, timeout)
            except CloudError as exc:
                if exc.status != 401 or attempt:
                    raise
                with self.lock:
                    if self.token == token:
                        self.token, self.expires = None, 0
        raise CloudError("CLOUD_AUTH", 401)

    def rotate_if_due(self):
        with self.lock:
            if not self.rotate_needed:
                return
            # Old credential remains usable for 24h if this response/save is lost.
            result = self.request("POST", "/connectors/me/rotate-credential", {})
            self.credentials.save(result)
            self.rotate_needed = False
            self.expires = 0
