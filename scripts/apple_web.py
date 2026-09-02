"""An App Store Connect web session without a browser, for the one write the public API refuses.

`POST /v1/apps` — the app record a TestFlight upload needs — answers 403 "does not
allow 'CREATE'" to every App Store Connect API key. The App Store Connect website
creates records through its own private API at `appstoreconnect.apple.com/iris/v1`,
authenticated by an Apple ID session, which is what `fastlane produce` drives.
This module does the same thing in plain HTTP:

1. SRP-6a sign-in at `idmsa.apple.com/appleauth/auth/signin/{init,complete}`, the
   `s2k` / `s2k_fo` password derivation Apple uses (the arithmetic mirrors pysrp 1.0.22
   with `rfc5054_enable()` and `no_username_in_x()`, the configuration pyicloud has
   proven against this endpoint), so the password itself never leaves the process;
2. the trusted-device second factor, read from the sign-in prompt on this Mac by
   Weles's `followup_ax_capture.swift` — the machine running this is the host the
   registry binds the Apple account to, so the prompt appears here;
3. `olympus/v1/session`, then `iris/v1/apps` with the CSRF pair the site's own
   responses hand out.

The trusted session's cookies are kept owner-only under `~/.stado/work`, so a second
run inside Apple's trust window signs in without a prompt.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import http.cookiejar
import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

AUTH = "https://idmsa.apple.com/appleauth/auth"
CONNECT = "https://appstoreconnect.apple.com"
IRIS = f"{CONNECT}/iris/v1"
SESSION_FILE = Path.home() / ".stado" / "work" / "apple-web-session.cookies"
CODE_FILE = Path.home() / ".stado" / "work" / "apple-web-2fa-code.txt"
CAPTURE_SCRIPT = (
    Path.home() / "Documents" / "CodingProjects" / "Wisent" / "weles" / "scripts"
    / "trajectories" / "apple" / "native_2fa" / "followup_ax_capture.swift"
)
TWO_FACTOR_WAIT_SECONDS = 120

# RFC 5054, appendix A: the 2048-bit group, generator 2. `idmsa` speaks this group
# with SHA-256 (pysrp: `NG_2048`, `SHA256`).
N = int(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
    16,
)
G = 2
N_BYTES = (N.bit_length() + 7) // 8


class WebSessionError(RuntimeError):
    """A refusal with the sentence Apple gave, never a guessed one."""


def _to_bytes(value: int) -> bytes:
    """pysrp `long_to_bytes`: big-endian, no leading zeros, `b''` for zero."""
    return value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""


def _digest(*parts: bytes | int, width: int | None = None) -> bytes:
    """pysrp `H` with `rfc5054_enable()`: each part left-padded to `width` when given."""
    h = hashlib.sha256()
    for part in parts:
        data = _to_bytes(part) if isinstance(part, int) else part
        if width is not None:
            h.update(bytes(width - len(data)))
        h.update(data)
    return h.digest()


def _int(data: bytes) -> int:
    return int.from_bytes(data, "big")


class SrpClient:
    """The client half of SRP-6a as pysrp computes it under `rfc5054_enable()` and
    `no_username_in_x()`; the password is Apple's `s2k`-derived key."""

    def __init__(self, account_name: str):
        self.account_name = account_name.encode()
        self.k = _int(_digest(N, G, width=N_BYTES))
        self.a = _int(secrets.token_bytes(256)) | (1 << 2047)
        self.A = pow(G, self.a, N)

    @staticmethod
    def derived_password(password: str, protocol: str, salt: bytes, iterations: int) -> bytes:
        digest = hashlib.sha256(password.encode()).digest()
        if protocol == "s2k_fo":
            digest = digest.hex().encode()
        elif protocol != "s2k":
            raise WebSessionError(f"idmsa proposed an unknown password protocol {protocol!r}")
        return hashlib.pbkdf2_hmac("sha256", digest, salt, iterations, 32)

    def prove(self, salt: bytes, B: int, derived: bytes) -> tuple[bytes, bytes]:
        """M1 and H(A, M1, K) for the server's salt and public value."""
        if B % N == 0:
            raise WebSessionError("idmsa sent an SRP public value that is a multiple of N")
        u = _int(_digest(self.A, B, width=N_BYTES))
        if u == 0:
            raise WebSessionError("SRP scrambling parameter is zero")
        x = _int(_digest(salt, _digest(b":" + derived)))
        v = pow(G, x, N)
        S = pow((B - self.k * v) % N, self.a + u * x, N)
        K = hashlib.sha256(_to_bytes(S)).digest()
        hN = hashlib.sha256(_to_bytes(N)).digest()
        hg = hashlib.sha256(bytes(N_BYTES - 1) + _to_bytes(G)).digest()
        xor = bytes(a ^ b for a, b in zip(hN, hg))
        M1 = hashlib.sha256(
            xor + hashlib.sha256(self.account_name).digest() + salt + _to_bytes(self.A) + _to_bytes(B) + K
        ).digest()
        M2 = hashlib.sha256(_to_bytes(self.A) + M1 + K).digest()
        return M1, M2


class AppStoreConnectWebSession:
    def __init__(self, session_file: Path = SESSION_FILE, log: Callable[[str], None] = print):
        self.session_file = session_file
        self.log = log
        self.jar = http.cookiejar.LWPCookieJar(str(session_file))
        if session_file.exists():
            self.jar.load(ignore_discard=True, ignore_expires=True)
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.service_key: str | None = None
        self.session_id: str | None = None
        self.scnt: str | None = None
        self.csrf: dict[str, str] = {}

    # --- HTTP --------------------------------------------------------------

    def _call(self, method: str, url: str, body: dict | None = None, headers: dict[str, str] | None = None,
              accept: tuple[int, ...] = (200, 201, 204)) -> tuple[int, dict, dict]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, method=method, data=data)
        request.add_header("Accept", "application/json, text/javascript")
        request.add_header("User-Agent", "skarbiec-apple-ios-signing")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with self.opener.open(request, timeout=60) as response:
                status = response.status
                raw = response.read()
                response_headers = {key.lower(): value for key, value in response.headers.items()}
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read()
            response_headers = {key.lower(): value for key, value in error.headers.items()}
        # iris answers gzip even without an Accept-Encoding, and a compressed refusal
        # read as text is a refusal nobody can act on.
        if response_headers.get("content-encoding", "").lower() in ("gzip", "x-gzip") and raw:
            try:
                raw = gzip.decompress(raw)
            except OSError:
                pass
        payload: dict = {}
        if raw:
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {"raw": raw.decode(errors="replace")[:600]}
        if status not in accept:
            raise WebSessionError(f"{method} {url.split('?')[0]} -> {status}: {self._sentence(payload)}")
        return status, payload, response_headers

    @staticmethod
    def _sentence(payload: dict) -> str:
        errors = payload.get("errors") or payload.get("serviceErrors") or []
        if isinstance(errors, list) and errors:
            return "; ".join(
                f"{item.get('title') or item.get('code', '')}: {item.get('detail') or item.get('message', '')}".strip(": ")
                for item in errors if isinstance(item, dict)
            )
        return " ".join(str(payload)[:400].split())

    def _auth_headers(self) -> dict[str, str]:
        headers = {
            "X-Apple-Widget-Key": self.service_key or "",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.session_id:
            headers["X-Apple-ID-Session-Id"] = self.session_id
        if self.scnt:
            headers["scnt"] = self.scnt
        return headers

    # --- sign-in -------------------------------------------------------------

    def _load_service_key(self) -> None:
        _, payload, _ = self._call("GET", f"{CONNECT}/olympus/v1/app/config?hostname=itunesconnect.apple.com")
        key = payload.get("authServiceKey")
        if not key:
            raise WebSessionError("olympus app config carries no authServiceKey")
        self.service_key = key

    def has_session(self) -> bool:
        """Whether the stored cookies still open App Store Connect."""
        try:
            status, payload, _ = self._call("GET", f"{CONNECT}/olympus/v1/session", accept=(200, 401))
        except WebSessionError:
            return False
        return status == 200 and bool(payload.get("user"))

    def sign_in(self, account_name: str, password: str, second_factor: Callable[[], str]) -> None:
        if self.has_session():
            self.log("session          reused the trusted App Store Connect session on disk")
            return
        self._load_service_key()
        client = SrpClient(account_name)
        _, init, _ = self._call(
            "POST", f"{AUTH}/signin/init",
            {
                "a": base64.b64encode(_to_bytes(client.A)).decode(),
                "accountName": account_name,
                "protocols": ["s2k", "s2k_fo"],
            },
            self._auth_headers(),
        )
        for field in ("salt", "b", "c", "iteration", "protocol"):
            if field not in init:
                raise WebSessionError(f"signin/init answered without {field}")
        salt = base64.b64decode(init["salt"])
        B = _int(base64.b64decode(init["b"]))
        derived = client.derived_password(password, init["protocol"], salt, int(init["iteration"]))
        M1, M2 = client.prove(salt, B, derived)
        status, payload, headers = self._call(
            "POST", f"{AUTH}/signin/complete?isRememberMeEnabled=true",
            {
                "accountName": account_name,
                "c": init["c"],
                "m1": base64.b64encode(M1).decode(),
                "m2": base64.b64encode(M2).decode(),
                "rememberMe": True,
            },
            self._auth_headers(),
            accept=(200, 409),
        )
        self.session_id = headers.get("x-apple-id-session-id")
        self.scnt = headers.get("scnt")
        if status == 409:
            self.log("sign-in          password accepted; Apple asks the trusted devices for a code")
            self._complete_two_factor(second_factor)
        else:
            self.log("sign-in          password accepted without a second factor")
        self._call("GET", f"{CONNECT}/olympus/v1/session")
        self.session_file.parent.mkdir(parents=True, exist_ok=True)
        self.jar.save(ignore_discard=True, ignore_expires=True)
        os.chmod(self.session_file, 0o600)
        self.log(f"session          trusted; cookies kept owner-only at {self.session_file}")

    def _complete_two_factor(self, second_factor: Callable[[], str]) -> None:
        headers = {**self._auth_headers(), "Accept": "application/json"}
        _, options, _ = self._call("GET", AUTH, headers=headers)
        length = int((options.get("securityCode") or {}).get("length") or 6)
        devices = len(options.get("trustedDevices") or [])
        phones = [
            f"id {phone.get('id')} {phone.get('numberWithDialCode') or phone.get('pushMode') or ''}".strip()
            for phone in (options.get("trustedPhoneNumbers") or [])
            if isinstance(phone, dict)
        ]
        self.log(
            f"second factor    Apple offers {length} digits to {devices} trusted device(s)"
            + (f" and {len(phones)} phone number(s): {'; '.join(phones)}" if phones else "")
        )
        code = second_factor()
        if not (code.isdigit() and len(code) == length):
            raise WebSessionError(f"the captured second factor is not {length} digits")
        self._call(
            "POST", f"{AUTH}/verify/trusteddevice/securitycode",
            {"securityCode": {"code": code}}, headers, accept=(200, 204),
        )
        self._call("GET", f"{AUTH}/2sv/trust", headers=headers, accept=(200, 204))

    # --- iris ----------------------------------------------------------------

    def _iris(self, method: str, path: str, body: dict | None = None, accept=(200, 201)) -> dict:
        headers = {"X-Requested-With": "XMLHttpRequest", **self.csrf}
        _, payload, response_headers = self._call(method, f"{IRIS}/{path}", body, headers, accept=accept)
        for name in ("csrf", "csrf_ts"):
            if name in response_headers:
                self.csrf[name] = response_headers[name]
        return payload

    def create_app(self, bundle_id: str, name: str, sku: str, primary_locale: str = "en-US",
                   platforms: tuple[str, ...] = ("IOS",), version: str = "1.0") -> str:
        """The record the App Store Connect site creates for "New App", in the shape
        `fastlane produce` posts (Spaceship `Tunes.post_app`)."""
        self._iris("GET", "apps?limit=1")
        included = [
            {
                "type": "appInfos",
                "id": "${new-appInfo-id}",
                "relationships": {
                    "appInfoLocalizations": {
                        "data": [{"type": "appInfoLocalizations", "id": "${new-appInfoLocalization-id}"}]
                    }
                },
            },
            {
                "type": "appInfoLocalizations",
                "id": "${new-appInfoLocalization-id}",
                "attributes": {"locale": primary_locale, "name": name},
            },
        ]
        for platform in platforms:
            included.append({
                "type": "appStoreVersions",
                "id": f"${{new-{platform}-appVersion-id}}",
                "attributes": {"platform": platform, "versionString": version},
                # iris refuses the whole create without this: "The provided entity is
                # missing a required relationship: appStoreVersionLocalizations".
                "relationships": {
                    "appStoreVersionLocalizations": {
                        "data": [{
                            "type": "appStoreVersionLocalizations",
                            "id": f"${{new-{platform}-appVersionLocalization-id}}",
                        }]
                    }
                },
            })
            included.append({
                "type": "appStoreVersionLocalizations",
                "id": f"${{new-{platform}-appVersionLocalization-id}}",
                "attributes": {"locale": primary_locale},
            })
        body = {
            "data": {
                "type": "apps",
                "attributes": {"sku": sku, "primaryLocale": primary_locale, "bundleId": bundle_id},
                "relationships": {
                    "appStoreVersions": {
                        "data": [{"type": "appStoreVersions", "id": f"${{new-{platform}-appVersion-id}}"} for platform in platforms]
                    },
                    "appInfos": {"data": [{"type": "appInfos", "id": "${new-appInfo-id}"}]},
                },
            },
            "included": included,
        }
        payload = self._iris("POST", "apps", body)
        app_id = (payload.get("data") or {}).get("id")
        if not app_id:
            raise WebSessionError(f"iris created no app: {self._sentence(payload)}")
        return app_id


# --- the second factor, read from this Mac's prompt ------------------------------


def capture_second_factor(script: Path = CAPTURE_SCRIPT, code_file: Path = CODE_FILE,
                          wait_seconds: int = TWO_FACTOR_WAIT_SECONDS, log: Callable[[str], None] = print) -> str:
    """Weles's `followup_ax_capture.swift`, the way `native_2fa.mjs` drives it: press
    Allow on the trusted-device prompt, read the six digits, press Done, and take the
    code from the owner-only file it writes. Accessibility must already trust the
    terminal this runs in; the helper says so when it does not."""
    if not script.is_file():
        raise WebSessionError(f"the Apple prompt capture helper is absent: {script}")
    code_file.parent.mkdir(parents=True, exist_ok=True)
    code_file.unlink(missing_ok=True)
    deadline = time.monotonic() + wait_seconds
    last = "no attempt yet"
    seen: dict[str, str] = {}
    while time.monotonic() < deadline:
        for flags in (["--click-allow", "--click-done"], ["--click-done"]):
            result = subprocess.run(
                ["/usr/bin/swift", str(script), *flags],
                env={**os.environ, "APPLE_2FA_CODE_FILE": str(code_file)},
                capture_output=True, text=True, timeout=45,
            )
            try:
                report = json.loads(result.stdout[result.stdout.find("{"):]) if result.stdout.strip() else {}
            except ValueError:
                report = {}
            if report.get("accessibilityTrusted") is False:
                raise WebSessionError("Accessibility does not trust this terminal, so the Apple prompt cannot be read")
            last = str(report.get("error") or result.stderr.strip() or "swift exited %s" % result.returncode)[:200]
            # Every Apple-looking window the helper saw, with its digits masked. A pass
            # that finds no code has to say what it did see, or "found none" is the same
            # silence for a prompt that never appeared and a prompt in a shape the
            # matcher does not know.
            for process in report.get("processes") or []:
                preview = str(process.get("textPreview") or "")
                if "apple" not in preview.lower():
                    continue
                key = f"{process.get('name')}#{process.get('windowIndex')}"
                if seen.get(key) == preview:
                    continue
                seen[key] = preview
                log(f"prompt           {key}: {preview}")
            if code_file.is_file():
                code = "".join(ch for ch in code_file.read_text() if ch.isdigit())[:6]
                code_file.unlink(missing_ok=True)
                if len(code) == 6:
                    log(f"second factor    read from the prompt on this Mac (clicked {report.get('clicked') or []})")
                    return code
        time.sleep(1.5)
    raise WebSessionError(f"no Apple verification code appeared on this Mac within {wait_seconds}s: {last}")
