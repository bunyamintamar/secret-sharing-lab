#!/usr/bin/env python3
"""Shamir Secret Sharing — yerel web arayüzü.

Çalıştırma:
    python3 web/server.py

Sadece 127.0.0.1'e bağlanır (dışarıya AÇIK DEĞİLDİR); sır yalnızca kendi
makinende işlenir. Tarayıcıda http://127.0.0.1:8765 açılır.

Bağımlılık yok — stdlib http.server + shamir çekirdeği.
"""

from __future__ import annotations

import json
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Proje kökünü içe aktarma yoluna ekle (shamir paketi için).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from shamir import Share, split, combine, SSSError  # noqa: E402
from shamir.encoding import (  # noqa: E402
    decode_share,
    encode_share,
    new_set_id,
    EncodingError,
)

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
_HOST = "127.0.0.1"
_PORT = 8765

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
}


def _do_split(payload: dict) -> dict:
    """{secret, n, k} -> {shares, set_id}. Hatalar SSSError ile yükselir."""
    secret = payload.get("secret", "")
    if not isinstance(secret, str) or secret == "":
        raise SSSError("Sır boş olamaz.")
    try:
        n = int(payload.get("n"))
        k = int(payload.get("k"))
    except (TypeError, ValueError):
        raise SSSError("n ve k tam sayı olmalı.")

    shares = split(secret.encode("utf-8"), threshold=k, shares=n)
    set_id = new_set_id()
    encoded = [encode_share(s.x, s.y, k, set_id) for s in shares]
    return {"shares": encoded, "set_id": f"{set_id:04x}", "n": n, "k": k}


def _do_combine(payload: dict) -> dict:
    """{shares: [str]} -> {secret, is_text}. Hatalar SSSError ile yükselir."""
    raw_shares = payload.get("shares", [])
    if not isinstance(raw_shares, list) or not raw_shares:
        raise SSSError("En az iki pay gerekir.")

    parsed = []
    seen_x: set[int] = set()
    for raw in raw_shares:
        line = str(raw).strip()
        if line == "":
            continue
        try:
            share = decode_share(line)
        except EncodingError as exc:
            raise SSSError(f"Pay çözülemedi: {exc}")
        if share.x in seen_x:
            continue
        seen_x.add(share.x)
        parsed.append(share)

    if len(parsed) < 2:
        raise SSSError("En az iki geçerli, benzersiz pay gerekir.")

    set_ids = {s.set_id for s in parsed}
    thresholds = {s.threshold for s in parsed}
    k = min(thresholds)
    warnings = []
    if len(set_ids) > 1:
        warnings.append("Paylar farklı bölmelerden geliyor (set kimlikleri farklı); "
                        "sonuç anlamsız olabilir.")
    if len(parsed) < k:
        raise SSSError(f"Yeterli pay yok: {len(parsed)} var, en az {k} gerekiyor.")

    secret_bytes = combine([Share(x=s.x, y=s.y) for s in parsed])
    try:
        return {"secret": secret_bytes.decode("utf-8"), "is_text": True,
                "warnings": warnings}
    except UnicodeDecodeError:
        return {"secret": secret_bytes.hex(), "is_text": False, "warnings": warnings}


_API = {"/api/split": _do_split, "/api/combine": _do_combine}


class Handler(BaseHTTPRequestHandler):
    server_version = "ShamirWeb/1.0"

    def _send_json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, path: str) -> None:
        # Yalnızca statik klasördeki dosyalar (yol kaçışına izin verme).
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.normpath(os.path.join(_STATIC_DIR, rel))
        if not full.startswith(_STATIC_DIR) or not os.path.isfile(full):
            self.send_error(404, "Bulunamadı")
            return
        ext = os.path.splitext(full)[1]
        with open(full, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", _CONTENT_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send_static(self.path.split("?", 1)[0])

    def do_POST(self) -> None:
        endpoint = self.path.split("?", 1)[0]
        handler = _API.get(endpoint)
        if handler is None:
            self._send_json({"ok": False, "error": "Bilinmeyen uç nokta."}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self._send_json({"ok": False, "error": "Geçersiz istek gövdesi."}, 400)
            return
        try:
            result = handler(payload)
            result["ok"] = True
            self._send_json(result)
        except SSSError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:  # beklenmeyen — istemci çökmesin
            self._send_json({"ok": False, "error": f"Beklenmeyen hata: {exc}"}, 500)

    def log_message(self, *args) -> None:  # sunucu günlüğünü sessizleştir
        pass


def main() -> int:
    httpd = ThreadingHTTPServer((_HOST, _PORT), Handler)
    url = f"http://{_HOST}:{_PORT}"
    print(f"Shamir web arayüzü çalışıyor:  {url}")
    print("Durdurmak için Ctrl+C.")
    if "--no-browser" not in sys.argv:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nKapatılıyor.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
