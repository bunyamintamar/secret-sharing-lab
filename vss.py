#!/usr/bin/env python3
"""Doğrulanabilir Sır Paylaşımı (Feldman VSS) — konsol uygulaması.

Çalıştırma:
    python3 vss.py

Klasik SSS'ten farkı: dağıtıcı açık **taahhütler** yayımlar. Her pay sahibi,
sırrı öğrenmeden payının doğru olduğunu kanıtlayabilir; hileli bir dağıtıcı
(ya da bozulmuş bir pay) anında yakalanır.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shamir import ui, vss
from shamir.vss import VSSShare, VSSError
from shamir.vss_encoding import (
    ParsedCommitments,
    ParsedVSSShare,
    decode_commitments,
    decode_share,
    encode_commitments,
    encode_share,
    new_set_id,
    VSSEncodingError,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Açıklama
# ─────────────────────────────────────────────────────────────────────────────

def show_intro() -> None:
    ui.header("Doğrulanabilir Sır Paylaşımı (VSS) nedir?")
    print(f"""
Klasik Shamir'de payları üreten {ui.BOLD}dağıtıcıya güvenmek{ui.RESET} zorundasın.
Sana bozuk bir pay verirse bunu ancak birleştirme anında — çok geç — anlarsın.

{ui.CYAN}Feldman VSS{ui.RESET} bunu çözer: dağıtıcı, paylarla birlikte herkese açık
{ui.BOLD}taahhütler{ui.RESET} yayımlar. Bu taahhütler sırrı ele vermez, ama herkesin
kendi payını doğrulamasına yeter.
""")
    ui.box([
        f"{ui.BOLD}Taahhütler{ui.RESET}  = g^(katsayı) mod p  (herkese açık)",
        f"{ui.BOLD}Doğrulama{ui.RESET}   = g^pay  ==  taahhütlerden beklenen değer",
        "",
        f"{ui.GREEN}Pay tutuyorsa{ui.RESET}  → dağıtıcı bu pay için dürüst",
        f"{ui.RED}Pay tutmuyorsa{ui.RESET} → pay bozuk ya da dağıtıcı hile yapmış",
    ])
    print(f"""
{ui.DIM}Güvenlik:{ui.RESET} Ayrık logaritma zor olduğundan taahhütten sır çıkarılamaz.
{ui.DIM}Grup:{ui.RESET} RFC 3526 2048-bit güvenli asal. Sır Z_q'da tek sayı olarak
kodlanır (en fazla {vss.MAX_SECRET_BYTES} bayt). Eğitim amaçlıdır.
""")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Böl
# ─────────────────────────────────────────────────────────────────────────────

def do_split() -> None:
    ui.header("Sırrı böl (taahhütlerle)")
    secret_text = ui.ask(
        "Sır (bir satır metin):",
        validator=lambda s: "Sır boş olamaz." if s == "" else None,
    )
    secret_bytes = secret_text.encode("utf-8")
    if len(secret_bytes) > vss.MAX_SECRET_BYTES:
        ui.error(f"Sır çok uzun: {len(secret_bytes)} bayt. En fazla "
                 f"{vss.MAX_SECRET_BYTES} bayt.")
        return
    ui.hint(f"{len(secret_bytes)} bayt (UTF-8).")
    print()

    n = ui.ask_int("Toplam pay sayısı n:", 2, 255)
    print()
    ui.info(f"Bu {n} paydan kaç tanesi sırrı geri getirsin?")
    k = ui.ask_int("Eşik değeri k:", 2, n)

    try:
        shares, commitments = vss.split(secret_bytes, threshold=k, shares=n)
    except VSSError as exc:
        ui.error(str(exc))
        return

    set_id = new_set_id()
    enc_shares = [encode_share(s.x, s.y, k, set_id) for s in shares]
    enc_commit = encode_commitments(commitments, k, set_id)

    print()
    ui.success(f"{n} pay ve 1 taahhüt bloğu üretildi. Herhangi {ui.BOLD}{k}{ui.RESET} pay sırrı getirir.")
    ui.hint(f"Set kimliği: {set_id:04x}")
    print()

    ui.info("PAYLAR (gizli — her biri farklı kişiye/yere):")
    for i, line in enumerate(enc_shares, start=1):
        ui.box([f"{ui.BOLD}Pay {i}/{n}{ui.RESET}", f"{ui.CYAN}{line}{ui.RESET}"], color=ui.GRAY)

    print()
    ui.info("TAAHHÜTLER (herkese açık — doğrulama için paylaş):")
    ui.box([f"{ui.MAGENTA}{_shorten(enc_commit)}{ui.RESET}",
            f"{ui.DIM}(tam metin {len(enc_commit)} karakter — kaydetmen önerilir){ui.RESET}"],
           color=ui.GRAY)

    print()
    ui.warn("Payları gizli tut, taahhütleri açıkça paylaş. Pay sahipleri payını "
            "'Payımı doğrula' ile kontrol edebilir.")
    print()
    if ui.confirm("Payları ve taahhütleri dosyalara kaydedeyim mi?", default=True):
        _save_all(enc_shares, enc_commit, set_id, k, n)
    ui.pause()


def _shorten(s: str, head: int = 40, tail: int = 12) -> str:
    return s if len(s) <= head + tail + 3 else f"{s[:head]}…{s[-tail:]}"


def _save_all(enc_shares: list[str], enc_commit: str, set_id: int, k: int, n: int) -> None:
    folder = ui.ask("Klasör yolu:",
                    validator=lambda s: "Boş olamaz." if s.strip() == "" else None).strip()
    folder = os.path.expanduser(folder)
    try:
        os.makedirs(folder, exist_ok=True)
        for i, line in enumerate(enc_shares, start=1):
            with open(os.path.join(folder, f"pay-{i:02d}.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"# VSS payı  set={set_id:04x} k={k} n={n} pay={i}\n")
                fh.write("# GIZLI. Dogrulama icin taahhutler.txt gerekir.\n")
                fh.write(line + "\n")
        with open(os.path.join(folder, "taahhutler.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"# VSS taahhutleri  set={set_id:04x} k={k}\n")
            fh.write("# ACIK veri — herkesle paylasilabilir.\n")
            fh.write(enc_commit + "\n")
    except OSError as exc:
        ui.error(f"Kaydedilemedi: {exc}")
        return
    ui.success(f"'{folder}' klasörüne {n} pay + taahhutler.txt kaydedildi.")


# ─────────────────────────────────────────────────────────────────────────────
#  Doğrula
# ─────────────────────────────────────────────────────────────────────────────

def do_verify() -> None:
    ui.header("Payımı doğrula")
    ui.info("Önce taahhütleri, sonra doğrulanacak payı ver.")
    print()

    commits = _ask_commitments()
    if commits is None:
        ui.pause()
        return

    line = ui.ask("Doğrulanacak pay:")
    try:
        share = decode_share(line)
    except VSSEncodingError as exc:
        ui.error(str(exc))
        ui.pause()
        return

    if share.set_id != commits.set_id:
        ui.warn(f"Pay ({share.set_id:04x}) ve taahhüt ({commits.set_id:04x}) set "
                f"kimlikleri farklı — muhtemelen aynı bölmeye ait değiller.")

    ok = vss.verify_share(share.x, share.y, commits.values)
    print()
    if ok:
        ui.success(f"Pay GEÇERLİ (x={share.x}). Dağıtıcı bu pay için dürüst; "
                   f"birleştirmede güvenle kullanılabilir.")
    else:
        ui.error(f"Pay GEÇERSİZ (x={share.x}). Taahhütlerle tutmuyor — pay bozulmuş "
                 f"ya da dağıtıcı hile yapmış. Bu payı KULLANMA.")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Birleştir
# ─────────────────────────────────────────────────────────────────────────────

def do_combine() -> None:
    ui.header("Payları birleştir")
    ui.info("İstersen önce taahhütleri ver; her pay birleştirmeden önce doğrulanır "
            "ve bozuk paylar elenir.")
    print()

    commits = None
    if ui.confirm("Taahhütlerle doğrulama yapayım mı? (önerilir)", default=True):
        commits = _ask_commitments()

    ui.info("Payları tek tek yapıştır. Bitince boş satır bırak.")
    parsed: list[ParsedVSSShare] = []
    seen: set[int] = set()
    while True:
        raw = ui.ask(f"Pay {len(parsed) + 1}:")
        if raw.strip() == "":
            break
        try:
            s = decode_share(raw)
        except VSSEncodingError as exc:
            ui.error(str(exc))
            continue
        if s.x in seen:
            ui.warn(f"x={s.x} zaten eklenmiş, atlandı.")
            continue
        if commits is not None and not vss.verify_share(s.x, s.y, commits.values):
            ui.error(f"Pay x={s.x} taahhütlerle TUTMUYOR — elendi (kullanılmayacak).")
            continue
        seen.add(s.x)
        parsed.append(s)
        tag = " (doğrulandı)" if commits is not None else ""
        ui.success(f"Pay eklendi (x={s.x}){tag}. Toplam {len(parsed)}.")

    if not parsed:
        ui.warn("Geçerli pay yok, iptal.")
        ui.pause()
        return

    k = min(s.threshold for s in parsed)
    if len(parsed) < k:
        ui.error(f"Yeterli pay yok: {len(parsed)} var, en az {k} gerekiyor.")
        ui.pause()
        return

    try:
        secret = vss.combine([VSSShare(x=s.x, y=s.y) for s in parsed])
        text = secret.decode("utf-8")
        print()
        ui.success("Sır geri getirildi:")
        ui.box([f"{ui.GREEN}{ui.BOLD}{text}{ui.RESET}"], color=ui.GREEN)
    except (VSSError, UnicodeDecodeError):
        ui.error("Sır geri getirilemedi — paylar eksik/uyumsuz olabilir.")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Taahhüt girişi (yapıştır ya da dosyadan)
# ─────────────────────────────────────────────────────────────────────────────

def _ask_commitments() -> ParsedCommitments | None:
    print(f"  {ui.BOLD}1{ui.RESET}) Taahhütleri yapıştır")
    print(f"  {ui.BOLD}2{ui.RESET}) Klasördeki taahhutler.txt'ten yükle")
    choice = ui.ask_int("Seçim:", 1, 2)
    if choice == 1:
        raw = ui.ask("Taahhüt bloğu (VCOM1-…):")
    else:
        folder = ui.ask("Klasör yolu:").strip()
        path = os.path.join(os.path.expanduser(folder), "taahhutler.txt")
        raw = _first_vcom_line(path)
        if raw is None:
            ui.error(f"'{path}' içinde taahhüt bulunamadı.")
            return None
    try:
        return decode_commitments(raw)
    except VSSEncodingError as exc:
        ui.error(str(exc))
        return None


def _first_vcom_line(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("VCOM1-"):
                    return line
    except OSError:
        return None
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Menü
# ─────────────────────────────────────────────────────────────────────────────

def main_menu() -> None:
    ui.header("Doğrulanabilir Sır Paylaşımı — Konsol")
    print(f"{ui.DIM}Dağıtıcıya güvenmeden: payları böl, doğrula, birleştir.{ui.RESET}")

    actions = {
        "1": ("Sırrı böl (taahhütlerle)", do_split),
        "2": ("Payımı doğrula", do_verify),
        "3": ("Payları birleştir", do_combine),
        "4": ("VSS nedir?", show_intro),
        "5": ("Çıkış", None),
    }
    while True:
        print()
        ui.rule()
        for key, (label, _) in actions.items():
            print(f"  {ui.BOLD}{ui.CYAN}{key}{ui.RESET}) {label}")
        ui.rule()
        choice = ui.ask("Seçiminiz:").strip()
        if choice not in actions:
            ui.error("Geçersiz seçim.")
            continue
        label, func = actions[choice]
        if func is None:
            print(f"\n{ui.CYAN}Görüşürüz! Paylarını güvende tut.{ui.RESET}\n")
            return
        func()


def main() -> int:
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{ui.GRAY}İptal edildi. Çıkılıyor.{ui.RESET}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
