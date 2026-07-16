#!/usr/bin/env python3
"""Shamir Secret Sharing — kullanıcı dostu konsol uygulaması.

Çalıştırma:
    python3 sss.py

Bir sırrı (metni) n paya böler; herhangi k pay bir araya gelince sır geri gelir,
k'den az pay hiçbir bilgi vermez. Tüm işlemler GF(256) sonlu cisminde yapılır.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shamir import Share, split, combine, SSSError, ui
from shamir.encoding import (
    ParsedShare,
    decode_share,
    encode_share,
    new_set_id,
    EncodingError,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Açıklama ekranı
# ─────────────────────────────────────────────────────────────────────────────

def show_intro() -> None:
    ui.header("Shamir Secret Sharing nedir?")
    print(f"""
Bir sırrınız var: bir parola, bir şifreleme anahtarı, bir kurtarma cümlesi.
Bunu {ui.BOLD}tek bir kişiye{ui.RESET} emanet etmek riskli (kaybeder, ele geçer),
{ui.BOLD}herkese kopyalamak{ui.RESET} da riskli (herkes tek başına açar).

Shamir'in çözümü bir {ui.CYAN}(k, n) eşik şeması{ui.RESET}dır:
""")
    ui.box([
        f"{ui.BOLD}n{ui.RESET} = toplam pay sayısı (kaç parçaya böleceğiz)",
        f"{ui.BOLD}k{ui.RESET} = eşik değeri (birleştirmek için gereken pay sayısı)",
        "",
        f"{ui.GREEN}Herhangi k pay{ui.RESET}  → sır tamamen geri gelir",
        f"{ui.YELLOW}k'den az pay{ui.RESET}   → sıfır bilgi (her sır eşit olası)",
    ])
    print(f"""
{ui.DIM}Nasıl çalışır?{ui.RESET} Sırrı, derecesi (k-1) olan gizli bir polinomun
sabit terimi yaparız. Paylar bu eğri üzerindeki noktalardır. k nokta eğriyi
benzersiz belirler ve sabit terimi (sırrı) verir; k-1 nokta ise sonsuz eğriye
uyar, yani hiçbir şey ele vermez.

{ui.DIM}Örnek (3, 5):{ui.RESET} Sırrı 5 paya böl, güvendiğin 5 kişiye ver.
Herhangi 3'ü bir araya gelirse sır kurtulur; 2 kişi anlaşsa bile açamaz.
""")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Sırrı böl
# ─────────────────────────────────────────────────────────────────────────────

def do_split() -> None:
    ui.header("Sırrı paylara böl")
    ui.info("Önce sırrı, sonra pay sayısını ve eşik değerini soracağım.")
    print()

    secret_text = ui.ask(
        "Sır (bir satır metin):",
        validator=lambda s: "Sır boş olamaz." if s == "" else None,
    )
    secret_bytes = secret_text.encode("utf-8")
    ui.hint(f"{len(secret_bytes)} bayt uzunluğunda (UTF-8).")
    print()

    ui.info("Pay sayısı (n): sırrı kaç parçaya böleceğiz? (en fazla 255)")
    n = ui.ask_int("Toplam pay sayısı n:", 2, 255)

    print()
    ui.info(f"Eşik (k): bu {n} paydan kaç tanesi sırrı geri getirsin?")
    ui.hint("k=n ise herkes gerekli; k küçüldükçe daha az pay yeter (ama daha az güvenli).")
    k = ui.ask_int("Eşik değeri k:", 2, n)

    try:
        shares = split(secret_bytes, threshold=k, shares=n)
    except SSSError as exc:
        ui.error(str(exc))
        return

    set_id = new_set_id()
    encoded = [encode_share(s.x, s.y, k, set_id) for s in shares]

    print()
    ui.success(f"{n} pay üretildi. Aşağıdaki paylardan herhangi {ui.BOLD}{k}{ui.RESET}"
               f" tanesi sırrı geri getirir.")
    ui.hint(f"Set kimliği: {set_id:04x} — aynı bölmeden çıkan tüm paylar bunu taşır.")
    print()

    for i, line in enumerate(encoded, start=1):
        ui.box([
            f"{ui.BOLD}Pay {i} / {n}{ui.RESET}",
            f"{ui.CYAN}{line}{ui.RESET}",
        ], color=ui.GRAY)

    print()
    ui.warn("Payları FARKLI yerlerde/kişilerde sakla. Hepsi tek yerdeyse şema anlamsızdır.")
    ui.warn(f"En az {k} payı kaybedersen sır KURTULAMAZ — yedeği yoktur.")
    print()

    if ui.confirm("Payları dosyalara kaydedeyim mi?", default=False):
        _save_shares(encoded, set_id, k, n)

    ui.pause()


def _save_shares(encoded: list[str], set_id: int, k: int, n: int) -> None:
    folder = ui.ask(
        "Klasör yolu:",
        validator=lambda s: "Boş olamaz." if s.strip() == "" else None,
    ).strip()
    folder = os.path.expanduser(folder)
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        ui.error(f"Klasör oluşturulamadı: {exc}")
        return

    for i, line in enumerate(encoded, start=1):
        path = os.path.join(folder, f"pay-{i:02d}.txt")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"# Shamir Secret Sharing payı\n")
                fh.write(f"# set={set_id:04x}  esik(k)={k}  toplam(n)={n}  pay={i}\n")
                fh.write(f"# Birlestirme icin en az {k} pay dosyasi gerekir.\n")
                fh.write(line + "\n")
        except OSError as exc:
            ui.error(f"'{path}' yazılamadı: {exc}")
            return

    ui.success(f"{n} pay '{folder}' klasörüne kaydedildi (pay-01.txt … pay-{n:02d}.txt).")


# ─────────────────────────────────────────────────────────────────────────────
#  Payları birleştir
# ─────────────────────────────────────────────────────────────────────────────

def do_combine() -> None:
    ui.header("Payları birleştir")
    ui.info("Payları elle yapıştırarak ya da dosya klasöründen yükleyerek verebilirsin.")
    print()

    print(f"  {ui.BOLD}1{ui.RESET}) Payları tek tek yapıştır")
    print(f"  {ui.BOLD}2{ui.RESET}) Bir klasördeki dosyalardan yükle")
    print()
    choice = ui.ask_int("Seçim:", 1, 2)

    if choice == 1:
        parsed = _collect_shares_pasted()
    else:
        parsed = _collect_shares_from_files()

    if not parsed:
        ui.warn("Hiç geçerli pay alınmadı, birleştirme iptal.")
        ui.pause()
        return

    _try_reconstruct(parsed)
    ui.pause()


def _collect_shares_pasted() -> list[ParsedShare]:
    ui.info("Her satıra bir pay yapıştır. Bitince boş satır bırak (Enter).")
    collected: list[ParsedShare] = []
    threshold_hint: int | None = None

    while True:
        remaining = ""
        if threshold_hint is not None:
            need = threshold_hint - len(collected)
            if need > 0:
                remaining = f"{ui.GRAY}(en az {need} pay daha){ui.RESET}"
            else:
                remaining = f"{ui.GREEN}(yeterli, bitirmek için Enter){ui.RESET}"
        line = ui.ask(f"Pay {len(collected) + 1} {remaining}:")
        if line.strip() == "":
            break
        try:
            share = decode_share(line)
        except EncodingError as exc:
            ui.error(str(exc))
            continue
        if any(s.x == share.x for s in collected):
            ui.warn(f"x={share.x} numaralı pay zaten eklenmiş, atlandı.")
            continue
        collected.append(share)
        threshold_hint = share.threshold
        ui.success(f"Pay eklendi (x={share.x}). Toplam {len(collected)} pay.")

    return collected


def _collect_shares_from_files() -> list[ParsedShare]:
    folder = ui.ask(
        "Pay dosyalarının bulunduğu klasör:",
        validator=lambda s: "Boş olamaz." if s.strip() == "" else None,
    ).strip()
    folder = os.path.expanduser(folder)
    if not os.path.isdir(folder):
        ui.error(f"Klasör bulunamadı: {folder}")
        return []

    collected: list[ParsedShare] = []
    seen_x: set[int] = set()
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError:
            continue
        for raw in content.splitlines():
            raw = raw.strip()
            if raw == "" or raw.startswith("#"):
                continue
            try:
                share = decode_share(raw)
            except EncodingError:
                continue
            if share.x in seen_x:
                continue
            seen_x.add(share.x)
            collected.append(share)

    if collected:
        ui.success(f"{len(collected)} geçerli pay yüklendi.")
    else:
        ui.warn("Klasörde geçerli pay bulunamadı.")
    return collected


def _try_reconstruct(parsed: list[ParsedShare]) -> None:
    # Set kimlikleri farklıysa büyük ihtimalle farklı sırların payları karışmış.
    set_ids = {s.set_id for s in parsed}
    if len(set_ids) > 1:
        ui.warn("Paylar farklı bölmelerden geliyor (set kimlikleri farklı) — "
                "muhtemelen ayrı sırların payları karıştı. Sonuç anlamsız olabilir.")

    thresholds = {s.threshold for s in parsed}
    k = min(thresholds)
    if len(thresholds) > 1:
        ui.warn(f"Paylar farklı eşik değerleri bildiriyor {sorted(thresholds)}; "
                f"en küçüğü ({k}) kullanılacak.")

    if len(parsed) < k:
        ui.error(f"Yeterli pay yok: {len(parsed)} pay var, en az {k} gerekiyor.")
        return

    shares = [Share(x=s.x, y=s.y) for s in parsed]
    try:
        secret_bytes = combine(shares)
    except SSSError as exc:
        ui.error(str(exc))
        return

    print()
    try:
        text = secret_bytes.decode("utf-8")
        ui.success("Sır başarıyla geri getirildi:")
        ui.box([f"{ui.GREEN}{ui.BOLD}{text}{ui.RESET}"], color=ui.GREEN)
    except UnicodeDecodeError:
        ui.warn("Sonuç geçerli bir metin değil (paylar hatalı ya da eksik olabilir).")
        ui.box([f"Ham bayt (hex): {secret_bytes.hex()}"], color=ui.YELLOW)


# ─────────────────────────────────────────────────────────────────────────────
#  Ana menü
# ─────────────────────────────────────────────────────────────────────────────

def main_menu() -> None:
    ui.header("Shamir Secret Sharing — Konsol")
    print(f"{ui.DIM}Bir sırrı paylara böl, sonra eşik sayıda payla geri getir.{ui.RESET}")

    actions = {
        "1": ("Sırrı paylara böl", do_split),
        "2": ("Payları birleştir (sırrı geri getir)", do_combine),
        "3": ("Shamir Secret Sharing nedir?", show_intro),
        "4": ("Çıkış", None),
    }

    while True:
        print()
        ui.rule()
        for key, (label, _) in actions.items():
            print(f"  {ui.BOLD}{ui.CYAN}{key}{ui.RESET}) {label}")
        ui.rule()

        choice = ui.ask("Seçiminiz:").strip()
        if choice not in actions:
            ui.error("Geçersiz seçim, lütfen menüden bir numara girin.")
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
