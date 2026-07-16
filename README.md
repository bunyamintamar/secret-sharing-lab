# Shamir Secret Sharing — Konsol Uygulaması

Bir sırrı (parola, şifreleme anahtarı, kurtarma cümlesi) `n` paya bölen ve
herhangi `k` payla geri getiren, **saf Python** ile yazılmış eğitim amaçlı bir
konsol uygulaması. Harici bağımlılık yok — sadece standart kütüphane.

> **(k, n) eşik şeması:** herhangi **k** pay sırrı tam olarak geri getirir;
> **k'den az** pay sıfır bilgi verir (her olası sır eşit derecede olasıdır).
> Bu güvence hesaplama gücünden bağımsızdır — bilgi-teoriktir.

## Hızlı başlangıç

```bash
python3 sss.py
```

Menüden:

1. **Sırrı paylara böl** — sırrı, pay sayısını (`n`) ve eşiği (`k`) sorar, payları üretir, isterse dosyaya kaydeder.
2. **Payları birleştir** — payları elle yapıştırarak veya bir klasörden yükleyerek sırrı geri getirir.
3. **Shamir Secret Sharing nedir?** — kısa, görsel bir açıklama.

Renkler otomatik: gerçek bir terminalde renkli, boru/dosyaya yazarken düz metin
(`NO_COLOR=1` ile de kapatılabilir).

## Web arayüzü

Aynı çekirdeğin üstünde çalışan yerel bir web arayüzü:

```bash
python3 web/server.py
```

Tarayıcıda `http://127.0.0.1:8765` açılır. Yalnızca `127.0.0.1`'e bağlanır —
sır makinenden dışarı çıkmaz. Üç sekme: **sırrı böl**, **payları birleştir**
(yapıştır veya dosyadan yükle), **nasıl çalışır**. Payları kopyalayabilir veya
tek `.txt` olarak indirebilirsin.

### Örnek

```
Sır          : Kasa kodu: 42
Pay sayısı n : 5
Eşik k       : 3
```

Beş pay üretilir; herhangi üçü sırrı geri getirir, ikisi hiçbir şey söylemez.
Her pay tek satırlık bir dizedir:

```
SSS1-dba9-3-2-88cfe0cad01d356751...-b15f
│    │    │ │ │                     └ sağlama toplamı (yazım hatasını yakalar)
│    │    │ │ └ pay verisi (onaltılık)
│    │    │ └ pay numarası (x)
│    │    └ eşik değeri (k)
│    └ set kimliği (aynı bölmenin payları; karışıklığı yakalar)
└ sürüm etiketi
```

## Nasıl çalışır?

- Sır UTF-8 baytlara çevrilir; **her bayt bağımsız olarak** paylaşılır.
- Her bayt için derecesi `k-1` olan gizli bir polinom kurulur; sabit terim = sır
  baytı, diğer katsayılar kriptografik rastgele (`secrets`). Pay `i`, polinomun
  `x=i` noktasındaki değeridir.
- Birleştirme, **Lagrange interpolasyonu** ile `f(0)`'ı (sırrı) geri hesaplar.
- Tüm aritmetik **GF(256)** sonlu cisminde yapılır (toplama = XOR, çarpma =
  indirgenemez polinom `x⁸+x⁴+x³+x+1` modülü — AES ile aynı). Böylece her işlemin
  sonucu geçerli bir bayt olur ve sızıntı tam sıfırdır.

## Proje yapısı

```
sss.py                 Konsol uygulaması (giriş noktası)
run_tests.py           Tüm testleri çalıştırır
shamir/
  gf256.py             GF(256) aritmetiği (log/antilog tabloları)
  core.py              split / combine (Lagrange interpolasyonu)
  encoding.py          Pay dizesi kodla/çöz (set kimliği + CRC)
  ui.py                Renkli konsol yardımcıları
web/
  server.py            Yerel web sunucusu + JSON API (stdlib http.server)
  static/              index.html, style.css, app.js (tek sayfa arayüz)
tests/
  test_core.py         Cisim aksiyomları + böl/birleştir round-trip
  test_encoding.py     Kodlama round-trip + sağlama + biçim hataları
  test_web.py          Web API iş mantığı (split/combine, doğrulama)
```

## Testler

```bash
python3 run_tests.py
```

## Güvenlik notları

- **Birleştirme anı tek zayıf noktadır:** paylar bir araya geldiğinde sır bir an
  için bellekte bütün halde bulunur. Sürekli kullanım gereken senaryolarda
  (ör. kripto cüzdan) multisig daha uygundur; bu araç güvenli **yedekleme/kurtarma**
  için idealdir.
- **Payları ayrı yerlerde sakla.** Hepsi tek yerdeyse şema anlamsızdır.
- **En az `k` payı kaybedersen sır kurtulamaz** — bilinçli bir ödünleşimdir.
- Eğitim amaçlıdır; üretim ortamı için gözden geçirilmiş, denetlenmiş bir
  kütüphane (ör. SLIP-0039 uygulamaları) tercih edilmelidir.
