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

## Tek dosya arayüzü (sunucusuz) — en kolay yol

`shamir.html` dosyasına **çift tıkla**, tarayıcıda açılır. Sunucu yok, internet
yok — tüm hesaplama (GF(256), Lagrange, pay kodlama) tarayıcının içinde,
JavaScript ile çalışır. Rastgelelik `crypto.getRandomValues` ile kriptografiktir.

Pay biçimi CLI ile **birebir uyumludur**: `sss.py` ile ürettiğin payları
`shamir.html` içinde birleştirebilir ya da tersini yapabilirsin (sağlama
toplamı `zlib.crc32` ile eşleşir).

## Doğrulanabilir Sır Paylaşımı — VSS (dağıtıcıya güvenmeme)

Klasik SSS'te payları üreten dağıtıcıya güvenmek zorundasın; sana bozuk bir pay
verirse ancak birleştirme anında anlarsın. **Feldman VSS** bunu çözer: dağıtıcı
paylarla birlikte açık **taahhütler** yayımlar, herkes kendi payının doğru
olduğunu sırrı öğrenmeden kanıtlar, hileli dağıtıcı anında yakalanır.

```bash
python3 vss.py
```

Menü: sırrı böl (taahhütlerle) · **payımı doğrula** · payları birleştir
(isteğe bağlı doğrulamayla, bozuk paylar elenir) · açıklama.

Sunucusuz tek dosya sürümü de var: `vss.html` dosyasına **çift tıkla**. Tüm
işlemler tarayıcıda BigInt ile çalışır; pay/taahhüt biçimi `vss.py` ile birebir
uyumludur (CLI'da üretileni tarayıcıda doğrulayıp birleştirebilirsin, tersi de).

Şema: RFC 3526 2048-bit güvenli asal grubu, `C_j = g^(a_j) mod p` taahhütleri,
`g^pay == Π C_j^(x^j)` doğrulaması, `Z_q` üzerinde Lagrange. Sır en fazla ~254
bayt (tek grup elemanı olarak kodlanır). Ayrıntı: [shamir/vss.py](shamir/vss.py).

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
shamir.html            Tek dosya, sunucusuz tarayıcı arayüzü (temel SSS)
vss.html               Tek dosya, sunucusuz tarayıcı arayüzü (Feldman VSS)
sss.py                 Temel SSS konsol uygulaması (GF(256))
vss.py                 Doğrulanabilir SS konsol uygulaması (Feldman VSS)
run_tests.py           Tüm testleri çalıştırır
shamir/
  gf256.py             GF(256) aritmetiği (log/antilog tabloları)
  core.py              Temel SSS: split / combine (Lagrange)
  encoding.py          SSS pay dizesi kodla/çöz (set kimliği + CRC)
  vss.py               Feldman VSS: split / verify_share / combine (Z_q)
  vss_encoding.py      VSS pay + taahhüt dizesi kodla/çöz
  ui.py                Renkli konsol yardımcıları
tests/
  test_core.py         Cisim aksiyomları + böl/birleştir round-trip
  test_encoding.py     SSS kodlama round-trip + sağlama + biçim
  test_vss.py          VSS round-trip + doğrulama + hile yakalama
  test_vss_encoding.py VSS pay/taahhüt kodlama round-trip
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
- **Dağıtıcıya güvenmiyorsan** temel SSS yerine `vss.py` (Feldman VSS) kullan:
  bozuk/hileli paylar taahhütlerle doğrulanarak yakalanır.
- Eğitim amaçlıdır; üretim ortamı için gözden geçirilmiş, denetlenmiş bir
  kütüphane (ör. SLIP-0039 uygulamaları) tercih edilmelidir.
