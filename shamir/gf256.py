"""GF(256) — 256 elemanlı sonlu cisim aritmetiği.

Her bayt (0..255) bu cismin bir elemanıdır. Sır paylaşımında tüm toplama
ve çarpma işlemleri burada yapılır; böylece her işlemin sonucu yine geçerli
bir bayt olur (taşma yok) ve eşik altındaki paylar sıfır bilgi sızdırır.

Kurallar:
  - Toplama ve çıkarma  = bit-bit XOR (elde/carry yoktur, a + a = 0).
  - Çarpma              = indirgenemez polinom x^8 + x^4 + x^3 + x + 1 (0x11B)
                          modülünde çarpım. Hız için log/antilog tabloları
                          önceden hesaplanır.

Bu, AES ile aynı cisim ve aynı polinomdur.
"""

# İndirgenemez polinom: x^8 + x^4 + x^3 + x + 1  ->  0b1_0001_1011 = 0x11B
_REDUCING_POLY = 0x11B

# Çarpımsal grubun bir üreteci (generator). 0x03, bu polinom için ilkeldir:
# 3^0, 3^1, ... 3^254 sıfır dışındaki 255 elemanın tamamını dolaşır.
_GENERATOR = 0x03

# exp[i] = GENERATOR^i  (antilog tablosu),  log[v] = i  öyle ki exp[i] = v
_EXP = [0] * 512  # 512: (log[a]+log[b]) taşmasında mod almadan indekslemek için
_LOG = [0] * 256


def _russian_peasant_multiply(a: int, b: int) -> int:
    """Tablo kurulumu için: iki baytı GF(256) içinde tablosuz çarpar.

    "Rus köylü çarpımı" — b'nin bitlerini gezerek a'yı toplar (XOR), her
    adımda a'yı x ile çarpar (sola kaydır) ve 8. bite taşarsa polinomla indirger.
    """
    result = 0
    while b:
        if b & 1:
            result ^= a          # toplama = XOR
        b >>= 1
        a <<= 1                  # a = a * x
        if a & 0x100:            # 8. bite taştıysa
            a ^= _REDUCING_POLY  # polinoma göre indirge
    return result


def _build_tables() -> None:
    """log/antilog tablolarını üreteç üzerinden bir kez doldurur."""
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _russian_peasant_multiply(x, _GENERATOR)
    # exp tablosunu 255..509 aralığında tekrarla; böylece çarpmada
    # (log[a] + log[b]) toplamı 255'i geçse bile mod almadan indeksleyebiliriz.
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def add(a: int, b: int) -> int:
    """GF(256) toplaması (= çıkarması). Bit-bit XOR."""
    return a ^ b


# Toplama ve çıkarma aynı işlem olduğundan sub, add'e bağlıdır.
sub = add


def mul(a: int, b: int) -> int:
    """GF(256) çarpması. 0 ile çarpım her zaman 0'dır."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def div(a: int, b: int) -> int:
    """GF(256) bölmesi: a / b. b sıfır olamaz."""
    if b == 0:
        raise ZeroDivisionError("GF(256) içinde sıfıra bölme")
    if a == 0:
        return 0
    return _EXP[_LOG[a] - _LOG[b] + 255]  # +255: çıkarma negatife düşmesin


def pow_(a: int, exponent: int) -> int:
    """GF(256) üs alma: a^exponent."""
    if exponent == 0:
        return 1
    if a == 0:
        return 0
    return _EXP[(_LOG[a] * exponent) % 255]


def inverse(a: int) -> int:
    """a'nın çarpımsal tersi (a * inverse(a) == 1). a sıfır olamaz."""
    if a == 0:
        raise ZeroDivisionError("GF(256) içinde 0'ın tersi yoktur")
    return _EXP[255 - _LOG[a]]
