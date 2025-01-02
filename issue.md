בהתחלה, השגיאה שקיבלתי מtshark debug היא:
...
לכן ביצעתי את המחקר הבא:

```python
"""
TLS Cipher Suite Registry, compatible with Wireshark's definition.

From Wireshark's source code:

wireshark/epan/dissectors/packet-ssl-utils.c (line 1806):
{60,            // cipher_suite ID
KEX_RSA,        // Key Exchange method
SIG_RSA,        // Signature algorithm
ENC_AES,        // Encryption algorithm
16,             // Block size
128,            // Key size
128,            // Export key size
DIG_SHA256,     // Digest algorithm
SSL_CIPHER_MODE_CBC}  // Cipher mode

wireshark/epan/dissectors/packet-ieee17221.c (line 1435):
#define KEY_TYPE_NONE            0
#define KEY_TYPE_SHA256          1
#define KEY_TYPE_AES128          2
#define KEY_TYPE_AES256          3
#define KEY_TYPE_RSA1024_PUBLIC  4

wireshark/epan/dissectors/packet-ssl-utils.h (line 286):
#define ENC_SEED        0x39
#define ENC_NULL        0x3A
#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
"""
```
הגדרתי באופן עצמאי את cipher_suite שהשרת והלקוח ישתמשו בו, בהתאם למה שראיתי בקוד המקור:
# cipher_suite.py
```python
from enum import IntEnum
from dataclasses import dataclass

class KeyExchange(IntEnum):
    RSA = 0x10       # KEX_RSA
    DH = 0x11        # KEX_DH
    PSK = 0x12       # KEX_PSK
    ECDH = 0x13      # KEX_ECDH
    RSA_PSK = 0x14   # KEX_RSA_PSK

class SignatureAlgorithm(IntEnum):
    RSA = 0x20       # SIG_RSA
    DSS = 0x21       # SIG_DSS
    NONE = 0x22      # SIG_NONE

class EncryptionMethod(IntEnum):
    DES = 0x30           # ENC_DES
    DES3 = 0x31         # ENC_3DES
    RC4 = 0x32          # ENC_RC4
    RC2 = 0x33          # ENC_RC2
    IDEA = 0x34         # ENC_IDEA
    AES = 0x35          # ENC_AES - This is AES128
    AES256 = 0x36       # ENC_AES256
    CAMELLIA128 = 0x37  # ENC_CAMELLIA128
    CAMELLIA256 = 0x38  # ENC_CAMELLIA256
    SEED = 0x39         # ENC_SEED
    NULL = 0x3A         # ENC_NULL

class DigestAlgorithm(IntEnum):
    MD5 = 0x40         # DIG_MD5
    SHA = 0x41         # DIG_SHA
    SHA256 = 0x42      # DIG_SHA256
    SHA384 = 0x43      # DIG_SHA384

class CipherMode(IntEnum):
    STREAM = 0         # SSL_CIPHER_MODE_STREAM
    CBC = 1            # SSL_CIPHER_MODE_CBC
    GCM = 2            # SSL_CIPHER_MODE_GCM

@dataclass
class CipherSuite:
    """TLS Cipher Suite compatible with Wireshark's definition"""
    id: int = 60                                         # TLS_RSA_WITH_AES_128_CBC_SHA256
    key_exchange: KeyExchange = KeyExchange.RSA          # 0x10
    signature: SignatureAlgorithm = SignatureAlgorithm.RSA  # 0x20
    encryption: EncryptionMethod = EncryptionMethod.AES  # 0x35
    block_size: int = 16                                 # מהמבנה המקורי
    key_size: int = 128                                  # מהמבנה המקורי
    export_key_size: int = 128                          # מהמבנה המקורי
    digest: DigestAlgorithm = DigestAlgorithm.SHA256    # 0x42
    mode: CipherMode = CipherMode.CBC                    # 1
```


לאחר מכן, ניסיתי להשתמש בwireshark debug, שנתן לי פירוט יותר אודות הבעיה:
אני רואה שהבעיות עדיין קיימות. בוא נסכם מה קורה בכל חבילה:

1. חבילה #6 (HTTP GET Request מהקליינט):
```
ciphertext len: 160
plaintext len: 112
בעיה: padding 220 too large for work 112
```

2. חבילה #7 (HTTP 200 OK מהשרת):
```
ciphertext len: 128
plaintext len: 80
בעיה: padding 225 too large for work 80
```

3. חבילה #8 (קובץ GIF מהשרת):
```
ciphertext len: 1152
plaintext len: 1104
padding: 243 
בעיה: MAC verification failed
```

כדי לפתור את הבעיה של padding, הגעתי לקוד המקור הזה:
# sniffer/ssl.cpp (line 842):
```c
/* strip padding for GenericBlockCipher */
	if (decoder->cipher_suite->mode == MODE_CBC) {
		pad=out_str->data[inl-1];
		if (worklen <= pad) {
			if (debug) printf("ssl_decrypt_record failed: padding %d too large for work %d\n",
				pad, worklen);
			return -1;
		}
		worklen-=(pad+1);
		if (debug) printf("ssl_decrypt_record found padding %d final len %d\n",
			pad, worklen);
	}
```
הקוד של Wireshark בודק את ה-padding בצורה הבאה:
```c
if (worklen <= pad) {
  printf("padding %d too large for work %d\n", pad, worklen);
  return -1;
}
```

כדי לפתור את בעיית ה-padding, נצטרך בקוד שלנו:
1. לוודא שה-padding המתווסף לא גדול מהמידע המוצפן
2. להוסיף את הpadding לפני ההצפנה
3. לעקוב אחרי חוקי ה-TLS: אורך הpadding צריך להיות פחות מ-256 והערך האחרון צריך להיות מספר הבתים שהתווספו כpadding

הנה התיקון:
```python
pad_length = 16 - (len(final_payload) % 16)
if pad_length > len(final_payload):
    pad_length = 16
padding = bytes([pad_length - 1] * pad_length)
final_block = final_payload + padding
encrypted = cipher.update(final_block) + cipher.finalize()
```