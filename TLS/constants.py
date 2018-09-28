from enum import Enum


class NamedCurve(Enum):
    sect163k1 = 1
    sect163r1 = 2
    sect163r2 = 3
    sect193r1 = 4
    sect193r2 = 5
    sect233k1 = 6
    sect233r1 = 7
    sect239k1 = 8
    sect283k1 = 9
    sect283r1 = 10
    sect409k1 = 11
    sect409r1 = 12
    sect571k1 = 13
    sect571r1 = 14
    secp160k1 = 15
    secp160r1 = 16
    secp160r2 = 17
    secp192k1 = 18
    secp192r1 = 19
    secp224k1 = 20
    secp224r1 = 21
    secp256k1 = 22
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    # rfc7027
    brainpoolP256r1 = 26
    brainpoolP384r1 = 27
    brainpoolP512r1 = 28
    ecdh_x25519 = 29  # Temp
    ecdh_x448 = 30  # Temp
    # rfc7919
    ffdhe2048 = 256
    ffdhe3072 = 257
    ffdhe4096 = 258
    ffdhe6144 = 259
    ffdhe8192 = 260
    # TODO: Add private use ones [RFC7919]
    arbitrary_explicit_prime_curves = 65281
    arbitrary_explicit_char2_curves = 65282


class CurveType(Enum):
    explicit_prime = 1
    explicit_char2 = 2
    named_curve = 3


class ECPointFormat(Enum):
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2


class KeyExchangeAlgorithm(Enum):
    dhe_dss = 'DHE_DSS'
    dhe_rsa = 'DHE_RSA'
    dh_anon = 'DH_anon'
    ecdhe_ecdsa = 'ECDHE_ECDSA'  # rfc4492
    ecdhe_rsa = 'ECDHE_RSA'  # rfc4492
    ecdhe_anon = 'ECDH_anon'  # rfc4492
    # Do not expect a ServerKeyExchange message for the following three
    rsa = 'RSA'
    dh_dss = 'DH_DSS'
    dh_rsa = 'DH_RSA'


class HashAlgorithm(Enum):
    none = 0
    md5 = 1
    sha1 = 2
    sha224 = 3
    sha256 = 4
    sha384 = 5
    sha512 = 6


class SignatureAlgorithm(Enum):
    anonymous = 0
    rsa = 1
    dsa = 2
    ecdsa = 3


class CompressionMethod(Enum):
    null = 0
    DEFLATE = 1  # RFC3749
    LZS = 64  # RFC3943


# ToDo: Make Enums
class HandshakeType:
    hello_request = 0
    client_hello = 1
    server_hello = 2
    certificate = 11
    server_key_exchange = 12
    server_hello_done = 14
    certificate_status = 22


class HandshakeTypeSsl2:
    client_hello = 1
    server_hello = 4


class ContentType:
    handshake = 22
    alert = 21
    heartbeat = 24


class AlertDescription:
    unexpected_message = 10
    handshake_failure = 40
    inappropriate_fallback = 86


class ExtensionType:
    # http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    server_name = 0
    elliptic_curves = 10  # rfc4492
    ec_point_formats = 11  # rfc4492
    signature_algorithms = 13  # rfc5246
    heartbeat = 15
    encrypt_then_mac = 22  # RFC7366
    extended_master_secret = 23  # RFC7627
    session_ticket_tls = 35
    pre_shared_key = 41  # rfc8446
    early_data = 42  # rfc8446
    supported_versions = 43  # rfc8446
    psk_key_exchange_modes = 45  # rfc8446
    signature_algorithms_cert = 50  # rfc8446
    key_share = 51  # rfc8446


class SignatureScheme(Enum):  # RFC8446
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601
    # ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    # RSASSA - PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    # EdDSA algorithms
    ed25519 = 0x0807
    ed448 = 0x0808
    # RSASSA - PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b
    # Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203


class NamedGroup(Enum):  # rfc8446
    # Elliptic Curve Groups(ECDHE)
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D  # 128 bits
    x448 = 0x001E  # 244 bits
    # Finite Field Groups(DHE)
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104
    # Reserved Code Points
    # ffdhe_private_use(0x01FC..0x01FF),
    # ecdhe_private_use(0xFE00..0xFEFF),
    # (0xFFFF)


class PskKeyExchangeMode(Enum):
    psk_ke = 0
    psk_dhe_ke = 1
