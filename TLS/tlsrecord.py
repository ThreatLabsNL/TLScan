import struct
import time
import os

from TLS.protocols import Protocol, versions
from TLS.extensions import Extension
from TLS.ciphers import Cipher, ciphers_ssl2, ciphers_tls
from TLS.constants import HandshakeType, HandshakeTypeSsl2, ContentType, CompressionMethod, NamedCurve
from TLS.constants import KeyExchangeAlgorithm


class Record(object):

    def __init__(self, version, content_type, body=b''):
        self.content_type = content_type
        self.version = version  # legacy_version? -> RFC8446
        self.length = 0
        self.body = body
        self.body_info = {}  # To hold details about the body
        self.messages = []

    def get_bytes(self):
        record_parts = []
        if Protocol.is_ssl3_tls(self.version):
            record_parts = [  # TLS/SSLv3 record: TYPE, LENGTH, VERSION, BODY (content)
                bytes([self.content_type]),
                bytes(self.version),
                struct.pack("!H", self.length),
                self.body
            ]
        elif Protocol.is_ssl2(self.version) and self.content_type == HandshakeTypeSsl2.client_hello:
            record_parts = [  # SSLv2 record : LENGTH, TYPE, VERSION, BODY (content)
                struct.pack("!H", self.length),
                bytes([self.content_type]),
                bytes(self.version),  # tuple -> bytes
                self.body
            ]
        # ToDo raise exceptions
        elif Protocol.is_ssl2(self.version) and self.content_type == HandshakeTypeSsl2.server_hello:
            print("The byte representation of SSL2 server_hello is not implemented")
        else:
            print("Byte representation of RecordType not implemented")
        return b''.join(record_parts)


class ClientHello(Record):

    def __init__(self, version, ciphers_dict):
        self.cipher_suites = ciphers_dict
        self.extension_list = []  # ToDo: make a dict to prevent duplicate extensions
        try:
            if Protocol.is_ssl3_tls(version):
                if Protocol.is_tls1_3(version):
                    # TLS1.3 uses 'legacy version' TLS1.2 for the record layer
                    super(self.__class__, self).__init__(versions['TLSv1_2'], ContentType.handshake)
                    self.handshake_version = versions['TLSv1_2']
                else:
                    # Record version set to TLSv1_0
                    super(self.__class__, self).__init__(versions['TLSv1_0'], ContentType.handshake)
                    self.handshake_version = version
                self.compression = b'\x00'
                self.length = len(self.cipher_spec) + len(self.compression) + 42  # 32 random + 4 length + ..
                self._set_tls_hello_body_bytes()

            elif Protocol.is_ssl2(version):
                super(self.__class__, self).__init__(version, HandshakeTypeSsl2.client_hello)
                self.challenge = os.urandom(16)
                record_length = len(self.cipher_spec) + len(self.challenge) + 9
                self.length = RecordHelper.get_ssl2_record_len(record_length, True)  # Set MSB (no padding)

                self._set_ssl2_hello_body_bytes()
        except:
            raise Exception("Failed to craft ClientHello")

    def _set_tls_hello_body_bytes(self):
        # ToDo change the way the length is calculated/determined
        extension_list_bytes = self.get_extension_list_bytes()
        extension_length = b''
        # ToDo, make method for sessionid
        session_id = b'\x37\x4d\x00\x00\xa0\xa0\xee\x98\x19\x53\x5f\x7e\x87\x4d\x01\xae' \
                     b'\xfc\x0a\x94\x67\x17\x98\x5f\x4f\x12\xf0\x1a\xb6\x0f\x04\xd5\xe8'
        if extension_list_bytes:
            # self.length = len(self.cipher_spec) + len(self.compression) + 42 + len(extension_list_bytes) + 2
            self.length = len(self.cipher_spec) + len(self.compression) + 42 + len(extension_list_bytes)\
                          + 2 + len(session_id)  # Dirty poc
            extension_length = struct.pack('!H', len(extension_list_bytes))
        body_len = self.length - 4
        body_parts = [  # Humor?
            bytes([HandshakeType.client_hello]),
            struct.pack("!L", body_len)[1:],
            bytes(self.handshake_version),
            self.hello_rand,
            #b'\x00',  # session_id length
            b'\x20',  # poc session_id length
            session_id,  # proof of concept session id
            struct.pack("!H", len(self.cipher_spec)),
            self.cipher_spec,
            struct.pack('!B', len(self.compression)),
            self.compression,
            extension_length,
            extension_list_bytes,
        ]
        self.body = b''.join(body_parts)

    def _set_ssl2_hello_body_bytes(self):
        body_parts = [
            struct.pack("!H", len(self.cipher_spec)),
            b'\x00\x00',
            struct.pack("!H", len(self.challenge)),
            self.cipher_spec,
            self.challenge
        ]
        self.body = b''.join(body_parts)

    def add_extension(self, extension):
        # ToDo check if extension_type is already present in hello
        if Protocol.is_ssl3_tls(self.version) and isinstance(extension, Extension):
            try:
                self.extension_list.append(extension)
                self._set_tls_hello_body_bytes()  # We need to update the hello_body
            except:
                raise Exception("Something went wrong adding extension type: {0}".format(extension.extension_type))
        else:
            raise Exception("Cannot add extension to the protocol!")

    def set_compression(self, compression: bytearray):
        if Protocol.is_ssl3_tls(self.version):
            self.compression = compression
            self._set_tls_hello_body_bytes()

    def get_extension_list_bytes(self):
        """
        Converts the extension_list to their byte representation for over the wire
        :return: bytes
        """
        list_bytes = b''
        if self.extension_list:
            for extension in self.extension_list:
                list_bytes += extension.get_bytes()
        return list_bytes

    @property
    def cipher_spec(self):
        return b''.join(self.cipher_suites)

    @property
    def hello_rand(self):
        rand = [
            struct.pack("!L", int(time.time())),  # 4 bytes
            os.urandom(28)
        ]
        return b''.join(rand)


class ServerHello(Record):

    def __init__(self, version, body):
        if Protocol.is_ssl3_tls(version):
            super(self.__class__, self).__init__(version, ContentType.handshake)
        elif Protocol.is_ssl2(version):
            super(self.__class__, self).__init__(version, HandshakeTypeSsl2.server_hello)
        else:
            raise TypeError("Protocol unsupported")  # ToDo TLSException
        self.handshake_type = body[0]  # Check if applicable for SSL2
        self.length = len(body)
        self.body = body

    def kex_algorithm(self):
        for kex in KeyExchangeAlgorithm:
            if "TLS_{0}".format(kex.value) in self.response_cipher.name:
                return kex

    @property
    def session_id_length(self):
        return struct.unpack('!b', self.body[38:39])[0]

    @property
    def response_cipher(self):
        # TYPE(1), LENGTH(3), VERSION(2), RANDOM(32), SID_LENGTH(1) <-- 39 Bytes
        start = 39 + self.session_id_length  # 39 Bytes + SID_LENGTH
        cipher = self.body[start:start + 2]
        if cipher in ciphers_tls:
            return Cipher((cipher, ciphers_tls[cipher]))
        else:
            return Cipher((cipher, 'UNKNOWN_CIPHER'))

    @property
    def ssl2_response_ciphers(self):  # Add check to see if version is SSLv2
        cert_length = struct.unpack('!H', self.body[4:6])[0]  # Body starts at SessionID
        cipher_spec_length = struct.unpack('!H', self.body[6:8])[0]
        if cipher_spec_length % 3 == 0:
            start = 10 + cert_length
            cipher_spec = self.body[start:start + cipher_spec_length]
            ciphers = list(RecordHelper.chunk_string(cipher_spec, 3))
            for i in range(0, len(ciphers), 1):
                ciphers[i] = ciphers[i], ciphers_ssl2[ciphers[i]]
        else:
            raise Exception("Something is wrong with the cipher length")
        return ciphers

    @property
    def handshake_protocol(self):
        if Protocol.is_ssl3_tls(self.version):
            version = Protocol.version_from_bytes(self.body[4:6])
        else:
            version = self.version
        return version

    @property
    def compression_method(self):
        if Protocol.is_ssl3_tls(self.version):
            start = 39 + self.session_id_length + 2
            compression = self.body[start:start + 1]
            return CompressionMethod(struct.unpack('!B', compression)[0])

    @property
    def extensions_length(self):
        start = 39 + self.session_id_length + 3
        length = 0
        try:
            length = struct.unpack('!H', self.body[start:start + 2])[0]
        except struct.error:
            pass
        return length

    def extensions(self):
        extensions = []
        cursor = 39 + self.session_id_length + 5
        while True:
            try:
                ext_type = struct.unpack('!H', self.body[cursor:cursor + 2])[0]
                ext_length = struct.unpack('!H', self.body[cursor + 2:cursor + 4])[0]
                extension = Extension(ext_type)
                extension.data = self.body[cursor + 4:cursor + 4 + ext_length]
                extensions.append(Extension(ext_type))

                cursor = cursor + 4 + ext_length
                if cursor >= (39 + self.session_id_length + 5 + self.extensions_length):
                    break  # no more extensions to process
            except:
                raise Exception("Failed to parse extensions provided by the server")

        return extensions


class Certificate(Record):

    def __init__(self, version, body):
        if Protocol.is_ssl3_tls(version):
            super(self.__class__, self).__init__(version, ContentType.handshake)
        self.handshake_type = body[0]
        self.length = len(body)
        self.body = body

    @property
    def certificates_length(self):
        length = struct.unpack('!i', b'\x00' + self.body[4:7])[0]
        return length

    def certificates(self):
        # ToDo
        pass


class ServerKeyExchange(Record):
    # This Record type is not seen in TLS1.3
    curve_type = None
    named_curve = None
    elliptic = False

    def __init__(self, version, body, key_exchange_algorithm):
        if Protocol.is_ssl3_tls(version):
            super(self.__class__, self).__init__(version, ContentType.handshake)
        self.handshake_type = body[0]  # ToDo DRY-up (other classes seem to do the same)
        self.length = len(body)
        self.body = body
        self.key_exchange_algorithm = key_exchange_algorithm
        self.key_length()
        if 'ecdhe' in key_exchange_algorithm.name:
            self.curve_type = self.body[4]
            self.elliptic = True
            for curve in NamedCurve:
                if curve.value == struct.unpack('!H', self.body[5:7])[0]:
                    self.named_curve = curve
                    break

    def key_length(self):
        """
        :return: key_length (in bytes)
        """
        length = 0
        if self.key_exchange_algorithm == KeyExchangeAlgorithm.dhe_rsa or \
                self.key_exchange_algorithm == KeyExchangeAlgorithm.dhe_dss or \
                self.key_exchange_algorithm == KeyExchangeAlgorithm.dh_anon:
            # TYPE(1), LENGTH(3), pLENGTH(2), p, gLENGTH(1), g, pubkeyLENGTH(2)
            # print(struct.unpack('!I', b'\x00' + self.body[1:4])[0])
            p_length = struct.unpack('!H', self.body[4:6])[0]
            g_length = struct.unpack('!H', self.body[p_length+6:p_length+8])[0]
            length = struct.unpack('!H', self.body[p_length+8+g_length:p_length+8+g_length+2])[0]
        elif self.key_exchange_algorithm == KeyExchangeAlgorithm.ecdhe_ecdsa or \
                self.key_exchange_algorithm == KeyExchangeAlgorithm.ecdhe_rsa or \
                self.key_exchange_algorithm == KeyExchangeAlgorithm.ecdhe_anon:
            length = self.body[7]
        return length


class RecordHelper(object):

    @staticmethod
    def chunk_string(input_string, length):
        return (input_string[0 + i:length + i] for i in range(0, len(input_string), length))

    @staticmethod
    def get_ssl2_record_len(value: int, msb=False):  # most significant bit
        if not msb:  # Clear msb
            value &= ~ (1 << 15)
        elif msb:  # Set msb
            value |= (1 << 15)
        return value
