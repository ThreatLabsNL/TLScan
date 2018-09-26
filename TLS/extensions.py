import struct
from abc import ABC, abstractmethod

from TLS.constants import ExtensionType


class Extension(object):
    """
    rfc6066
    """
    def __init__(self, extension_type: int):
        self.extension_type = extension_type
        # self.length = len(self.extension_data)  # ToDo use this and remove from inherited classes
        self.length = 0
        self.data = b''

    @property
    @abstractmethod
    def extension_data(self):
        return self.data

    def get_bytes(self):
        extension_parts = [
            struct.pack("!H", self.extension_type),
            struct.pack("!H", self.length),  # ToDo: ==> len(self.extension_data)
            self.extension_data,
        ]
        return b''.join(extension_parts)


class EllipticCurves(Extension):
    """
    RFC4492
    """
    def __init__(self, elliptic_curve_list):
        """
        :param elliptic_curve_list: Enum containing the elliptic curves
        """
        super(self.__class__, self).__init__(ExtensionType.elliptic_curves)
        self.elliptic_curve_list = elliptic_curve_list
        self.length = len(self.extension_data)
        # self.length = len(self.list_bytes) + 2  # include a length field of 2 bytes
        # self.length = len(self.extension_data)  # ToDo use this instead of above

    @property
    def extension_data(self):
        curves_bytes = self.list_bytes
        data = [
            struct.pack("!H", len(curves_bytes)),  # LENGTH
            curves_bytes
        ]
        return b''.join(data)

    @property
    def list_bytes(self):
        curve_bytes = b''
        for curve in self.elliptic_curve_list:
            curve_bytes += struct.pack('!H', curve.value)
        return curve_bytes


class ECPointFormats(Extension):
    """
    RFC4492
    """
    def __init__(self, ec_point_format_list):
        """
        :param ec_point_format_list: Enum containing the ec point formats
        """
        super(self.__class__, self).__init__(ExtensionType.ec_point_formats)
        self.ec_point_format_list = ec_point_format_list
        self.length = len(self.extension_data)
        # self.length = len(self.ec_point_format_list) + 1  # include a length field of 1 byte

    @property
    def extension_data(self):
        data = [
            bytes([len(self.ec_point_format_list)]),
            bytes(self.get_point_format_values),
        ]
        return b''.join(data)

    @property  # this should not be a property
    def get_point_format_values(self):
        point_format = []
        for ec_point_format in self.ec_point_format_list:
            point_format.append(ec_point_format.value)
        return point_format


class SignatureAlgorithms(Extension):
    """
    RFC5246
    """
    def __init__(self, signature_hash_list):
        """
        :param signature_hash_list: Enum containing the signature hashing algorithms ??
        """
        super(self.__class__, self).__init__(ExtensionType.signature_algorithms)
        self.signature_hash_list = signature_hash_list
        self.length = len(self.extension_data)
        # self.length = len(self.hash_signature_bytes) + 2  # include the length field

    @property
    def extension_data(self):
        data = [
            struct.pack('!H', len(self.hash_signature_bytes)),
            self.hash_signature_bytes
        ]
        return b''.join(data)

    @property
    def hash_signature_bytes(self):
        hs_bytes = b''
        for hs in self.signature_hash_list:
            hs_bytes += bytes([hs[0].value]) + bytes([hs[1].value])
        return hs_bytes


class SessionTicketTLS(Extension):  # Incomplete implementation
    """
    rfc4507
    """
    def __init__(self):
        super(self.__class__, self).__init__(ExtensionType.session_ticket_tls)
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        return b''


class EncryptThenMAC(Extension):  # Incomplete implementation
    def __init__(self):
        super(self.__class__, self).__init__(ExtensionType.encrypt_then_mac)
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        return b''


class ExtendedMasterSecret(Extension):  # Incomplete implementation
    def __init__(self):
        super(self.__class__, self).__init__(ExtensionType.extended_master_secret)
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        return b''


class ServerName(Extension):
    # ToDo: allow list of server_names

    def __init__(self, server_name):
        super(self.__class__, self).__init__(ExtensionType.server_name)
        self.server_name = server_name
        self.length = len(self.extension_data)
        # self.length = len(self.server_name) + 5

    @property
    def extension_data(self):
        data = [
            struct.pack('!H', len(self.server_name) + 3),
            b'\x00',  # Name type "host_name"
            struct.pack('!H', len(self.server_name)),
            bytes(self.server_name, 'utf-8'),
        ]
        return b''.join(data)


class HeartBeat(Extension):
    """
    rfc6520
    """
    def __init__(self, allowed):
        super(self.__class__, self).__init__(ExtensionType.heartbeat)
        if allowed:
            self.allowed = True
        else:
            self.allowed = False
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        allowed = 2  # peer_not_allowed_to_send
        if self.allowed:
            allowed = 1  # peer_allowed_to_send
        data = [
            bytes([allowed]),
        ]
        return b''.join(data)


# https://tools.ietf.org/html/rfc8446#section-4.2.1
class SupportedVersions(Extension):  # ToDo test
    """
    rfc8446
    """
    def __init__(self, version_list: list):
        """
        :param version_list: list of TLS version tuples (order is important)
        """
        super(self.__class__, self).__init__(ExtensionType.supported_versions)
        self.version_list = version_list
        self.length = len(self.extension_data)

    @property
    def extension_data(self):  # ToDo
        v_bytes = self._version_bytes()

        data = [
            struct.pack('!B', len(v_bytes)),
            v_bytes,
        ]
        return b''.join(data)

    def _version_bytes(self):
        v_bytes = b''
        for version in self.version_list:
            v_bytes += bytes([version[0]]) + bytes([version[1]])
        return v_bytes


# Ugly workaround, fix the original class to accommodate both legacy and new
class SignatureAlgorithmsTLS13(Extension):
    """
    RFC####
    """
    def __init__(self, signature_scheme_list):
        """
        :param signature_scheme_list: Enum containing the signature hashing algorithms
        """
        super(self.__class__, self).__init__(ExtensionType.signature_algorithms)
        self.signature_scheme_list = signature_scheme_list
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        ssl_bytes = self.signature_scheme_list_bytes

        data = [
            struct.pack('!H', len(ssl_bytes)),
            ssl_bytes
        ]
        return b''.join(data)

    @property
    def signature_scheme_list_bytes(self):
        ssl_bytes = b''
        for ss in self.signature_scheme_list:
            ssl_bytes += ss.value.to_bytes(2, byteorder='big')
        return ssl_bytes


class SignatureAlgorithmsCert(Extension):  # ToDo test
    """
    rfc8446
    """
    def __init__(self, signature_scheme_list):
        super(self.__class__, self).__init__(ExtensionType.signature_algorithms_cert)
        self.signature_scheme_list = signature_scheme_list
        self.length = len(self.extension_data)
        # self.length = len(self.signature_scheme_list_bytes) + 2

    @property
    def extension_data(self):
        ssl_bytes = self.signature_scheme_list_bytes

        data = [
            struct.pack('!H', len(ssl_bytes)),
            ssl_bytes
        ]
        return b''.join(data)

    @property
    def signature_scheme_list_bytes(self):
        ssl_bytes = b''
        for ss in self.signature_scheme_list:
            ssl_bytes += ss.value.to_bytes(2, byteorder='big')
        return ssl_bytes


class SupportedGroups(Extension):

    def __init__(self, named_group_list):
        """
        :param named_group_list: Enum list containing the named groups
        """
        super(self.__class__, self).__init__(ExtensionType.elliptic_curves)  # Renamed for TLS1.3 (RFC8244)
        self.named_group_list = named_group_list
        # self.length = len(self.list_bytes) + 2
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        curves_bytes = self.list_bytes
        data = [
            struct.pack("!H", len(curves_bytes)),  # LENGTH
            curves_bytes
        ]
        return b''.join(data)

    @property
    def list_bytes(self):
        named_bytes = b''
        for group in self.named_group_list:
            named_bytes += group.value.to_bytes(2, byteorder='big')  # Inconsistent use struct
        return named_bytes


class PreSharedKeyExchangeModes(Extension):

    def __init__(self, kex_modes_list):
        """
        :param kex_modes_list: Enum list containing kex_modes
        """
        super(self.__class__, self).__init__(ExtensionType.psk_key_exchange_modes)
        self.kex_modes_list = kex_modes_list
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        k_bytes = self._kex_modes_bytes()

        data = [
            struct.pack('!B', len(k_bytes)),
            k_bytes
        ]
        return b''.join(data)

    def _kex_modes_bytes(self):
        k_bytes = b''
        for k in self.kex_modes_list:
            k_bytes += bytes([k.value])
        return k_bytes


class EarlyData(Extension):

    def __init__(self):
        super(self.__class__, self).__init__(ExtensionType.early_data)
        self.length = len(self.extension_data)

    @property
    def extension_data(self):

        data = [
            b''
        ]
        return b''.join(data)


# https://tools.ietf.org/html/rfc8446#section-4.2.8
class KeyShare(Extension):  # ToDo complete/fix (dirty hack)
    def __init__(self):
        super(self.__class__, self).__init__(ExtensionType.key_share)
        self.length = len(self.extension_data)

    @property
    def extension_data(self):

        data = [
            b'\x00\x24\x00\x1d\x00\x20\x73\x26\xb6\x86\xb5\xb1\x92\x7e\xa5\x8c\xc7\xcd\x2d'
            b'\x5a\x41\x71\x58\x21\xd9\x15\x4f\xb9\x21\xf7\xb3\x0b\x9d\x87\x90\x19\x5b\x27'
        ]
        return b''.join(data)
