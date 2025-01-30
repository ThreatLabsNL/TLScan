from collections import OrderedDict

versions = OrderedDict([
    ('SSLv2', (0, 2)),
    ('SSLv3', (3, 0)),
    ('TLSv1_0', (3, 1)),
    ('TLSv1_1', (3, 2)),
    ('TLSv1_2', (3, 3)),
    ('TLSv1_3', (3, 4)),
])


class Protocol:
    TLS = 'TLS'  # All TLS versions and SSLv3
    TLS1_3 = 'TLSv1_3'
    SSL2 = 'SSLv2'

    @staticmethod
    def is_ssl2(version):
        if version == versions[Protocol.SSL2]:
            return True

    @staticmethod
    def is_ssl3_tls(version):
        if version in versions.values() and not Protocol.is_ssl2(version):
            return True

    @staticmethod
    def is_tls1_3(version):
        if version in versions.values() and version == versions[Protocol.TLS1_3]:
            return True

    @staticmethod
    def version_from_bytes(version_bytes):
        version = ()
        if Protocol.is_ssl3_tls((version_bytes[0], version_bytes[1]))\
                or Protocol.is_ssl2((version_bytes[0], version_bytes[1])):
            version = version_bytes[0], version_bytes[1]
        else:  # ToDo: raise exception
            print("Version not recognized {0}".format(version_bytes))
        return version


# ToDo continue work here

class TLS(Protocol):
    max_record_length = 2**14  # 2^14 bytes
    max_mac_bytes = 20
    version = None


class SSLv2(Protocol):
    version = (0, 2)
    # ToDo max_length?


class SSLv3(TLS):
    version = (3, 0)
    protocol_name = 'SSLv3'  # IDEA


class TLSv1_0(TLS):
    version = (3, 1)



class TLSv1_1(TLS):
    version = (3, 2)


class TLSv1_2(TLS):
    version = (3, 3)
    max_mac_bytes = 32


class TLSv1_3(TLS):
    max_record_length = 2**14 + 1
    version = (3, 4)
