

from scanner import Target

from TLS.protocols import Protocol, versions
from TLS.tlsrecord import ClientHello, ServerHello, Certificate, ServerKeyExchange
from TLS.tlsconnection import TLSConnection
from TLS.ciphers import ciphers_tls, ciphers_ssl2, TLS_FALLBACK_SCSV
from TLS.extensions import *
from TLS.constants import NamedGroupList, NamedGroup, ECPointFormat, HashAlgorithm, SignatureAlgorithm, SignatureScheme
from TLS.constants import PskKeyExchangeMode, ContentType
from TLS.tcp import TCP, StartTLS

from ASN1 import x509

start_tls = {
    'smtp': [25, 587],
    'pop': [110],
    'imap': [143],
    'mssql': [1433],
    'ftp': [21],
    'rdp': [3389],
}


class Enumerator(object):

    def __init__(self, target: Target):
        self.target = target
        self.verbose = False
        self.clear_text_layer = None
        self.sni = True
        self.sni_name = target.host

    def set_clear_text_layer(self, preamble):
        if preamble:
            self.clear_text_layer = preamble
            self.print_verbose("  [*] Using STARTTLS sequence for {}".format(preamble.upper()))

    def get_version_support(self, version_list):
        supported = []
        if self.sni:
            self.print_verbose("  [*] Using SNI: '{}'".format(self.sni_name))
        else:
            self.print_verbose("  [*] SNI extension disabled.")

        self.print_verbose("Enumerating TLS/SSL protocol version support for: {0} port {1}"
                           .format(self.target.host, self.target.port))

        for v in version_list:
            response = self.send_client_hello(v)

            if len(response) > 0:
                s_hello = None
                for record in response:
                    if isinstance(record, ServerHello):
                        s_hello = record
                        break
                if s_hello:
                    if s_hello.handshake_protocol == versions[v]:
                        supported.append(v)
                        self.print_verbose("  [+] {0}".format(v))
                        if s_hello.compression_method is not None:
                            self.print_verbose("      Compression: {0}".format(s_hello.compression_method.name))
                    if Protocol.is_tls1_3(versions[v]) and \
                            s_hello.extensions_length > 0:  # Check if relevant extension is present
                        for extension in s_hello.extensions():
                            if extension.extension_type == ExtensionType.supported_versions:
                                supported.append(v)
                                self.print_verbose("  [+] {0}".format(v))

        return supported

    def print_verbose(self, string):
        if self.verbose:
            print(string)

    def get_cipher_support(self, version):
        supported = []
        retries = 0
        cipher_list = None
        if Protocol.is_ssl3_tls(versions[version]):
            cipher_list = list(ciphers_tls)
        elif Protocol.is_ssl2(versions[version]):
            cipher_list = list(ciphers_ssl2)
        server_hello_cipher = True
        self.print_verbose("Enumerating supported ciphers for: {0}".format(version))
        while server_hello_cipher:
            for _ in cipher_list:
                try:
                    with TCP(self.target.host, self.target.port).connect() as tcp:
                        if self.clear_text_layer:
                            stls = StartTLS(self.clear_text_layer)
                            stls.prepare_socket(tcp)

                        tls = TLSConnection(tcp)

                        if Protocol.is_ssl3_tls(versions[version]):
                            if versions[version] == versions[Protocol.TLS1_3]:
                                response = tls.send_record(self.create_tls13_extended_client_hello(cipher_list))
                            else:
                                response = tls.send_record(self.create_ecc_extended_client_hello(versions[version],
                                                                                                 cipher_list))
                            if len(response) > 0:
                                s_hello = None
                                s_key_exchange = None
                                for record in response:
                                    if isinstance(record, ServerHello):
                                        s_hello = record
                                    elif isinstance(record, ServerKeyExchange):
                                        s_key_exchange = record
                                    for message in record.messages:
                                        if isinstance(message, ServerKeyExchange):
                                            s_key_exchange = message
                                            break
                                if s_hello:
                                    hello_cipher = s_hello.response_cipher
                                    if hello_cipher and hello_cipher in supported:
                                        server_hello_cipher = False
                                        break
                                    elif hello_cipher:
                                        supported.append(hello_cipher)
                                        self.print_cipher(hello_cipher, s_key_exchange)
                                        cipher_list.remove(hello_cipher.bytes)
                                        retries = 0
                                else:  # No hello received, could be an alert
                                    server_hello_cipher = False
                                    break
                            else:  # Bug-fix
                                if retries < 3:
                                    retries += 1
                                else:
                                    server_hello_cipher = False
                                    break
                        elif Protocol.is_ssl2(versions[version]):
                            response = tls.send_record(ClientHello(versions[version], cipher_list))
                            if len(response) > 0:
                                if isinstance(response[0], ServerHello):
                                    supported = response[0].ssl2_response_ciphers  # ssl2 returns all ciphers at once
                                    [self.print_verbose("  [+] {0}".format(s[1])) for s in supported]
                                server_hello_cipher = False
                                break
                            else:
                                server_hello_cipher = False
                                break
                except AttributeError:
                    break
                except:
                    raise
        return supported

    # ToDo: Make SSLv2 proof
    def get_certificate(self, protocol):
        self.print_verbose("Subject certificate details")
        response = self.send_client_hello(protocol, ciphers_tls=ciphers_tls)
        certificate = None
        cert = None
        if len(response) > 0:
            for record in response:
                if isinstance(record, ServerHello):
                    for message in record.messages:  # There may be nested handshake_messages
                        if isinstance(message, Certificate):
                            cert = message.certificates()[0]  # The sender's certificate MUST come first in the list.
                            break
                elif isinstance(record, Certificate):
                    cert = record.certificates()[0]
                    break
            if cert:
                certificate = x509.get_x509_from_bytes(cert)
                if self.verbose:
                    certificate.pretty_print(indent='  ')
        return certificate

    def check_fallback_support(self, supported_protocols):  # Experimental
        cipher_list = dict(ciphers_tls)  # Make a copy as we are going to add a cipher
        cipher_list[TLS_FALLBACK_SCSV[0]] = TLS_FALLBACK_SCSV[1]
        svsc_supported = False

        if len(supported_protocols) >= 2:  # Else there is nothing to downgrade
            test_protocol = supported_protocols[1]  # Index 0 should be the highest supported protocol version

            response = self.send_client_hello(test_protocol, ciphers_tls=cipher_list)

            if len(response) > 0:
                s_hello = None
                for record in response:
                    if isinstance(record, ServerHello):
                        s_hello = record
                        break
                    elif record.content_type == ContentType.alert:
                        # and record.alert_description # ToDo?
                        svsc_supported = True
                        self.print_verbose("  [+] TLS_FALLBACK_SCSV supported (received Alert).")
                if s_hello:
                    self.print_verbose("  [+] TLS_FALLBACK_SCSV not supported (received ServerHello).")

        return svsc_supported

    def cipher_preference(self):
        pass  # ToDo

    @staticmethod
    def get_hash_sig_list():
        h_s_list = []
        for h in HashAlgorithm:
            for s in SignatureAlgorithm:
                h_s_list.append((h, s))
        return h_s_list

    def print_cipher(self, cipher, s_kex: ServerKeyExchange):
        if s_kex:
            self.print_verbose("  [+] {0} ({1} bits) - {dh}{curve}{bits}".
                               format(cipher.name, cipher.bits, bits="{} bits".
                                      format(s_kex.key_length() * 8)
                                      if not s_kex.elliptic else "",
                                      dh="ECDH" if s_kex.elliptic else "DHE",
                                      curve=" {} ".format(s_kex.named_curve.name)
                                      if s_kex.elliptic else " "))
        else:
            self.print_verbose("  [+] {0} ({1} bits)".format(cipher.name, cipher.bits))

    def send_client_hello(self, version, ciphers_tls=ciphers_tls):
        response = None
        with TCP(self.target.host, self.target.port).connect() as tcp:
            if self.clear_text_layer:
                stls = StartTLS(self.clear_text_layer)
                stls.prepare_socket(tcp)
            tls = TLSConnection(tcp)  # Pass the socket object (connection) to start a TLSConnection instance
            if Protocol.is_tls1_3(versions[version]):
                # TLS1.3 should ignore ciphers not supported so we SHOULD be able to provide all TLS ciphers we know
                client_hello = self.create_tls13_extended_client_hello(ciphers_tls)
                response = tls.send_record(client_hello)
            elif Protocol.is_ssl3_tls(versions[version]):
                client_hello = self.create_ecc_extended_client_hello(versions[version], ciphers_tls)
                client_hello.set_compression(bytearray(b'\x01\x00'))  # DEFLATE, null
                response = tls.send_record(client_hello)
            elif Protocol.is_ssl2(versions[version]):
                response = tls.send_record(ClientHello(versions[version], ciphers_ssl2))

        return response

    def create_ecc_extended_client_hello(self, version, cipher_list):
        client_hello = ClientHello(version, cipher_list)

        # Extensions required for ECC cipher detection
        client_hello.add_extension(EllipticCurves(NamedGroup))
        client_hello.add_extension(ECPointFormats(ECPointFormat))
        client_hello.add_extension(SignatureAlgorithms(Enumerator.get_hash_sig_list()))
        if self.sni:
            client_hello.add_extension(ServerName(self.sni_name))
        client_hello.add_extension(HeartBeat(True))
        client_hello.add_extension(SessionTicketTLS())
        return client_hello

    def create_tls13_extended_client_hello(self, cipher_list):
        version_list = [versions['TLSv1_3'], versions['TLSv1_2'], versions['TLSv1_1'], versions['TLSv1_0']]
        client_hello = ClientHello(versions['TLSv1_3'], cipher_list)

        client_hello.add_extension(SupportedGroups(NamedGroupList))  # Extension 10
        client_hello.add_extension(ECPointFormats(ECPointFormat))
        client_hello.add_extension(SignatureAlgorithmsTLS13(SignatureScheme))
        if self.sni:
            client_hello.add_extension(ServerName(self.sni_name))
        client_hello.add_extension(HeartBeat(True))
        client_hello.add_extension(SessionTicketTLS())
        client_hello.add_extension(EncryptThenMAC())
        client_hello.add_extension(ExtendedMasterSecret())

        # Mandatory extensions for TLS1.3
        client_hello.add_extension(SupportedVersions(version_list))  # Extension 43
        client_hello.add_extension(PreSharedKeyExchangeModes([PskKeyExchangeMode.psk_dhe_ke]))  # Extension 45
        # If containing a "supported_groups" extension, it MUST also contain a "key_share" extension, and vice versa.
        client_hello.add_extension(KeyShare())  # Extension 51

        return client_hello

