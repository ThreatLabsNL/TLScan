from scanner import Target

from TLS.protocols import Protocol, versions
from TLS.tlsrecord import ClientHello, ServerHello, Certificate, ServerKeyExchange
from TLS.tlsconnection import TLSConnection
from TLS.ciphers import ciphers_tls, ciphers_ssl2
from TLS.extensions import *
from TLS.constants import NamedCurve, NamedGroup, ECPointFormat, HashAlgorithm, SignatureAlgorithm, SignatureScheme
from TLS.constants import PskKeyExchangeMode
from TLS.tcp import TCP, StartTLS


class Enumerator(object):

    def __init__(self, target: Target):
        self.target = target
        self.verbose = False
        self.clear_text_layer = None
        self.sni = True

    def set_clear_text_layer(self, string):
        self.clear_text_layer = string

    def get_version_support(self, version_list):
        #for version in iter(version_list):
        #    print(version)
        supported = []
        self.print_verbose("Enumerating TLS/SSL version support for: {0} port {1}"
                           .format(self.target.host, self.target.port))
        if self.sni:
            self.print_verbose("[i] Uing SNI: '{}'".format(self.target.host))
        else:
            self.print_verbose("[i] SNI extension disabled.")
        for v in version_list:
            with TCP(self.target.host, self.target.port).connect() as tcp:
                if self.clear_text_layer:
                    stls = StartTLS(self.clear_text_layer)
                    stls.prepare_socket(tcp)
                tls = TLSConnection(tcp)  # Pass the socket object (connection) to start a TLSConnection instance
                if Protocol.is_tls1_3(versions[v]):
                    # TLS1.3 should ignore ciphers not supported so we SHOULD be able to provide all TLS ciphers we know
                    client_hello = self.get_tls13_extended_client_hello(ciphers_tls)
                    response = tls.send_record(client_hello)
                elif Protocol.is_ssl3_tls(versions[v]):
                    client_hello = self.get_ecc_extended_client_hello(versions[v], ciphers_tls)
                    client_hello.set_compression(bytearray(b'\x01\x00'))  # DEFLATE, null
                    response = tls.send_record(client_hello)
                elif Protocol.is_ssl2(versions[v]):
                    response = tls.send_record(ClientHello(versions[v], ciphers_ssl2))

                if len(response) > 0:  # ToDo: response may be referenced before assignment -> fix!
                    s_hello = None
                    # The ServerHello may not be the first Record received
                    for record in response:
                        if isinstance(record, ServerHello):
                            s_hello = record
                            break
                    if s_hello:
                        if s_hello.handshake_protocol == versions[v]:
                            supported.append(v)
                            self.print_verbose("  [+]: {0}".format(v))
                            if s_hello.compression_method is not None:
                                self.print_verbose("      Compression: {0}".format(s_hello.compression_method.name))
                        if Protocol.is_tls1_3(versions[v]) and \
                                s_hello.extensions_length > 0:  # Need to see if extension is present
                            for extension in s_hello.extensions():
                                if extension.extension_type == ExtensionType.supported_versions:
                                    supported.append(v)
                                    self.print_verbose("  [+]: {0}".format(v))

        return supported

    def print_verbose(self, string):
        if self.verbose:
            print(string)

    def get_ecc_extended_client_hello(self, version, cipher_list):
        client_hello = ClientHello(version, cipher_list)
        # Extensions required for ECC cipher detection
        client_hello.add_extension(EllipticCurves(NamedCurve))
        client_hello.add_extension(ECPointFormats(ECPointFormat))
        client_hello.add_extension(SignatureAlgorithms(Enumerator.get_hash_sig_list()))
        if self.sni:
            client_hello.add_extension(ServerName(self.target.host))
        client_hello.add_extension(HeartBeat(True))
        client_hello.add_extension(SessionTicketTLS())
        return client_hello

    # ToDo remove overlap with above ?
    def get_tls13_extended_client_hello(self, cipher_list):
        version_list = [versions['TLSv1_3'], versions['TLSv1_2'], versions['TLSv1_1'], versions['TLSv1_0']]

        client_hello = ClientHello(versions['TLSv1_3'], cipher_list)
        client_hello.add_extension(SupportedGroups(NamedGroup))  # Extension 10
        client_hello.add_extension(ECPointFormats(ECPointFormat))
        # client_hello.add_extension(ECPointFormats([ECPointFormat.uncompressed,
        #                                           ECPointFormat.ansiX962_compressed_prime,
        #                                           ECPointFormat.ansiX962_compressed_char2]))
        client_hello.add_extension(SignatureAlgorithmsTLS13(SignatureScheme))
        if self.sni:
            client_hello.add_extension(ServerName(self.target.host))
        client_hello.add_extension(HeartBeat(True))
        client_hello.add_extension(SessionTicketTLS())  # Empty ticket
        client_hello.add_extension(EncryptThenMAC())
        client_hello.add_extension(ExtendedMasterSecret())

        # Mandatory extensions for TLS1.3
        client_hello.add_extension(SupportedVersions(version_list))  # Extension 43
        client_hello.add_extension(PreSharedKeyExchangeModes([PskKeyExchangeMode.psk_dhe_ke]))  # Extension 45
        # If containing a "supported_groups" extension, it MUST also contain a "key_share" extension, and vice versa.
        client_hello.add_extension(KeyShare())  # Extension 51

        return client_hello

    def get_cipher_support(self, version):
        supported = []
        retries = 0
        cipher_list = None
        if Protocol.is_ssl3_tls(versions[version]):
            cipher_list = list(ciphers_tls)  # TLS.get_cipher_list(TLS.Protocols.TLS)
        elif Protocol.is_ssl2(versions[version]):
            cipher_list = list(ciphers_ssl2)
        server_hello_cipher = True
        self.print_verbose("Enumerating ciphers for: {0}".format(version))
        while server_hello_cipher:
            for c in cipher_list:
                try:
                    with TCP(self.target.host, self.target.port).connect() as tcp:
                        if self.clear_text_layer:
                            stls = StartTLS(self.clear_text_layer)
                            stls.prepare_socket(tcp)

                        tls = TLSConnection(tcp)

                        if Protocol.is_ssl3_tls(versions[version]):
                            if versions[version] == versions[Protocol.TLS1_3]:
                                response = tls.send_record(self.get_tls13_extended_client_hello(cipher_list))
                            else:
                                response = tls.send_record(self.get_ecc_extended_client_hello(versions[version],
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
                                        # Should we check if the response is using TLSv1.3?
                                        '''if versions[version] == versions[Protocol.TLS1_3]:
                                            for extension in s_hello.extensions():
                                                if extension.extension_type == ExtensionType.supported_versions:
                                                    break
                                        '''
                                        supported.append(hello_cipher)
                                        # This is ugly but hey it's not the only thing...
                                        if s_key_exchange:
                                            self.print_verbose("  [+] {0} ({1} bits) - {dh}{curve}{bits}".
                                                               format(hello_cipher.name,
                                                                      hello_cipher.bits,
                                                                      bits="{} bits".
                                                                      format(s_key_exchange.key_length()*8)
                                                                      if not s_key_exchange.elliptic else "",
                                                                      dh="ECDH" if s_key_exchange.elliptic else "DH",
                                                                      curve=" {} ".format(s_key_exchange.
                                                                                          named_curve.name)
                                                                      if s_key_exchange.elliptic else " "))
                                        else:
                                            self.print_verbose("  [+] {0} ({1} bits)".
                                                               format(hello_cipher.name,
                                                                      hello_cipher.bits))
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
                                    if self.verbose:
                                        [print("  [+] {0}".format(s[1])) for s in supported]
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

    def cipher_preference(self):
        pass  # ToDo

    @staticmethod
    def get_hash_sig_list():
        h_s_list = []
        for h in HashAlgorithm:
            for s in SignatureAlgorithm:
                h_s_list.append((h, s))
        return h_s_list
