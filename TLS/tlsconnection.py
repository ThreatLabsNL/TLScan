import struct
import socket
import errno

from TLS.protocols import Protocol
from TLS.tlsrecord import Record, ServerHello, Certificate, ServerKeyExchange, RecordHelper
from TLS.constants import HandshakeType, HandshakeTypeSsl2, ContentType


class TLSConnection(object):

    def __init__(self, tcp):
        self.verbose = False
        self.TCP = tcp
        self.kex_algorithm = None

    def get_header(self, size):
        if self.TCP.wrapper:
            wrapped = self.TCP.receive_buffer(8)  # TODO make dynamic?
        return self.TCP.receive_buffer(size)  # TYPE(1), VERSION(2), LENGTH(2)

    # ToDo move the functionality that obtains the response records to separate method
    def send_record(self, record):  # TODO record instance
        response = []  # Create a list of record objects
        if not isinstance(record, Record):
            raise Exception("send_record (TLS) was not passed a Record instance")
        try:
            self.TCP.send_all(record.get_bytes())  # Sending the byte representation of the object
            if Protocol.is_ssl3_tls(record.version):  # TLS/SSL
                header = self.get_header(5)  # TYPE(1), VERSION(2), LENGTH(2)
                while header:
                    if header and len(header) == 5:
                        rec = Record(Protocol.version_from_bytes(header[1:3]), struct.unpack('!B', header[0:1])[0])
                        rec.length = struct.unpack('!H', header[3:5])[0]
                        if 0 < rec.length:
                            response.append(self.get_response_record(rec))
                    next_header = self.TCP.receive_buffer(5)
                    if next_header:
                        header = next_header
                        del next_header
                    else:
                        break
            elif Protocol.is_ssl2(record.version):
                header = self.get_header(3)  # LENGTH(2), TYPE(1)
                if header and len(header) == 3:
                    rec = Record(record.version, struct.unpack('!B', header[2:3])[0])  # Version is assumed
                    rec.length = RecordHelper.get_ssl2_record_len(struct.unpack('!H', header[0:2])[0] - 3)
                    if 0 < rec.length:
                        response.append(self.get_response_record(rec))
        except socket.error as e:
            if e.errno == errno.ECONNRESET:  # 54; Microsoft sometimes just resets the connection
                msg = "Connection reset"  # Usually means: not supported or not an acceptable offer
                pass
            elif e.errno == errno.ECONNREFUSED:  # 61
                msg = "Connection refused"
            else:
                raise e
        return response

    # ToDo refactor to read_response_record
    def get_response_record(self, record):
        response = record
        buffer = self.TCP.receive_buffer(record.length)
        if buffer:
            record.body = buffer
            if Protocol.is_ssl3_tls(record.version):
                if record.content_type == ContentType.handshake:
                    if record.body[0] == HandshakeType.server_hello:
                        response = ServerHello(record.version, record.body)
                        self.kex_algorithm = response.kex_algorithm()
                    elif record.body[0] == HandshakeType.certificate:
                        response = Certificate(record.version, record.body)
                    elif record.body[0] == HandshakeType.server_key_exchange:
                    #    print("got server kex pre")
                        response = ServerKeyExchange(record.version, record.body, self.kex_algorithm)
                    #    print("got server kex post")
                elif record.content_type == ContentType.alert:
                    self.print_verbose("Received an alert!")  # TODO: return alert object
                else:
                    self.print_verbose("Unhandled response for TLS request record")
            elif Protocol.is_ssl2(record.version):
                if record.content_type == HandshakeTypeSsl2.server_hello:  # server hello
                    version = Protocol.version_from_bytes(response.body[2:4])  # For SSL2 version is part of the 'body'
                    response = ServerHello(version, record.body)
                    response.length = record.length
                else:
                    self.print_verbose("Unhandled response for SSL2 request record")
        else:
            self.print_verbose("No body received")
        return response

    def print_verbose(self, string):
        if self.verbose:
            print(string)
