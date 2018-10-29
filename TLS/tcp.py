import socket
import errno
import struct
import re
import codecs


class TCP(object):
    wrapper = None

    def __init__(self, host, port):
        self.timeout = 5
        self.retries = 1  # Not used ATM
        self.host = host
        self.port = port
        self.socket = None

    def connect(self):
        try:
            self.socket = socket.create_connection((self.host, int(self.port)), self.timeout)
            # return self.socket
            return self
        except socket.gaierror:
            print("Invalid/unknown host ({0})".format(self.host))
        except (socket.timeout, ConnectionRefusedError):
            print("Unable to connect to the remote host/service")
        except socket.error as e:
            if e.errno == errno.EHOSTDOWN or e.errno == errno.EHOSTUNREACH:
                print("The host provided is down/unreachable")
            else:
                raise e
        except:
            raise

    def send_all(self, data):  # Just a wrapper
        if self.wrapper:
            data = self.wrapper.get_message(data)
        self.socket.sendall(data)

    def receive_buffer(self, length):
        data = b''
        timeout_retries = 0
        total_received = 0
        empty_buffer_count = 0
        to_receive = length
        self.socket.settimeout(0.2)
        while total_received < length and empty_buffer_count < 2:
            try:
                new_data = self.socket.recv(to_receive)
                if new_data:
                    data += new_data
                    total_received = len(data)
                    to_receive = length - total_received if length > total_received else 0
                    del new_data
                else:
                    empty_buffer_count += 1
            except socket.timeout:
                if len(data) == 0 and timeout_retries == 2:
                    break
                timeout_retries += 1
                if timeout_retries == 2:
                    break
        self.socket.settimeout(self.timeout)

        return data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()


class StartTLS:

    def __init__(self, protocol):
        if re.match('smtp|pop|imap|mssql|ftp', protocol):
            self.protocol = protocol
        else:
            raise NotImplemented("STARTTLS not implemented for: {0}".format(protocol))

    def _do_mssql_sequence(self, tcp: TCP):
        sock = tcp.socket
        tds7 = TDS7()
        tds7.set_message(TDS7.pre_login_message)
        sock.sendall(tds7.get_bytes())
        response = sock.recv(100)
        message = tds7.strip_response(response)
        if message[5] == 1:
            # print("Option token: Encryption is present")
            offset = struct.unpack('!H', message[6:8])[0]
            if message[offset] == 1:
                tcp.wrapper = TDS7Wrapper(tds7)  # ToDo remove the need of passing tds7
                return True

    def _do_smtp_sequence(self, tcp: TCP):
        sock = tcp.socket
        buffer = codecs.decode(sock.recv(50), 'ascii')
        ready = False
        while not ready:
            if re.search(r'^220 .*?\n$', buffer, re.MULTILINE | re.DOTALL):
                ready = True
                break
            more = sock.recv(50)
            if not more:
                print("Did not receive a complete SMTP ready message")
                break
            else:
                buffer += more
        if ready:
            sock.sendall(b'HELO example.org\r\n')
            response = sock.recv(100)
            if b'250 ' in response:
                sock.send(b'STARTTLS\r\n')
                response = sock.recv(100)
                if b'220 ' in response:
                    return True

    def _do_pop_sequence(self, tcp: TCP):
        sock = tcp.socket
        buffer = codecs.decode(sock.recv(100), 'ascii')
        if re.search(r'^\+OK .*?\n$', buffer, re.MULTILINE | re.DOTALL):
            sock.send(b'STLS\r\n')
            response = codecs.decode(sock.recv(100), 'ascii')
            if re.search(r'^\+OK .*?\n$', response, re.MULTILINE | re.DOTALL):
                return True

    def _do_imap_sequence(self, tcp: TCP):
        sock = tcp.socket
        buffer = codecs.decode(sock.recv(100), 'ascii')
        if re.search(r'^\* OK .*?\n$', buffer):
            sock.send(b'A001 STARTTLS\r\n')
            response = sock.recv(100)
            if b'A001 OK ' in response:
                return True

    def _do_ftp_sequence(self, tcp: TCP):
        sock = tcp.socket
        buffer = codecs.decode(sock.recv(100), 'ascii')
        if re.search(r'^220 .*?\n$', buffer):
            sock.send(b'AUTH TLS\r\n')
            response = sock.recv(100)
            if b'234' in response:
                return True

    def prepare_socket(self, tcp):
        if getattr(self, '_do_' + self.protocol + '_sequence')(tcp):
            success = True
        else:
            success = False
        return success


class TDS7Wrapper:  # TODO DRYup
    tds7 = None

    def __init__(self, tds7):
        self.tds7 = tds7

    def get_message(self, data):
        self.tds7.set_message(data)
        return self.tds7.get_bytes()

    """def get_response(self, data):  # unwrap
        # if (data[0] == 12 or data[0] == 4) and data[1] == 1 :
        return self.tds7.strip_response(data)  # remove the TDS7 header"""


class TDS7:  # Sequence and wrapper
    type = 18  # TDS7 pre-login message
    status = 1  # int
    channel = 0  # short
    packet_number = 0
    window = 0
    # Start_TLS_options
    message = b''
    # Start_TLS_prelogin
    pre_login_message = b'\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x04' \
                        b'\xff\x09\x00\x05\x77\x00\x00\x01\x00\x00\x00\x00\x00'

    def __init__(self):
        pass

    def set_message(self, data: bytes):
        self.message = data

    def get_bytes(self):
        pre_login_parts = [
            struct.pack("!B", self.type),
            struct.pack("!B", self.status),
            struct.pack("!H", self.length),
            struct.pack("!H", self.channel),
            struct.pack("!B", self.packet_number),
            struct.pack("!B", self.window),
            self.message
        ]
        self.packet_number = self.packet_number + 1  # increment packet number (not sure if needed)

        return b''.join(pre_login_parts)

    @property
    def length(self):
        return len(self.message) + 8  # TDS7 'header' is 8 bytes

    def strip_response(self, data: bytes):  # ugly
        return data[8:]
