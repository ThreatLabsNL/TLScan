import re
import socket


class Target:

    def __init__(self, host, port):  # ToDo port: int
        # ToDo protocol (TCP/UDP)
        self.host = host
        self.port = port


class TargetParser:

    ipv6_notation_regex = '^[(.*?)]:+([0-9]{1,5})$'  # RFC3986 (section 3.2.2)
    ipv4_hostname_notation_regex = '^(.*)[:]+([0-9]{1,5})$'
    host = None
    port = None

    def __init__(self, input_string):
        self.string = input_string

        if self.is_ipv6_notation:
            self._parse_ipv6_notation()
        elif self.is_ipv4_hostname_notation:
            self._parse_ipv4_hostname_notation()
        else:
            raise ValueError("Not a valid address/hostname")

    @property
    def is_ipv6_notation(self):
        if re.match(TargetParser.ipv6_notation_regex, self.string):
            return True

    @property
    def is_ipv4_hostname_notation(self):
        if re.match(TargetParser.ipv4_hostname_notation_regex, self.string):
            return True

    @staticmethod  # https://stackoverflow.com/questions/2532053/validate-a-hostname-string
    def is_valid_hostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile('(?!-)[A-Z0-9]{1,63}(?<!-)$', re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    @staticmethod
    def get_address_type(address):
        try:
            socket.inet_pton(socket.AF_INET, address)  # TODO: pton may not be available on Windows
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, address)
            except socket.error:
                return None  # not a valid IP address
            return socket.AF_INET6
        return socket.AF_INET

    def _parse_ipv6_notation(self):
        m = re.match(TargetParser.ipv6_notation_regex, self.string)
        if TargetParser.get_address_type(m.group(1)) == socket.AF_INET6:
            self.host = m.group(1)
            self.port = m.group(2)
        else:
            raise ValueError("Invalid IPv6 address: {0}".format(m.group(1)))

    def _parse_ipv4_hostname_notation(self):
        m = re.match(TargetParser.ipv4_hostname_notation_regex, self.string)
        if TargetParser.get_address_type(m.group(1)) == socket.AF_INET or TargetParser.is_valid_hostname(m.group(1)):
            self.host = m.group(1)
            self.port = m.group(2)
        else:
            raise ValueError("Invalid format for IPv4 or hostname: {0}".format(m.group(1)))

    def get_target(self):
        """
        returns the Target object
        :return: Target object
        """
        return Target(self.host, self.port)
