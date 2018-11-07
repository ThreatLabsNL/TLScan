from . import Tag, UniversalTag, Element, PC
import datetime


class Decoder(object):

    def __init__(self):
        pass

    @staticmethod
    def _flip(string):
        return string[::-1]

    @staticmethod
    def _bits_to_int(bit_string):
        return int(bit_string, 2)

    @staticmethod
    def _bytes_to_int(byte_string):
        return int.from_bytes(byte_string, 'big')

    @staticmethod
    def encode_oid(string):
        encoded_bytes = []
        parts = string.split('.')
        encoded_bytes.append(bytes([int(parts.pop(0)) * 0 + int(parts.pop(0))]))  # Special encoding for first two
        for part in parts:
            part = int(part)
            if part > 127:  # Multiple bytes required: do special encoding : ToDo Check this is correct (was 255)
                byte_repr = part.to_bytes((part.bit_length() + 7) // 8, 'big') or b'\0'
                final = ''
                for b in byte_repr:
                    final += bin(b)[2:].zfill(8)  # Zero filling is important due to 7bit encoding
                final = Decoder._flip(final)  # Reverse byte order to be able to chunk correctly
                chunks = [Decoder._flip(final[i:i + 7]) for i in range(0, len(final), 7)]   # chunk into 7 bits
                chunks.reverse()  # Reverse the list back again
                for c in chunks[:-1]:  # all but the last
                    if int(c, 2):
                        encoded_bytes.append(bytes([int(c, 2) + 128]))
                encoded_bytes.append(bytes([int(chunks[-1], 2)]))  # Finally add the last out of the list
            else:  # Will fit into one byte
                encoded_bytes.append(bytes([part]))
        return b''.join(encoded_bytes)

    @staticmethod
    def decode_oid(byte_string: bytearray):
        parts = [
            str(int(byte_string[0] / 40)),
            str(byte_string[0] % 40)
        ]
        byte_string = byte_string[1:]  # Remove the first byte
        tmp = ''
        for byte in byte_string:
            if byte > 127:  # Multi-byte
                t_byte = (byte - 128)  # (remove the MSB)
                tmp += bin(t_byte)[2:].zfill(7)  # 7 bit encoding
            else:  # Single-byte or last byte
                tmp += bin(byte)[2:].zfill(7)  # Zero filling is probably unneeded here
                parts.append(str(Decoder._bits_to_int(tmp)))
                tmp = ''
        # TODO return object/enum
        return '.'.join(parts)

    @staticmethod
    def decode_tag(tag_int: int):  # need the integer form of the byte
        bin_string = bin(tag_int)[2:].zfill(8)
        return Tag(Decoder._bits_to_int(bin_string[:2]),
                   Decoder._bits_to_int(bin_string[2:3]),
                   Decoder._bits_to_int(bin_string[3:]))

    @staticmethod
    def decode_tag_value(tag: Tag, value):
        if tag.tag_value == UniversalTag.PrintableString:
            value = value.decode('ascii')
        elif tag.tag_value == UniversalTag.UTF8String:
            value = value.decode('utf-8')
        # elif tag.tag == UniversalTag.OCTET_STRING:
        #    This is a special one that will/may contain other tags (i.e. Constructed)
        elif tag.tag_value == UniversalTag.INTEGER:
            value = Decoder._bytes_to_int(value)
        elif tag.tag_value == UniversalTag.OBJECT_IDENTIFIER:
            value = Decoder.decode_oid(value)
        elif tag.tag_value == UniversalTag.UCTTime:
            value = Decoder.decode_date(value)
        return value

    @staticmethod
    def decode_tag_value_length(length_bytes):
        tmp = b''
        if length_bytes[0] > 127:  # Multi-byte
            nr_bytes = length_bytes[0] - 128  # Remove MSB
            for i in range(1, nr_bytes + 1, 1):
                tmp += bytes([length_bytes[i]])
        return Decoder._bytes_to_int(tmp)

    @staticmethod
    def decode_date(input_bytes: bytearray):  # ToDo: Finalize multiple cases
        # http://www.obj-sys.com/asn1tutorial/node15.html
        # 991231235959+0200
        # 991231235959Z
        # 9912312359Z
        s = input_bytes.decode('utf-8')  # So much juggling!
        year = 1900 + int(s[:2]) if int(s[:2]) > 90 else 2000 + int(s[:2])
        date = datetime.datetime(year, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]))
        return date.__str__()  # Temporary, make better: like return a datetime object?

    @staticmethod
    def parse_bytes(input_bytes: bytearray):  # Recursive function to process/map all bytes in the DER encoded string
        offset = 0
        structure = []
        while offset < len(input_bytes):
            tag = Decoder.decode_tag(input_bytes[offset])  # We should always start with a Tag
            offset += 1
            length = b''
            if input_bytes[offset] > 127:  # Multi-byte
                nr_bytes = input_bytes[offset] - 128  # Remove MSB
                offset += 1
                for i in range(1, nr_bytes + 1, 1):
                    length += bytes([input_bytes[offset]])
                    offset += 1
            else:  # Single-byte length
                length += bytes([input_bytes[offset]])
                offset += 1
            length = Decoder._bytes_to_int(length)
            # print("Found {0} with length: {1}".format(tag.tag, length))
            value = input_bytes[offset:offset + length]
            offset += length
            # An Octet string should not always be a 'constructed' one! TODO fix
            if tag.pc is PC.Constructed:  # or tag.tag_value == UniversalTag.OCTET_STRING:  # Resolve further
                structure.append(Element(tag, length, Decoder.parse_bytes(value)))  # TLV
            else:
                structure.append(Element(tag, length, Decoder.decode_tag_value(tag, value)))
        return structure
