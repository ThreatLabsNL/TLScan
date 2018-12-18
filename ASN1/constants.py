from enum import Enum


class UniversalTag(Enum):  # http://obj-sys.com/asn1tutorial/node124.html
    # Universal ASN.1 tags (incomplete list)
    BOOLEAN = 1
    INTEGER = 2
    BIT_STRING = 3
    OCTET_STRING = 4
    NULL = 5
    OBJECT_IDENTIFIER = 6
    UTF8String = 12
    SEQUENCE = 16
    SET = 17
    NumericString = 18
    PrintableString = 19
    TeletexString = 20
    IA5String = 22
    UCTTime = 23
    UNICODE_STRING = 30


class TagType(Enum):
    Universal = 0
    Application = 1
    Context_Specific = 2
    Private = 3


class PC(Enum):
    Primitive = 0
    Constructed = 1
