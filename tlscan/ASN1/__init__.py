from .constants import TagType, UniversalTag, PC
from enum import Enum


class Tag(object):

    def __init__(self, tag_class, pc, tag):
        self.type_class = TagType(tag_class)
        self.pc = PC(pc)
        if self.type_class == TagType.Universal:
            self.tag_value = UniversalTag(tag)
        else:
            self.tag_value = tag

    def __repr__(self):  # Added for printing
        return "Tag object: {0}".format(self.tag_value)


class Element(object):

    def __init__(self, tag: Tag, length: int, value):
        self.tag = tag
        self.length = length
        self.value = value

    def __repr__(self):  # Added for printing
        return "Element object: {0} ({1} bytes)".format(self.tag.tag_value, self.length)


class ObjectIdentifier(Enum):  # http://www.alvestrand.no/objectid/top.html
    commonName = '2.5.4.3'                  # CN
    countryName = '2.5.4.6'                 # C
    localityName = '2.5.4.7'                # L
    stateOrProvinceName = '2.5.4.8'         # ST
    streetAddress = '2.5.4.9'               # STREET
    organizationName = '2.5.4.10'           # O
    organizationalUnitName = '2.5.4.11'     # OU
    title = '2.5.4.12'                      # T
    businessCategory = '2.5.4.15'           # BC
    postalCode = '2.5.4.17'                 # PC
    emailAddress = '1.2.840.113549.1.9.1'   # E

    # signatureAlgorithm
    rsaEncryption = '1.2.840.113549.1.1.1'
    md5WithRSAEncryption = '1.2.840.113549.1.1.4'
    sha1WithRSAEncryption = '1.2.840.113549.1.1.5'
    sha256WithRSAEncryption = '1.2.840.113549.1.1.11'

    id_ecPublicKey = '1.2.840.10045.2.1'
    ecdsa_with_SHA224 = '1.2.840.10045.4.3.1'
    ecdsa_with_SHA256 = '1.2.840.10045.4.3.2'
    ecdsa_with_SHA384 = '1.2.840.10045.4.3.3'
    ecdsa_with_SHA512 = '1.2.840.10045.4.3.4'
