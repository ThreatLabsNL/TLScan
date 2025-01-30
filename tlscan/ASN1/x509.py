from . import Element, UniversalTag
from .DER import Decoder
from . import ObjectIdentifier as OID


X509_MAP = {
    OID.commonName.value: 'CN',           # commonName
    OID.countryName.value: 'C',           # countryName
    OID.localityName.value: 'L',          # localityName (City)
    OID.stateOrProvinceName.value: 'ST',  # stateOrProvinceName (State)
    OID.streetAddress.value: 'STREET',    # streetAddress
    OID.organizationName.value: 'O',      # organizationName
    OID.organizationalUnitName: 'OU',     # organizationalUnitName
    OID.title.value: 'T',                 # title
    # '2.5.4.15': 'BC',                   # businessCategory
    OID.emailAddress: 'E',                # e-mailAddress

    # Public Key and Signature Algorithms (most widely used)
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',

    '1.2.840.10045.2.1': 'id-ecPublicKey',
    '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',

    # Curves
    '1.2.840.10045.3.1.1': 'prime192v1',  # secp192r1
    '1.2.840.10045.3.1.2': 'prime192v2',
    '1.2.840.10045.3.1.3': 'prime192v3',
    '1.2.840.10045.3.1.4': 'prime239v1',
    '1.2.840.10045.3.1.5': 'prime239v2',
    '1.2.840.10045.3.1.6': 'prime239v3',
    '1.2.840.10045.3.1.7': 'prime256v1',  # secp256r1

}


def create_dn_string(input_elem: Element):
    string = ""
    if input_elem.tag.tag_value == UniversalTag.SEQUENCE:
        content = input_elem.value
        # content.reverse()  # Added to have CN first
        for sets in content:
            if sets.tag.tag_value == UniversalTag.SET:
                for seq in sets.value:  # All but last
                    if seq.tag.tag_value == UniversalTag.SEQUENCE and seq.value[0].value in X509_MAP:
                        string += "{0}={1}, ".format(X509_MAP[seq.value[0].value], seq.value[1].value)
    return string[:-2]  # Ugly workaround to remove the trailing comma


class Certificate:

    issuer = None
    subject = None
    validity = None
    public_key_info = None
    signature_algorithm = None

    def pretty_print(self, indent):
        indent = indent
        print("{indent}Signature Algorithm: {}".format(self.oid_to_text(self.signature_algorithm.value[0].value),
                                                       indent=indent))
        indent = indent * 2
        print("{indent}Subject: {}".format(create_dn_string(self.subject), indent=indent))
        print("{indent}Validity".format(indent=indent))
        print("{indent}Not before: {}".format(self.validity.value[0].value, indent=indent*2))
        print("{indent}Not after : {}".format(self.validity.value[1].value, indent=indent*2))
        print("{indent}Issuer: {}".format(create_dn_string(self.issuer), indent=indent))
        print("{indent}Subject Public Key Info:".format(indent=indent))
        print("{indent}Public Key Algorithm: {}".format(self.oid_to_text(self.public_key_info.value[0].value[0].value),
                                                        indent=indent*2))
        if self.public_key_info.value[0].value[0].value == OID.id_ecPublicKey.value:  # named curve
            print("{indent} OID: {}".format(self.oid_to_text(self.public_key_info.value[0].value[1].value),
                                            indent=indent*3))
        elif self.public_key_info.value[0].value[0].value == OID.rsaEncryption.value:
            # The BIT STRING will be constructed (modulus, publicExponent)
            rsa_public_key = Decoder.parse_bytes(self.public_key_info.value[1].value[1:])
            modulus_len = rsa_public_key[0].value[0].value.bit_length()
            print("{indent}Public-Key: {} bit   ".format(modulus_len, indent=indent*3))
        else:
            print("Failed to get Public Key info")

    def oid_to_text(self, oid):
        try:
            text = X509_MAP[oid]
        except KeyError:
            text = "Unknown OID"
        return text


def get_x509_from_bytes(input_bytes):
    cert = Certificate()
    decoded = Decoder.parse_bytes(input_bytes)
    tbs_certificate = decoded[0].value[0].value

    cert.signature_algorithm = decoded[0].value[1]
    cert.issuer = tbs_certificate[3]
    cert.subject = tbs_certificate[5]
    cert.validity = tbs_certificate[4]
    cert.public_key_info = tbs_certificate[6]

    return cert
