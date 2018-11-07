from sys import exit
from argparse import ArgumentParser
from datetime import datetime

from scanner import TargetParser, Enumerator, start_tls
from TLS.protocols import versions as p_versions

# ToDo
# cipher preference
# encrypted sni (https://tools.ietf.org/html/draft-ietf-tls-esni-02)


def print_start():
    print("Starting enumeration at: {}".format(datetime.now().strftime('%d-%m-%Y %H:%M:%S')))


def test(target, preamble, sni_name):

    enum = Enumerator(target)
    if sni_name:
        enum.sni_name = sni_name
    enum.set_clear_text_layer(preamble)
    enum.verbose = True  # Enumerator will print in verbose mode

    print_start()
    supported_protocols = enum.get_version_support(reversed(p_versions))

    if len(supported_protocols) == 0:
        for key, value in start_tls.items():
            if int(target.port) in value:  # Try again: adding a clear-text protocol for the port
                print_start()
                enum.set_clear_text_layer(key)
                supported_protocols = enum.get_version_support(reversed(p_versions))
                break

    if len(supported_protocols) == 0:  # Try again with SNI extension disabled (all following actions will not use SNI)
        enum.sni = False
        print_start()
        supported_protocols = enum.get_version_support(reversed(p_versions))

    enum.check_fallback_support(supported_protocols)

    for p in supported_protocols:
        enum.get_cipher_support(p)

    if p_versions[supported_protocols[0]] == p_versions['TLSv1_3'] and len(supported_protocols) > 1:
        enum.get_certificate(supported_protocols[1])
    else:
        enum.get_certificate(supported_protocols[0])


def main():
    parser = ArgumentParser(description='Scanner to enumerate encryption protocol support', prog='TLScan3')
    parser.add_argument('target', type=str, help="specify target as: host:port e.g. www.example.com:443 or "
                                                 "[::1]:443 for IPv6")
    parser.add_argument('--version', action='version', version='%(prog)s 3.1')
    p_group = parser.add_mutually_exclusive_group()
    for key, value in start_tls.items():
        p_group.add_argument("--{}".format(key), dest=key, action='store_true',
                             help='Use {} as protocol layer'.format(key.upper()))
    parser.add_argument('--sni', type=str, dest='sni', help="SNI name to use in the handshake")

    args = parser.parse_args()
    preamble = None

    for key, value in start_tls.items():
        try:
            if getattr(args, key):
                preamble = key
                break
        except AttributeError:
            pass

    try:
        try:
            t = TargetParser(args.target).get_target()
        except ValueError:
            print("[!] Failed to parse target, trying again by adding a default port (443)")
            t = TargetParser(args.target + ":443").get_target()
        test(t, preamble, args.sni)
    except KeyboardInterrupt:
        print("[!] Received termination signal, exiting!")
        exit(3)
    except:
        raise


if __name__ == '__main__':
    main()
