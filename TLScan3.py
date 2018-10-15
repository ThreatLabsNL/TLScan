from sys import exit
from argparse import ArgumentParser

from scanner import TargetParser, Enumerator
from TLS.protocols import versions as p_versions

# ToDo
# cipher preference
# certificate details (e.g. pub-key, expiry)
# timestamp
# SVSC check


def test(target, preamble):

    versions = reversed(p_versions)

    enum = Enumerator(target)
    enum.set_clear_text_layer(preamble)
    enum.verbose = True  # Enumerator will print in verbose mode

    supported_protocols = enum.get_version_support(versions)

    if len(supported_protocols) == 0:  # Try again with SNI extension disabled
        enum.sni = False
        tt = reversed(p_versions)
        supported_protocols = enum.get_version_support(tt)

    for p in supported_protocols:
        enum.get_cipher_support(p)


def main():
    parser = ArgumentParser(description='Scanner to enumerate encryption protocol support', prog='TLScan3')
    parser.add_argument('target', type=str, help="specify target as: host:port e.g. www.example.com:443 or "
                                                 "[::1]:443 for IPv6")
    parser.add_argument('--version', action='version', version='%(prog)s 3.1')
    p_group = parser.add_mutually_exclusive_group()
    p_group.add_argument('--smtp', dest='smtp', action='store_true', help='Use SMTP as protocol layer')
    p_group.add_argument('--pop', dest='pop', action='store_true', help='Use POP(3) as protocol layer')
    p_group.add_argument('--imap', dest='imap', action='store_true', help='Use IMAP as protocol layer')
    p_group.add_argument('--mssql', dest='mssql', action='store_true', help='Use MSSQL as protocol layer')
    p_group.add_argument('--ftp', dest='ftp', action='store_true', help='Use FTP as protocol layer')

    args = parser.parse_args()
    preamble = ''
    if args.smtp:
        preamble = 'smtp'
    elif args.pop:
        preamble = 'pop'
    elif args.imap:
        preamble = 'imap'
    elif args.mssql:
        preamble = 'mssql'
    elif args.ftp:
        preamble = 'ftp'

    try:
        try:
            t = TargetParser(args.target).get_target()
        except ValueError:
            print("[!] Failed to parse target, adding default port (443)")
            t = TargetParser(args.target + ":443").get_target()
        test(t, preamble)
    except KeyboardInterrupt:
        print("[!] Received termination signal, exiting!")
        exit(3)
    except:
        raise


if __name__ == '__main__':
    main()
