#!/usr/bin/env python2

"""
Script to extract Premaster secrets from a PCAP of TLS connections. For usage in DROWN attacks with
TLS-Attacker (`-premasterSecretsFile` argument), call it with `--hex` as output option.
"""

from __future__ import print_function
import argparse
from base64 import b64encode
from binascii import hexlify
import struct

from scapy.all import *


def main():

    arg_parser = argparse.ArgumentParser(description=u'Extract the encrypted Premaster secrets of '
                                                     u'all TLS connections in a PCAP')
    output_args = arg_parser.add_mutually_exclusive_group(required=True)
    output_args.add_argument(u'--hex', action='store_true', help=u'Print results as hex strings')
    output_args.add_argument(u'--base64', action='store_true', help=u'Print results as base-64 '
                                                                    u'strings')
    output_args.add_argument(u'--ints', action='store_true', help=u'Print results as lists of '
                                                                  u'integers')
    output_args.add_argument(u'--java-bytes', action='store_true',
                             help=u'Print results as list of byte lists in Java syntax')
    arg_parser.add_argument(u'pcap_file', metavar=u'pcap-file')
    args = arg_parser.parse_args()

    # Enable Scapy TLS support
    load_layer('tls')

    packets = rdpcap(args.pcap_file)
    secrets = extract_secrets(packets)

    if args.java_bytes:
        print(u'{')
    for secret in secrets:
        if args.hex:
            print(hexlify(secret))
        elif args.base64:
            print(b64encode(secret))
        elif args.ints:
            print(format_list(secret, u', '))
        elif args.java_bytes:
            print(u'{(byte)' + format_list(secret, u', (byte)') + u'},')
    if args.java_bytes:
        print(u'}')


def extract_secrets(packets):

    class MalformedCKE(Exception):
        pass

    def get_cke_bytes(packet):
        exchkeys = str(packet[TLSClientKeyExchange].exchkeys)
        # "the RSA-encrypted PreMasterSecret in a ClientKeyExchange is preceded by two length
        # bytes" (RFC 5246), these are (currently) not interpreted by Scapy
        secret_len = struct.unpack('!H', exchkeys[:2])[0]
        # Scapy sometimes erroneously identifies packets as having a TLSClientKeyExchange layer
        if secret_len != len(exchkeys) - 2:
            raise MalformedCKE()
        return exchkeys[2:]

    cke_packets = (p for p in packets if p.haslayer(TLSClientKeyExchange))
    secrets = []
    for p in cke_packets:
        try:
            secrets.append(get_cke_bytes(p))
        except MalformedCKE:
            pass

    return secrets


def format_list(byte_str, separator):

    byte_numbers = (struct.unpack('B', b)[0] for b in byte_str)
    return separator.join(unicode(n) for n in byte_numbers)


if __name__ == '__main__':

    main()
