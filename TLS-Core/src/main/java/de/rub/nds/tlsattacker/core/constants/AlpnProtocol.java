/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum AlpnProtocol {
    GREASE_0A(new String(new byte[] {0x0A, 0x0A}), "GREASE (0x0A0A)"),
    GREASE_1A(new String(new byte[] {0x1A, 0x1A}), "GREASE (0x1A1A)"),
    GREASE_2A(new String(new byte[] {0x2A, 0x2A}), "GREASE (0x2A2A)"),
    GREASE_3A(new String(new byte[] {0x3A, 0x3A}), "GREASE (0x3A3A)"),
    GREASE_4A(new String(new byte[] {0x4A, 0x4A}), "GREASE (0x4A4A)"),
    GREASE_5A(new String(new byte[] {0x5A, 0x5A}), "GREASE (0x5A5A)"),
    GREASE_6A(new String(new byte[] {0x6A, 0x6A}), "GREASE (0x6A6A)"),
    GREASE_7A(new String(new byte[] {0x7A, 0x7A}), "GREASE (0x7A7A)"),
    GREASE_8A(new String(new byte[] {(byte) 0x8A, (byte) 0x8A}), "GREASE (0x8A8A)"),
    GREASE_9A(new String(new byte[] {(byte) 0x9A, (byte) 0x9A}), "GREASE (0x9A9A)"),
    GREASE_AA(new String(new byte[] {(byte) 0xAA, (byte) 0xAA}), "GREASE (0xAAAA)"),
    GREASE_BA(new String(new byte[] {(byte) 0xBA, (byte) 0xBA}), "GREASE (0xBABA)"),
    GREASE_CA(new String(new byte[] {(byte) 0xCA, (byte) 0xCA}), "GREASE (0xCACA)"),
    GREASE_DA(new String(new byte[] {(byte) 0xDA, (byte) 0xDA}), "GREASE (0xDADA)"),
    GREASE_EA(new String(new byte[] {(byte) 0xEA, (byte) 0xEA}), "GREASE (0xEAEA)"),
    GREASE_FA(new String(new byte[] {(byte) 0xFA, (byte) 0xFA}), "GREASE (0xFAFA)"),
    HTTP_0_9("http/0.9", "HTTP 0.9"),
    HTTP_1_0("http/1.0", "HTTP 1.0"),
    HTTP_1_1("http/1.1", "HTTP 1.1"),
    SPDY_1("spdy/1", "SPDY v.1"),
    SPDY_2("spdy/2", "SPDY v.2"),
    SPDY_3("spdy/3", "SPDY v.3"),
    STUN_TURN("stun.turn", "TURN"),
    STUN_NAT_DISCOVERY("stun.nat-discovery", "STUN"),
    HTTP_2("h2", "HTTP/2 over TLS"),
    HTTP_2_C("h2c", "HTTP/2 over TCP"),
    WEBRTC("webrtc", "WebRTC"),
    C_WEBRTC("c-webrtc", "Confidential WebRTC"),
    FTP("ftp", "FTP"),
    IMAP("imap", "IMAP"),
    POP3("pop3", "POP3"),
    MANAGESIEVE("managesieve", "ManageSieve"),
    COAP("coap", "CoAP"),
    XMPP_CLIENT("xmpp-client", "XMPP (client)"),
    XMPP_SERVER("xmpp-server", "XMPP (server)"),
    ACME_TLS("acme-tls/1", "ACME TLS/1"),
    OASIS_MQTT("mqtt", "MQTT"),
    DNS_OVER_TLS("dot", "DNS-over-TLS"),
    NTSKE_1("ntske/1", "NTSKE"),
    SUN_RPC("sunrpc", "SunRPC");

    private final String constant;
    private final String printableName;

    private AlpnProtocol(String constant, String printableName) {
        this.constant = constant;
        this.printableName = printableName;
    }

    public String getConstant() {
        return constant;
    }

    public String getPrintableName() {
        return printableName;
    }

    public boolean isGrease() {
        return this.name().contains("GREASE");
    }
}
