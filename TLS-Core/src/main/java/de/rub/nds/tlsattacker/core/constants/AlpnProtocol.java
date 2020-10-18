/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum AlpnProtocol {
    HTTP_1_1("http/1.1"),
    SPDY_1("spdy/1"),
    SPDY_2("spdy/2"),
    SPDY_3("spdy/3"),
    STUN_TURN("stun.turn"),
    STUN_NAT_DISCOVERY("stun.nat-discovery"),
    HTTP_2("h2"),
    HTTP_2_C("h2c"),
    WEBRTC("webrtc"),
    C_WEBRTC("c-webrtc"),
    FTP("ftp"),
    IMAP("imap"),
    POP3("pop3"),
    MANAGESIEVE("managesieve");

    private final String constant;

    private AlpnProtocol(String constant) {
        this.constant = constant;
    }

    public String getConstant() {
        return constant;
    }
}
