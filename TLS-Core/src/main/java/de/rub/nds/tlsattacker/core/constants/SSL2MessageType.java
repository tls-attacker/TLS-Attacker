/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.Arrays;

public enum SSL2MessageType {
    SSL_CLIENT_HELLO(0x01),
    SSL_CLIENT_MASTER_KEY(0x02),
    SSL_SERVER_VERIFY(0x03),
    SSL_SERVER_HELLO(0x04),
    SSL_UNKNOWN(0x00);

    private int type;

    SSL2MessageType(int type) {
        this.type = type;
    }

    public byte getType() {
        return (byte) this.type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public static SSL2MessageType getMessageType(byte value) {
        return Arrays.stream(SSL2MessageType.values())
                .filter(knownType -> knownType.getType() == value)
                .findFirst()
                .orElse(SSL2MessageType.SSL_UNKNOWN);
    }
}
