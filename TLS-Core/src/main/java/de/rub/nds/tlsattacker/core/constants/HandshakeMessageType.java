/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.HashMap;
import java.util.Map;

/** Also called Handshake Type */
public enum HandshakeMessageType {
    UNKNOWN((byte) 255),
    HELLO_REQUEST((byte) 0),
    CLIENT_HELLO((byte) 1),
    SERVER_HELLO((byte) 2),
    HELLO_VERIFY_REQUEST((byte) 3),
    NEW_SESSION_TICKET((byte) 4),
    END_OF_EARLY_DATA((byte) 5),
    // HELLO_RETRY_REQUEST((byte) 6), ONLY IN TLS 1.3 DRAFT
    ENCRYPTED_EXTENSIONS((byte) 8),
    CERTIFICATE((byte) 11),
    SERVER_KEY_EXCHANGE((byte) 12),
    CERTIFICATE_REQUEST((byte) 13),
    SERVER_HELLO_DONE((byte) 14),
    CERTIFICATE_VERIFY((byte) 15),
    CLIENT_KEY_EXCHANGE((byte) 16),
    FINISHED((byte) 20),
    KEY_UPDATE((byte) 24),
    CERTIFICATE_STATUS((byte) 22),
    SUPPLEMENTAL_DATA((byte) 23),
    MESSAGE_HASH((byte) 254);

    private int value;

    private static final Map<Byte, HandshakeMessageType> MAP;

    private HandshakeMessageType(byte value) {
        this.value = value;
    }

    private HandshakeMessageType() {
        this.value = -1;
    }

    static {
        MAP = new HashMap<>();
        for (HandshakeMessageType cm : HandshakeMessageType.values()) {
            if (cm == UNKNOWN || cm.name().contains("SSL2")) {
                continue;
            }
            MAP.put((byte) cm.value, cm);
        }
    }

    public static HandshakeMessageType getMessageType(byte value) {
        HandshakeMessageType type = MAP.get(value);
        if (type == null) {
            type = UNKNOWN;
        }
        return type;
    }

    public byte getValue() {
        return (byte) value;
    }

    public byte[] getArrayValue() {
        return new byte[] {(byte) value};
    }

    public String getName() {
        return this.name();
    }
}
