/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.HashMap;
import java.util.Map;

public enum ProtocolMessageType {
    UNKNOWN((byte) 99),
    CHANGE_CIPHER_SPEC((byte) 20),
    ALERT((byte) 21),
    HANDSHAKE((byte) 22),
    APPLICATION_DATA((byte) 23),
    HEARTBEAT((byte) 24);

    private byte value;

    private static final Map<Byte, ProtocolMessageType> MAP;

    private ProtocolMessageType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ProtocolMessageType cm : ProtocolMessageType.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static ProtocolMessageType getContentType(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }
}
