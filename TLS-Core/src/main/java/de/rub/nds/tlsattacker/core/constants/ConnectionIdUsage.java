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

public enum ConnectionIdUsage {
    CID_IMMEDIATE((byte) 0),
    CID_SPARE((byte) 1);

    private byte value;

    ConnectionIdUsage(byte value) {
        this.value = value;
    }

    private static final Map<Byte, ConnectionIdUsage> MAP;

    static {
        MAP = new HashMap<>();
        for (ConnectionIdUsage usage : values()) {
            MAP.put(usage.value, usage);
        }
    }

    public static ConnectionIdUsage getConnectionIdUsage(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] {value};
    }
}
