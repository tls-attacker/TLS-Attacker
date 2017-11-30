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

/**
 * Available exchange modes for pre-shared keys (TLS 1.3)
 */
public enum PskKeyExchangeMode {
    PSK_KE((byte) 0),
    PSK_DHE_KE((byte) 1);

    private byte value;

    private static final Map<Byte, PskKeyExchangeMode> MAP;

    private PskKeyExchangeMode(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (PskKeyExchangeMode cm : PskKeyExchangeMode.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static PskKeyExchangeMode getExchangeMode(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }
}
