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
 * RFC6066
 */
public enum TrustedCaIndicationIdentifierType {
    PRE_AGREED((byte) 0),
    KEY_SHA1_HASH((byte) 1),
    X509_NAME((byte) 2),
    CERT_SHA1_HASH((byte) 3);

    private final byte value;
    private static final Map<Byte, TrustedCaIndicationIdentifierType> MAP;

    private TrustedCaIndicationIdentifierType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();

        for (TrustedCaIndicationIdentifierType type : TrustedCaIndicationIdentifierType.values()) {
            MAP.put(type.value, type);
        }
    }

    public byte getValue() {
        return value;
    }

    public static TrustedCaIndicationIdentifierType getIdentifierByByte(byte key) {
        return MAP.get(key);
    }

}
