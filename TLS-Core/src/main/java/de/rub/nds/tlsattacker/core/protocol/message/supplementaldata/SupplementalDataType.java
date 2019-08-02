/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.supplementaldata;

import java.util.HashMap;
import java.util.Map;

public enum SupplementalDataType {

    USER_MAPPING_DATA(new byte[] { (byte) 0, (byte) 0 }),
    AUTHZ_DATA(new byte[] { (byte) 0x40, (byte) 0x02 }),
    UNKNOWN(new byte[0]);

    private byte[] value;

    SupplementalDataType(byte[] value) {
        this.value = value;
    }

    private static final Map<Integer, SupplementalDataType> MAP;
    static {
        MAP = new HashMap<>();
        for (SupplementalDataType s : SupplementalDataType.values()) {
            MAP.put(valueToInt(s.value), s);
        }
    }

    private static int valueToInt(byte[] value) {
        if (value.length == 2) {
            return (value[0] & 0xff) << 8 | (value[1] & 0xff);
        } else {
            return -1;
        }
    }

    public static SupplementalDataType getSupplementalDataType(byte[] value) {
        SupplementalDataType type = MAP.get(valueToInt(value));
        if (type == null) {
            return UNKNOWN;
        }
        return type;
    }

    public byte[] getValue() {
        return value;
    }
}
