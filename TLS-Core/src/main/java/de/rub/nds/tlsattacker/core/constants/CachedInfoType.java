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

/** RFC7924 */
public enum CachedInfoType {
    CERT((byte) 1),
    CERT_REQ((byte) 2);

    private final byte value;
    private static final Map<Byte, CachedInfoType> MAP;

    CachedInfoType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (CachedInfoType cit : values()) {
            MAP.put(cit.getValue(), cit);
        }
    }

    public byte getValue() {
        return value;
    }

    public static CachedInfoType getEnumByByte(byte value) {
        return MAP.get(value);
    }
}
