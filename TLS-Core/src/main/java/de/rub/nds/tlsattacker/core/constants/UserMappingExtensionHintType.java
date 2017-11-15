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
 * RFC 4681
 */
public enum UserMappingExtensionHintType {
    UPN_DOMAIN_HINT((byte) 0x40);

    private final byte value;
    private static final Map<Byte, UserMappingExtensionHintType> MAP;

    private UserMappingExtensionHintType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (UserMappingExtensionHintType c : UserMappingExtensionHintType.values()) {
            MAP.put(c.value, c);
        }
    }

    public static UserMappingExtensionHintType getExtensionType(byte value) {
        return MAP.get(value);

    }

    public byte getValue() {
        return value;
    }

}
