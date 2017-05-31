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
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public enum TokenBindingVersion {
    ZERO_BYTE((byte) 0),
    DRAFT_1((byte) 1),
    DRAFT_2((byte) 2),
    DRAFT_3((byte) 3),
    DRAFT_4((byte) 4),
    DRAFT_5((byte) 5),
    DRAFT_6((byte) 6),
    DRAFT_7((byte) 7),
    DRAFT_8((byte) 8),
    DRAFT_9((byte) 9),
    DRAFT_10((byte) 0xA),
    DRAFT_11((byte) 0xB),
    DRAFT_12((byte) 0xC),
    DRAFT_13((byte) 0xD),
    DRAFT_14((byte) 0xE);

    private final byte tokenBindingVersion;

    private static final Map<Byte, TokenBindingVersion> MAP;

    static {
        MAP = new HashMap<>();
        for (TokenBindingVersion c : TokenBindingVersion.values()) {
            MAP.put(c.tokenBindingVersion, c);
        }
    }

    private TokenBindingVersion(byte tokenBindingVersion) {
        this.tokenBindingVersion = tokenBindingVersion;
    }

    public byte getByteValue() {
        return tokenBindingVersion;
    }

    public static TokenBindingVersion getExtensionType(byte value) {
        TokenBindingVersion type = MAP.get(value);
        return type;
    }
}
