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

public enum TokenBindingType {
    PROVIDED_TOKEN_BINDING((byte) 0),
    REFERRED_TOKEN_BINDING((byte) 1);

    private final byte tokenBindingTypeValue;
    private static final Map<Byte, TokenBindingType> MAP;

    private TokenBindingType(byte tokenBindingTypeValue) {
        this.tokenBindingTypeValue = tokenBindingTypeValue;
    }

    static {
        MAP = new HashMap<>();
        for (TokenBindingType c : TokenBindingType.values()) {
            MAP.put(c.tokenBindingTypeValue, c);
        }
    }

    public static TokenBindingType getTokenBindingType(byte value) {
        TokenBindingType type = MAP.get(value);
        return type;
    }

    public byte getTokenBindingTypeValue() {
        return tokenBindingTypeValue;
    }
}
