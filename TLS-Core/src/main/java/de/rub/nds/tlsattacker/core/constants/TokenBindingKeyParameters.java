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

public enum TokenBindingKeyParameters {
    RSA2048_PKCS1_5((byte) 0),
    RSA2048_PSS((byte) 1),
    ECDSAP256((byte) 2);

    private final byte keyParameterValue;
    private static final Map<Byte, TokenBindingKeyParameters> MAP;

    TokenBindingKeyParameters(byte keyParameterValue) {
        this.keyParameterValue = keyParameterValue;
    }

    static {
        MAP = new HashMap<>();
        for (TokenBindingKeyParameters c : values()) {
            MAP.put(c.keyParameterValue, c);
        }
    }

    public static TokenBindingKeyParameters getTokenBindingKeyParameter(byte value) {
        TokenBindingKeyParameters type = MAP.get(value);
        return type;
    }

    public byte getValue() {
        return keyParameterValue;
    }
}
