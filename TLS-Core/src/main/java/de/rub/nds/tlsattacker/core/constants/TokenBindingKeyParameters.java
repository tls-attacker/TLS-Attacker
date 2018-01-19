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

public enum TokenBindingKeyParameters {
    RSA2048_PKCS1_5((byte) 0),
    RSA2048_PSS((byte) 1),
    ECDSAP256((byte) 2);

    private final byte keyParameterValue;
    private static final Map<Byte, TokenBindingKeyParameters> MAP;

    private TokenBindingKeyParameters(byte keyParameterValue) {
        this.keyParameterValue = keyParameterValue;
    }

    static {
        MAP = new HashMap<>();
        for (TokenBindingKeyParameters c : TokenBindingKeyParameters.values()) {
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
