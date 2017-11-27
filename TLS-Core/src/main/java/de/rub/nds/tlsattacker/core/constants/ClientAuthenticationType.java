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
 * https://tools.ietf.org/html/rfc5077#section-4
 * 
 */
public enum ClientAuthenticationType {
    ANONYMOUS((byte) 0x00),
    CERTIFICATE_BASED((byte) 0x01),
    PSK((byte) 0x02);

    private byte value;

    private static final Map<Byte, ClientAuthenticationType> MAP;

    private ClientAuthenticationType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ClientAuthenticationType c : ClientAuthenticationType.values()) {
            MAP.put(c.value, c);
        }
    }

    public static ClientAuthenticationType getClientAuthenticationType(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }
}