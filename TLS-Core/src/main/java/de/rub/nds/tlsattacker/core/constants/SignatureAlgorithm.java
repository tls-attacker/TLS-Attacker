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
import java.util.Random;

public enum SignatureAlgorithm {

    ANONYMOUS((byte) 0),
    RSA((byte) 1),
    DSA((byte) 2),
    ECDSA((byte) 3),
    RSA_PSS((byte) 8),
    X448((byte) 0xFF), // byte value not defined
    X25519((byte) 0xFF);// Byte value not defined

    private byte value;

    private static final Map<Byte, SignatureAlgorithm> MAP;

    private SignatureAlgorithm(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (SignatureAlgorithm cm : SignatureAlgorithm.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static SignatureAlgorithm getSignatureAlgorithm(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }

    public static SignatureAlgorithm getRandom(Random random) {
        SignatureAlgorithm c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (SignatureAlgorithm) o[random.nextInt(o.length)];
        }
        return c;
    }

    public String getJavaName() {
        if (value == 0) {
            return "";
        }
        return toString();
    }
}
