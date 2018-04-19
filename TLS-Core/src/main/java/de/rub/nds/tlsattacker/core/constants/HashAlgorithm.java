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

public enum HashAlgorithm {

    NONE((byte) 0, ""),
    MD5((byte) 1, "MD5"),
    SHA1((byte) 2, "SHA-1"),
    SHA224((byte) 3, "SHA-224"),
    SHA256((byte) 4, "SHA-256"),
    SHA384((byte) 5, "SHA-384"),
    SHA512((byte) 6, "SHA-512"),
    INTRINSIC((byte) 8, "INSTRINSIC");

    private final byte value;

    private final String javaName;

    private static final Map<Byte, HashAlgorithm> MAP;

    private HashAlgorithm(byte value, String javaName) {
        this.value = value;
        this.javaName = javaName;
    }

    static {
        MAP = new HashMap<>();
        for (HashAlgorithm cm : HashAlgorithm.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static HashAlgorithm getHashAlgorithm(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }

    public String getJavaName() {
        return javaName;
    }

    public static HashAlgorithm getRandom(Random random) {
        HashAlgorithm c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (HashAlgorithm) o[random.nextInt(o.length)];
        }
        return c;
    }
}
