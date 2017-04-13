/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import de.rub.nds.tlsattacker.modifiablevariable.util.RandomHelper;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum SignatureAlgorithm {

    ANONYMOUS((byte) 0),
    RSA((byte) 1),
    DSA((byte) 2),
    ECDSA((byte) 3);

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

    public static SignatureAlgorithm getRandom() {
        SignatureAlgorithm c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (SignatureAlgorithm) o[RandomHelper.getRandom().nextInt(o.length)];
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
