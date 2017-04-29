/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.RandomHelper;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum NamedCurve {

    SECT163K1(new byte[] { (byte) 0, (byte) 1 }),
    SECT163R1(new byte[] { (byte) 0, (byte) 2 }),
    SECT163R2(new byte[] { (byte) 0, (byte) 3 }),
    SECT193R1(new byte[] { (byte) 0, (byte) 4 }),
    SECT193R2(new byte[] { (byte) 0, (byte) 5 }),
    SECT233K1(new byte[] { (byte) 0, (byte) 6 }),
    SECT233R1(new byte[] { (byte) 0, (byte) 7 }),
    SECT239K1(new byte[] { (byte) 0, (byte) 8 }),
    SECT283K1(new byte[] { (byte) 0, (byte) 9 }),
    SECT283R1(new byte[] { (byte) 0, (byte) 10 }),
    SECT409K1(new byte[] { (byte) 0, (byte) 11 }),
    SECT409R1(new byte[] { (byte) 0, (byte) 12 }),
    SECT571K1(new byte[] { (byte) 0, (byte) 13 }),
    SECT571R1(new byte[] { (byte) 0, (byte) 14 }),
    SECP160K1(new byte[] { (byte) 0, (byte) 15 }),
    SECP160R1(new byte[] { (byte) 0, (byte) 16 }),
    SECP160R2(new byte[] { (byte) 0, (byte) 17 }),
    SECP192K1(new byte[] { (byte) 0, (byte) 18 }),
    SECP192R1(new byte[] { (byte) 0, (byte) 19 }),
    SECP224K1(new byte[] { (byte) 0, (byte) 20 }),
    SECP224R1(new byte[] { (byte) 0, (byte) 21 }),
    SECP256K1(new byte[] { (byte) 0, (byte) 22 }),
    SECP256R1(new byte[] { (byte) 0, (byte) 23 }),
    SECP384R1(new byte[] { (byte) 0, (byte) 24 }),
    SECP521R1(new byte[] { (byte) 0, (byte) 25 }),
    BRAINPOOLP256R1(new byte[] { (byte) 0, (byte) 26 }),
    BRAINPOOLP384R1(new byte[] { (byte) 0, (byte) 27 }),
    BRAINPOOLP512R1(new byte[] { (byte) 0, (byte) 28 }),
    ECDH_X25519(new byte[] { (byte) 0, (byte) 29 }),
    ECDH_X448(new byte[] { (byte) 0, (byte) 30 }),
    FFDHE2048(new byte[] { (byte) 1, (byte) 0 }),
    FFDHE3072(new byte[] { (byte) 1, (byte) 1 }),
    FFDHE4096(new byte[] { (byte) 1, (byte) 2 }),
    FFDHE6144(new byte[] { (byte) 1, (byte) 3 }),
    FFDHE8192(new byte[] { (byte) 1, (byte) 4 }),
    NONE(new byte[] { (byte) 0, (byte) 0 });

    public static final int LENGTH = 2;

    private byte[] value;

    private static final Map<Integer, NamedCurve> MAP;

    private NamedCurve(byte[] value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (NamedCurve c : NamedCurve.values()) {
            MAP.put(valueToInt(c.value), c);
        }
    }

    private static int valueToInt(byte[] value) {
        return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public static NamedCurve getNamedCurve(byte[] value) {
        return MAP.get(valueToInt(value));
    }

    public byte[] getValue() {
        return value;
    }

    public static NamedCurve getRandom() {
        NamedCurve c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (NamedCurve) o[RandomHelper.getRandom().nextInt(o.length)];
        }
        return c;
    }

    public int getIntValue() {
        return valueToInt(value);
    }
}
