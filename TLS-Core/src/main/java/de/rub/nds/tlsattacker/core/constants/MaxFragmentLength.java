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
import java.util.Random;

public enum MaxFragmentLength {
    TWO_9((byte) 1, 512),
    TWO_10((byte) 2, 1024),
    TWO_11((byte) 3, 2048),
    TWO_12((byte) 4, 4096);

    private byte value;

    private int lengthValue;

    private static final Map<Byte, MaxFragmentLength> MAP;

    private MaxFragmentLength(byte value, int lengthValue) {
        this.value = value;
        this.lengthValue = lengthValue;
    }

    static {
        MAP = new HashMap<>();
        for (MaxFragmentLength cm : values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static MaxFragmentLength getMaxFragmentLength(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] {value};
    }

    public static MaxFragmentLength getRandom(Random random) {
        MaxFragmentLength c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (MaxFragmentLength) o[random.nextInt(o.length)];
        }
        return c;
    }

    public int getReceiveLimit() {
        return lengthValue;
    }
}
