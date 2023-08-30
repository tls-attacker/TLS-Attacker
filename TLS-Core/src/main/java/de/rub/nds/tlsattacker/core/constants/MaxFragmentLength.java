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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum MaxFragmentLength {
    TWO_9((byte) 1),
    TWO_10((byte) 2),
    TWO_11((byte) 3),
    TWO_12((byte) 4);

    private static final Logger LOGGER = LogManager.getLogger();

    private byte value;

    private static final Map<Byte, MaxFragmentLength> MAP;

    private MaxFragmentLength(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (MaxFragmentLength cm : MaxFragmentLength.values()) {
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

    public Integer getReceiveLimit() {
        switch (this) {
            case TWO_9:
                return 512;
            case TWO_10:
                return 1024;
            case TWO_11:
                return 2048;
            case TWO_12:
                return 4096;
            default:
                LOGGER.warn("Unknown MaxFragmentLength encountered. Using 1024.");
                return 1024;
        }
    }
}
