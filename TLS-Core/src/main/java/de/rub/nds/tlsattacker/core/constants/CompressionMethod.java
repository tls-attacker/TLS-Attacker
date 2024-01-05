/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.*;

public enum CompressionMethod {
    NULL((byte) 0x00),
    DEFLATE((byte) 0x01),
    LZS((byte) 0x40);

    private byte value;

    private static final Map<Byte, CompressionMethod> MAP;

    private CompressionMethod(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (CompressionMethod cm : CompressionMethod.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static CompressionMethod getCompressionMethod(byte value) {
        return MAP.get(value);
    }

    public static List<CompressionMethod> getCompressionMethods(byte[] values) {
        // TODO no stable enough, also add unit tests
        List<CompressionMethod> compressionMethods = new LinkedList<>();
        for (int i = 0; i < values.length; i++) {
            compressionMethods.add(getCompressionMethod(values[i]));
        }
        return compressionMethods;
    }

    public byte getValue() {
        return value;
    }

    public static CompressionMethod getRandom(Random random) {
        CompressionMethod c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (CompressionMethod) o[random.nextInt(o.length)];
        }
        return c;
    }

    public byte[] getArrayValue() {
        return new byte[] {value};
    }
}
