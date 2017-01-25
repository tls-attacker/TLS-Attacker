/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import de.rub.nds.tlsattacker.util.RandomHelper;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
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

    public byte getValue() {
        return value;
    }

    public static CompressionMethod getRandom() {
        CompressionMethod c = null;
        while (c == null) {
            Object[] o = MAP.values().toArray();
            c = (CompressionMethod) o[RandomHelper.getRandom().nextInt(o.length)];
        }
        return c;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }
}
