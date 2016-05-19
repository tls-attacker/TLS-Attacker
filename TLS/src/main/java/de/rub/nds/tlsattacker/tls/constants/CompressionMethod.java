/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.constants;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public enum CompressionMethod {

    NULL((byte) 0x00);

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

    public byte[] getArrayValue() {
	return new byte[] { value };
    }
}
