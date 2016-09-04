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
public enum ECPointFormat {

    UNCOMPRESSED((byte) 0),
    ANSIX962_COMPRESSED_PRIME((byte) 1),
    ANSIX962_COMPRESSED_CHAR2((byte) 2);

    private byte value;

    private static final Map<Byte, ECPointFormat> MAP;

    private ECPointFormat(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (ECPointFormat cm : ECPointFormat.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static ECPointFormat getECPointFormat(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public static ECPointFormat getRandom() {
	ECPointFormat c = null;
	while (c == null) {
	    Object[] o = MAP.values().toArray();
	    c = (ECPointFormat) o[RandomHelper.getRandom().nextInt(o.length)];
	}
	return c;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public short getShortValue() {
	return (short) (value & 0xFF);
    }
}
