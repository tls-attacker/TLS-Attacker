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
public enum HeartbeatMode {

    PEER_ALLOWED_TO_SEND((byte) 1),
    PEER_NOT_ALLOWED_TO_SEND((byte) 2);

    private byte value;

    private static final Map<Byte, HeartbeatMode> MAP;

    private HeartbeatMode(byte value) {
	this.value = value;
    }

    static {
	MAP = new HashMap<>();
	for (HeartbeatMode cm : HeartbeatMode.values()) {
	    MAP.put(cm.value, cm);
	}
    }

    public static HeartbeatMode getHeartbeatMessageType(byte value) {
	return MAP.get(value);
    }

    public byte getValue() {
	return value;
    }

    public byte[] getArrayValue() {
	return new byte[] { value };
    }

    public static HeartbeatMode getRandom() {
	HeartbeatMode c = null;
	while (c == null) {
	    Object[] o = MAP.values().toArray();
	    c = (HeartbeatMode) o[RandomHelper.getRandom().nextInt(o.length)];
	}
	return c;
    }
}
