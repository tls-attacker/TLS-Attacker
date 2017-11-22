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

/**
 * Alert level
 */
public enum AlertLevel {

    UNDEFINED((byte) 0),
    WARNING((byte) 1),
    FATAL((byte) 2);

    private byte value;

    private static final Map<Byte, AlertLevel> MAP;

    private AlertLevel(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (AlertLevel cm : AlertLevel.values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static AlertLevel getAlertLevel(byte value) {
        AlertLevel level = MAP.get(value);
        if (level == null) {
            level = UNDEFINED;
        }
        return level;
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] { value };
    }

    @Override
    public String toString() {
        return "AlertLevel{" + "value=" + this.name() + '}';
    }

}
