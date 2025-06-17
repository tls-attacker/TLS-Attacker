/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Available exchange modes for pre-shared keys (TLS 1.3) */
public enum PskKeyExchangeMode {
    PSK_KE((byte) 0),
    PSK_DHE_KE((byte) 1);

    private byte value;

    private static final Map<Byte, PskKeyExchangeMode> MAP;

    private static final Logger LOGGER = LogManager.getLogger();

    private PskKeyExchangeMode(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (PskKeyExchangeMode cm : values()) {
            MAP.put(cm.value, cm);
        }
    }

    public static PskKeyExchangeMode getExchangeMode(byte value) {
        return MAP.get(value);
    }

    public static List<PskKeyExchangeMode> getExchangeModes(byte[] sourceBytes) {
        if (sourceBytes == null || sourceBytes.length == 0) {
            return new ArrayList<>();
        }

        List<PskKeyExchangeMode> modes = new ArrayList<>(sourceBytes.length);
        for (byte sourceByte : sourceBytes) {
            PskKeyExchangeMode mode = getExchangeMode(sourceByte);
            if (mode != null) {
                modes.add(mode);
            } else {
                LOGGER.warn("Ignoring unknown PskKeyExchangeMode {}", sourceByte);
            }
        }

        return modes;
    }

    public byte getValue() {
        return value;
    }
}
