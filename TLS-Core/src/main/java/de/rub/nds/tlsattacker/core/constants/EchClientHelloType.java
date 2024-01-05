/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.math.BigInteger;
import java.util.HashMap;

public enum EchClientHelloType {
    OUTER(new byte[] {0x00}),
    INNER(new byte[] {0x01});

    private final byte[] byteValue;

    private static final HashMap<BigInteger, EchClientHelloType> MAP;

    private EchClientHelloType(byte[] byteValue) {
        this.byteValue = byteValue;
    }

    public byte[] getByteValue() {
        return byteValue;
    }

    static {
        MAP = new HashMap<>();
        for (EchClientHelloType version : EchClientHelloType.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static EchClientHelloType getEnumByByte(byte[] versionBytes) {
        BigInteger hashMapKey = new BigInteger(versionBytes);
        return MAP.get(hashMapKey);
    }
}
