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
import java.util.Map;

public enum EchConfigVersion {

    // support draft 6-14
    DRAFT_FF03(new byte[] {(byte) 0xfe, (byte) 0x03}),
    DRAFT_FF07(new byte[] {(byte) 0xfe, (byte) 0x07}),
    DRAFT_FF08(new byte[] {(byte) 0xfe, (byte) 0x08}),
    DRAFT_FF09(new byte[] {(byte) 0xfe, (byte) 0x09}),
    DRAFT_FF0A(new byte[] {(byte) 0xfe, (byte) 0x0a}),
    DRAFT_FF0B(new byte[] {(byte) 0xfe, (byte) 0x0b}),
    DRAFT_FF0C(new byte[] {(byte) 0xfe, (byte) 0x0c}),
    DRAFT_FF0D(new byte[] {(byte) 0xfe, (byte) 0x0d});

    private EchConfigVersion(byte[] byteValue) {
        this.byteValue = byteValue;
    }

    private static final Map<BigInteger, EchConfigVersion> MAP;
    private final byte[] byteValue;

    public byte[] getByteValue() {
        return this.byteValue;
    }

    static {
        MAP = new HashMap<>();
        for (EchConfigVersion version : EchConfigVersion.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static EchConfigVersion getEnumByByte(byte[] versionBytes) {
        BigInteger hashMapKey = new BigInteger(versionBytes);
        return MAP.get(hashMapKey);
    }
}
