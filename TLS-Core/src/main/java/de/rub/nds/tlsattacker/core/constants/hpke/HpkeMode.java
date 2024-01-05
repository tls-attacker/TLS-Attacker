/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.hpke;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * HPKE is a standardized way (RFC 9180) to derive a symmetric key from a server's public DH key and
 * send an encrypted message and the clients DHE share to the server.
 */
public enum HpkeMode {
    MODE_BASE(new byte[] {(byte) 0x00}),
    MODE_PSK(new byte[] {(byte) 0x01}),
    MODE_AUTH(new byte[] {(byte) 0x02}),
    MODE_AUTH_PSK(new byte[] {(byte) 0x03}),
    ;

    private HpkeMode(byte[] byteValue) {
        this.byteValue = byteValue;
    }

    private static final Map<BigInteger, HpkeMode> MAP;
    private final byte[] byteValue;

    public byte[] getByteValue() {
        return this.byteValue;
    }

    static {
        MAP = new HashMap<>();
        for (HpkeMode version : HpkeMode.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static HpkeMode getEnumByByte(byte[] versionBytes) {
        BigInteger hashMapKey = new BigInteger(versionBytes);
        return MAP.get(hashMapKey);
    }
}
