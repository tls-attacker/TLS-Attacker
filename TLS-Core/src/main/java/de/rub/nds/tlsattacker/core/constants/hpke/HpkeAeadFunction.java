/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.hpke;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public enum HpkeAeadFunction {
    RESERVED(new byte[] {(byte) 0x00, (byte) 0x00}, 0, 0, 0, CipherSuite.TLS_NULL_WITH_NULL_NULL),
    AES_128_GCM(
            new byte[] {(byte) 0x00, (byte) 0x01}, 16, 12, 16, CipherSuite.TLS_AES_128_GCM_SHA256),
    AES_256_GCM(
            new byte[] {(byte) 0x00, (byte) 0x02}, 32, 12, 16, CipherSuite.TLS_AES_256_GCM_SHA384),
    CHACHA20_POLY1305(
            new byte[] {(byte) 0x00, (byte) 0x03},
            32,
            12,
            16,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256),
    EXPORT_ONLY(
            new byte[] {(byte) 0xFF, (byte) 0xFF}, 0, 0, 0, CipherSuite.TLS_NULL_WITH_NULL_NULL);

    private static final Map<BigInteger, HpkeAeadFunction> MAP;
    private final byte[] byteValue;
    // nK in rfc 9180
    private final int keyLength;
    // nN in rfc 9180
    private final int nonceLength;
    // nT in rfc 9180
    private final int tagLength;
    private final CipherSuite cipherSuite;

    private HpkeAeadFunction(
            byte[] byteValue,
            int keyLength,
            int nonceLength,
            int tagLength,
            CipherSuite cipherSuite) {
        this.byteValue = byteValue;
        this.keyLength = keyLength;
        this.nonceLength = nonceLength;
        this.tagLength = tagLength;
        this.cipherSuite = cipherSuite;
    }

    public byte[] getByteValue() {
        return byteValue;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public int getNonceLength() {
        return nonceLength;
    }

    public int getTagLength() {
        return tagLength;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    static {
        MAP = new HashMap<>();
        for (HpkeAeadFunction version : HpkeAeadFunction.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static HpkeAeadFunction getEnumByByte(byte[] versionBytes) {
        if (versionBytes == null) {
            return HpkeAeadFunction.RESERVED;
        } else {
            BigInteger hashMapKey = new BigInteger(versionBytes);
            return MAP.get(hashMapKey);
        }
    }
}
