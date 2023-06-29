/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants.hpke;

import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public enum HpkeKeyDerivationFunction {
    RESERVED(new byte[] {(byte) 0x00, (byte) 0x00}, 0, HKDFAlgorithm.TLS_HKDF_SHA256),
    HKDF_SHA256(new byte[] {(byte) 0x00, (byte) 0x01}, 32, HKDFAlgorithm.TLS_HKDF_SHA256),
    HKDF_SHA384(new byte[] {(byte) 0x00, (byte) 0x02}, 48, HKDFAlgorithm.TLS_HKDF_SHA384),
    HKDF_SHA512(new byte[] {(byte) 0x00, (byte) 0x03}, 64, HKDFAlgorithm.TLS_HKDF_SHA512),
    ;

    private static final Map<BigInteger, HpkeKeyDerivationFunction> MAP;
    private final byte[] byteValue;
    // nH in rfc 9180
    private final int hashLength;
    private final HKDFAlgorithm hkdfAlgorithm;

    private HpkeKeyDerivationFunction(
            byte[] byteValue, int hashLength, HKDFAlgorithm hkdfAlgorithm) {
        this.byteValue = byteValue;
        this.hashLength = hashLength;
        this.hkdfAlgorithm = hkdfAlgorithm;
    }

    public byte[] getByteValue() {
        return byteValue;
    }

    public int getHashLength() {
        return hashLength;
    }

    public HKDFAlgorithm getHkdfAlgorithm() {
        return hkdfAlgorithm;
    }

    static {
        MAP = new HashMap<>();
        for (HpkeKeyDerivationFunction version : HpkeKeyDerivationFunction.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static HpkeKeyDerivationFunction getEnumByByte(byte[] versionBytes) {
        if (versionBytes == null) {
            return HpkeKeyDerivationFunction.RESERVED;
        } else {
            BigInteger hashMapKey = new BigInteger(versionBytes);
            return MAP.get(hashMapKey);
        }
    }
}
