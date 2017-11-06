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
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * RFC6091 and RFC7250
 */
public enum CertificateType {
    X509((byte) 0),
    OPEN_PGP((byte) 1),
    RAW_PUBLIC_KEY((byte) 2);

    private final byte value;
    private static final Map<Byte, CertificateType> MAP;

    private CertificateType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (CertificateType c : CertificateType.values()) {
            MAP.put(c.getValue(), c);
        }
    }

    public byte getValue() {
        return value;
    }

    public static CertificateType getCertificateType(byte value) {
        return MAP.get(value);
    }

    public static List<CertificateType> getCertificateTypesAsList(byte[] values) {
        List<CertificateType> certificateList = new LinkedList<>();
        for (byte b : values) {
            certificateList.add(getCertificateType(b));
        }
        return certificateList;
    }

    public static byte[] toByteArray(List<CertificateType> list) {
        CertificateType[] ctAsArray = new CertificateType[list.size()];
        list.toArray(ctAsArray);
        byte[] ctAsByteArray = new byte[ctAsArray.length];

        for (int i = 0; i < ctAsByteArray.length; i++) {
            ctAsByteArray[i] = ctAsArray[i].getValue();
        }
        return ctAsByteArray;
    }
}
