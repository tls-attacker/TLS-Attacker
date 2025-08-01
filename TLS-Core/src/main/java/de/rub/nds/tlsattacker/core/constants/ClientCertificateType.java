/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.HashMap;
import java.util.Map;

/** <a href="http://tools.ietf.org/html/rfc5246#section-7.4.4">RFC 5246 Section 7.4.4</a> */
public enum ClientCertificateType {
    RSA_SIGN((byte) 1),
    DSS_SIGN((byte) 2),
    RSA_FIXED_DH((byte) 3),
    DSS_FIXED_DH((byte) 4),
    RSA_EPHEMERAL_DH_RESERVED((byte) 5),
    DSS_EPHEMERAL_DH_RESERVED((byte) 6),
    FORTEZZA_DMS_RESERVED((byte) 20),
    GOSTR34101994((byte) 21),
    GOSTR34102001((byte) 22),
    ECDSA_SIGN((byte) 64), // TODO Implement these
    RSA_FIXED_ECDH((byte) 65),
    ECDSA_FIXED_ECDH((byte) 66),
    GOST_SIGN256((byte) 66),
    GOST_SIGN512((byte) 67),
    GOSTR34102012_256((byte) 238),
    GOSTR34102012_512((byte) 239);

    /** length of the ClientCertificateType in the TLS byte arrays */
    public static final int LENGTH = 1;

    private byte value;

    private static final Map<Byte, ClientCertificateType> MAP;

    ClientCertificateType(byte value) {
        this.value = value;
    }

    static {
        MAP = new HashMap<>();
        for (ClientCertificateType c : values()) {
            MAP.put(c.value, c);
        }
    }

    public static ClientCertificateType getClientCertificateType(byte value) {
        return MAP.get(value);
    }

    public byte getValue() {
        return value;
    }

    public byte[] getArrayValue() {
        return new byte[] {value};
    }
}
