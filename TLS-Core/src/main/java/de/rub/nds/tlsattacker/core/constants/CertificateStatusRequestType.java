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
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public enum CertificateStatusRequestType {
    OCSP((int) 1);

    private final int certificateStatusRequestValue;
    private static final Map<Integer, CertificateStatusRequestType> MAP;

    private CertificateStatusRequestType(int value) {
        this.certificateStatusRequestValue = value;
    }

    static {
        MAP = new HashMap<>();
        for (CertificateStatusRequestType c : CertificateStatusRequestType.values()) {
            MAP.put(c.certificateStatusRequestValue, c);
        }
    }

    public int getCertificateStatusRequestValue() {
        return certificateStatusRequestValue;
    }

    public static CertificateStatusRequestType getCertificateStatusRequestType(int value) {
        return MAP.get(value);
    }

}
