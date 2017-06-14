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
public enum CertificateStatusRequestExtensionType {
    OCSP((int) 1);

    private final int CertificateStatusRequestValue;
    private static final Map<Integer, CertificateStatusRequestExtensionType> MAP;

    private CertificateStatusRequestExtensionType(int value) {
        this.CertificateStatusRequestValue = value;
    }

    static {
        MAP = new HashMap<>();
        for (CertificateStatusRequestExtensionType c : CertificateStatusRequestExtensionType.values()) {
            MAP.put(c.CertificateStatusRequestValue, c);
        }
    }

    public int getCertificateStatusRequestValue() {
        return CertificateStatusRequestValue;
    }

    public static CertificateStatusRequestExtensionType getCertificateStatusRequestType(int value) {
        return MAP.get(value);
    }

}
