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

/** RFC6066 and RFC6961 */
public enum CertificateStatusRequestType {
    OCSP((int) 1),
    OCSP_multi((int) 2);

    private final int certificateStatusRequestValue;
    private static final Map<Integer, CertificateStatusRequestType> MAP;

    CertificateStatusRequestType(int value) {
        this.certificateStatusRequestValue = value;
    }

    static {
        MAP = new HashMap<>();
        for (CertificateStatusRequestType c : values()) {
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
