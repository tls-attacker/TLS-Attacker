/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum HKDFAlgorithm {
    TLS_HKDF_SHA256(MacAlgorithm.HMAC_SHA256),
    TLS_HKDF_SHA384(MacAlgorithm.HMAC_SHA384),
    TLS_HKDF_SHA512(MacAlgorithm.HMAC_SHA512);

    private HKDFAlgorithm(MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    private final MacAlgorithm macAlgorithm;

    public MacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }
}
