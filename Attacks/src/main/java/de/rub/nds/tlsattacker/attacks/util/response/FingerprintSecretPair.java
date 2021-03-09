/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.util.response;

/**
 *
 */
public class FingerprintSecretPair {

    private final ResponseFingerprint fingerprint;
    private final int appliedSecret;

    private FingerprintSecretPair() {
        fingerprint = null;
        appliedSecret = 0;
    }

    public FingerprintSecretPair(ResponseFingerprint fingerprint, int appliedSecret) {
        this.fingerprint = fingerprint;
        this.appliedSecret = appliedSecret;
    }

    /**
     * @return the fingerprint
     */
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    /**
     * @return the appliedSecret
     */
    public int getAppliedSecret() {
        return appliedSecret;
    }
}
