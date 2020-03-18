/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.util.response;

/**
 *
 */
public class FingerprintSecretPair {

    private final ResponseFingerprint fingerprint;
    private final int appliedSecret;

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
