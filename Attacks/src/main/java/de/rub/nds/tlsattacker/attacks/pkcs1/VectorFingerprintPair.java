/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class VectorFingerprintPair {

    private ResponseFingerprint fingerprint;

    private Pkcs1Vector vector;

    public VectorFingerprintPair(ResponseFingerprint fingerprint, Pkcs1Vector vector) {
        this.fingerprint = fingerprint;
        this.vector = vector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(ResponseFingerprint fingerprint) {
        this.fingerprint = fingerprint;
    }

    public Pkcs1Vector getVector() {
        return vector;
    }

    public void setVector(Pkcs1Vector vector) {
        this.vector = vector;
    }

    @Override
    public String toString() {
        return "PKCS#1 Vector: " + vector.getDescription() + " Fingerprint=" + fingerprint.toString();
    }
}
