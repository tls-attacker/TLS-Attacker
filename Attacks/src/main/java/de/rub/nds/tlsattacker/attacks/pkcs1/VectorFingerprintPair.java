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
import java.util.Objects;

/**
 *
 *
 */
public class VectorFingerprintPair {

    private ResponseFingerprint fingerprint;

    private Pkcs1Vector vector;

    /**
     *
     * @param fingerprint
     * @param vector
     */
    public VectorFingerprintPair(ResponseFingerprint fingerprint, Pkcs1Vector vector) {
        this.fingerprint = fingerprint;
        this.vector = vector;
    }

    /**
     *
     * @return
     */
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    /**
     *
     * @param fingerprint
     */
    public void setFingerprint(ResponseFingerprint fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     *
     * @return
     */
    public Pkcs1Vector getVector() {
        return vector;
    }

    /**
     *
     * @param vector
     */
    public void setVector(Pkcs1Vector vector) {
        this.vector = vector;
    }

    /**
     *
     * @return
     */
    @Override
    public String toString() {
        return "PKCS#1 Vector: " + vector.getDescription() + " Fingerprint=" + fingerprint.toString();
    }

    /**
     *
     * @return
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 67 * hash + Objects.hashCode(this.fingerprint);
        hash = 67 * hash + Objects.hashCode(this.vector);
        return hash;
    }

    /**
     *
     * @param obj
     * @return
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final VectorFingerprintPair other = (VectorFingerprintPair) obj;
        if (!Objects.equals(this.fingerprint, other.fingerprint)) {
            return false;
        }
        return Objects.equals(this.vector, other.vector);
    }

}
