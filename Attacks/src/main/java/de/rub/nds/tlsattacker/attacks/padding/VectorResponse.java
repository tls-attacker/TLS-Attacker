/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;

public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final PaddingVector paddingVector;

    public VectorResponse(PaddingVector paddingVector, ResponseFingerprint fingerprint) {
        this.paddingVector = paddingVector;
        this.fingerprint = fingerprint;
    }

    public PaddingVector getPaddingVector() {
        return paddingVector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", paddingVector=" + paddingVector + '}';
    }
}
