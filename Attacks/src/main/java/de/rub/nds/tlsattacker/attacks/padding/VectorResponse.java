/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;

public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final Vector vector;

    private VectorResponse() {
        fingerprint = null;
        vector = null;
    }

    public VectorResponse(Vector vector, ResponseFingerprint fingerprint) {
        this.vector = vector;
        this.fingerprint = fingerprint;
    }

    public Vector getVector() {
        return vector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", vector=" + vector + '}';
    }
}
