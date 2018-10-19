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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final PaddingVector paddingVector;

    private final ProtocolVersion version;

    private final CipherSuite suite;

    private final Integer length;

    public VectorResponse(PaddingVector paddingVector, ResponseFingerprint fingerprint, ProtocolVersion version,
            CipherSuite suite, int appDataLength) {
        this.paddingVector = paddingVector;
        this.fingerprint = fingerprint;
        this.version = version;
        this.suite = suite;
        if (fingerprint != null && version != null && suite != null) {
            length = paddingVector.getRecordLength(suite, version, appDataLength);
        } else {
            length = null;
        }
    }

    public Integer getLength() {
        return length;
    }

    public PaddingVector getPaddingVector() {
        return paddingVector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", paddingVector=" + paddingVector + ", version="
                + version + ", suite=" + suite + ", length=" + length + '}';
    }
}
