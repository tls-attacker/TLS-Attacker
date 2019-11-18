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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;

/**
 *
 *
 */
public abstract class PaddingVectorGenerator {

    /**
     *
     * @param suite
     * @param version
     * @return
     */
    public abstract List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version);

    /**
     * Creates an array of (padding+1) padding bytes.
     *
     * Example for padding 03: [03 03 03 03]
     *
     * @param padding
     * @return
     */
    protected final byte[] createPaddingBytes(int padding) {
        byte[] paddingBytes = new byte[padding + 1];
        for (int i = 0; i < paddingBytes.length; i++) {
            paddingBytes[i] = (byte) padding;
        }
        return paddingBytes;
    }
}
