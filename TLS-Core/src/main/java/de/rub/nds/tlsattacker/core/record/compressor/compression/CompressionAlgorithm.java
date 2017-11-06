/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.compressor.compression;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;

/**
 *

 */
public abstract class CompressionAlgorithm {

    private final CompressionMethod method;

    public CompressionAlgorithm(CompressionMethod method) {
        this.method = method;
    }

    public abstract byte[] compress(byte[] data);
}
