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
 *
 */
public class NullCompression extends CompressionAlgorithm {

    public NullCompression() {
        super(CompressionMethod.NULL);
    }

    /**
     * Null Compression just passes the data through
     *
     * @param data
     *            The Data that should be compressed
     * @return Compressed Bytes
     */
    @Override
    public byte[] compress(byte[] data) {
        return data;
    }

    @Override
    public byte[] decompress(byte[] data) {
        return data;
    }

}
