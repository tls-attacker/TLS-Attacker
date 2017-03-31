/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record.compressor.compression;

import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class NullCompression extends CompressionAlgorithm{

    public NullCompression() {
        super(CompressionMethod.NULL);
    }

    /**
     * Null Compression just passes the data through
     * @param data
     * @return 
     */
    @Override
    public byte[] compress(byte[] data) {
        return data;
    }
    
}
