/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.compressor;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.compressor.compression.CompressionAlgorithm;
import de.rub.nds.tlsattacker.core.record.compressor.compression.DeflateCompression;
import de.rub.nds.tlsattacker.core.record.compressor.compression.NullCompression;

public class AlgorithmFactory {
    public CompressionAlgorithm getAlgorithm(ProtocolVersion version, CompressionMethod method) {
        CompressionAlgorithm algorithm;
        if (version.isTLS13()) {
            algorithm = new NullCompression();
        } else {
            if (method == CompressionMethod.DEFLATE) {
                algorithm = new DeflateCompression();
            } else {
                algorithm = new NullCompression();
            }
        }
        return algorithm;
    }
}
