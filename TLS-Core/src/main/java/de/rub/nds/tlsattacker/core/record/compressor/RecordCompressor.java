/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.compressor;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.compressor.compression.CompressionAlgorithm;

public class RecordCompressor extends Compressor<Record> {

    private CompressionAlgorithm algorithm;
    private final ProtocolVersion version;

    public RecordCompressor(TlsContext tlsContext) {
        version = tlsContext.getChooser().getSelectedProtocolVersion();
        if (version.isTLS13()) {
            setMethod(CompressionMethod.NULL);
        } else {
            setMethod(tlsContext.getChooser().getSelectedCompressionMethod());
        }
    }

    @Override
    public void compress(Record record) {
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        byte[] compressedBytes = algorithm.compress(cleanBytes);
        record.setCleanProtocolMessageBytes(compressedBytes);
    }

    public void setMethod(CompressionMethod method) {
        LOGGER.debug("Changing Compression method to {}", method);
        AlgorithmFactory factory = new AlgorithmFactory();
        algorithm = factory.getAlgorithm(version, method);
    }
}
