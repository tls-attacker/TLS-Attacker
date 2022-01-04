/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.compressor;

import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.compressor.compression.CompressionAlgorithm;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RecordCompressor extends Compressor<Record> {

    private CompressionAlgorithm algorithm;
    private ProtocolVersion version;

    public RecordCompressor(TlsContext context) {
        version = context.getChooser().getSelectedProtocolVersion();
        if (version.isTLS13()) {
            setMethod(CompressionMethod.NULL);
        } else {
            setMethod(context.getChooser().getSelectedCompressionMethod());
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
