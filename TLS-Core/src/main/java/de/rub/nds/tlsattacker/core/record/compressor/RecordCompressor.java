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
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.compressor.compression.*;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class RecordCompressor extends Compressor<AbstractRecord> {

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
    public void compress(AbstractRecord record) {
        byte[] cleanBytes = record.getCleanProtocolMessageBytes().getValue();
        byte[] compressedBytes = algorithm.compress(cleanBytes);
        record.setCleanProtocolMessageBytes(compressedBytes);
    }

    public void setMethod(CompressionMethod method) {
        AlgorithmFactory factory = new AlgorithmFactory();
        algorithm = factory.getAlgorithm(version, method);
    }

}
