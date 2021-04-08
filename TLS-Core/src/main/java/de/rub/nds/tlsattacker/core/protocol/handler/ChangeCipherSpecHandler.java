/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecHandler extends TlsMessageHandler<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChangeCipherSpecHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ChangeCipherSpecParser getParser(byte[] message, int pointer) {
        return new ChangeCipherSpecParser(pointer, message, tlsContext.getChooser().getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public ChangeCipherSpecPreparator getPreparator(ChangeCipherSpecMessage message) {
        return new ChangeCipherSpecPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ChangeCipherSpecSerializer getSerializer(ChangeCipherSpecMessage message) {
        return new ChangeCipherSpecSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ChangeCipherSpecMessage message) {
        if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()
            && tlsContext.getChooser().getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            tlsContext.getRecordLayer().updateDecryptionCipher();
            tlsContext.setReadSequenceNumber(0);
            tlsContext.getRecordLayer().updateDecompressor();
            tlsContext.increaseDtlsReadEpoch();
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ChangeCipherSpecMessage message) {

        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getConnectionEndType()) {
            if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
                tlsContext.setWriteSequenceNumber(0);
                tlsContext.getRecordLayer().updateEncryptionCipher();
                tlsContext.getRecordLayer().updateCompressor();
                tlsContext.increaseDtlsWriteEpoch();
            }
        }
    }

}
