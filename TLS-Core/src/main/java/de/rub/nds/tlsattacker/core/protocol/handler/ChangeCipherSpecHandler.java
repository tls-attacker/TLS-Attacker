/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ChangeCipherSpecHandler extends ProtocolMessageHandler<ChangeCipherSpecMessage> {

    public ChangeCipherSpecHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ChangeCipherSpecParser getParser(byte[] message, int pointer) {
        return new ChangeCipherSpecParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
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
        // receiving
        if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()) {
            tlsContext.getRecordLayer().updateDecryptionCipher();
            tlsContext.setReadSequenceNumber(0);
            tlsContext.getRecordLayer().updateDecompressor();
            // DTLS
            // TODO check that prior handshake-related messages have been
            // received
            // If they haven't, it means that this message has arrived out of
            // order.
            // and that we should not increase the next receive epoch, as we
            // still
            // have messages left to process in the current epoch.
            tlsContext.increaseDtlsNextReceiveEpoch();
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ChangeCipherSpecMessage message) {
        // sending
        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getConnectionEndType()) {
            tlsContext.getRecordLayer().updateEncryptionCipher();
            tlsContext.setWriteSequenceNumber(0);
            tlsContext.getRecordLayer().updateCompressor();
            // DTLS
            tlsContext.increaseDtlsSendEpoch();
        }
    }

}
