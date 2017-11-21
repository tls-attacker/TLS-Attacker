/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EndOfEarlyDataParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EndOfEarlyDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EndOfEarlyDataSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EndOfEarlyDataHandler extends HandshakeMessageHandler<EndOfEarlyDataMessage> {

    public EndOfEarlyDataHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new EndOfEarlyDataParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(EndOfEarlyDataMessage message) {
        return new EndOfEarlyDataPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ProtocolMessageSerializer getSerializer(EndOfEarlyDataMessage message) {
        return new EndOfEarlyDataSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(EndOfEarlyDataMessage message) {
        if (tlsContext.getConnectionEnd().getConnectionEndType() == ConnectionEndType.CLIENT) {
            adjustRecordLayerForEndOfEarlyData();
        }
        // recordLayer is being adjusted in RecordDecryptor, to decrypt
        // ClientFinished
    }

    private void adjustRecordLayerForEndOfEarlyData() {
        try {
            LOGGER.debug("Adjusting recordCipher to encrypt EOED properly");

            tlsContext.setActiveKeySetType(Tls13KeySetType.EARLY_TRAFFIC_SECRETS);
            KeySet keySet = KeySetGenerator.generateKeySet(tlsContext);
            RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet,
                    tlsContext.getEarlyDataCipherSuite());
            tlsContext.getRecordLayer().setRecordCipher(recordCipher);
            tlsContext.getRecordLayer().updateEncryptionCipher();
            tlsContext.setWriteSequenceNumber(1); // 2nd message using
                                                  // EarlySecret

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(EndOfEarlyDataHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
