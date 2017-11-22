/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ApplicationMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ApplicationMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ApplicationMessageSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ApplicationHandler extends ProtocolMessageHandler<ApplicationMessage> {

    public ApplicationHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ApplicationMessageParser getParser(byte[] message, int pointer) {
        return new ApplicationMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ApplicationMessagePreparator getPreparator(ApplicationMessage message) {
        return new ApplicationMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ApplicationMessageSerializer getSerializer(ApplicationMessage message) {
        return new ApplicationMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(ApplicationMessage message) {
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()
                || tlsContext.isExtensionProposed(ExtensionType.EARLY_DATA)) {
            adjustRecordLayer();
        }
        tlsContext.setLastHandledApplicationMessageData(message.getData().getValue());
        String readableAppData = ArrayConverter.bytesToHexString(tlsContext.getLastHandledApplicationMessageData());
        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getMyConnectionPeer()) {
            LOGGER.debug("Received Data:" + readableAppData);
        } else {
            LOGGER.debug("Send Data:" + readableAppData);
        }
    }

    private void adjustRecordLayer() {
        try {
            KeySet keySetWrite = KeySetGenerator.generateKeySet(tlsContext, ProtocolVersion.TLS13,
                    tlsContext.getActiveKeySetTypeWrite());
            RecordCipher recordCipherEnc = RecordCipherFactory.getRecordCipher(tlsContext, keySetWrite,
                    tlsContext.getEarlyDataCipherSuite());
            KeySet keySetRead = KeySetGenerator.generateKeySet(tlsContext, ProtocolVersion.TLS13,
                    tlsContext.getActiveKeySetTypeRead());
            RecordCipher recordCipherDec = RecordCipherFactory.getRecordCipher(tlsContext, keySetRead,
                    tlsContext.getEarlyDataCipherSuite());

            if (tlsContext.getRecordLayer().getEncryptor().getKeySet() == null
                    || tlsContext.getRecordLayer().getEncryptor().getKeySet().getKeySetType() != tlsContext
                            .getActiveKeySetTypeWrite()) {
                tlsContext.getRecordLayer().setRecordCipher(recordCipherEnc);
                tlsContext.getRecordLayer().updateEncryptionCipher();
                tlsContext.setWriteSequenceNumber(0); // Reset SQN
                LOGGER.debug("Updated Encryption Cipher");
            }

            if (tlsContext.getRecordLayer().getDecryptor().getKeySet() == null
                    || tlsContext.getRecordLayer().getDecryptor().getKeySet().getKeySetType() != tlsContext
                            .getActiveKeySetTypeRead()) {
                tlsContext.getRecordLayer().setRecordCipher(recordCipherDec);
                tlsContext.getRecordLayer().updateDecryptionCipher();
                tlsContext.setReadSequenceNumber(0); // Reset SQN
                LOGGER.debug("Updated Decryption Cipher");
            }

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ApplicationHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ApplicationMessage message) {
        if (tlsContext.getActiveClientKeySetType() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            tlsContext.setActiveClientKeySetType(Tls13KeySetType.NONE);
        }
    }
}
