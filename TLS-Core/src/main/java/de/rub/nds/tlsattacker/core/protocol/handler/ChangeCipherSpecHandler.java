/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ChangeCipherSpecParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ChangeCipherSpecPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ChangeCipherSpecSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;

public class ChangeCipherSpecHandler extends ProtocolMessageHandler<ChangeCipherSpecMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

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
        if (tlsContext.getTalkingConnectionEndType() != tlsContext.getChooser().getConnectionEndType()
                && tlsContext.getChooser().getSelectedProtocolVersion() != ProtocolVersion.TLS13) {
            tlsContext.getRecordLayer().updateDecryptionCipher();
            tlsContext.setReadSequenceNumber(0);
            tlsContext.getRecordLayer().updateDecompressor();
            tlsContext.increaseDtlsReadEpoch();
        }
    }

    private KeySet getKeySet(TlsContext context, Tls13KeySetType keySetType) {
        try {
            LOGGER.debug("Generating new KeySet");
            return KeySetGenerator.generateKeySet(context, tlsContext.getChooser().getSelectedProtocolVersion(),
                    keySetType);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
    }

    private void setServerRecordCipher() {
        tlsContext.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
        LOGGER.debug("Setting cipher for server to use handshake secrets");
        KeySet serverKeySet = getKeySet(tlsContext, tlsContext.getActiveServerKeySetType());
        RecordCipher recordCipherServer = RecordCipherFactory.getRecordCipher(tlsContext, serverKeySet, tlsContext
                .getChooser().getSelectedCipherSuite());
        tlsContext.getRecordLayer().setRecordCipher(recordCipherServer);
    }

    private void setClientRecordCipher() {
        Tls13KeySetType keySetType = Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS;
        tlsContext.setActiveClientKeySetType(keySetType);
        LOGGER.debug("Setting cipher for client to use " + keySetType);
        KeySet clientKeySet = getKeySet(tlsContext, tlsContext.getActiveClientKeySetType());
        RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet, tlsContext
                .getChooser().getSelectedCipherSuite());
        tlsContext.getRecordLayer().setRecordCipher(recordCipherClient);

        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            tlsContext.setReadSequenceNumber(0);
            tlsContext.getRecordLayer().updateDecryptionCipher();
        } else {
            tlsContext.setWriteSequenceNumber(0);
            tlsContext.getRecordLayer().updateEncryptionCipher();
        }
    }

    @Override
    public void adjustTlsContextAfterSerialize(ChangeCipherSpecMessage message) {
        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getConnectionEndType()) {
            if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()
                    && tlsContext.getConfig().getTls13BackwardsCompatibilityMode()) {
                if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
                    setServerRecordCipher();
                } else {
                    setClientRecordCipher();
                }
            }
            tlsContext.getRecordLayer().updateEncryptionCipher();
            tlsContext.setWriteSequenceNumber(0);
            tlsContext.getRecordLayer().updateCompressor();
            tlsContext.increaseDtlsWriteEpoch();
        }
    }

}
