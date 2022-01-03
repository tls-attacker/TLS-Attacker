/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EndOfEarlyDataParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EndOfEarlyDataPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EndOfEarlyDataSerializer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EndOfEarlyDataHandler extends HandshakeMessageHandler<EndOfEarlyDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EndOfEarlyDataHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public EndOfEarlyDataParser getParser(byte[] message, int pointer) {
        return new EndOfEarlyDataParser(pointer, message, tlsContext.getLastRecordVersion(), tlsContext.getConfig());
    }

    @Override
    public EndOfEarlyDataPreparator getPreparator(EndOfEarlyDataMessage message) {
        return new EndOfEarlyDataPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public EndOfEarlyDataSerializer getSerializer(EndOfEarlyDataMessage message) {
        return new EndOfEarlyDataSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(EndOfEarlyDataMessage message) {
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            adjustClientCipherAfterEarly();
        }
    }

    private void adjustClientCipherAfterEarly() {
        try {
            tlsContext.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use handshake secrets");
            KeySet clientKeySet = KeySetGenerator.generateKeySet(tlsContext,
                tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext.getActiveClientKeySetType());
            RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet);
            tlsContext.getRecordLayer().updateDecryptionCipher(recordCipherClient);
        } catch (CryptoException | NoSuchAlgorithmException ex) {
            LOGGER.error("Generating KeySet failed", ex);
            throw new WorkflowExecutionException(ex.toString());
        }
    }
}
