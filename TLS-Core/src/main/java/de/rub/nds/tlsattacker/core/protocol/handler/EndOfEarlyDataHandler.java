/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
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
    public void adjustContext(EndOfEarlyDataMessage message) {
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.SERVER) {
            adjustClientCipherAfterEarly();
        }
    }

    private void adjustClientCipherAfterEarly() {
        try {
            tlsContext.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use handshake secrets");
            KeySet clientKeySet =
                    KeySetGenerator.generateKeySet(
                            tlsContext,
                            tlsContext.getChooser().getSelectedProtocolVersion(),
                            tlsContext.getActiveClientKeySetType());
            RecordCipher recordCipherClient =
                    RecordCipherFactory.getRecordCipher(tlsContext, clientKeySet, false);
            tlsContext.getRecordLayer().updateDecryptionCipher(recordCipherClient);
        } catch (CryptoException | NoSuchAlgorithmException ex) {
            LOGGER.error("Generating KeySet failed", ex);
            throw new WorkflowExecutionException(ex);
        }
    }
}
