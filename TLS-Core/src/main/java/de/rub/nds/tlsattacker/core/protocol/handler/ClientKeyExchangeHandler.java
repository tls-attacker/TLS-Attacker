/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeyDerivator;
import de.rub.nds.tlsattacker.core.state.session.IdSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <Message> The ClientKeyExchangeMessage that should be Handled
 */
public abstract class ClientKeyExchangeHandler<Message extends ClientKeyExchangeMessage>
        extends HandshakeMessageHandler<Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    public void adjustPremasterSecret(Message message) {
        if (message.getComputations().getPremasterSecret() != null) {
            byte[] premasterSecret = message.getComputations().getPremasterSecret().getValue();
            tlsContext.setPreMasterSecret(premasterSecret);
            LOGGER.debug("Set PremasterSecret in Context to {}", premasterSecret);
        } else {
            LOGGER.debug("Did not set in Context PremasterSecret");
        }
    }

    public void adjustMasterSecret(Message message) {
        byte[] masterSecret;
        try {
            masterSecret =
                    KeyDerivator.calculateMasterSecret(
                            tlsContext,
                            message.getComputations().getClientServerRandom().getValue());
        } catch (CryptoException ex) {
            throw new UnsupportedOperationException("Could not calculate masterSecret", ex);
        }
        tlsContext.setMasterSecret(masterSecret);
        LOGGER.debug("Set MasterSecret in Context to {}", masterSecret);
    }

    protected void spawnNewSession() {
        if (tlsContext.getChooser().getServerSessionId().length != 0) {
            IdSession session =
                    new IdSession(
                            tlsContext.getChooser().getMasterSecret(),
                            tlsContext.getChooser().getServerSessionId());
            tlsContext.addNewSession(session);
            LOGGER.debug("Spawning new resumable Session");
        }
    }
}
