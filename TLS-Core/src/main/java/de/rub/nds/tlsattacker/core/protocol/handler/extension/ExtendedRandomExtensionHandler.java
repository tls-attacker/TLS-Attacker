/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This Class handles the Extended Random Extension as defined as in <a
 * href="https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02">draft-rescorla-tls-extended-random-02</a>
 */
public class ExtendedRandomExtensionHandler
        extends ExtensionHandler<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedRandomExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(ExtendedRandomExtensionMessage message) {
        if (tlsContext.getTalkingConnectionEndType().equals(ConnectionEndType.SERVER)) {
            tlsContext.setServerExtendedRandom(message.getExtendedRandom().getValue());
            LOGGER.debug(
                    "The context server extended Random was set to {}",
                    message.getExtendedRandom());
        }
        if (tlsContext.getTalkingConnectionEndType().equals(ConnectionEndType.CLIENT)) {
            tlsContext.setClientExtendedRandom(message.getExtendedRandom().getValue());
            LOGGER.debug(
                    "The context client extended Random was set to {}",
                    message.getExtendedRandom());
        }

        // If both extended Randoms are received (i.e. client and server agreed
        // on using extended Random)
        // then extend the client and server random for premaster computations.
        if (!(tlsContext.getClientExtendedRandom() == null)
                && !(tlsContext.getServerExtendedRandom() == null)) {
            LOGGER.debug(
                    "Extended Random was agreed on. Concatenating extended Randoms to normal Randoms.");
            byte[] clientConcatRandom =
                    ArrayConverter.concatenate(
                            tlsContext.getClientRandom(), tlsContext.getClientExtendedRandom());
            byte[] serverConcatRandom =
                    ArrayConverter.concatenate(
                            tlsContext.getServerRandom(), tlsContext.getServerExtendedRandom());
            tlsContext.setClientRandom(clientConcatRandom);
            LOGGER.debug("ClientRandom: {}", tlsContext.getClientRandom());
            tlsContext.setServerRandom(serverConcatRandom);
            LOGGER.debug("ServerRandom: {}", tlsContext.getServerRandom());
        }
    }
}
