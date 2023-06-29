/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ConnectionIdExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionIdExtensionPreperator
        extends ExtensionPreparator<ConnectionIdExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ConnectionIdExtensionMessage message;

    public ConnectionIdExtensionPreperator(Chooser chooser, ConnectionIdExtensionMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing ConnectionIdExtensionMessage");
        message.setConnectionId(chooser.getConfig().getDefaultConnectionId());
        LOGGER.debug("ConnectionId: {}", message.getConnectionId().getValue());
        message.setConnectionIdLength(message.getConnectionId().getValue().length);
        LOGGER.debug("ConnectionId length: " + message.getConnectionIdLength().getValue());
    }
}
