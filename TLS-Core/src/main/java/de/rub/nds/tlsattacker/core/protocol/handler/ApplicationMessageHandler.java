/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ApplicationMessageHandler extends ProtocolMessageHandler<ApplicationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ApplicationMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(ApplicationMessage message) {
        tlsContext.setLastHandledApplicationMessageData(message.getData().getValue());
        if (LOGGER.isDebugEnabled()) {
            if (tlsContext.getTalkingConnectionEndType()
                    == tlsContext.getChooser().getMyConnectionPeer()) {
                LOGGER.debug(
                        "Received Data: {}", tlsContext.getLastHandledApplicationMessageData());
            } else {
                LOGGER.debug("Send Data: {}", tlsContext.getLastHandledApplicationMessageData());
            }
        }
    }
}
