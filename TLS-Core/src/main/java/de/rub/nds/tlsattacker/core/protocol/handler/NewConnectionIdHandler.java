/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ConnectionIdUsage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.NewConnectionIdMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdHandler extends HandshakeMessageHandler<NewConnectionIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(NewConnectionIdMessage message) {
        if (tlsContext.getTalkingConnectionEndType()
                != tlsContext.getConnection().getLocalConnectionEndType()) {
            if (message.getUsage() == ConnectionIdUsage.CID_IMMEDIATE
                    && message.getConnectionIds() != null
                    && !message.getConnectionIds().isEmpty()) {
                LOGGER.debug("set new write connectionId in context");
                tlsContext.setWriteConnectionId(
                        message.getConnectionIds().get(0).getConnectionId().getValue());
            } else {
                LOGGER.debug("write connectionId does not need to update");
            }
        }
    }
}
