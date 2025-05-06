/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
            if (message.getConnectionIds() != null && !message.getConnectionIds().isEmpty()) {
                // set the first one immediately if usage is set to it
                tlsContext.addNewWriteConnectionId(
                        message.getConnectionIds().get(0).getConnectionId().getValue(),
                        message.getUsage() == ConnectionIdUsage.CID_SPARE);
                for (int i = 1; i < message.getConnectionIds().size(); i++) {
                    tlsContext.addNewWriteConnectionId(
                            message.getConnectionIds().get(i).getConnectionId().getValue(), true);
                }
            }
        }
    }
}
