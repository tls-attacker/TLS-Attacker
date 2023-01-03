/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import java.util.LinkedList;

public class AckHandler extends ProtocolMessageHandler<AckMessage> {
    public AckHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(AckMessage message) {
        if (tlsContext.getChooser().getConnectionEndType()
                != tlsContext.getTalkingConnectionEndType()) {
            LOGGER.debug("Add received acknowledged records in context.");
            if (tlsContext.getReceivedAcknowledgedRecords() == null) {
                tlsContext.setReceivedAcknowledgedRecords(new LinkedList<>());
            }
            tlsContext.getReceivedAcknowledgedRecords().addAll(message.getRecordNumbers());
        }
    }
}
