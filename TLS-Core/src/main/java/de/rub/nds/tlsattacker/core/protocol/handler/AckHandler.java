/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckHandler extends ProtocolMessageHandler<AckMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckHandler(Context context) {
        super(context.getTlsContext());
    }

    @Override
    public void adjustContext(AckMessage message) {
        if (tlsContext.getChooser().getConnectionEndType()
                != tlsContext.getTalkingConnectionEndType()) {
            if (tlsContext.getDtls13ReceivedAcknowledgedRecords() == null) {
                tlsContext.setDtls13ReceivedAcknowledgedRecords(new LinkedList<>());
            }
            tlsContext.getDtls13ReceivedAcknowledgedRecords().addAll(message.getRecordNumbers());
        }
    }
}
