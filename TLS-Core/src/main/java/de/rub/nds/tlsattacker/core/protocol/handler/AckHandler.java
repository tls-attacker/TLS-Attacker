/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import java.util.Arrays;
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
            byte[] recordNumbers = message.getRecordNumbers().getValue();
            for (int i = 0; i < recordNumbers.length; i += AckByteLength.RECORD_NUMBER_LENGTH) {
                tlsContext
                        .getReceivedAcknowledgedRecords()
                        .add(
                                Arrays.copyOfRange(
                                        recordNumbers, i, AckByteLength.RECORD_NUMBER_LENGTH));
            }
        }
    }
}
