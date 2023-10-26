/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ack.RecordNumber;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckPreperator extends ProtocolMessagePreparator<AckMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;
    private final AckMessage message;

    public AckPreperator(Chooser chooser, AckMessage message, TlsContext tlsContext) {
        super(chooser, message);
        this.message = message;
        this.tlsContext = tlsContext;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing AckMessage");
        prepareRecordNumbers();
        prepareRecordNumbersLength();
    }

    private void prepareRecordNumbersLength() {
        message.setRecordNumberLength(
                message.getRecordNumbers().size() * AckByteLength.RECORD_NUMBER);
        LOGGER.debug("RecordNumbers Length: " + message.getRecordNumberLength());
    }

    private void prepareRecordNumbers() {
        if (message.getRecordNumbers() == null) {
            message.setRecordNumbers(new LinkedList<>());
        }
        if (tlsContext.getDtlsAcknowledgedRecords() != null) {
            message.getRecordNumbers().addAll(tlsContext.getDtlsAcknowledgedRecords());
            tlsContext.getDtlsAcknowledgedRecords().clear();
        }

        LOGGER.debug("RecordNumbers: ");
        for (RecordNumber recordNumber : message.getRecordNumbers()) {
            LOGGER.debug(
                    " - Epoch "
                            + recordNumber.getEpoch().getValue()
                            + " | SQN "
                            + recordNumber.getSequenceNumber().getValue());
        }
    }
}
