/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ack.RecordNumber;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckSerializer extends ProtocolMessageSerializer<AckMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckSerializer(AckMessage message) {
        super(message);
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing AckMessage");
        writeRecordNumberLength();
        writeRecordNumbers();
        return getAlreadySerialized();
    }

    private void writeRecordNumberLength() {
        LOGGER.debug("RecordNumbersLength: " + message.getRecordNumberLength().getValue());
        appendInt(
                message.getRecordNumberLength().getValue(),
                AckByteLength.RECORD_NUMBER_LENGTH_LENGTH);
    }

    private void writeRecordNumbers() {
        LOGGER.debug("RecordNumbers:");
        for (RecordNumber recordNumber : message.getRecordNumbers()) {
            appendBigInteger(
                    recordNumber.getEpoch().getValue(), AckByteLength.RECORD_NUMBER_EPOCH_LENGTH);
            appendBigInteger(
                    recordNumber.getSequenceNumber().getValue(),
                    AckByteLength.RECORD_NUMBER_SEQUENCE_NUMBER_LENGTH);
            LOGGER.debug(
                    " - Epoch "
                            + recordNumber.getEpoch().getValue()
                            + " | SQN "
                            + recordNumber.getSequenceNumber().getValue());
        }
    }
}
