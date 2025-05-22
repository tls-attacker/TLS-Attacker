/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
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
        writeRecordNumbersLength();
        writeRecordNumbers();
        return getAlreadySerialized();
    }

    private void writeRecordNumbersLength() {
        LOGGER.debug("RecordNumberLength: {}", message.getRecordNumberLength().getValue());
        appendInt(message.getRecordNumberLength().getValue(), AckByteLength.RECORD_NUMBERS_LENGTH);
    }

    private void writeRecordNumbers() {
        LOGGER.debug("RecordNumbers: ");
        for (RecordNumber recordNumber : message.getRecordNumbers()) {
            appendBigInteger(
                    recordNumber.getEpoch().getValue(), RecordByteLength.DTLS13_EPOCH_NUMBER);
            appendBigInteger(
                    recordNumber.getSequenceNumber().getValue(), RecordByteLength.SEQUENCE_NUMBER);
            LOGGER.debug("\t - {}", recordNumber);
        }
    }
}
