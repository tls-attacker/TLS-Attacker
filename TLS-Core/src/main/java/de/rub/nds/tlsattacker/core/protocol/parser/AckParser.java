/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.constants.RecordByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ack.RecordNumber;
import java.io.InputStream;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckParser extends ProtocolMessageParser<AckMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(AckMessage ackMessage) {
        LOGGER.debug("Parsing AckMessage");
        parseRecordNumbersLength(ackMessage);
        parseRecordNumbers(ackMessage);
    }

    private void parseRecordNumbers(AckMessage ackMessage) {
        ackMessage.setRecordNumbers(new LinkedList<>());
        LOGGER.debug("RecordNumbers: ");
        for (int i = 0;
                i < ackMessage.getRecordNumberLength().getValue();
                i += AckByteLength.RECORD_NUMBER) {
            RecordNumber recordNumber = new RecordNumber();
            recordNumber.setEpoch(parseBigIntField(RecordByteLength.DTLS13_EPOCH_NUMBER));
            recordNumber.setSequenceNumber(parseBigIntField(RecordByteLength.SEQUENCE_NUMBER));
            ackMessage.getRecordNumbers().add(recordNumber);
            LOGGER.debug("\t - {}", recordNumber);
        }
    }

    private void parseRecordNumbersLength(AckMessage ackMessage) {
        ackMessage.setRecordNumberLength(parseIntField(AckByteLength.RECORD_NUMBERS_LENGTH));
        LOGGER.debug("RecordNumberLength: {}", ackMessage.getRecordNumberLength().getValue());
    }
}
