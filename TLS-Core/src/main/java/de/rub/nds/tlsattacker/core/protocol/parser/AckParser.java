/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.AckByteLength;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.AckMessage;
import java.io.InputStream;
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
        parseRecordNumberLength(ackMessage);
        parseRecordNumbers(ackMessage);
    }

    private void parseRecordNumbers(AckMessage ackMessage) {
        ackMessage.setRecordNumbers(
                parseByteArrayField(ackMessage.getRecordNumberLength().getValue()));
        LOGGER.debug(
                "RecordNumbers: "
                        + ArrayConverter.bytesToHexString(
                                ackMessage.getRecordNumbers().getValue()));
    }

    private void parseRecordNumberLength(AckMessage ackMessage) {
        ackMessage.setRecordNumberLength(parseIntField(AckByteLength.RECORD_NUMBER_LENGTH_LENGTH));
        LOGGER.debug("RecordNumberLength: " + ackMessage.getRecordNumberLength().getValue());
    }
}
