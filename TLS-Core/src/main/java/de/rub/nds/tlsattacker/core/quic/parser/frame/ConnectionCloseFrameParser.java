/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionCloseFrameParser extends QuicFrameParser<ConnectionCloseFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ConnectionCloseFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ConnectionCloseFrame frame) {
        parseErrorCode(frame);
        QuicFrameType frameType = QuicFrameType.getFrameType(frame.getFrameType().getValue());
        if (frameType == QuicFrameType.CONNECTION_CLOSE_QUIC_FRAME) {
            parseFrameType(frame);
        }
        parseReasonPhraseLength(frame);
        parseReasonPhrase(frame);
    }

    protected void parseErrorCode(ConnectionCloseFrame frame) {
        frame.setErrorCode((int) parseVariableLengthInteger());
        LOGGER.debug("Error Code: {}", frame.getErrorCode().getValue());
    }

    protected void parseFrameType(ConnectionCloseFrame frame) {
        frame.setTriggerFrameType((int) parseVariableLengthInteger());
        LOGGER.debug("Frame Type: {}", frame.getTriggerFrameType().getValue());
    }

    protected void parseReasonPhraseLength(ConnectionCloseFrame frame) {
        frame.setReasonPhraseLength((int) parseVariableLengthInteger());
        LOGGER.debug("Reason Phrase Length: {}", frame.getReasonPhraseLength().getValue());
    }

    protected void parseReasonPhrase(ConnectionCloseFrame frame) {
        frame.setReasonPhrase(
                parseByteArrayField(frame.getReasonPhraseLength().getValue().intValue()));
        LOGGER.debug("Reason Phrase: {}", frame.getReasonPhrase().getValue());
    }
}
