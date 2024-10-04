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
import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AckFrameParser extends QuicFrameParser<AckFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AckFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(AckFrame frame) {
        parseLargestAcknowledged(frame);
        parseAckDelay(frame);
        parseAckRangeCount(frame);
        parseFirstAckRange(frame);
        // TODO: AckFrame only stores one ack range, this discards all other ranges
        for (int i = 1; i < frame.getAckRangeCount().getValue(); i++) {
            parseVariableLengthInteger();
            parseVariableLengthInteger();
        }
        QuicFrameType frameType = QuicFrameType.getFrameType(frame.getFrameType().getValue());
        if (frameType == QuicFrameType.ACK_FRAME_WITH_ECN) {
            parseEcnCounts(frame);
        }
    }

    protected void parseLargestAcknowledged(AckFrame frame) {
        frame.setLargestAcknowledged((int) parseVariableLengthInteger());
        LOGGER.debug("Largest Acknowledged: {}", frame.getLargestAcknowledged().getValue());
    }

    protected void parseAckDelay(AckFrame frame) {
        frame.setAckDelay((int) parseVariableLengthInteger());
        LOGGER.debug("ACK Delay: {}", frame.getAckDelay().getValue());
    }

    protected void parseAckRangeCount(AckFrame frame) {
        frame.setAckRangeCount((int) parseVariableLengthInteger());
        LOGGER.debug("ACK Range Count: {}", frame.getAckRangeCount().getValue());
    }

    protected void parseFirstAckRange(AckFrame frame) {
        frame.setFirstACKRange((int) parseVariableLengthInteger());
        LOGGER.debug("First ACK Range: {}", frame.getFirstACKRange().getValue());
    }

    protected void parseEcnCounts(AckFrame frame) {
        frame.setEct0(parseVariableLengthInteger());
        LOGGER.debug("ECT0 Count: {}", frame.getEct0().getValue());
        frame.setEct1(parseVariableLengthInteger());
        LOGGER.debug("ECT1 Count: {}", frame.getEct1().getValue());
        frame.setEcnCe(parseVariableLengthInteger());
        LOGGER.debug("ECT-CE Count: {}", frame.getEcnCe().getValue());
    }
}
