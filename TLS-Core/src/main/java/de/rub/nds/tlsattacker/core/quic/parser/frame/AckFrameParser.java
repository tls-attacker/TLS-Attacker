/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import java.io.InputStream;

public class AckFrameParser extends QuicFrameParser<AckFrame> {

    public AckFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(AckFrame frame) {
        parseLargestAcknowledged(frame);
        parseAckDelay(frame);
        parseAckRangeCount(frame);
        parseFirstAckRange(frame);
    }

    protected void parseLargestAcknowledged(AckFrame frame) {
        frame.setLargestAcknowledged((int) parseVariableLengthInteger());
    }

    protected void parseAckDelay(AckFrame frame) {
        frame.setAckDelay((int) parseVariableLengthInteger());
    }

    protected void parseAckRangeCount(AckFrame frame) {
        frame.setAckRangeCount((int) parseVariableLengthInteger());
    }

    protected void parseFirstAckRange(AckFrame frame) {
        frame.setFirstACKRange((int) parseVariableLengthInteger());
    }
}
