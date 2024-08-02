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
import de.rub.nds.tlsattacker.core.quic.frame.AckFrameWithEcn;
import java.io.InputStream;

public class AckFrameParser extends QuicFrameParser<AckFrame> {

    private final boolean hasEcn;

    public AckFrameParser(InputStream stream) {
        super(stream);
        this.hasEcn = false;
    }

    public AckFrameParser(InputStream stream, boolean hasEcn) {
        super(stream);
        this.hasEcn = hasEcn;
    }

    @Override
    public void parse(AckFrame frame) {
        parseLargestAcknowledged(frame);
        parseAckDelay(frame);
        parseAckRangeCount(frame);
        parseFirstAckRange(frame);

        // TODO AckFrame only stores one ack range, this discards all other ranges
        for (int i = 1; i < frame.getAckRangeCount().getValue(); i++) {
            parseVariableLengthInteger();
            parseVariableLengthInteger();
        }

        if (hasEcn) {
            parseEcnCounts((AckFrameWithEcn) frame);
        }
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

    protected void parseEcnCounts(AckFrameWithEcn frame) {
        frame.setEct0(parseVariableLengthInteger());
        frame.setEct1(parseVariableLengthInteger());
        frame.setEcnCe(parseVariableLengthInteger());
    }
}
