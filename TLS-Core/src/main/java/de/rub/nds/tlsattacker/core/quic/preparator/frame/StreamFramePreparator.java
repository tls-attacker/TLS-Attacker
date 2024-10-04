/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.preparator.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StreamFrame;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StreamFramePreparator extends QuicFramePreparator<StreamFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StreamFramePreparator(Chooser chooser, StreamFrame frame) {
        super(chooser, frame);
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing STREAM Frame");
        prepareData(getObject());
        prepareLengthData(getObject());
        prepareOffsetData(getObject());
        prepareStreamId(getObject());
        prepareFrameType(getObject());
    }

    protected void prepareData(StreamFrame frame) {
        frame.setData(frame.getDataConfig());
        LOGGER.debug("Crypto Data: {}", frame.getData().getValue());
    }

    protected void prepareLengthData(StreamFrame frame) {
        frame.setLength(frame.getLengthConfig());
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    protected void prepareOffsetData(StreamFrame frame) {
        frame.setOffset(frame.getOffsetConfig());
        LOGGER.debug("Offset: {}", frame.getOffset().getValue());
    }

    protected void prepareStreamId(StreamFrame frame) {
        frame.setStreamId(frame.getStreamIdConfig());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void prepareFrameType(StreamFrame frame) {
        // The three low-order bits of the frame type determine the fields that are present in the
        // frame.
        byte quicFrameType = 0b00001000;
        if (frame.getOffset() != null) {
            quicFrameType |= 0b00000100;
        }
        if (frame.getLength() != null) {
            quicFrameType |= 0b00000010;
        }
        if (frame.isFinalFrameConfig()) {
            quicFrameType |= 0b00000001;
        }
        frame.setFrameType(quicFrameType);
        LOGGER.debug("Frame Type: {}", frame.getData().getValue());
    }
}
