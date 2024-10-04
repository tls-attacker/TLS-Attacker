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
import de.rub.nds.tlsattacker.core.quic.frame.StreamFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StreamFrameParser extends QuicFrameParser<StreamFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StreamFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(StreamFrame frame) {
        parseStreamId(frame);
        QuicFrameType frameType = QuicFrameType.getFrameType(frame.getFrameType().getValue());
        if (frameType == QuicFrameType.STREAM_FRAME_OFF
                || frameType == QuicFrameType.STREAM_FRAME_OFF_LEN
                || frameType == QuicFrameType.STREAM_FRAME_OFF_LEN_FIN) {
            parseOffset(frame);
        } else {
            frame.setOffset(0);
        }
        if (frameType == QuicFrameType.STREAM_FRAME_LEN
                || frameType == QuicFrameType.STREAM_FRAME_OFF_LEN
                || frameType == QuicFrameType.STREAM_FRAME_LEN_FIN) {
            parseLength(frame);
        }
        parseData(frame, frameType);
    }

    protected void parseStreamId(StreamFrame frame) {
        frame.setStreamId((int) parseVariableLengthInteger());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void parseOffset(StreamFrame frame) {
        frame.setOffset((int) parseVariableLengthInteger());
        LOGGER.debug("Offset: {}", frame.getOffset().getValue());
    }

    protected void parseLength(StreamFrame frame) {
        frame.setLength((int) parseVariableLengthInteger());
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    protected void parseData(StreamFrame frame, QuicFrameType frameType) {
        if (frameType == QuicFrameType.STREAM_FRAME
                || frameType == QuicFrameType.STREAM_FRAME_OFF
                || frameType == QuicFrameType.STREAM_FRAME_FIN) {
            frame.setData(parseTillEnd());
        } else {
            frame.setData(parseByteArrayField(frame.getLength().getValue()));
        }
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
