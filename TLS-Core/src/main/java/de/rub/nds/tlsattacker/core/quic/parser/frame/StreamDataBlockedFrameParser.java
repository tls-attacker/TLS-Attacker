/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StreamDataBlockedFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StreamDataBlockedFrameParser extends QuicFrameParser<StreamDataBlockedFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StreamDataBlockedFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(StreamDataBlockedFrame frame) {
        parseStreamId(frame);
        parseMaximumStreamData(frame);
    }

    protected void parseStreamId(StreamDataBlockedFrame frame) {
        frame.setStreamId((int) parseVariableLengthInteger());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void parseMaximumStreamData(StreamDataBlockedFrame frame) {
        frame.setMaximumStreamData((int) parseVariableLengthInteger());
        LOGGER.debug("Maximum Stream Data: {}", frame.getMaximumStreamData().getValue());
    }
}
