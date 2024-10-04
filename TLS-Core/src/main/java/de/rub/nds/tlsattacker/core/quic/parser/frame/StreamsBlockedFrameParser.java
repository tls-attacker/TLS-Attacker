/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StreamsBlockedFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StreamsBlockedFrameParser extends QuicFrameParser<StreamsBlockedFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StreamsBlockedFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(StreamsBlockedFrame frame) {
        parseMaximumStreams(frame);
    }

    protected void parseMaximumStreams(StreamsBlockedFrame frame) {
        frame.setMaximumStreams((int) parseVariableLengthInteger());
        LOGGER.debug("Maximum Streams: {}", frame.getMaximumStreams().getValue());
    }
}
