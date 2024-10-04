/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.MaxStreamsFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxStreamsFrameParser extends QuicFrameParser<MaxStreamsFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public MaxStreamsFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(MaxStreamsFrame frame) {
        parseMaximumStreams(frame);
    }

    protected void parseMaximumStreams(MaxStreamsFrame frame) {
        frame.setMaximumStreams((int) parseVariableLengthInteger());
        LOGGER.debug("Maximum Streams: {}", frame.getMaximumStreams().getValue());
    }
}
