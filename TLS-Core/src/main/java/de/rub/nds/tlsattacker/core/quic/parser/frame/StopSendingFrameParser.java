/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.StopSendingFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StopSendingFrameParser extends QuicFrameParser<StopSendingFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public StopSendingFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(StopSendingFrame frame) {
        parseStreamId(frame);
        parseApplicationProtocolErrorCode(frame);
    }

    protected void parseStreamId(StopSendingFrame frame) {
        frame.setStreamId((int) parseVariableLengthInteger());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void parseApplicationProtocolErrorCode(StopSendingFrame frame) {
        frame.setApplicationProtocolErrorCode((int) parseVariableLengthInteger());
        LOGGER.debug(
                "Application Protocol Error Code: {}",
                frame.getApplicationProtocolErrorCode().getValue());
    }
}
