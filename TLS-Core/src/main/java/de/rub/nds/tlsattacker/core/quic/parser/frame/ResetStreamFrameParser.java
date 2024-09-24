/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.ResetStreamFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ResetStreamFrameParser extends QuicFrameParser<ResetStreamFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ResetStreamFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ResetStreamFrame frame) {
        parseStreamId(frame);
        parseApplicationProtocolErrorCode(frame);
        parseFinalSize(frame);
    }

    protected void parseStreamId(ResetStreamFrame frame) {
        frame.setStreamId((int) parseVariableLengthInteger());
        LOGGER.debug("Stream ID: {}", frame.getStreamId().getValue());
    }

    protected void parseApplicationProtocolErrorCode(ResetStreamFrame frame) {
        frame.setApplicationProtocolErrorCode((int) parseVariableLengthInteger());
        LOGGER.debug(
                "Application Protocol Error Code: {}",
                frame.getApplicationProtocolErrorCode().getValue());
    }

    protected void parseFinalSize(ResetStreamFrame frame) {
        frame.setFinalSize((int) parseVariableLengthInteger());
        LOGGER.debug("Final Size: {}", frame.getFinalSize().getValue());
    }
}
