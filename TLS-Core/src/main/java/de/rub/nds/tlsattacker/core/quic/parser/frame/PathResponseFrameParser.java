/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PathResponseFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PathResponseFrameParser extends QuicFrameParser<PathResponseFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PathResponseFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PathResponseFrame frame) {
        parseData(frame);
    }

    protected void parseData(PathResponseFrame frame) {
        frame.setData(parseByteArrayField(PathResponseFrame.PATH_CHALLENGE_LENGTH));
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
