/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.PathChallengeFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PathChallengeFrameParser extends QuicFrameParser<PathChallengeFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PathChallengeFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(PathChallengeFrame frame) {
        parseData(frame);
    }

    protected void parseData(PathChallengeFrame frame) {
        frame.setData(parseByteArrayField(PathChallengeFrame.PATH_CHALLENGE_LENGTH));
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
