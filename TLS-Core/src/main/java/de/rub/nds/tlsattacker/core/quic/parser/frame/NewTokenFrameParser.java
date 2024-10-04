/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.NewTokenFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewTokenFrameParser extends QuicFrameParser<NewTokenFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewTokenFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(NewTokenFrame frame) {
        parseLength(frame);
        parseToken(frame);
    }

    protected void parseLength(NewTokenFrame frame) {
        frame.setTokenLength((int) parseVariableLengthInteger());
        LOGGER.debug("Length: {}", frame.getTokenLength().getValue());
    }

    protected void parseToken(NewTokenFrame frame) {
        frame.setToken(parseByteArrayField(frame.getTokenLength().getValue().intValue()));
        LOGGER.debug("Token: {}", frame.getToken().getValue());
    }
}
