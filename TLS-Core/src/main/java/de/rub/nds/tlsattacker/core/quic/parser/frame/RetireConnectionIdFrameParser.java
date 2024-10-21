/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.RetireConnectionIdFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RetireConnectionIdFrameParser extends QuicFrameParser<RetireConnectionIdFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RetireConnectionIdFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(RetireConnectionIdFrame frame) {
        parseSequenceNumber(frame);
    }

    protected void parseSequenceNumber(RetireConnectionIdFrame frame) {
        frame.setSequenceNumber((int) parseVariableLengthInteger());
        LOGGER.debug("Sequence  Number: {}", frame.getSequenceNumber().getValue());
    }
}
