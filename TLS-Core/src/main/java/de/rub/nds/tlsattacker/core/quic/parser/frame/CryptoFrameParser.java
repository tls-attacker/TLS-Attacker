/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CryptoFrameParser extends QuicFrameParser<CryptoFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public CryptoFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(CryptoFrame frame) {
        parseOffset(frame);
        parseLength(frame);
        parseCryptoData(frame);
    }

    protected void parseOffset(CryptoFrame frame) {
        frame.setOffset((int) parseVariableLengthInteger());
        LOGGER.debug("Parsed CryptoFrame Offset: {}", frame.getOffset().getValue());
    }

    protected void parseLength(CryptoFrame frame) {
        frame.setLength((int) parseVariableLengthInteger());
        LOGGER.debug("Parsed CryptoFrame Length: {}", frame.getLength().getValue());
    }

    protected void parseCryptoData(CryptoFrame frame) {
        frame.setCryptoData(parseByteArrayField(frame.getLength().getValue().intValue()));
        LOGGER.debug("Parsed CryptoFrame CryptoData: {}", frame.getCryptoData().getValue());
    }
}
