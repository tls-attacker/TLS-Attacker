/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.frame.DatagramFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DatagramFrameParser extends QuicFrameParser<DatagramFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DatagramFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(DatagramFrame frame) {
        QuicFrameType frameType = QuicFrameType.getFrameType(frame.getFrameType().getValue());
        frame.setLengthField(frameType == QuicFrameType.DATAGRAM_FRAME_LEN);
        if (frame.isLengthField()) {
            parseLength(frame);
        }
        parseData(frame);
    }

    protected void parseLength(DatagramFrame frame) {
        frame.setLength((int) parseVariableLengthInteger());
        LOGGER.debug("Length: {}", frame.getLength().getValue());
    }

    protected void parseData(DatagramFrame frame) {
        if (frame.getLength() == null) {
            frame.setData(parseTillEnd());
        } else {
            frame.setData(parseByteArrayField(frame.getLength().getValue()));
        }
        LOGGER.debug("Data: {}", frame.getData().getValue());
    }
}
