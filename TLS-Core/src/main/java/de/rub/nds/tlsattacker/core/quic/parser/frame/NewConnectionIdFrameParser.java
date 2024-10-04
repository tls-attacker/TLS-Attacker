/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.NewConnectionIdFrame;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NewConnectionIdFrameParser extends QuicFrameParser<NewConnectionIdFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    public NewConnectionIdFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(NewConnectionIdFrame frame) {
        parseSequenceNumber(frame);
        parseRetirePriorTo(frame);
        parseConnectionIdLength(frame);
        parseConnectionId(frame);
        parseStatelessResetToken(frame);
    }

    protected void parseSequenceNumber(NewConnectionIdFrame frame) {
        frame.setSequenceNumber((int) parseVariableLengthInteger());
        LOGGER.debug("Sequence  Number: {}", frame.getSequenceNumber().getValue());
    }

    protected void parseRetirePriorTo(NewConnectionIdFrame frame) {
        frame.setRetirePriorTo((int) parseVariableLengthInteger());
        LOGGER.debug("Retire Prior To: {}", frame.getRetirePriorTo().getValue());
    }

    protected void parseConnectionIdLength(NewConnectionIdFrame frame) {
        frame.setConnectionIdLength(
                parseIntField(NewConnectionIdFrame.CONNECTION_ID_LENGTH_FIELD_LENGTH));
        LOGGER.debug("Length: {}", frame.getConnectionIdLength().getValue());
    }

    protected void parseConnectionId(NewConnectionIdFrame frame) {
        frame.setConnectionId(parseByteArrayField(frame.getConnectionIdLength().getValue()));
        LOGGER.debug("Connection ID: {}", frame.getConnectionId().getValue());
    }

    protected void parseStatelessResetToken(NewConnectionIdFrame frame) {
        frame.setStatelessResetToken(
                parseByteArrayField(NewConnectionIdFrame.STATELESS_RESET_TOKEN_LENGTH));
        LOGGER.debug("Stateless Reset Token: {}", frame.getStatelessResetToken().getValue());
    }
}
