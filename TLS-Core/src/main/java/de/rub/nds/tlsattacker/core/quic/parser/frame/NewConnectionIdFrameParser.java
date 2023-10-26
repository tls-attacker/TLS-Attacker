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

public class NewConnectionIdFrameParser extends QuicFrameParser<NewConnectionIdFrame> {

    public NewConnectionIdFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(NewConnectionIdFrame frame) {
        parseSequenceNumber(frame);
        parseRetirePriorTo(frame);
        parseLength(frame);
        parseConnectionId(frame);
        parseStatelessResetToken(frame);
    }

    protected void parseSequenceNumber(NewConnectionIdFrame frame) {
        frame.setSequenceNumber((int) parseVariableLengthInteger());
    }

    protected void parseRetirePriorTo(NewConnectionIdFrame frame) {
        frame.setRetirePriorTo((int) parseVariableLengthInteger());
    }

    protected void parseLength(NewConnectionIdFrame frame) {
        frame.setLength(parseIntField(1));
    }

    protected void parseConnectionId(NewConnectionIdFrame frame) {
        frame.setConnectionId(parseByteArrayField(frame.getLength().getValue()));
    }

    protected void parseStatelessResetToken(NewConnectionIdFrame frame) {
        frame.setStatelessResetToken(
                parseByteArrayField(NewConnectionIdFrame.STATELESS_RESET_TOKEN_LENGTH));
    }
}
