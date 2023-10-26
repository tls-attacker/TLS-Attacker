/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.parser.frame;

import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import java.io.InputStream;

public class ConnectionCloseFrameParser extends QuicFrameParser<ConnectionCloseFrame> {

    public ConnectionCloseFrameParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ConnectionCloseFrame frame) {
        parseErrorCode(frame);
        parseFrameType(frame);
        parseReasonPhraseLength(frame);
        parseReasonPhrase(frame);
    }

    protected void parseErrorCode(ConnectionCloseFrame frame) {
        frame.setErrorCode((int) parseVariableLengthInteger());
    }

    protected void parseFrameType(ConnectionCloseFrame frame) {
        frame.setTriggerFrameType((int) parseVariableLengthInteger());
    }

    protected void parseReasonPhraseLength(ConnectionCloseFrame frame) {
        frame.setReasonPhraseLength((int) parseVariableLengthInteger());
    }

    protected void parseReasonPhrase(ConnectionCloseFrame frame) {
        frame.setReasonPhrase(
                parseByteArrayField(frame.getReasonPhraseLength().getValue().intValue()));
    }
}
