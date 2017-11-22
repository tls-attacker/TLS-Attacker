/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;

public class ParserResult {

    private ProtocolMessage message;
    private int parserPosition;

    public ParserResult(ProtocolMessage message, int parserPosition) {
        this.message = message;
        this.parserPosition = parserPosition;
    }

    public ProtocolMessage getMessage() {
        return message;
    }

    public void setMessage(ProtocolMessage message) {
        this.message = message;
    }

    public int getParserPosition() {
        return parserPosition;
    }

    public void setParserPosition(int parserPosition) {
        this.parserPosition = parserPosition;
    }

}
