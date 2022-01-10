/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

public class ParserResult {

    private TlsMessage message;
    private int parserPosition;

    public ParserResult(TlsMessage message, int parserPosition) {
        this.message = message;
        this.parserPosition = parserPosition;
    }

    public TlsMessage getMessage() {
        return message;
    }

    public void setMessage(TlsMessage message) {
        this.message = message;
    }

    public int getParserPosition() {
        return parserPosition;
    }

    public void setParserPosition(int parserPosition) {
        this.parserPosition = parserPosition;
    }

}
