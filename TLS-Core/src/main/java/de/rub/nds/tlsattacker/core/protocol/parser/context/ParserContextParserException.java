/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.context;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;

@SuppressWarnings("serial")
public class ParserContextParserException extends ParserException {

    private final ParserContext currentContext;

    private final ParserContext previousContext;

    public ParserContextParserException(String message, ParserContext currentContext, ParserContext previousContext) {
        super(message);
        this.currentContext = currentContext;
        this.previousContext = previousContext;
    }

    public ParserContext getCurrentContext() {
        return currentContext;
    }

    public ParserContext getPreviousContext() {
        return previousContext;
    }
}
