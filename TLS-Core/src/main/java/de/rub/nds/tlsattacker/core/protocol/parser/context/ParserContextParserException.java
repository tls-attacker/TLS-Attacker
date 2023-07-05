/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.context;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;

@SuppressWarnings("serial")
public class ParserContextParserException extends ParserException {

    private final ParserContext currentContext;

    private final ParserContext previousContext;

    public ParserContextParserException(
            String message, ParserContext currentContext, ParserContext previousContext) {
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
