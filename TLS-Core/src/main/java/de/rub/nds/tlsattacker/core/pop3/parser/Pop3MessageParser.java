/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import java.io.InputStream;

public abstract class Pop3MessageParser<MessageT extends Pop3Message> extends Parser<MessageT> {

    private static final byte LF = 0x0A;

    /**
     * Constructor for the Parser
     *
     * @param stream The Inputstream to read data from
     */
    public Pop3MessageParser(InputStream stream) {
        super(stream);
    }

    /**
     * Every Pop3 command and reply consists of CRLF-terminated lines. This method parses a single
     * line from the input. It will parse the line until the CRLF is reached or the end of the
     * stream is reached. Will remove the CRLF from the returned string.
     *
     * @return a single line from the input
     */
    public String parseSingleLine() {
        String lineUntilLF = parseStringTill(LF);
        if (!lineUntilLF.endsWith("\r\n")) {
            throw new ParserException("Reached end of stream before CRLF was found");
        }
        return lineUntilLF.trim();
    }
}
