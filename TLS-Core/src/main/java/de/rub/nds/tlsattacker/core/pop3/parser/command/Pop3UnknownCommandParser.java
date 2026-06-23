/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3UnknownCommand;
import java.io.InputStream;

public class Pop3UnknownCommandParser extends Pop3CommandParser<Pop3UnknownCommand> {

    public Pop3UnknownCommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Special parser for unknown commands which also accesses the verb string. Other parsers do not
     * have access to the verb string, because they are created based on the verb string matching a
     * known verb.
     *
     * @param pop3Command
     */
    @Override
    public void parse(Pop3UnknownCommand pop3Command) {
        // TODO: make this robust against not having CRLF, fails at the moment when no CR
        // parseStringTill(CRLF) is sadly not possible
        String line = parseSingleLine();
        // throws EndOfStreamException if no LF is found

        // 4.1.1 In the interest of improved interoperability, SMTP receivers SHOULD tolerate
        // trailing white space before the terminating &lt;CRLF&gt;.
        String actualCommand = line.trim();
        String[] verbAndParams = actualCommand.split(" ", 2);

        pop3Command.setUnknownCommandVerb(verbAndParams[0]);
        if (verbAndParams.length == 2) {
            pop3Command.setArguments(verbAndParams[1]);
        }
    }
}
