/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand;
import java.io.InputStream;
import java.util.List;

public class DATAContentParser extends SmtpCommandParser<SmtpDATAContentCommand> {

    public DATAContentParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAContentCommand smtpCommand) {
        List<String> lines = parseAllLines();

        String finalLine = lines.get(lines.size() - 1);
        if (!finalLine.equals("."))
            throw new ParserException("Data-Content does not end with a single line period.");

        for (String line : lines) {
            if (!isAsciiString(line))
                throw new ParserException("Data-Content contains non-ASCII characters.");
        }

        lines.remove(lines.size() - 1); // don't add final period to actual lines.
        smtpCommand.setLines(lines);
    }

    private boolean isAsciiString(String str) {
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) > 127) return false;
        }

        return true;
    }
}
