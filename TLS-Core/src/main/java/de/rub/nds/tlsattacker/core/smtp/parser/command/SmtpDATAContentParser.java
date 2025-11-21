/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SmtpDATAContentParser extends SmtpCommandParser<SmtpDATAContentCommand> {

    public SmtpDATAContentParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(SmtpDATAContentCommand smtpCommand) {
        List<String> lines = readWholeDATAContent();

        lines.remove(lines.size() - 1); // don't add final period to actual lines.
        smtpCommand.setLines(lines);
    }

    private List<String> readWholeDATAContent() {
        boolean isValid = false;
        List<String> lines = new ArrayList<>();
        String line;
        while ((line = parseSingleLine()) != null) {
            lines.add(line);
            if (isEndOfDataContent(line)) {
                isValid = true;
                break;
            }
        }

        // TODO: consider removing exception and save data regardless.
        if (!isValid) {
            throw new ParserException("DATA Content does not end with single line period");
        }
        return lines;
    }

    private boolean isEndOfDataContent(String line) {
        return line.equals(".");
    }
}
