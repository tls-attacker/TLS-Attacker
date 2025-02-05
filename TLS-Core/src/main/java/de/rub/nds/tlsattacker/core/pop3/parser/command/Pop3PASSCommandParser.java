/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3PASSCommand;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The password provided in the PASS command may contain spaces, so everything past PASS is
 * considered the password.
 */
public class Pop3PASSCommandParser extends Pop3MessageParser<Pop3PASSCommand> {

    public Pop3PASSCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(Pop3PASSCommand passCommand) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ", 2);
        String keyword = lineContents[0];

        passCommand.setKeyword(keyword);

        if (lineContents.length == 2) {
            String password = lineContents[1];
            passCommand.setArguments(password);
            passCommand.setPassword(password);
        }
    }
}
