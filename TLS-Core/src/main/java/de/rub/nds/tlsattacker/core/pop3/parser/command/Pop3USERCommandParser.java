/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3USERCommand;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parses the provided username of a USER command. */
public class Pop3USERCommandParser extends Pop3CommandParser<Pop3USERCommand> {
    private static final Logger LOGGER = LogManager.getLogger();

    public Pop3USERCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(Pop3USERCommand userCommand) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ");
        String keyword = lineContents[0];

        userCommand.setKeyword(keyword);

        if (lineContents.length == 1) {
            LOGGER.warn("Expected username but only got keyword. Proceeding with username = null.");

            return;
        }

        String arguments = line.substring(keyword.length() + 1);
        userCommand.setArguments(arguments);
        userCommand.setUsername(lineContents[1]);

        if (lineContents.length > 2) {
            LOGGER.warn(
                    "Expected only keyword and username but got: "
                            + arguments
                            + ". '"
                            + lineContents[1]
                            + "' will be saved as username.");
        }
    }
}
