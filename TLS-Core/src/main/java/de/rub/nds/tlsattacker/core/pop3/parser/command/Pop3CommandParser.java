/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.pop3.command.MessageNumber;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parses Pop3Command from an InputStream. Simple parser to set command keyword and arguments.
 * Subclasses need to implement specific parsing for specific commands
 *
 * @param <CommandT> command to be parsed
 */
public class Pop3CommandParser<CommandT extends Pop3Command> extends Pop3MessageParser<CommandT> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructor for the Parser
     *
     * @param stream The Inputstream to read data from
     */
    public Pop3CommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Does general parsing of setting the keyword and arguments specific parsing of arguments is
     * implemented by specific command parser
     *
     * @param pop3Command Command that is parsed
     */
    public void parse(CommandT pop3Command) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ");

        String keyword = lineContents[0];
        pop3Command.setKeyword(keyword);

        if (lineContents.length == 1) return;

        String arguments = line.substring(keyword.length() + 1);
        pop3Command.setArguments(arguments);
        tryParseMessageNumber(pop3Command, lineContents[1]);

        // TODO: check whether there are multi-argument commands
        if (lineContents.length > 2) {
            LOGGER.warn(
                    "Expected one argument but got: "
                            + arguments
                            + ". The first argument will be treated as message number.");
        }
    }

    public void tryParseMessageNumber(CommandT command, String possibleMessageNumber) {
        if (!(command instanceof MessageNumber)) {
            LOGGER.warn(
                    "Expected no arguments but got at least: '"
                            + possibleMessageNumber
                            + "'. Arguments will be ignored.");
            return;
        }

        try {
            ((MessageNumber) command).setMessageNumber(Integer.parseInt(possibleMessageNumber));
        } catch (NumberFormatException ex) {
            throw new ParserException(
                    "Expected numeric message number but got: " + possibleMessageNumber);
        }
    }
}
