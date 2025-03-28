/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.parser.command;

import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3MessageNumber;
import de.rub.nds.tlsattacker.core.pop3.parser.Pop3MessageParser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parses Pop3Command from an InputStream. Simple parser to set command keyword and arguments.
 * Subclasses need to implement specific parsing for specific commands.
 *
 * @param <CommandT> command to be parsed
 */
public class Pop3CommandParser<CommandT extends Pop3Command> extends Pop3MessageParser<CommandT> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Pop3CommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Parses keyword and arguments of a reply. If the command is expected to contain a message
     * number, the message number will also be parsed.
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

        if (lineContents.length > 2) {
            LOGGER.warn(
                    "Expected one argument but got: "
                            + arguments
                            + ". The first argument will be treated as message number.");
        }
    }

    /**
     * As described in the Pop3MessageNumber Interface, this function will parse message numbers
     * regardless of which pop3 command is present. This is the central parsing functionality for
     * almost all implemented pop3 commands.
     *
     * @param command Any pop3 command.
     * @param possibleMessageNumber A string that may contain a message number.
     */
    public void tryParseMessageNumber(CommandT command, String possibleMessageNumber) {
        if (!(command instanceof Pop3MessageNumber)) {
            LOGGER.warn(
                    "Expected no arguments but got at least: '"
                            + possibleMessageNumber
                            + "'. Arguments will be ignored.");
            return;
        }

        try {
            ((Pop3MessageNumber) command).setMessageNumber(Integer.parseInt(possibleMessageNumber));
        } catch (NumberFormatException ex) {
            LOGGER.warn(
                    "Expected numeric message number but got: [ " + possibleMessageNumber + " ].");
        }
    }
}
