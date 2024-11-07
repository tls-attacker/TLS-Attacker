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

/**
 * Parses Pop3Command from an InputStream. Simple parser to set command keyword and arguments.
 * Subclasses need to implement specific parsing for specific commands
 *
 * @param <CommandT> command to be parsed
 */
public class Pop3CommandParser<CommandT extends Pop3Command> extends Pop3MessageParser<CommandT> {

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
        String[] lineContents = line.split(" ", 2);
        pop3Command.setKeyword(lineContents[0]);
        if (lineContents.length == 2) {
            pop3Command.setArguments(lineContents[1]);
        }
        parseArguments(pop3Command, pop3Command.getArguments());
    }

    /**
     * Parse arguments of Pop3Command. Subclass needs to implement this method. For invalid
     * arguments a ParserException should be thrown
     *
     * @param command pop3Command to parse arguments for
     * @param arguments arguments string containing everything after first space
     */
    public void parseArguments(CommandT command, String arguments) {
        String[] args = arguments.split(" ");
        String keyword = args[0];

        if (!command.getCommandName().equals(keyword))
            throw new ParserException("Unexpected keyword. Expected: '" + command.getCommandName() + "'. Got: '" + keyword + "'.");

        if (!(command instanceof MessageNumber) || args.length < 2) return;

        String messageNumber = args[1];
        try {
            ((MessageNumber) command).setMessageNumber(Integer.parseInt(messageNumber));
        } catch (NumberFormatException ex) {
            throw new ParserException("Expected numeric message number but got: " + messageNumber);
        }
    }
}
