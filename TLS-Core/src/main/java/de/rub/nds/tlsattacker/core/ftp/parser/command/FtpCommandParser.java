/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.parser.command;

import de.rub.nds.tlsattacker.core.ftp.command.FtpCommand;
import de.rub.nds.tlsattacker.core.ftp.parser.FtpMessageParser;
import java.io.InputStream;

/**
 * Parses an FtpCommand from an InputStream. Sets the command keyword and arguments. Subclasses may
 * implement specific parsing for individual commands.
 *
 * @param <CommandT> command to be parsed
 */
public class FtpCommandParser<CommandT extends FtpCommand> extends FtpMessageParser<CommandT> {

    public FtpCommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Parses keyword and arguments of a command.
     *
     * @param ftpCommand Command that is parsed
     */
    public void parse(CommandT ftpCommand) {
        String line = parseSingleLine();
        String[] lineContents = line.split(" ", 2);

        String keyword = lineContents[0];

        if (lineContents.length == 1) {
            return;
        }

        ftpCommand.setArguments(lineContents[1]);
        if (line.length() <= keyword.length()) {
            LOGGER.warn("Expected arguments after keyword '{}' but found none.", keyword);
        }
    }
}
