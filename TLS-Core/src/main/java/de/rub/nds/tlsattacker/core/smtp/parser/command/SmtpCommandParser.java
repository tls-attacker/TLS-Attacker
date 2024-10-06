/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import java.io.InputStream;

public class SmtpCommandParser<CommandT extends SmtpCommand> extends SmtpMessageParser<CommandT> {

    public SmtpCommandParser(InputStream stream) {
        super(stream);
    }

    public void parse(CommandT smtpCommand) {
        // TODO: make this robust against not having CRLF, fails at the moment when no CR
        // parseStringTill(CRLF) is sadly not possible
        String line = parseSingleLine();
        // throws EndOfStreamException if no LF is found

        // 4.1.1 In the interest of improved interoperability, SMTP receivers SHOULD tolerate
        // trailing white space before the terminating <CRLF>.
        String actualCommand = line.trim();
        String[] verbAndParams = actualCommand.split(" ", 2);
        smtpCommand.setVerb(verbAndParams[0]);
        if (verbAndParams.length == 2) {
            smtpCommand.setParameters(verbAndParams[1]);
        }
        parseArguments(smtpCommand, smtpCommand.getParameters());
    }

    /**
     * Parses the arguments of the SmtpCommand. This method needs to be implemented by subclasses,
     * if the command has any arguments. Implementations should throw a ParserException if the
     * arguments are not valid. Implementors are responsible for checking arguments for nullness.
     *
     * @param command a CommandT object only partially initialized by Method parse
     * @param arguments parameter string containing everything after first space
     */
    public void parseArguments(CommandT command, String arguments) {}
}
