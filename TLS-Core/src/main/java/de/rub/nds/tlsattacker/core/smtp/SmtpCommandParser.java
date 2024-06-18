/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import java.io.InputStream;

public class SmtpCommandParser<CommandT extends SmtpCommand> extends SmtpMessageParser<CommandT> {

    private static final byte SP = 0x20;
    private static final byte CR = 0x0D;
    private static final byte LF = 0x0A;

    public SmtpCommandParser(InputStream stream) {
        super(stream);
    }

    public void parse(CommandT smtpCommand) {
        // TODO: make this robust against not having CRLF, fails at the moment when no CR
        // parseStringTill(CRLF) is sadly not possible
        String untilLF = parseStringTill(LF);
        // throws EndOfStreamException if no LF is found

        if (getBytesLeft() > 0) {
            throw new ParserException(
                    "Could not parse as SmtpCommand: Multiple commands in one message are not supported");
        }
        if (!untilLF.endsWith("\r\n")) {
            throw new ParserException(
                    "Could not parse as SmtpCommand: Command does not end with CRLF");
        }
        // 4.1.1 In the interest of improved interoperability, SMTP receivers SHOULD tolerate
        // trailing white space before the terminating <CRLF>.
        String actualCommand = untilLF.substring(0, untilLF.length() - 2).trim();
        if (hasParameters()) {
            if (!actualCommand.contains(" ")) {
                throw new ParserException(
                        "Command does not contain any arguments although it was expected");
            }
            String[] verbAndParams = actualCommand.split(" ", 2);
            smtpCommand.setVerb(verbAndParams[0]);
            smtpCommand.setParameters(verbAndParams[1]);
            parseArguments(smtpCommand, verbAndParams[1]);
        } else {
            smtpCommand.setVerb(actualCommand);
        }
    }
    /**
     * Parses the arguments of the SmtpCommand. This method needs to be implemented by subclasses,
     * if the command has any arguments.
     * Is only called if hasArguments() evaluates as true.
     *
     * @param command a CommandT object only partially initialized by Method parse
     * @param arguments parameter string containing everything after first space
     */
    public void parseArguments(CommandT command, String arguments) {
        throw new UnsupportedOperationException(
                "You need to subclass SmtpCommandParser and implement this method, if the command has any arguments.");
    }

    /**
     * Evaluate whether the command type to be parsed expects parameters
     * You need to subclass SmtpCommandParser and implement this method, if the command has any
     * arguments.
     *
     * @return true if parsed command expects parameters; false otherwise
     */
    public boolean hasParameters() {
        return false;
    }
}
