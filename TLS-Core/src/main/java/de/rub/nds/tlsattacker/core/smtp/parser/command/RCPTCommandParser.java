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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRCPTCommand;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import de.rub.nds.tlsattacker.core.smtp.parser.SmtpSyntaxParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Parser to parse message into RCPT command, which contains the command, information
 * about the recipient (forward-path), and optional additional parameters. If the
 * recipient information has an invalid syntax, the validRecipient parameter is
 * set to False.
 * This is a simplified version where we do not specifically parse (deprecated) source routing forward paths.
 */
public class RCPTCommandParser extends SmtpCommandParser<SmtpRCPTCommand> {
    public RCPTCommandParser(InputStream stream) {
        super(stream);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Tries to parse the argument as recipient. Sets the validRecipient parameter to False
     * on failure
     *
     * @param command   Containing the recipient
     * @param arguments Arguments extracted from command
     */
    @Override
    public void parseArguments(SmtpRCPTCommand command, String arguments) {
        if (arguments == null) {
            throw new ParserException("RCPT command requires parameters.");
        }

        // recipients_string equals syntax: "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path
        if (arguments.startsWith("TO:")) {
            arguments = arguments.substring(arguments.indexOf("TO:") + 3);
        } else {
            LOGGER.warn("No \"TO:\" found in {}\n", arguments);
//            command.setValidRecipient(false);
            return;
        }

        String[] argumentsArray = arguments.split(" ");

        if (argumentsArray.length == 0) {
            LOGGER.warn("No recipients found in {}\n", arguments);
//            command.setValidRecipient(false);
            return;
        }
        // only one recipient
        //extract from < >
        if (argumentsArray[0].startsWith("<") && argumentsArray[0].endsWith(">")) {
            argumentsArray[0] = argumentsArray[0].substring(1, argumentsArray[0].length() - 1);
        }
        command.setRecipient(argumentsArray[0]);

        if(argumentsArray.length > 1) {
            // first is recipient, rest is rcpt-parameter
            command.setRcptParameters(new ArrayList<>(List.of(argumentsArray).subList(1, argumentsArray.length)));
        }
    }
}
