/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRCPTCommand;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RCPTCommandParser extends SmtpCommandParser<SmtpRCPTCommand> {
    public RCPTCommandParser(InputStream stream) {
        super(stream);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    public void parsePostmaster(SmtpRCPTCommand command) {
        String parameters = command.getParameters();
        String recipientsString =
                parameters.substring(parameters.indexOf("<") + 1, parameters.indexOf(">"));

        if (!command.getRecipient().isEmpty()) {
            // recipient is already set
            return;
        }

        if (SmtpSyntaxParser.isValidPostmaster(recipientsString)) {
            command.setRecipient(recipientsString);
        }
    }

    public void parseMailbox(SmtpRCPTCommand command) {
        String parameters = command.getParameters();
        String recipientsString =
                parameters.substring(parameters.indexOf("<") + 1, parameters.indexOf(">"));

        if (!command.getRecipient().isEmpty()) {
            // recipient is already set
            return;
        }

        if (SmtpSyntaxParser.isValidMailbox(recipientsString)) {
            command.setRecipient(recipientsString);
        }
    }

    public void parseIPAddress(SmtpRCPTCommand command) {
        String parameters = command.getParameters();
        String recipientsString =
                parameters.substring(parameters.indexOf("<") + 1, parameters.indexOf(">"));

        if (!command.getRecipient().isEmpty()) {
            // recipient is already set
            return;
        }

        if (SmtpSyntaxParser.isValidIPAddress(recipientsString)) {
            command.setRecipient(recipientsString);
        }
    }

    public void parseForwardPathStructure(SmtpRCPTCommand command) {
        String parameters = command.getParameters();
        String recipientsString =
                parameters.substring(parameters.indexOf("<") + 1, parameters.indexOf(">"));

        if (!command.getRecipient().isEmpty()) {
            // recipient is already set
            return;
        }

        if (SmtpSyntaxParser.isValidForwardPath(recipientsString)) {
            command.setRecipient(recipientsString);

            // extract hops
            String allHops = recipientsString.substring(0, recipientsString.indexOf(":"));
            command.setHops(allHops.split(","));
        }
    }

    @Override
    public void parseArguments(SmtpRCPTCommand command, String arguments) {
        if (arguments == null) {
            throw new ParserException("RCPT command requires parameters.");
        }
        // arguments = "RCPT TO:<@hosta.int,@jkl.org:userc@d.bar.org>\r\n";
        // recipients_string equals syntax: "<Postmaster@" Domain ">" / "<Postmaster>" /
        // Forward-path
        String parameters = command.getParameters();
        if (parameters.startsWith("TO:")) {
            parameters = parameters.substring(parameters.indexOf("TO:") + 3);
            command.setParameters(parameters);
        } else {
            LOGGER.warn("No \"TO:\" found in {}\n", parameters);
            command.setValidRecipient(false);
            return;
        }

        // try parsing different possible syntax
        parsePostmaster(command);
        parseMailbox(command);
        parseIPAddress(command);
        parseForwardPathStructure(command);

        if (command.getRecipient().isEmpty()) {
            // save not correctly parseable string as recipient
            command.setValidRecipient(false);
            command.setRecipient(command.getParameters());

            // Output failed parsing
            LOGGER.warn("Not able to parse recipients from {}\n", command.getParameters());
        } else {
            command.setValidRecipient(true);

            // Output the parsed recipient list
            LOGGER.warn("Parsed from {}\n{}\n", command.getParameters(), command.getRecipient());
        }
    }
}
