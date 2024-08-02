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

/**
 * Parser to parse message into RCPT command, which contains the command, information
 * about the recipient (forward-path), and optional additional parameters. If the
 * recipient information has an invalid syntax, the validRecipient parameter is
 * set to False.
 */
public class RCPTCommandParser extends SmtpCommandParser<SmtpRCPTCommand> {
    public RCPTCommandParser(InputStream stream) {
        super(stream);
    }

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Tries to parse the argument as postmaster.
     *
     * @param command Containing the recipient
     */
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

    /**
     * Tries to parse the argument as mailbox.
     *
     * @param command Containing the recipient
     */
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

    /**
     * Tries to parse the argument as IP address.
     *
     * @param command Containing the recipient
     */
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

    /**
     * Tries to parse the argument as forward-path.
     *
     * @param command Containing the recipient
     */
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

    /**
     * Tries to parse the argument as recipient. Sets the validRecipient parameter to False
     * on failure
     *
     * @param command Containing the recipient
     * @param arguments Arguments extracted from command
     */
    @Override
    public void parseArguments(SmtpRCPTCommand command, String arguments) {
        if (arguments == null) {
            throw new ParserException("RCPT command requires parameters.");
        }

        // recipients_string equals syntax: "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path
        String parameters = command.getParameters();
        if (parameters.startsWith("TO:")) {
            parameters = parameters.substring(parameters.indexOf("TO:") + 3);
            command.setParameters(parameters);
        } else {
            LOGGER.warn("No \"TO:\" found in {}\n", parameters);
            command.setValidRecipient(false);
            return;
        }

        // try parsing different possible syntaxes
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
            // argument is correctly parsed
            command.setValidRecipient(true);

            // Output the parsed recipient list
            LOGGER.warn("Parsed from {}\n{}\n", command.getParameters(), command.getRecipient());
        }
    }
}
