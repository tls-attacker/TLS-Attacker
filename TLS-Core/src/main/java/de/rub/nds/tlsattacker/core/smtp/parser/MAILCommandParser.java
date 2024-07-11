/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.extensions.SmtpServiceExtension;
import de.rub.nds.tlsattacker.core.smtp.parameters.SmtpParameters;
import java.io.InputStream;

public class MAILCommandParser extends SmtpCommandParser<SmtpMAILCommand> {
    public MAILCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpMAILCommand command, String arguments) {
        String[] parameters = arguments.split(" ", 2);
        if (!parameters[0].startsWith("<") || !parameters[0].endsWith(">")) {
            throw new IllegalArgumentException(
                    "Malformed MAIL Command - Invalid forward path <> is missing");
        }
        // routed email through reverse path, mostly deprecated ( [A-d-l ":"] in RFC 5321)
        String mailbox = parameters[0].replaceAll("[<>]", "");
        // check valid email here
        if (SmtpSyntaxParser.isValidMailbox(mailbox)) {
            command.setReversePath(parameters[0].replace("\"", ""));
            if (parameters.length > 1) {
                for (int i = 1; i < parameters.length; i++) {
                    String[] currentParameter = parameters[i].split(" ", 2);
                    if (!SmtpSyntaxParser.isValidSpecialParameter(currentParameter)) {
                        throw new IllegalArgumentException(
                                ("Malformed MAIL Command - invalid Special Parameter"));
                    }
                    currentParameter[1] = currentParameter[1].replaceAll("[\\[\\]]", "");
                    currentParameter[1] = currentParameter[1].replace("\"=\"", "");
                    SmtpServiceExtension extension =
                            SmtpSyntaxParser.parseKeyword(currentParameter[0], currentParameter[1]);
                    SmtpParameters MAILparameters =
                            new SmtpParameters(extension, currentParameter[1]);
                    command.getMAILparameters().add(MAILparameters);
                }
            }
        } else throwInvalidParameterException();
    }

    private void throwInvalidParameterException() {
        throw new IllegalArgumentException(
                "The MAIL-command parameter is invalid: "
                        + "It's not a valid mailbox or the input format is wrong");
    }

    @Override
    public boolean hasParameters() {
        return true;
    }
}
