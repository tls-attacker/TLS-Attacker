/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;
import java.io.InputStream;

public class SmtpVRFYCommandParser extends SmtpCommandParser<SmtpVRFYCommand> {
    public SmtpVRFYCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpVRFYCommand command, String parameter) {
        if (parameter == null) throw new ParserException("VRFY-parameter must not be empty.");

        command.setUsername(parameter);
    }
}
