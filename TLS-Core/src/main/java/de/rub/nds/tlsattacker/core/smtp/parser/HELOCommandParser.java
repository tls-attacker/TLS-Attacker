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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELOCommand;

import java.io.InputStream;

public class HELOCommandParser extends SmtpCommandParser<SmtpHELOCommand> {
    public HELOCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpHELOCommand command, String arguments) {
        // just a domain
        if(arguments.contains(" ")) {
            throw new ParserException("HELO command must have exactly one argument");
        }
        command.setDomain(arguments);
    }

    @Override
    public boolean hasParameters() {
        return true;
    }
}
