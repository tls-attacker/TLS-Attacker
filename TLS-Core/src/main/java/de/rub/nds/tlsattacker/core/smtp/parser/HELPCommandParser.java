/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELPCommand;
import org.bouncycastle.util.IPAddress;

import java.io.InputStream;

/**
 * Parser to parse message into HELP command, which contains the command and
 * optionally a subject as for example the name of a command.
 */
public class HELPCommandParser extends SmtpCommandParser<SmtpHELPCommand> {
    public HELPCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpHELPCommand command, String arguments) {
        if (arguments == null || arguments.isEmpty()){
            command.setSubject("");
        }
        else{
            command.setSubject(arguments);
        }
        command.setValidParsing(true);
    }
}
