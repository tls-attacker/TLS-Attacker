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
import java.io.InputStream;

public class MAILCommandParser extends SmtpCommandParser<SmtpMAILCommand> {
    public MAILCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpMAILCommand command, String arguments) {
        command.setReversePath(arguments);
    }

    @Override
    public boolean hasParameters() {
        return true;
    }
}
